/**
 * Secrets Routes
 *
 * Environment secrets management — decrypt and write to .ellulai-env.
 * Secrets arrive encrypted (RSA-OAEP + AES-256-GCM) from the browser
 * and are decrypted locally using the VPS private key.
 *
 * Endpoints:
 * - GET    /_auth/secrets       - List secret names (no values)
 * - POST   /_auth/secrets       - Set a single secret
 * - POST   /_auth/secrets/bulk  - Set multiple secrets atomically
 * - DELETE /_auth/secrets/:name - Delete a secret
 */

import type { Hono, Context } from 'hono';
import type { SecurityTier } from '../config';
import { getDeviceFingerprint, getClientIp } from '../auth/fingerprint';
import { validateSession } from '../auth/session';
import { verifyJwtToken } from '../auth/jwt';
import { getCurrentTier } from '../services/tier.service';
import { logAuditEvent } from '../services/audit.service';
import { checkApiRateLimit } from '../services/rate-limiter';
import { parseCookies } from '../utils/cookie';
import {
  setSecret,
  setSecretsBulk,
  deleteSecret,
  listSecrets,
  type EncryptedEnvelope,
} from '../services/secrets.service';

const SECRET_NAME_REGEX = /^_*[A-Z][A-Z0-9_]*$/;

interface AuthResult {
  authenticated: boolean;
  error?: string;
  method?: 'passkey' | 'jwt';
  tier: SecurityTier;
}

/**
 * Check authentication for secrets management.
 * All tiers can manage secrets:
 * - web_locked: passkey session
 * - standard: JWT token
 */
function checkAuth(c: Context): AuthResult {
  const currentTier = getCurrentTier();
  const ip = getClientIp(c);

  // Web Locked: validate passkey session
  if (currentTier === 'web_locked') {
    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;
    if (sessionId) {
      const fingerprintData = getDeviceFingerprint(c);
      const result = validateSession(sessionId, ip, fingerprintData, '/_auth/secrets');
      if (result.valid) {
        return { authenticated: true, method: 'passkey', tier: currentTier };
      }
    }
    return { authenticated: false, error: 'Passkey authentication required', tier: currentTier };
  }

  // Standard: validate JWT — pass the HonoRequest, not the raw token string
  const decoded = verifyJwtToken(c.req);
  if (decoded) {
    return { authenticated: true, method: 'jwt', tier: currentTier };
  }

  return { authenticated: false, error: 'Authentication required', tier: currentTier };
}

function validateEnvelope(body: any): body is EncryptedEnvelope {
  return (
    typeof body?.encryptedKey === 'string' &&
    typeof body?.iv === 'string' &&
    typeof body?.encryptedData === 'string'
  );
}

/**
 * Register secrets routes on Hono app
 */
export function registerSecretsRoutes(app: Hono): void {

  /**
   * List secret names (no values exposed)
   */
  app.get('/_auth/secrets', async (c) => {
    const ip = getClientIp(c);
    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const auth = checkAuth(c);
    if (!auth.authenticated) {
      return c.json({ error: auth.error }, 401);
    }

    const names = listSecrets();
    return c.json({ names });
  });

  /**
   * Set a single secret
   */
  app.post('/_auth/secrets', async (c) => {
    const ip = getClientIp(c);
    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const auth = checkAuth(c);
    if (!auth.authenticated) {
      return c.json({ error: auth.error }, 401);
    }

    const body = await c.req.json().catch(() => null);
    if (!body || typeof body.name !== 'string') {
      return c.json({ error: 'Missing name' }, 400);
    }

    if (!SECRET_NAME_REGEX.test(body.name)) {
      return c.json({ error: 'Invalid name. Must match ^_*[A-Z][A-Z0-9_]*$' }, 400);
    }

    if (!validateEnvelope(body)) {
      return c.json({ error: 'Missing encrypted envelope fields (encryptedKey, iv, encryptedData)' }, 400);
    }

    try {
      setSecret(body.name, body);
      logAuditEvent({ type: 'secret_set', ip, details: { name: body.name } });
      return c.json({ success: true });
    } catch (err) {
      logAuditEvent({ type: 'secret_set_failed', ip, details: { name: body.name, error: (err as Error).message } });
      return c.json({ error: 'Failed to set secret' }, 500);
    }
  });

  /**
   * Set multiple secrets atomically
   */
  app.post('/_auth/secrets/bulk', async (c) => {
    const ip = getClientIp(c);
    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const auth = checkAuth(c);
    if (!auth.authenticated) {
      return c.json({ error: auth.error }, 401);
    }

    const body = await c.req.json().catch(() => null);
    if (!body || !Array.isArray(body.secrets)) {
      return c.json({ error: 'Missing secrets array' }, 400);
    }

    const items: Array<{ name: string; envelope: EncryptedEnvelope }> = [];
    for (const secret of body.secrets) {
      if (typeof secret.name !== 'string' || !SECRET_NAME_REGEX.test(secret.name)) {
        return c.json({ error: `Invalid name: ${secret.name}` }, 400);
      }
      if (!validateEnvelope(secret)) {
        return c.json({ error: `Missing envelope for ${secret.name}` }, 400);
      }
      items.push({ name: secret.name, envelope: secret });
    }

    try {
      setSecretsBulk(items);
      logAuditEvent({ type: 'secrets_bulk_set', ip, details: { count: items.length, names: items.map(i => i.name) } });
      return c.json({ success: true, count: items.length });
    } catch (err) {
      logAuditEvent({ type: 'secrets_bulk_set_failed', ip, details: { error: (err as Error).message } });
      return c.json({ error: 'Failed to set secrets' }, 500);
    }
  });

  /**
   * Delete a secret
   */
  app.delete('/_auth/secrets/:name', async (c) => {
    const ip = getClientIp(c);
    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const auth = checkAuth(c);
    if (!auth.authenticated) {
      return c.json({ error: auth.error }, 401);
    }

    const name = c.req.param('name');
    const existed = deleteSecret(name);

    logAuditEvent({ type: 'secret_deleted', ip, details: { name, existed } });
    return c.json({ success: true, existed });
  });
}
