/**
 * Git Authorization Routes
 *
 * Passkey-protected git repo linking for Web Locked tier.
 * Prevents a compromised API from linking malicious repos without user verification.
 *
 * Endpoints:
 * - POST /_auth/git/authorize-link     - Authorize git link (requires passkey session + PoP)
 * - POST /_auth/git/verify-link-token  - Verify link token (called by platform API)
 * - POST /_auth/git/authorize-unlink   - Authorize git unlink (requires passkey session + PoP)
 * - POST /_auth/git/verify-unlink-token - Verify unlink token (called by platform API)
 */

import type { Hono, Context } from 'hono';
import crypto from 'crypto';
import fs from 'fs';
import { TIER_FILE } from '../config';
import { getDeviceFingerprint, getClientIp } from '../auth/fingerprint';
import { validateSession } from '../auth/session';
import type { Session } from '../auth/session';
import { verifyRequestPoP } from '../auth/pop';
import { db } from '../database';
import { logAuditEvent } from '../services/audit.service';
import { parseCookies } from '../utils/cookie';

// ============================================
// IN-MEMORY TOKEN STORE
// ============================================

interface GitLinkToken {
  repoFullName: string;
  provider: string;
  expiresAt: number;
}

interface GitUnlinkToken {
  expiresAt: number;
}

const gitLinkTokens = new Map<string, GitLinkToken>();
const gitUnlinkTokens = new Map<string, GitUnlinkToken>();

const TOKEN_TTL_MS = 60_000; // 60 seconds

// Cleanup expired tokens every 60s
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of gitLinkTokens) {
    if (data.expiresAt < now) gitLinkTokens.delete(token);
  }
  for (const [token, data] of gitUnlinkTokens) {
    if (data.expiresAt < now) gitUnlinkTokens.delete(token);
  }
}, 60_000);

// ============================================
// HELPERS
// ============================================

function getCurrentTier(): string {
  try {
    return fs.readFileSync(TIER_FILE, 'utf8').trim();
  } catch {
    return 'standard';
  }
}

function requirePasskeySession(c: Context): { valid: boolean; sessionId?: string } {
  const cookies = parseCookies(c.req.header('cookie'));
  const sessionId = cookies.shield_session;

  if (!sessionId) {
    return { valid: false };
  }

  const ip = getClientIp(c);
  const fingerprintData = getDeviceFingerprint(c);
  const result = validateSession(sessionId, ip, fingerprintData, c.req.path);

  if (!result.valid) {
    return { valid: false };
  }

  return { valid: true, sessionId };
}

// ============================================
// ROUTES
// ============================================

export function registerGitRoutes(app: Hono): void {

  /**
   * Authorize a git repo link.
   * Requires passkey session + PoP. Only enforced for web_locked tier.
   */
  app.post('/_auth/git/authorize-link', async (c) => {
    const tier = getCurrentTier();

    // Non-web_locked tiers don't need authorization
    if (tier !== 'web_locked') {
      return c.json({ authorized: true, token: null });
    }

    // Require passkey session
    const session = requirePasskeySession(c);
    if (!session.valid) {
      return c.json({ error: 'Authentication required', needsAuth: true }, 401);
    }

    // Require Proof-of-Possession
    const sessionRecord = db.prepare('SELECT * FROM sessions WHERE id = ?').get(session.sessionId) as Session | undefined;
    if (!sessionRecord) {
      return c.json({ error: 'Invalid session' }, 401);
    }
    if (!sessionRecord.pop_public_key) {
      return c.json({ error: 'Session not fully initialized', reason: 'pop_not_bound' }, 401);
    }
    const popResult = await verifyRequestPoP(c, sessionRecord);
    if (!popResult.valid) {
      logAuditEvent({
        type: 'git_link_pop_failed',
        ip: getClientIp(c),
        fingerprint: getDeviceFingerprint(c).hash,
        sessionId: sessionRecord.id,
        details: { reason: popResult.reason },
      });
      return c.json({ error: 'PoP validation failed', reason: popResult.reason }, 401);
    }

    const body = await c.req.json() as {
      repoFullName?: string;
      provider?: string;
    };

    if (!body.repoFullName || !body.provider) {
      return c.json({ error: 'repoFullName and provider are required' }, 400);
    }

    const validProviders = ['github', 'gitlab', 'bitbucket'];
    if (!validProviders.includes(body.provider)) {
      return c.json({ error: 'Invalid provider' }, 400);
    }

    // Generate single-use token bound to this repo
    const token = crypto.randomBytes(32).toString('hex');
    gitLinkTokens.set(token, {
      repoFullName: body.repoFullName,
      provider: body.provider,
      expiresAt: Date.now() + TOKEN_TTL_MS,
    });

    logAuditEvent({
      type: 'git_link_authorized',
      ip: getClientIp(c),
      fingerprint: getDeviceFingerprint(c).hash,
      details: {
        repoFullName: body.repoFullName,
        provider: body.provider,
      },
    });

    return c.json({
      authorized: true,
      token,
      expiresIn: TOKEN_TTL_MS / 1000,
    });
  });

  /**
   * Verify a git link token. Called by the platform API over TLS.
   * No session required — trusts TLS + token validity.
   */
  app.post('/_auth/git/verify-link-token', async (c) => {
    const body = await c.req.json() as {
      token?: string;
      repoFullName?: string;
      provider?: string;
    };

    if (!body.token || !body.repoFullName || !body.provider) {
      return c.json({ valid: false, error: 'missing_fields' });
    }

    // Look up and delete immediately (single-use)
    const stored = gitLinkTokens.get(body.token);
    gitLinkTokens.delete(body.token);

    if (!stored) {
      return c.json({ valid: false, error: 'invalid_token' });
    }

    if (Date.now() > stored.expiresAt) {
      return c.json({ valid: false, error: 'expired' });
    }

    if (stored.repoFullName !== body.repoFullName) {
      logAuditEvent({
        type: 'git_link_token_mismatch',
        ip: getClientIp(c),
        details: {
          expected: stored.repoFullName,
          received: body.repoFullName,
        },
      });
      return c.json({ valid: false, error: 'repo_mismatch' });
    }

    if (stored.provider !== body.provider) {
      return c.json({ valid: false, error: 'provider_mismatch' });
    }

    logAuditEvent({
      type: 'git_link_token_verified',
      ip: getClientIp(c),
      details: {
        repoFullName: body.repoFullName,
        provider: body.provider,
      },
    });

    return c.json({
      valid: true,
      repoFullName: body.repoFullName,
      provider: body.provider,
    });
  });

  /**
   * Authorize a git repo unlink.
   * Requires passkey session + PoP. Only enforced for web_locked tier.
   */
  app.post('/_auth/git/authorize-unlink', async (c) => {
    const tier = getCurrentTier();

    if (tier !== 'web_locked') {
      return c.json({ authorized: true, token: null });
    }

    const session = requirePasskeySession(c);
    if (!session.valid) {
      return c.json({ error: 'Authentication required', needsAuth: true }, 401);
    }

    // Require Proof-of-Possession
    const sessionRecord = db.prepare('SELECT * FROM sessions WHERE id = ?').get(session.sessionId) as Session | undefined;
    if (!sessionRecord) {
      return c.json({ error: 'Invalid session' }, 401);
    }
    if (!sessionRecord.pop_public_key) {
      return c.json({ error: 'Session not fully initialized', reason: 'pop_not_bound' }, 401);
    }
    const popResult = await verifyRequestPoP(c, sessionRecord);
    if (!popResult.valid) {
      logAuditEvent({
        type: 'git_unlink_pop_failed',
        ip: getClientIp(c),
        fingerprint: getDeviceFingerprint(c).hash,
        sessionId: sessionRecord.id,
        details: { reason: popResult.reason },
      });
      return c.json({ error: 'PoP validation failed', reason: popResult.reason }, 401);
    }

    const token = crypto.randomBytes(32).toString('hex');
    gitUnlinkTokens.set(token, {
      expiresAt: Date.now() + TOKEN_TTL_MS,
    });

    logAuditEvent({
      type: 'git_unlink_authorized',
      ip: getClientIp(c),
      fingerprint: getDeviceFingerprint(c).hash,
      details: {},
    });

    return c.json({
      authorized: true,
      token,
      expiresIn: TOKEN_TTL_MS / 1000,
    });
  });

  /**
   * Verify a git unlink token. Called by the platform API over TLS.
   */
  app.post('/_auth/git/verify-unlink-token', async (c) => {
    const body = await c.req.json() as {
      token?: string;
    };

    if (!body.token) {
      return c.json({ valid: false, error: 'missing_token' });
    }

    const stored = gitUnlinkTokens.get(body.token);
    gitUnlinkTokens.delete(body.token);

    if (!stored) {
      return c.json({ valid: false, error: 'invalid_token' });
    }

    if (Date.now() > stored.expiresAt) {
      return c.json({ valid: false, error: 'expired' });
    }

    logAuditEvent({
      type: 'git_unlink_token_verified',
      ip: getClientIp(c),
      details: {},
    });

    return c.json({ valid: true });
  });
}
