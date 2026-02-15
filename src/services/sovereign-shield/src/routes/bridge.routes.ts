/**
 * Bridge Routes
 *
 * Platform bridge API for postMessage communication with the dashboard.
 * Enables the dashboard to manage security settings via hidden iframe.
 *
 * Endpoints:
 * - GET  /_auth/bridge                         - Bridge HTML page (postMessage communication)
 * - GET  /_auth/bridge/session                 - Check session (JSON response)
 * - GET  /_auth/bridge/keys                    - Get SSH keys
 * - GET  /_auth/bridge/passkeys                - Get passkeys
 * - GET  /_auth/bridge/tier                    - Get tier info and owner ID
 * - DELETE /_auth/bridge/passkey/:credentialId - Remove passkey
 * - POST /_auth/bridge/upgrade-to-web-locked   - Upgrade from Standard
 * - POST /_auth/bridge/downgrade-to-standard   - Downgrade from Web Locked
 * - POST /_auth/bridge/switch-tier             - Switch security tier
 * - GET  /_auth/bridge/settings               - Get local settings state
 * - POST /_auth/bridge/toggle-terminal        - Toggle terminal (passkey-only)
 * - POST /_auth/bridge/toggle-ssh             - Toggle SSH (passkey-only)
 * - POST /_auth/bridge/kill-ports             - Kill processes on dev ports (passkey-only)
 * - POST /_auth/bridge/git-action             - Execute git operation (passkey-only)
 * - POST /_auth/bridge/switch-deployment      - Switch deployment model (passkey-only)
 * - POST /_auth/bridge/confirm-infra          - Get infra confirmation token (passkey-only)
 * - GET  /_auth/bridge/audit-log             - Read cryptographic audit log (passkey-only)
 * - POST /_internal/validate-infra-token      - Validate infra token (localhost-only)
 */

import type { Hono } from 'hono';
import fs from 'fs';
import BRIDGE_HTML from '../static/bridge-page.html';
import { db } from '../database';
import { SSH_AUTH_KEYS_PATH } from '../config';
import { getDeviceFingerprint, getClientIp } from '../auth/fingerprint';
import { validateSession, refreshSession, setSessionCookie } from '../auth/session';
import type { Session } from '../auth/session';
import { verifyRequestPoP } from '../auth/pop';
import { logAuditEvent } from '../services/audit.service';
import { checkApiRateLimit } from '../services/rate-limiter';
import {
  getCurrentTier,
  executeTierSwitch,
  notifyPlatformPasskeyRemoved,
  notifyPlatformSettingsChange,
  notifyPlatformHeartbeatKeyReset,
} from '../services/tier.service';
import { readSettings, applyTierOverrides, toggleTerminal, toggleSsh } from '../services/settings.service';
import { killPorts, DEV_PORTS } from '../services/process.service';
import { executeGitAction, type GitAction } from '../services/git.service';
import { switchDeployment, type DeploymentSwitchOpts } from '../services/deployment.service';
import { getSshKeys } from './keys.routes';
import { parseCookies } from '../utils/cookie';
import { createConfirmation, validateConfirmation } from '../services/infra-confirm.service';
import { cryptoAudit, readAuditLog, getChainHead } from '../services/crypto-audit.service';

/**
 * Register bridge routes on Hono app
 */
export function registerBridgeRoutes(app: Hono, hostname: string): void {

  /**
   * Bridge HTML page - hidden iframe for postMessage communication
   */
  app.get('/_auth/bridge', async (c) => {
    c.header('Cache-Control', 'no-store, no-cache, must-revalidate');
    c.header('Pragma', 'no-cache');
    const tier = getCurrentTier();
    return c.html(BRIDGE_HTML.replace('__SECURITY_TIER__', tier));
  });

  /**
   * Bridge API: Check session (JSON response, not redirect)
   */
  app.get('/_auth/bridge/session', async (c) => {
    const ip = getClientIp(c);

    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;

    if (!sessionId) {
      return c.json({ error: 'No session' }, 401);
    }

    const fingerprintData = getDeviceFingerprint(c);
    const result = validateSession(sessionId, ip, fingerprintData, '/_auth/bridge/session');

    if (!result.valid) {
      return c.json({ error: 'Invalid session', reason: result.reason }, 401);
    }

    // Refresh session
    const refresh = refreshSession(result.session!, ip, fingerprintData);
    if (refresh.rotated) {
      setSessionCookie(c, refresh.sessionId, hostname);
    }

    return c.json({ valid: true });
  });

  /**
   * Bridge API: Get SSH keys (JSON response)
   */
  app.get('/_auth/bridge/keys', async (c) => {
    const ip = getClientIp(c);

    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;

    if (!sessionId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const fingerprintData = getDeviceFingerprint(c);
    const result = validateSession(sessionId, ip, fingerprintData, '/_auth/bridge/keys');

    if (!result.valid) {
      return c.json({ error: 'Session expired' }, 401);
    }

    const keys = getSshKeys();
    return c.json(keys);
  });

  /**
   * Bridge API: Get passkeys (JSON response)
   */
  app.get('/_auth/bridge/passkeys', async (c) => {
    const ip = getClientIp(c);

    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;

    if (!sessionId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const fingerprintData = getDeviceFingerprint(c);
    const result = validateSession(sessionId, ip, fingerprintData, '/_auth/bridge/passkeys');

    if (!result.valid) {
      return c.json({ error: 'Session expired' }, 401);
    }

    const passkeys = db.prepare('SELECT id, name, createdAt FROM credential').all() as Array<{
      id: string;
      name: string | null;
      createdAt: number;
    }>;
    return c.json(passkeys.map(p => ({
      id: p.id,
      name: p.name || 'Passkey',
      registeredAt: p.createdAt,
    })));
  });

  /**
   * Bridge API: Get current tier info and owner ID
   * SECURITY: Owner ID from immutable owner.lock is used by platform to verify ownership
   * SECURITY: Requires valid session for detailed info (keys, passkeys).
   *   Tier + ownerId are always included in the response body (even on 401)
   *   so the platform bridge can verify server security without a browser session.
   */
  app.get('/_auth/bridge/tier', async (c) => {
    const ip = getClientIp(c);

    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const tier = getCurrentTier();

    // Read owner ID from immutable lock file (Identity Pinning)
    let ownerId = null;
    try {
      ownerId = fs.readFileSync('/etc/ellulai/owner.lock', 'utf8').trim();
    } catch {
      // owner.lock doesn't exist (shouldn't happen in production)
    }

    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;

    if (!sessionId) {
      return c.json({ error: 'Authentication required', tier }, 401);
    }

    const fingerprintData = getDeviceFingerprint(c);
    const result = validateSession(sessionId, ip, fingerprintData, '/_auth/bridge/tier');

    if (!result.valid) {
      return c.json({ error: 'Session invalid or expired', tier }, 401);
    }

    const sshKeys = getSshKeys();
    const passkeys = db.prepare('SELECT id FROM credential').all();

    return c.json({
      tier,
      ownerId,
      sshKeyCount: sshKeys.length,
      passkeyCount: passkeys.length,
      sshKeys,
      passkeys: passkeys.map((p: any) => ({ id: p.id })),
    });
  });

  /**
   * Bridge API: Remove passkey
   */
  app.delete('/_auth/bridge/passkey/:credentialId', async (c) => {
    const ip = getClientIp(c);

    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;

    if (!sessionId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const fingerprintData = getDeviceFingerprint(c);
    const result = validateSession(sessionId, ip, fingerprintData, '/_auth/bridge/passkey');

    if (!result.valid) {
      return c.json({ error: 'Session expired' }, 401);
    }

    const credentialId = c.req.param('credentialId');

    // Don't allow removing the last passkey in Web Locked mode
    const tier = getCurrentTier();
    const passkeys = db.prepare('SELECT id FROM credential').all();
    if (tier === 'web_locked' && passkeys.length <= 1) {
      return c.json({ error: 'Cannot remove the last passkey in Web Locked mode' }, 400);
    }

    // Get passkey name before deletion for notification
    const passkey = db.prepare('SELECT name FROM credential WHERE id = ?').get(credentialId) as { name: string | null } | undefined;
    const passkeyName = passkey?.name || 'Passkey';

    // Remove the passkey
    db.prepare('DELETE FROM credential WHERE id = ?').run(credentialId);

    logAuditEvent({
      type: 'passkey_removed',
      ip,
      details: { credentialId }
    });

    // Notify platform
    await notifyPlatformPasskeyRemoved(credentialId, passkeyName);

    return c.json({ success: true, credentialId });
  });

  /**
   * Bridge API: Upgrade from Standard to Web Locked
   */
  app.post('/_auth/bridge/upgrade-to-web-locked', async (c) => {
    const ip = getClientIp(c);

    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;

    if (!sessionId) {
      return c.json({ error: 'Unauthorized - passkey registration required first' }, 401);
    }

    const fingerprintData = getDeviceFingerprint(c);
    const result = validateSession(sessionId, ip, fingerprintData, '/_auth/bridge/upgrade-to-web-locked');

    if (!result.valid) {
      return c.json({ error: 'Session expired' }, 401);
    }

    const currentTier = getCurrentTier();
    if (currentTier !== 'standard') {
      return c.json({ error: 'Can only upgrade to Web Locked from Standard tier' }, 400);
    }

    // Verify we have at least one passkey registered
    const passkeys = db.prepare('SELECT id FROM credential').all();
    if (passkeys.length === 0) {
      return c.json({ error: 'At least one passkey must be registered first' }, 400);
    }

    // Check for SSH keys as recovery backup
    const hasSSHKeys = fs.existsSync(SSH_AUTH_KEYS_PATH) &&
      fs.readFileSync(SSH_AUTH_KEYS_PATH, 'utf8').trim().length > 0;

    // If no SSH keys, require explicit acknowledgment of permanent lockout risk
    const body = await c.req.json().catch(() => ({})) as { acknowledgeNoRecovery?: boolean };
    if (!hasSSHKeys && !body.acknowledgeNoRecovery) {
      return c.json({
        error: 'No SSH keys configured',
        warning: 'PERMANENT LOCKOUT RISK: You have no SSH keys. If you lose your passkey device, you will permanently lose access to this server. There is NO recovery path.',
        requiresAcknowledgment: true,
        hint: 'Add an SSH key first, or set acknowledgeNoRecovery: true to proceed at your own risk',
      }, 400);
    }

    // Execute the tier upgrade
    try {
      await executeTierSwitch('web_locked', ip, c.req.header('user-agent') || 'unknown');
      return c.json({ success: true, tier: 'web_locked' });
    } catch (e) {
      return c.json({ error: (e as Error).message || 'Failed to upgrade to Web Locked' }, 500);
    }
  });

  /**
   * Bridge API: Downgrade from Web Locked to Standard
   */
  app.post('/_auth/bridge/downgrade-to-standard', async (c) => {
    const ip = getClientIp(c);

    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;

    if (!sessionId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const fingerprintData = getDeviceFingerprint(c);
    const result = validateSession(sessionId, ip, fingerprintData, '/_auth/bridge/downgrade-to-standard');

    if (!result.valid) {
      return c.json({ error: 'Session expired' }, 401);
    }

    const currentTier = getCurrentTier();
    if (currentTier !== 'web_locked') {
      return c.json({ error: 'Can only downgrade to Standard from Web Locked tier' }, 400);
    }

    // Web Locked: Require Proof-of-Possession for tier downgrade
    const sessionRecord = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId) as Session | undefined;
    if (!sessionRecord) {
      return c.json({ error: 'Invalid session' }, 401);
    }
    if (!sessionRecord.pop_public_key) {
      return c.json({ error: 'Session not fully initialized', reason: 'pop_not_bound' }, 401);
    }
    const popResult = await verifyRequestPoP(c, sessionRecord);
    if (!popResult.valid) {
      logAuditEvent({
        type: 'downgrade_pop_failed',
        ip,
        fingerprint: fingerprintData.hash,
        sessionId: sessionRecord.id,
        details: { reason: popResult.reason },
      });
      return c.json({ error: 'PoP validation failed', reason: popResult.reason }, 401);
    }

    // Execute the tier downgrade
    try {
      await executeTierSwitch('standard', ip, c.req.header('user-agent') || 'unknown');
      return c.json({ success: true, tier: 'standard' });
    } catch (e) {
      return c.json({ error: (e as Error).message || 'Failed to downgrade to Standard' }, 500);
    }
  });

  /**
   * Bridge API: Switch security tier
   */
  app.post('/_auth/bridge/switch-tier', async (c) => {
    const ip = getClientIp(c);

    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;

    if (!sessionId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const fingerprintData = getDeviceFingerprint(c);
    const result = validateSession(sessionId, ip, fingerprintData, '/_auth/bridge/switch-tier');

    if (!result.valid) {
      return c.json({ error: 'Session expired' }, 401);
    }

    const body = await c.req.json() as { targetTier?: string; acknowledgeNoRecovery?: boolean };
    const { targetTier } = body;

    if (!targetTier || !['standard', 'web_locked'].includes(targetTier)) {
      return c.json({ error: 'Invalid target tier' }, 400);
    }

    // For web_locked without SSH, warn about permanent lockout risk
    if (targetTier === 'web_locked') {
      const keys = getSshKeys();
      if (keys.length === 0 && !body.acknowledgeNoRecovery) {
        return c.json({
          error: 'No SSH keys configured',
          warning: 'PERMANENT LOCKOUT RISK: You have no SSH keys. If you lose your passkey device, you will permanently lose access to this server. There is NO recovery path.',
          requiresAcknowledgment: true,
          hint: 'Add an SSH key first, or set acknowledgeNoRecovery: true to proceed at your own risk',
        }, 400);
      }
    }

    // Execute tier switch and notify platform
    try {
      await executeTierSwitch(targetTier as 'standard' | 'web_locked', ip, c.req.header('user-agent') || 'unknown');
      return c.json({ success: true, tier: targetTier });
    } catch (e) {
      return c.json({ error: (e as Error).message || 'Failed to switch tier' }, 500);
    }
  });

  // =========================================================================
  // Settings endpoints — PASSKEY-ONLY auth (no JWT, no bearer token)
  //
  // SECURITY: Settings changes require physical device attestation via WebAuthn.
  // Architecturally impossible for AI agents to bypass.
  // =========================================================================

  /**
   * Authenticate settings requests. PASSKEY ONLY — no JWT, no bearer token.
   * Returns null if valid, or a Response object for error cases.
   */
  function requirePasskeySession(c: any, ip: string): { valid: boolean; error?: string; status?: number; requiresPasskey?: boolean } {
    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;

    if (!sessionId) {
      // Check if user has any passkeys registered
      const passkeys = db.prepare('SELECT id FROM credential').all();
      if (passkeys.length === 0) {
        return {
          valid: false,
          error: 'Register a passkey to manage settings',
          status: 403,
          requiresPasskey: true,
        };
      }
      return { valid: false, error: 'Passkey authentication required', status: 401 };
    }

    const fingerprintData = getDeviceFingerprint(c);
    const result = validateSession(sessionId, ip, fingerprintData, c.req.path);
    if (!result.valid) {
      return { valid: false, error: result.reason || 'Session expired', status: 401 };
    }

    return { valid: true };
  }

  /**
   * Bridge API: Get local settings state
   */
  app.get('/_auth/bridge/settings', async (c) => {
    const ip = getClientIp(c);

    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const auth = requirePasskeySession(c, ip);
    if (!auth.valid) {
      return c.json(
        { error: auth.error, ...(auth.requiresPasskey ? { requiresPasskey: true } : {}) },
        (auth.status || 401) as any,
      );
    }

    const settings = readSettings();
    const effective = applyTierOverrides(settings);
    return c.json(effective);
  });

  /**
   * Bridge API: Toggle terminal
   */
  app.post('/_auth/bridge/toggle-terminal', async (c) => {
    const ip = getClientIp(c);

    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const auth = requirePasskeySession(c, ip);
    if (!auth.valid) {
      return c.json(
        { error: auth.error, ...(auth.requiresPasskey ? { requiresPasskey: true } : {}) },
        (auth.status || 401) as any,
      );
    }

    const body = await c.req.json().catch(() => ({})) as { enabled?: boolean };
    if (typeof body.enabled !== 'boolean') {
      return c.json({ error: 'enabled must be boolean' }, 400);
    }

    try {
      const result = toggleTerminal(body.enabled);
      logAuditEvent({ type: 'settings_changed', ip, details: { field: 'terminal', enabled: result.terminalEnabled } });
      cryptoAudit('setting_changed', 'passkey', { field: 'terminal', enabled: body.enabled });
      // Fire-and-forget webhook (non-blocking — heartbeat reconciles on failure)
      notifyPlatformSettingsChange(result, ip, c.req.header('user-agent') || 'unknown')
        .catch(e => console.warn('[shield] Settings webhook failed:', e.message));
      return c.json({ success: true, ...result });
    } catch (e) {
      return c.json({ error: (e as Error).message }, 500);
    }
  });

  /**
   * Bridge API: Toggle SSH
   */
  app.post('/_auth/bridge/toggle-ssh', async (c) => {
    const ip = getClientIp(c);

    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const auth = requirePasskeySession(c, ip);
    if (!auth.valid) {
      return c.json(
        { error: auth.error, ...(auth.requiresPasskey ? { requiresPasskey: true } : {}) },
        (auth.status || 401) as any,
      );
    }

    const body = await c.req.json().catch(() => ({})) as { enabled?: boolean };
    if (typeof body.enabled !== 'boolean') {
      return c.json({ error: 'enabled must be boolean' }, 400);
    }

    try {
      const result = toggleSsh(body.enabled);
      logAuditEvent({ type: 'settings_changed', ip, details: { field: 'ssh', enabled: result.sshEnabled } });
      cryptoAudit('setting_changed', 'passkey', { field: 'ssh', enabled: body.enabled });
      // Fire-and-forget webhook (non-blocking — heartbeat reconciles on failure)
      notifyPlatformSettingsChange(result, ip, c.req.header('user-agent') || 'unknown')
        .catch(e => console.warn('[shield] Settings webhook failed:', e.message));
      return c.json({ success: true, ...result });
    } catch (e) {
      return c.json({ error: (e as Error).message }, 500);
    }
  });

  // =========================================================================
  //  OPERATIONS — Kill Ports, Git, Deployment
  //
  //  Bridge-routed operations (Phase 4). Previously dispatched via heartbeat
  //  response commands. Now executed directly on VPS via passkey-authenticated
  //  bridge endpoints. Dashboard gets instant feedback via postMessage.
  // =========================================================================

  /**
   * Bridge API: Kill processes on dev ports
   */
  app.post('/_auth/bridge/kill-ports', async (c) => {
    const ip = getClientIp(c);

    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const auth = requirePasskeySession(c, ip);
    if (!auth.valid) {
      return c.json(
        { error: auth.error, ...(auth.requiresPasskey ? { requiresPasskey: true } : {}) },
        (auth.status || 401) as any,
      );
    }

    const body = await c.req.json().catch(() => ({})) as { ports?: number[] };
    const ports = Array.isArray(body.ports) ? body.ports : DEV_PORTS;

    try {
      const result = killPorts(ports);
      logAuditEvent({ type: 'operation', ip, details: { action: 'kill_ports', ports, killed: result.killed, skipped: result.skipped } });
      cryptoAudit('ports_killed', 'passkey', { ports, killed: result.killed });
      return c.json({ success: true, ...result });
    } catch (e) {
      return c.json({ error: (e as Error).message }, 500);
    }
  });

  /**
   * Bridge API: Execute git operation
   */
  app.post('/_auth/bridge/git-action', async (c) => {
    const ip = getClientIp(c);

    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const auth = requirePasskeySession(c, ip);
    if (!auth.valid) {
      return c.json(
        { error: auth.error, ...(auth.requiresPasskey ? { requiresPasskey: true } : {}) },
        (auth.status || 401) as any,
      );
    }

    const body = await c.req.json().catch(() => ({})) as { action?: string; appName?: string };
    const validActions: GitAction[] = ['push', 'pull', 'force-push', 'setup', 'teardown'];
    if (!body.action || !validActions.includes(body.action as GitAction)) {
      return c.json({ error: `Invalid action. Must be one of: ${validActions.join(', ')}` }, 400);
    }

    try {
      const result = executeGitAction(body.action as GitAction, body.appName);
      logAuditEvent({ type: 'operation', ip, details: { action: 'git', gitAction: body.action, appName: body.appName } });
      cryptoAudit('git_action', 'passkey', { action: body.action, appName: body.appName });
      return c.json({ success: true, action: body.action, output: result.output });
    } catch (e) {
      return c.json({ error: (e as Error).message }, 500);
    }
  });

  /**
   * Bridge API: Switch deployment model
   */
  app.post('/_auth/bridge/switch-deployment', async (c) => {
    const ip = getClientIp(c);

    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const auth = requirePasskeySession(c, ip);
    if (!auth.valid) {
      return c.json(
        { error: auth.error, ...(auth.requiresPasskey ? { requiresPasskey: true } : {}) },
        (auth.status || 401) as any,
      );
    }

    const body = await c.req.json().catch(() => ({})) as Partial<DeploymentSwitchOpts>;
    const validModels = ['cloudflare', 'direct', 'gateway'];
    if (!body.model || !validModels.includes(body.model) || !body.domain) {
      return c.json({ error: 'model (cloudflare|direct|gateway) and domain are required' }, 400);
    }

    try {
      const result = switchDeployment(body as DeploymentSwitchOpts);
      if (!result.success) {
        return c.json({ error: result.error }, 500);
      }
      logAuditEvent({ type: 'operation', ip, details: { action: 'switch_deployment', model: body.model, domain: body.domain } });
      cryptoAudit('deployment_switched', 'passkey', { model: body.model, domain: body.domain });
      return c.json({ success: true });
    } catch (e) {
      return c.json({ error: (e as Error).message }, 500);
    }
  });

  // =========================================================================
  //  INFRASTRUCTURE CONFIRMATION — Passkey-gated one-time tokens
  //
  //  Dangerous daemon operations (migrate/pack, migrate/pull) require a
  //  passkey-approved confirmation token. The dashboard obtains a token via
  //  this endpoint, then the platform API includes it in X-Infra-Confirm
  //  when calling the daemon. file-api validates via /_internal/validate-infra-token.
  // =========================================================================

  /**
   * Bridge API: Create infrastructure confirmation token
   */
  app.post('/_auth/bridge/confirm-infra', async (c) => {
    const ip = getClientIp(c);

    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const auth = requirePasskeySession(c, ip);
    if (!auth.valid) {
      return c.json(
        { error: auth.error, ...(auth.requiresPasskey ? { requiresPasskey: true } : {}) },
        (auth.status || 401) as any,
      );
    }

    const body = await c.req.json().catch(() => ({})) as { operation?: string };
    const validOperations = ['hibernate', 'migrate', 'maintenance'];
    if (!body.operation || !validOperations.includes(body.operation)) {
      return c.json({ error: `Invalid operation. Must be one of: ${validOperations.join(', ')}` }, 400);
    }

    const confirmation = createConfirmation(body.operation);
    logAuditEvent({ type: 'operation', ip, details: { action: 'infra_confirm', operation: body.operation } });
    cryptoAudit('infra_confirmed', 'passkey', { operation: body.operation });
    return c.json(confirmation);
  });

  // =========================================================================
  //  HEARTBEAT RESET — Manual recovery for broken heartbeat auth
  // =========================================================================

  /**
   * Bridge API: Regenerate Ed25519 heartbeat keypair
   * Use case: manual recovery when heartbeat auth is broken
   */
  app.post('/_auth/bridge/reset-heartbeat', async (c) => {
    const ip = getClientIp(c);

    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) return c.json({ error: 'Rate limit exceeded' }, 429);

    const auth = requirePasskeySession(c, ip);
    if (!auth.valid) {
      return c.json(
        { error: auth.error, ...(auth.requiresPasskey ? { requiresPasskey: true } : {}) },
        (auth.status || 401) as any,
      );
    }

    try {
      const { execSync } = await import('child_process');

      // Regenerate Ed25519 keypair
      execSync('openssl genpkey -algorithm Ed25519 -out /etc/ellulai/heartbeat.key', { timeout: 5_000 });
      execSync('openssl pkey -in /etc/ellulai/heartbeat.key -pubout -out /etc/ellulai/heartbeat.pub', { timeout: 5_000 });
      execSync('chmod 600 /etc/ellulai/heartbeat.key && chmod 644 /etc/ellulai/heartbeat.pub', { timeout: 5_000 });

      // Notify platform to clear stored public key (TOFU will re-register on next heartbeat)
      await notifyPlatformHeartbeatKeyReset();

      // Restart enforcer to pick up new keypair immediately
      execSync('systemctl restart ellulai-enforcer 2>/dev/null || true', { timeout: 10_000 });

      logAuditEvent({ type: 'operation', ip, details: { action: 'heartbeat_key_reset' } });
      cryptoAudit('heartbeat_key_reset', 'passkey', {});
      return c.json({ success: true });
    } catch (e) {
      return c.json({ success: false, error: (e as Error).message }, 500);
    }
  });

  // =========================================================================
  //  AUDIT LOG — Cryptographic hash-chained audit trail
  // =========================================================================

  /**
   * Bridge API: Read cryptographic audit log
   * Returns hash-chained, Ed25519-signed audit entries for remote verification.
   * Query param `since` filters entries with seq > since (default 0).
   * Limited to last 100 entries.
   */
  app.get('/_auth/bridge/audit-log', async (c) => {
    const ip = getClientIp(c);

    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }

    const auth = requirePasskeySession(c, ip);
    if (!auth.valid) {
      return c.json(
        { error: auth.error, ...(auth.requiresPasskey ? { requiresPasskey: true } : {}) },
        (auth.status || 401) as any,
      );
    }

    const sinceParam = c.req.query('since');
    const since = sinceParam ? parseInt(sinceParam, 10) || 0 : 0;

    const entries = readAuditLog(since, 100);
    const chainHeadValue = getChainHead();

    return c.json({ entries, chainHead: chainHeadValue });
  });

  /**
   * Internal API: Validate infrastructure confirmation token
   * Localhost-only — called by file-api to verify X-Infra-Confirm headers.
   * No passkey session required (already validated at token creation time).
   */
  app.post('/_internal/validate-infra-token', async (c) => {
    // Restrict to localhost only
    const ip = getClientIp(c);
    if (ip !== '127.0.0.1' && ip !== '::1' && ip !== '::ffff:127.0.0.1') {
      return c.json({ error: 'Forbidden' }, 403);
    }

    const body = await c.req.json().catch(() => ({})) as { token?: string; operation?: string };
    if (!body.token || !body.operation) {
      return c.json({ error: 'Missing token or operation' }, 400);
    }

    const valid = validateConfirmation(body.token, body.operation);
    if (!valid) {
      return c.json({ error: 'Invalid or expired confirmation token' }, 403);
    }

    return c.json({ valid: true });
  });
}
