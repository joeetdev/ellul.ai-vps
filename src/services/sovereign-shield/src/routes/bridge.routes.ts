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
 */

import type { Hono } from 'hono';
import fs from 'fs';
import { db } from '../database';
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
} from '../services/tier.service';
import { getSshKeys } from './keys.routes';
import { parseCookies } from '../utils/cookie';

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
    return c.html(`<!DOCTYPE html>
<html>
<head><title>Auth Bridge</title></head>
<body>
<!-- Load PoP script to add signature headers to fetch requests -->
<script src="/_auth/static/session-pop.js"></script>
<script type="module">
import { startAuthentication, startRegistration } from '/_auth/static/simplewebauthn-browser.js';

const DASHBOARD_ORIGINS = ['https://console.phone-stack.app', 'https://phone-stack.app'];
let session = null;
let pendingAuth = null;
let popReady = false;

// SECURITY: Capture the exact parent origin when iframe loads
let PARENT_ORIGIN = null;
try {
  if (document.referrer) {
    const referrerUrl = new URL(document.referrer);
    PARENT_ORIGIN = referrerUrl.origin;
    console.log('[Bridge] Parent origin captured:', PARENT_ORIGIN);
  }
} catch (e) {
  console.warn('[Bridge] Could not parse referrer:', e.message);
}

// Initialize PoP before signaling ready
async function initPoP() {
  if (popReady) return;
  if (typeof SESSION_POP === 'undefined') {
    throw new Error('SESSION_POP not available');
  }
  await SESSION_POP.initialize();
  if (!window.__popFetchWrapped) {
    SESSION_POP.wrapFetch();
    window.__popFetchWrapped = true;
  }
  popReady = true;
  console.log('[Bridge] PoP initialized');
}

// Secure origin validation
function isValidOrigin(origin) {
  if (PARENT_ORIGIN) {
    if (origin === PARENT_ORIGIN) return true;
    if (DASHBOARD_ORIGINS.includes(origin)) return true;
    console.warn('[Bridge] Rejected message from non-parent origin:', origin);
    return false;
  }
  if (DASHBOARD_ORIGINS.includes(origin)) return true;
  const subdomainPattern = new RegExp('^https:\\\\/\\\\/[a-zA-Z0-9-]+\\\\.phone-stack\\\\.app$');
  return subdomainPattern.test(origin);
}

// Listen for dashboard messages
window.addEventListener('message', async (event) => {
  if (!isValidOrigin(event.origin)) return;

  const { type, requestId, ...data } = event.data;

  try {
    const result = await handleMessage(type, data);
    respond(event.origin, requestId, { success: true, ...result });
  } catch (err) {
    respond(event.origin, requestId, { success: false, error: err.message });
  }
});

// Shared token fetch with PoP error recovery
// Retries on any PoP-related failure, reinitializing PoP between attempts
async function fetchTokenWithPopRecovery(endpoint, label) {
  await requireSession();
  for (let attempt = 1; attempt <= 3; attempt++) {
    const res = await fetch(endpoint, { method: 'POST', credentials: 'include' });
    if (res.ok) return await res.json();
    const err = await res.json().catch(() => ({}));
    const isPopError = err.reason && (
      err.reason === 'pop_not_bound' ||
      err.reason.includes('pop') ||
      err.reason === 'missing_pop_headers'
    );
    if (isPopError && attempt < 3) {
      // PoP key may be stale/missing - reinitialize before retry
      popReady = false;
      try { await initPoP(); } catch {}
      await new Promise(r => setTimeout(r, 500 * attempt));
      continue;
    }
    throw new Error(err.error || 'Failed to get ' + label);
  }
  throw new Error('Failed to get ' + label + ' after retries');
}

async function handleMessage(type, data) {
  switch (type) {
    case 'check_session':
      return { hasSession: await checkSession() };

    case 'get_ssh_keys':
      await requireSession();
      return { keys: await fetchKeys() };

    case 'add_ssh_key':
      await requireSession();
      return await addKey(data.name, data.publicKey);

    case 'remove_ssh_key':
      await requireSession();
      return await removeKey(data.fingerprint);

    case 'get_passkeys':
      await requireSession();
      return { passkeys: await fetchPasskeys() };

    case 'register_passkey':
      return await registerPasskey(data.name);

    case 'remove_passkey':
      await requireSession();
      return await removePasskey(data.credentialId);

    case 'upgrade_to_web_locked':
      return await upgradeToWebLocked(data.name);

    case 'downgrade_to_standard':
      await requireSession();
      return await downgradeToStandard();

    case 'switch_to_ssh_only':
      await requireSession();
      return await switchToSshOnly();

    case 'switch_to_web_locked':
      return await switchToWebLocked(data.name);

    case 'get_current_tier':
      return await getCurrentTierInfo();

    case 'confirm_operation':
      await requireSession();
      return await confirmOperation(data.operation);

    case 'get_code_token':
      return await fetchTokenWithPopRecovery('/_auth/code/authorize', 'code token');

    case 'get_code_session':
      return await fetchTokenWithPopRecovery('/_auth/code/session', 'code session');

    case 'get_agent_token':
      return await fetchTokenWithPopRecovery('/_auth/agent/authorize', 'agent token');

    case 'get_terminal_token':
      return await fetchTokenWithPopRecovery('/_auth/terminal/authorize', 'terminal token');

    case 'reauthenticate':
      // Force fresh passkey authentication and reinitialize PoP
      // Step 1: Clear the local PoP key from IndexedDB
      if (typeof SESSION_POP !== 'undefined') {
        await SESSION_POP.clearKeyPair();
        console.log('[Bridge] Cleared PoP key from IndexedDB');
      }
      // Step 2: Logout to clear the session (forces new session on reauth)
      try {
        await fetch('/_auth/logout', { method: 'POST', credentials: 'include' });
        console.log('[Bridge] Logged out to clear session');
      } catch (e) {
        console.log('[Bridge] Logout failed (may not exist):', e.message);
      }
      // Step 3: Clear local session state
      session = null;
      popReady = false;
      // Step 4: Do fresh passkey auth (creates new session)
      await doPasskeyAuth();
      // Step 5: Initialize PoP with fresh key
      await initPoP();
      console.log('[Bridge] Reauthentication complete');
      return { success: true, authenticated: true };

    case 'authorize_git_link':
      await requireSession();
      return await authorizeGitLink(data.repoFullName, data.provider);

    case 'authorize_git_unlink':
      await requireSession();
      return await authorizeGitUnlink();

    default:
      throw new Error('Unknown message type: ' + type);
  }
}

async function checkSession() {
  try {
    const res = await fetch('/_auth/bridge/session', { credentials: 'include' });
    if (res.ok) {
      session = await res.json();
      return true;
    }
  } catch {}
  session = null;
  return false;
}

async function requireSession() {
  if (pendingAuth) {
    await pendingAuth;
    return;
  }
  if (session) {
    if (!popReady) {
      try { await initPoP(); } catch (e) { console.warn('[Bridge] PoP init failed:', e.message); }
    }
    return;
  }
  const hasSession = await checkSession();
  if (hasSession) {
    if (!popReady) {
      try { await initPoP(); } catch (e) { console.warn('[Bridge] PoP init failed:', e.message); }
    }
    return;
  }
  // Don't auto-trigger passkey auth - let the dashboard show an auth wall
  // The user must explicitly click "Login with Passkey" to authenticate
  throw new Error('Authentication required');
}

async function doPasskeyAuth() {
  const optionsRes = await fetch('/_auth/login/options', {
    method: 'POST',
    credentials: 'include'
  });
  if (!optionsRes.ok) throw new Error('Failed to get auth options');
  const options = await optionsRes.json();
  const credential = await startAuthentication({ optionsJSON: options });
  const verifyRes = await fetch('/_auth/login/verify', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ assertion: credential }),
  });
  if (!verifyRes.ok) {
    const err = await verifyRes.json();
    throw new Error(err.error || 'Passkey verification failed');
  }
  session = await verifyRes.json();
  popReady = false; // Reset so initPoP() re-binds to the new session
}

async function fetchKeys() {
  const res = await fetch('/_auth/bridge/keys', { credentials: 'include' });
  if (!res.ok) throw new Error('Failed to fetch keys');
  return res.json();
}

async function addKey(name, publicKey) {
  const res = await fetch('/_auth/keys', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, publicKey }),
  });
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.error || 'Failed to add key');
  }
  return res.json();
}

async function removeKey(fingerprint) {
  const res = await fetch('/_auth/keys/' + encodeURIComponent(fingerprint), {
    method: 'DELETE',
    credentials: 'include',
  });
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.error || 'Failed to remove key');
  }
  return { fingerprint };
}

async function fetchPasskeys() {
  const res = await fetch('/_auth/bridge/passkeys', { credentials: 'include' });
  if (!res.ok) throw new Error('Failed to fetch passkeys');
  return res.json();
}

async function switchTier(targetTier) {
  const res = await fetch('/_auth/bridge/switch-tier', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ targetTier }),
  });
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.error || 'Failed to switch tier');
  }
  return res.json();
}

async function registerPasskey(name) {
  const optionsRes = await fetch('/_auth/register/options', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: name || 'Passkey' }),
  });
  if (!optionsRes.ok) {
    const err = await optionsRes.json();
    throw new Error(err.error || 'Failed to get registration options');
  }
  const options = await optionsRes.json();
  const credential = await startRegistration({ optionsJSON: options });
  const verifyRes = await fetch('/_auth/register/verify', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ attestation: credential, name: name || 'Passkey' }),
  });
  if (!verifyRes.ok) {
    const err = await verifyRes.json();
    throw new Error(err.error || 'Passkey registration failed');
  }
  const result = await verifyRes.json();
  session = result;
  return { credentialId: result.credentialId, name: name || 'Passkey' };
}

async function removePasskey(credentialId) {
  const res = await fetch('/_auth/bridge/passkey/' + encodeURIComponent(credentialId), {
    method: 'DELETE',
    credentials: 'include',
  });
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.error || 'Failed to remove passkey');
  }
  return { credentialId };
}

async function upgradeToWebLocked(name) {
  // WebAuthn registration requires user activation and can't work in cross-origin iframe
  // Return a popup URL for the dashboard to open
  const encodedName = encodeURIComponent(name || 'Passkey');
  return {
    requiresPopup: true,
    popupUrl: '/_auth/standard-upgrade?name=' + encodedName,
    message: 'Open popup to register passkey'
  };
}

async function downgradeToStandard() {
  const res = await fetch('/_auth/bridge/downgrade-to-standard', {
    method: 'POST',
    credentials: 'include',
  });
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.error || 'Failed to downgrade to Standard');
  }
  return res.json();
}

async function switchToSshOnly() {
  const keys = await fetchKeys();
  if (!keys || keys.length === 0) {
    throw new Error('SSH Only requires at least one SSH key configured');
  }
  const res = await fetch('/_auth/bridge/switch-tier', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ targetTier: 'ssh_only' }),
  });
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.error || 'Failed to switch to SSH Only');
  }
  return res.json();
}

async function switchToWebLocked(name) {
  const tierInfo = await getCurrentTierInfo();
  if (tierInfo.passkeys.length === 0 && tierInfo.tier === 'ssh_only') {
    return {
      requiresRegistration: true,
      registrationUrl: '/_auth/ssh-only-upgrade',
      message: 'Open popup to register passkey'
    };
  }
  if (!session && tierInfo.passkeys.length > 0) {
    throw new Error('Authentication required');
  }
  if (tierInfo.passkeys.length === 0) {
    await registerPasskey(name);
  }
  const res = await fetch('/_auth/bridge/switch-tier', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ targetTier: 'web_locked' }),
  });
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.error || 'Failed to switch to Web Locked');
  }
  return { tier: 'web_locked' };
}

async function getCurrentTierInfo() {
  const res = await fetch('/_auth/bridge/tier', { credentials: 'include' });
  if (!res.ok) throw new Error('Failed to get tier info');
  return res.json();
}

async function confirmOperation(operation) {
  const VALID_OPERATIONS = ['delete', 'rebuild', 'update', 'rollback', 'deployment', 'change-tier', 'settings'];
  if (!operation || !VALID_OPERATIONS.includes(operation)) {
    throw new Error('Invalid operation. Must be one of: ' + VALID_OPERATIONS.join(', '));
  }
  for (let attempt = 1; attempt <= 3; attempt++) {
    const res = await fetch('/_auth/confirm-operation', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ operation }),
    });
    if (res.ok) {
      return await res.json();
    }
    const error = await res.json().catch(() => ({}));
    if (error.reason === 'pop_not_bound' && attempt < 3) {
      // PoP not bound yet — try to bind it before retrying
      if (!popReady) {
        try { await initPoP(); } catch (e) { console.warn('[Bridge] PoP init failed:', e.message); }
      }
      await new Promise(r => setTimeout(r, 500 * attempt));
      continue;
    }
    if (error.needsAuth) {
      throw new Error('Authentication required');
    }
    throw new Error(error.error || 'Failed to confirm operation');
  }
  throw new Error('Failed to confirm operation after retries');
}

async function authorizeGitLink(repoFullName, provider) {
  if (!repoFullName || !provider) {
    throw new Error('repoFullName and provider are required');
  }
  const res = await fetch('/_auth/git/authorize-link', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repoFullName, provider }),
  });
  if (!res.ok) {
    const error = await res.json();
    if (error.needsAuth) {
      throw new Error('Authentication required');
    }
    throw new Error(error.error || 'Failed to authorize git link');
  }
  return res.json();
}

async function authorizeGitUnlink() {
  const res = await fetch('/_auth/git/authorize-unlink', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  if (!res.ok) {
    const error = await res.json();
    if (error.needsAuth) {
      throw new Error('Authentication required');
    }
    throw new Error(error.error || 'Failed to authorize git unlink');
  }
  return res.json();
}

function respond(origin, requestId, data) {
  parent.postMessage({ requestId, ...data }, origin);
}

// Send message to parent - prefer captured PARENT_ORIGIN to avoid postMessage mismatches
function notifyParent(data) {
  if (PARENT_ORIGIN) {
    try { parent.postMessage(data, PARENT_ORIGIN); } catch {}
  } else {
    // Fallback: try all known origins if referrer wasn't captured
    DASHBOARD_ORIGINS.forEach(origin => {
      try { parent.postMessage(data, origin); } catch {}
    });
  }
}

// Initialize PoP then signal ready to dashboard
initPoP()
  .then(() => {
    notifyParent({ type: 'bridge_ready', pop: true });
  })
  .catch((err) => {
    console.error('[Bridge] PoP initialization failed:', err);
    notifyParent({
      type: 'bridge_ready',
      pop: false,
      error: err.message || 'pop_init_failed'
    });
  });
</script>
</body>
</html>`);
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
      ownerId = fs.readFileSync('/etc/phonestack/owner.lock', 'utf8').trim();
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
    const hasSSHKeys = fs.existsSync('/home/dev/.ssh/authorized_keys') &&
      fs.readFileSync('/home/dev/.ssh/authorized_keys', 'utf8').trim().length > 0;

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

    if (!targetTier || !['standard', 'ssh_only', 'web_locked'].includes(targetTier)) {
      return c.json({ error: 'Invalid target tier' }, 400);
    }

    // For ssh_only, require at least one SSH key
    if (targetTier === 'ssh_only') {
      const keys = getSshKeys();
      if (keys.length === 0) {
        return c.json({ error: 'SSH Only requires at least one SSH key' }, 400);
      }
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
      await executeTierSwitch(targetTier as 'standard' | 'ssh_only' | 'web_locked', ip, c.req.header('user-agent') || 'unknown');
      return c.json({ success: true, tier: targetTier });
    } catch (e) {
      return c.json({ error: (e as Error).message || 'Failed to switch tier' }, 500);
    }
  });
}
