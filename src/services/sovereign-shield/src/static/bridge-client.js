import { startAuthentication, startRegistration } from '/_auth/static/simplewebauthn-browser.js';

const DASHBOARD_ORIGINS = ['https://console.ellul.ai', 'https://ellul.ai'];
let session = null;
let sessionCheckedAt = 0; // Timestamp of last successful session check
const SESSION_CHECK_TTL = 60000; // Don't re-check within 60s of a successful check
let pendingAuth = null;
let pendingSessionCheck = null;
let popReady = false;

// SECURITY: Capture the exact parent origin when iframe loads
let PARENT_ORIGIN = null;
try {
  if (document.referrer) {
    const referrerUrl = new URL(document.referrer);
    PARENT_ORIGIN = referrerUrl.origin;
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
  const subdomainPattern = new RegExp('^https://[a-zA-Z0-9-]+\\.ellul\\.(ai|app)$');
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
    const errMsg = typeof err?.message === 'string' ? err.message : String(err?.message ?? err ?? 'Unknown error');
    respond(event.origin, requestId, { success: false, error: errMsg });
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

async function fetchJson(url) {
  const res = await fetch(url, { credentials: 'include' });
  if (!res.ok) {
    const error = await res.json().catch(() => ({}));
    throw new Error(error.error || 'Request failed');
  }
  return res.json();
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({}));
    throw new Error(error.error || 'Request failed');
  }
  return res.json();
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

    case 'get_preview_token':
      return await fetchTokenWithPopRecovery('/_auth/preview/authorize', 'preview token');

    case 'reauthenticate':
      // Force fresh passkey authentication and reinitialize PoP
      // Step 1: Clear the local PoP key from IndexedDB
      if (typeof SESSION_POP !== 'undefined') {
        await SESSION_POP.clearKeyPair();
        // PoP key cleared
      }
      // Step 2: Logout to clear the session (forces new session on reauth)
      try {
        await fetch('/_auth/logout', { method: 'POST', credentials: 'include' });
        // Session cleared
      } catch (e) {
        // Logout endpoint may not exist — that's fine
      }
      // Step 3: Clear local session state
      session = null;
      sessionCheckedAt = 0;
      popReady = false;
      // Step 4: Do fresh passkey auth (creates new session)
      await doPasskeyAuth();
      // Step 5: Initialize PoP with fresh key
      await initPoP();
      // Reauthentication complete
      return { success: true, authenticated: true };

    case 'get_settings':
      await requireSession();
      return await fetchJson('/_auth/bridge/settings');

    case 'toggle_terminal':
      await requireSession();
      return await postJson('/_auth/bridge/toggle-terminal', { enabled: data.enabled });

    case 'toggle_ssh':
      await requireSession();
      return await postJson('/_auth/bridge/toggle-ssh', { enabled: data.enabled });

    case 'set_secret':
      await requireSession();
      return await setSecretViaApi(data.name, data.encryptedKey, data.iv, data.encryptedData);

    case 'delete_secret':
      await requireSession();
      return await deleteSecretViaApi(data.name);

    case 'list_secrets':
      await requireSession();
      return await listSecretsViaApi();

    case 'set_secrets_bulk':
      await requireSession();
      return await setSecretsBulkViaApi(data.secrets);

    case 'authorize_git_link':
      await requireSession();
      return await authorizeGitLink(data.repoFullName, data.provider);

    case 'authorize_git_unlink':
      await requireSession();
      return await authorizeGitUnlink();

    case 'kill_ports':
      await requireSession();
      return await postJson('/_auth/bridge/kill-ports', { ports: data.ports });

    case 'git_action':
      await requireSession();
      return await postJson('/_auth/bridge/git-action', { action: data.action, appName: data.appName });

    case 'switch_deployment':
      await requireSession();
      return await postJson('/_auth/bridge/switch-deployment', data);

    case 'confirm_infra':
      await requireSession();
      return await postJson('/_auth/bridge/confirm-infra', { operation: data.operation });

    case 'reset_heartbeat':
      await requireSession();
      return await postJson('/_auth/bridge/reset-heartbeat', {});

    default:
      throw new Error('Unknown message type: ' + type);
  }
}

async function checkSession() {
  // Return cached result if recently validated (prevents hammering /_auth/bridge/session)
  if (session && sessionCheckedAt && (Date.now() - sessionCheckedAt < SESSION_CHECK_TTL)) {
    return true;
  }
  // Deduplicate concurrent calls — share a single in-flight request
  if (pendingSessionCheck) return pendingSessionCheck;
  pendingSessionCheck = (async () => {
    try {
      const res = await fetch('/_auth/bridge/session', { credentials: 'include' });
      if (res.ok) {
        session = await res.json();
        sessionCheckedAt = Date.now();
        return true;
      }
    } catch {}
    session = null;
    sessionCheckedAt = 0;
    return false;
  })();
  try { return await pendingSessionCheck; } finally { pendingSessionCheck = null; }
}

async function requireSession() {
  // Standard tier doesn't use browser sessions — fail fast
  // so callers can fall back to direct JWT-authenticated requests
  if (SECURITY_TIER !== 'web_locked') {
    throw new Error('Authentication required');
  }
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

async function switchToWebLocked(name) {
  const tierInfo = await getCurrentTierInfo();
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

async function setSecretViaApi(name, encryptedKey, iv, encryptedData) {
  if (!name || !encryptedKey || !iv || !encryptedData) {
    throw new Error('Missing required fields: name, encryptedKey, iv, encryptedData');
  }
  const res = await fetch('/_auth/secrets', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, encryptedKey, iv, encryptedData }),
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({}));
    throw new Error(error.error || 'Failed to set secret');
  }
  return res.json();
}

async function deleteSecretViaApi(name) {
  if (!name) throw new Error('Missing secret name');
  const res = await fetch('/_auth/secrets/' + encodeURIComponent(name), {
    method: 'DELETE',
    credentials: 'include',
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({}));
    throw new Error(error.error || 'Failed to delete secret');
  }
  return res.json();
}

async function listSecretsViaApi() {
  const res = await fetch('/_auth/secrets', { credentials: 'include' });
  if (!res.ok) {
    const error = await res.json().catch(() => ({}));
    throw new Error(error.error || 'Failed to list secrets');
  }
  return res.json();
}

async function setSecretsBulkViaApi(secrets) {
  if (!Array.isArray(secrets) || secrets.length === 0) {
    throw new Error('secrets must be a non-empty array');
  }
  const res = await fetch('/_auth/secrets/bulk', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ secrets }),
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({}));
    throw new Error(error.error || 'Failed to set secrets');
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

// Initialize PoP only for web_locked tier (standard doesn't need it)
if (SECURITY_TIER === 'web_locked') {
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
} else {
  // Standard: no PoP needed, bridge is immediately ready
  notifyParent({ type: 'bridge_ready', pop: true });
}
