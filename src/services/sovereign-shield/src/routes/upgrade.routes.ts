/**
 * Upgrade Routes
 *
 * Direct tier upgrade endpoints from Standard tier (JWT authenticated).
 * These endpoints allow users in Standard tier to upgrade directly
 * without going through the bridge.
 *
 * Endpoints:
 * - POST /_auth/upgrade-to-web-locked       - Initiate Web Locked upgrade
 * - POST /_auth/upgrade-to-web-locked/verify - Complete Web Locked upgrade
 */

import type { Hono } from 'hono';
import crypto from 'crypto';
import fs from 'fs';
import { db } from '../database';
import {
  RP_NAME,
  TRUSTED_AAGUIDS,
} from '../config';
import { getDeviceFingerprint, getClientIp } from '../auth/fingerprint';
import { createSession, setSessionCookie } from '../auth/session';
import { verifyJwtToken } from '../auth/jwt';
import { logAuditEvent } from '../services/audit.service';
import {
  getCurrentTier,
  executeTierSwitch,
  notifyPlatformPasskeyRegistered,
} from '../services/tier.service';
import { loadAttestationPolicy } from '../services/setup.service';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  storeChallenge,
  getChallenge,
  deleteChallenge,
} from '../auth/webauthn';
import { generateRecoveryCodes, storeRecoveryCodes } from '../auth/recovery';

/**
 * Register upgrade routes on Hono app
 */
export function registerUpgradeRoutes(app: Hono, hostname: string): void {
  const RP_ID = hostname;
  // Accept both deployment model domains (-srv for Cloudflare, -dc for Direct Connect)
  const shortId = hostname.replace(/-(?:srv|dc)\.ellul\.ai$/, '');
  const ORIGINS = [
    `https://${hostname}`,
    `https://${shortId}-srv.ellul.ai`,
    `https://${shortId}-dc.ellul.ai`,
  ];

  /**
   * Initiate Web Locked upgrade from Standard
   * This starts the passkey registration flow
   */
  app.post('/_auth/upgrade-to-web-locked', async (c) => {
    // Only accept JWT cookie (must be in Standard tier)
    const decoded = verifyJwtToken(c.req);

    if (!decoded) {
      return c.json({ error: 'Authentication required' }, 401);
    }

    // Check current tier
    const currentTier = getCurrentTier();
    if (currentTier !== 'standard') {
      return c.json({ error: 'Can only upgrade to Web Locked from Standard tier', currentTier }, 400);
    }

    const body = await c.req.json() as { name?: string };
    const { name } = body;

    // Generate WebAuthn registration options
    const userName = name || 'ellul.ai User';

    // Load attestation policy
    const attestationPolicy = loadAttestationPolicy();

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userName,
      userDisplayName: userName,
      // Request attestation based on policy
      attestationType: attestationPolicy.mode === 'none' ? 'none' : 'direct',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required', // Enforce biometric/PIN
      },
    });

    // Store challenge for verification with 'upgrade_registration' type
    storeChallenge(options.challenge, {
      type: 'registration', // Use 'registration' type for compatibility
      userId: crypto.randomBytes(16).toString('base64url'),
      createdAt: Date.now(),
    });

    return c.json({ options, upgradeFlow: true });
  });

  /**
   * Complete Web Locked upgrade
   * Verifies the passkey registration and activates Web Locked tier
   */
  app.post('/_auth/upgrade-to-web-locked/verify', async (c) => {
    // Accept JWT cookie for initial upgrade
    const decoded = verifyJwtToken(c.req);

    if (!decoded) {
      return c.json({ error: 'Authentication required' }, 401);
    }

    // Check current tier
    const currentTier = getCurrentTier();
    if (currentTier !== 'standard') {
      return c.json({ error: 'Can only upgrade to Web Locked from Standard tier', currentTier }, 400);
    }

    const ip = getClientIp(c);
    const fingerprintData = getDeviceFingerprint(c);
    const body = await c.req.json() as {
      attestation?: { response?: { clientDataJSON?: string } };
      name?: string;
    };
    const { attestation, name } = body;

    if (!attestation) {
      return c.json({ error: 'Attestation required' }, 400);
    }

    // Extract challenge from attestation response
    const clientDataJSON = attestation?.response?.clientDataJSON;
    if (!clientDataJSON) {
      return c.json({ error: 'Invalid attestation' }, 400);
    }
    const clientData = JSON.parse(Buffer.from(clientDataJSON, 'base64').toString());
    const expectedChallenge = clientData.challenge;

    const challengeData = getChallenge(expectedChallenge);
    if (!challengeData || challengeData.type !== 'registration') {
      return c.json({ error: 'Registration session expired' }, 400);
    }

    try {
      const verification = await verifyRegistrationResponse({
        response: attestation,
        expectedChallenge,
        expectedOrigin: ORIGINS,
        expectedRPID: RP_ID,
        requireUserVerification: true, // Enforce biometric/PIN
      });

      if (!verification.verified || !verification.registrationInfo) {
        return c.json({ error: 'Verification failed' }, 400);
      }

      const { credential, aaguid, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
      const credId = crypto.randomUUID();
      const credentialIdB64 = typeof credential.id === 'string'
        ? credential.id
        : Buffer.from(credential.id as Uint8Array).toString('base64url');
      const aaguidStr = aaguid || '00000000-0000-0000-0000-000000000000';
      const authenticatorName = TRUSTED_AAGUIDS[aaguidStr] || 'Unknown Authenticator';

      // Store credential
      db.prepare(
        'INSERT INTO credential (id, credentialId, publicKey, counter, transports, aaguid, device_type, backed_up, name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
      ).run(
        credId,
        credentialIdB64,
        Buffer.from(credential.publicKey).toString('base64url'),
        credential.counter,
        JSON.stringify(credential.transports || []),
        aaguidStr,
        credentialDeviceType || 'unknown',
        credentialBackedUp ? 1 : 0,
        name || authenticatorName || 'Passkey'
      );

      deleteChallenge(expectedChallenge);

      // Execute tier switch to Web Locked
      await executeTierSwitch('web_locked', ip, c.req.header('user-agent') || 'unknown');

      logAuditEvent({
        type: 'tier_upgrade_web_locked',
        ip,
        fingerprint: fingerprintData.hash,
        credentialId: credId,
      });

      // Notify platform
      await notifyPlatformPasskeyRegistered(credentialIdB64, name || 'Passkey');

      // Create session
      const session = createSession(credId, ip, fingerprintData);
      setSessionCookie(c, session.id, hostname);

      // Generate recovery codes for first passkey
      const credCount = (db.prepare('SELECT COUNT(*) as count FROM credential').get() as { count: number }).count;
      if (credCount === 1) {
        const codes = generateRecoveryCodes();
        const displayCodes = storeRecoveryCodes(codes);

        logAuditEvent({
          type: 'recovery_codes_generated',
          ip,
          fingerprint: fingerprintData.hash,
          credentialId: credId
        });

        return c.json({
          success: true,
          tier: 'web_locked',
          sessionId: session.id,
          recoveryCodes: displayCodes,
          recoveryWarning: 'SAVE THESE RECOVERY CODES NOW. They will not be shown again.',
        });
      }

      return c.json({
        success: true,
        tier: 'web_locked',
        sessionId: session.id,
        message: 'Upgraded to Web Locked. Passkey authentication is now required.',
      });
    } catch (e) {
      console.error('[shield] Error verifying Web Locked upgrade:', e);
      return c.json({ error: (e as Error).message || 'Verification error' }, 400);
    }
  });

  /**
   * Standard to Web Locked upgrade - popup page for passkey registration
   * This is opened as a popup from the dashboard to handle WebAuthn
   */
  app.get('/_auth/standard-upgrade', async (c) => {
    // Verify JWT authentication
    const decoded = verifyJwtToken(c.req);
    const isEmbedded = c.req.query('embed') === 'true';

    if (!decoded) {
      const errorHtml = isEmbedded
        ? `<div style="padding:1rem;color:#fca5a5;text-align:center;">Authentication required. Please refresh and try again.</div>`
        : `<!DOCTYPE html><html><head><title>Authentication Required</title><style>body{font-family:system-ui;background:#0a0a0a;color:white;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;}.container{max-width:400px;text-align:center;padding:2rem;}h2{color:#ef4444;}</style></head><body><div class="container"><h2>Authentication Required</h2><p style="color:#888;">Please log in first, then try again.</p></div></body></html>`;
      return c.html(errorHtml, 401);
    }

    // Check current tier
    const currentTier = getCurrentTier();
    if (currentTier !== 'standard') {
      const errorHtml = isEmbedded
        ? `<div style="padding:1rem;color:#fcd34d;text-align:center;">This upgrade is only available from Standard tier.</div>`
        : `<!DOCTYPE html><html><head><title>Invalid Tier</title><style>body{font-family:system-ui;background:#0a0a0a;color:white;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;}.container{max-width:400px;text-align:center;padding:2rem;}h2{color:#f59e0b;}</style></head><body><div class="container"><h2>Invalid Tier</h2><p style="color:#888;">This upgrade is only available from Standard tier. Current tier: ${currentTier}</p></div></body></html>`;
      return c.html(errorHtml, 400);
    }

    const name = c.req.query('name') || 'Passkey';

    // Embedded mode: minimal UI for iframe in modal
    if (isEmbedded) {
      return c.html(`<!DOCTYPE html>
<html><head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; background: transparent; color: white; padding: 1rem; }
  button { width: 100%; background: #7c3aed; color: white; border: none; border-radius: 8px; padding: 1rem; font-size: 1rem; font-weight: 600; cursor: pointer; transition: background 0.2s; display: flex; align-items: center; justify-content: center; gap: 8px; }
  button:hover { background: #6d28d9; }
  button:disabled { background: #374151; cursor: not-allowed; }
  .error { background: #7f1d1d; border: 1px solid #dc2626; border-radius: 8px; padding: 0.75rem; margin-top: 1rem; color: #fca5a5; font-size: 0.85rem; display: none; }
  .success { background: #14532d; border: 1px solid #22c55e; border-radius: 8px; padding: 0.75rem; margin-top: 1rem; color: #86efac; font-size: 0.85rem; display: none; }
  .recovery { background: rgba(245,158,11,0.1); border: 1px solid #f59e0b; border-radius: 8px; padding: 0.75rem; margin-top: 1rem; }
  .recovery h3 { color: #f59e0b; margin: 0 0 0.5rem 0; font-size: 0.85rem; }
  .recovery code { display: block; background: #0a0a0a; padding: 0.4rem; border-radius: 4px; font-size: 0.75rem; color: #fcd34d; margin: 0.2rem 0; }
  .fingerprint { font-size: 1.5rem; }
</style>
</head>
<body>
<button id="registerBtn" onclick="startRegistration()">
  <span class="fingerprint">&#9757;</span>
  <span id="btnText">Register Passkey</span>
</button>
<div class="error" id="error"></div>
<div class="success" id="success"></div>
<div class="recovery" id="recovery" style="display:none;">
  <h3>Save Your Recovery Codes</h3>
  <div id="recoveryCodes"></div>
</div>

<script type="module">
import { startRegistration } from '/_auth/static/simplewebauthn-browser.js';

const passkeyName = ${JSON.stringify(name)};
const DASHBOARD_ORIGINS = ['https://console.ellul.ai', 'https://ellul.ai'];

function notifyParent(data) {
  DASHBOARD_ORIGINS.forEach(origin => {
    try { window.parent.postMessage(data, origin); } catch {}
  });
}

window.startRegistration = async function() {
  const btn = document.getElementById('registerBtn');
  const btnText = document.getElementById('btnText');
  const errorDiv = document.getElementById('error');
  const successDiv = document.getElementById('success');
  const recoveryDiv = document.getElementById('recovery');

  btn.disabled = true;
  btnText.textContent = 'Waiting for device...';
  errorDiv.style.display = 'none';

  try {
    const optRes = await fetch('/_auth/upgrade-to-web-locked', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: passkeyName })
    });

    if (!optRes.ok) {
      const err = await optRes.json();
      throw new Error(err.error || 'Failed to get registration options');
    }

    const { options } = await optRes.json();
    const credential = await startRegistration({ optionsJSON: options });

    btnText.textContent = 'Verifying...';

    const verifyRes = await fetch('/_auth/upgrade-to-web-locked/verify', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attestation: credential, name: passkeyName })
    });

    if (!verifyRes.ok) {
      const err = await verifyRes.json();
      throw new Error(err.error || 'Verification failed');
    }

    const result = await verifyRes.json();

    successDiv.innerHTML = '<strong>✓ Web Locked Enabled!</strong>';
    successDiv.style.display = 'block';
    btn.style.display = 'none';

    if (result.recoveryCodes && result.recoveryCodes.length > 0) {
      const codesHtml = result.recoveryCodes.map(c => '<code>' + c + '</code>').join('');
      document.getElementById('recoveryCodes').innerHTML = codesHtml;
      recoveryDiv.style.display = 'block';
      // Delay notification so user can see recovery codes
      setTimeout(() => notifyParent({ type: 'upgrade_complete', tier: 'web_locked', credentialId: result.credentialId }), 10000);
    } else {
      notifyParent({ type: 'upgrade_complete', tier: 'web_locked', credentialId: result.credentialId });
    }

  } catch (e) {
    errorDiv.textContent = e.name === 'NotAllowedError' ? 'Registration cancelled.' : (e.message || 'Registration failed');
    errorDiv.style.display = 'block';
    btn.disabled = false;
    btnText.textContent = 'Register Passkey';
  }
};
</script>
</body>
</html>`);
    }

    // Standalone mode: full page for popup
    return c.html(`<!DOCTYPE html>
<html><head>
<title>Upgrade to Web Locked</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  * { box-sizing: border-box; }
  body { font-family: system-ui, -apple-system, sans-serif; background: #0a0a0a; color: white; margin: 0; padding: 1rem; min-height: 100vh; display: flex; justify-content: center; align-items: center; }
  .container { max-width: 420px; width: 100%; }
  h1 { color: #7c3aed; font-size: 1.5rem; margin: 0 0 0.5rem 0; text-align: center; }
  .subtitle { color: #888; font-size: 0.9rem; text-align: center; margin-bottom: 1.5rem; }
  .card { background: #1a1a1a; border: 1px solid #333; border-radius: 12px; padding: 1.5rem; }
  .info { background: #1e1b4b; border: 1px solid #4c1d95; border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem; font-size: 0.85rem; color: #c4b5fd; }
  .info strong { color: #a78bfa; }
  button { width: 100%; background: #7c3aed; color: white; border: none; border-radius: 8px; padding: 1rem; font-size: 1rem; font-weight: 600; cursor: pointer; transition: background 0.2s; display: flex; align-items: center; justify-content: center; gap: 8px; }
  button:hover { background: #6d28d9; }
  button:disabled { background: #374151; cursor: not-allowed; }
  .error { background: #7f1d1d; border: 1px solid #dc2626; border-radius: 8px; padding: 1rem; margin-top: 1rem; color: #fca5a5; display: none; }
  .success { background: #14532d; border: 1px solid #22c55e; border-radius: 8px; padding: 1rem; margin-top: 1rem; color: #86efac; display: none; }
  .recovery { background: #1a1a1a; border: 1px solid #f59e0b; border-radius: 8px; padding: 1rem; margin-top: 1rem; }
  .recovery h3 { color: #f59e0b; margin: 0 0 0.5rem 0; font-size: 0.9rem; }
  .recovery code { display: block; background: #0a0a0a; padding: 0.5rem; border-radius: 4px; font-size: 0.8rem; color: #fcd34d; margin: 0.25rem 0; }
  .fingerprint { font-size: 1.5rem; }
</style>
</head>
<body>
<div class="container">
  <h1>Upgrade to Web Locked</h1>
  <p class="subtitle">Register a passkey to enable Web Locked mode</p>

  <div class="card">
    <div class="info">
      <strong>What is Web Locked?</strong><br>
      Requires passkey (Face ID/Touch ID) for all web access. This is the highest security tier.
    </div>

    <button id="registerBtn" onclick="startRegistration()">
      <span class="fingerprint">&#9757;</span>
      <span id="btnText">Register Passkey</span>
    </button>

    <div class="error" id="error"></div>
    <div class="success" id="success"></div>
    <div class="recovery" id="recovery" style="display:none;">
      <h3>⚠️ Save Your Recovery Codes</h3>
      <p style="color:#888;font-size:0.8rem;margin:0 0 0.5rem 0;">These codes can be used if you lose your passkey. Save them now!</p>
      <div id="recoveryCodes"></div>
    </div>
  </div>
</div>

<script type="module">
import { startRegistration } from '/_auth/static/simplewebauthn-browser.js';

const passkeyName = ${JSON.stringify(name)};

window.startRegistration = async function() {
  const btn = document.getElementById('registerBtn');
  const btnText = document.getElementById('btnText');
  const errorDiv = document.getElementById('error');
  const successDiv = document.getElementById('success');
  const recoveryDiv = document.getElementById('recovery');

  btn.disabled = true;
  btnText.textContent = 'Waiting for device...';
  errorDiv.style.display = 'none';

  try {
    const optRes = await fetch('/_auth/upgrade-to-web-locked', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: passkeyName })
    });

    if (!optRes.ok) {
      const err = await optRes.json();
      throw new Error(err.error || 'Failed to get registration options');
    }

    const { options } = await optRes.json();
    const credential = await startRegistration({ optionsJSON: options });

    btnText.textContent = 'Verifying...';

    const verifyRes = await fetch('/_auth/upgrade-to-web-locked/verify', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attestation: credential, name: passkeyName })
    });

    if (!verifyRes.ok) {
      const err = await verifyRes.json();
      throw new Error(err.error || 'Verification failed');
    }

    const result = await verifyRes.json();

    successDiv.innerHTML = '<strong>✓ Web Locked Enabled!</strong><br>Passkey registered successfully.';
    successDiv.style.display = 'block';

    if (result.recoveryCodes && result.recoveryCodes.length > 0) {
      const codesHtml = result.recoveryCodes.map(c => '<code>' + c + '</code>').join('');
      document.getElementById('recoveryCodes').innerHTML = codesHtml;
      recoveryDiv.style.display = 'block';
    }

    // Notify parent window (popup mode)
    if (window.opener) {
      window.opener.postMessage({ type: 'upgrade_complete', tier: 'web_locked', credentialId: result.credentialId }, '*');
    }

    const delay = result.recoveryCodes ? 30000 : 2000;
    setTimeout(() => {
      if (window.opener) {
        window.close();
      } else {
        window.location.href = '/';
      }
    }, delay);

  } catch (e) {
    errorDiv.textContent = e.name === 'NotAllowedError' ? 'Registration cancelled.' : (e.message || 'Registration failed');
    errorDiv.style.display = 'block';
    btn.disabled = false;
    btnText.textContent = 'Register Passkey';
  }
};
</script>
</body>
</html>`);
  });

}
