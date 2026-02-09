/**
 * Setup Routes
 *
 * Initial passkey registration during server setup.
 *
 * Endpoints:
 * - GET  /_auth/setup           - Setup UI page
 * - POST /_auth/register/options - Generate registration options
 * - POST /_auth/register/verify  - Verify registration response
 * - GET  /_auth/ssh-only-upgrade - SSH Only -> Web Locked upgrade page
 */

import type { Hono } from 'hono';
import crypto from 'crypto';
import fs from 'fs';
import { execSync } from 'child_process';
import { db } from '../database';
import {
  RP_NAME,
  TRUSTED_AAGUIDS,
  SETUP_TOKEN_FILE,
  PENDING_SSH_BLOCK_FILE,
  SSH_TRANSITION_MARKER,
  TERMINAL_DISABLED_FILE,
  TIER_FILE,
  SHIELD_MARKER,
  SOVEREIGN_KEYS_FILE,
  SETUP_EXPIRY_FILE,
} from '../config';
import { getDeviceFingerprint, getClientIp } from '../auth/fingerprint';
import { createSession, setSessionCookie } from '../auth/session';
import { logAuditEvent } from '../services/audit.service';
import { generateRecoveryCodes, storeRecoveryCodes } from '../auth/recovery';
import { validateSetupToken, loadAttestationPolicy, cleanupSetupToken } from '../services/setup.service';
import { notifyPlatformPasskeyRegistered, getServerCredentials } from '../services/tier.service';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  storeChallenge,
  getChallenge,
  deleteChallenge,
  type CredentialRecord,
} from '../auth/webauthn';

/**
 * Register setup routes on Hono app
 */
export function registerSetupRoutes(app: Hono, hostname: string): void {
  const RP_ID = hostname;
  // Accept both deployment model domains (-srv for Cloudflare, -dc for Direct Connect)
  const shortId = hostname.replace(/-(?:srv|dc)\.ellul\.ai$/, '');
  const ORIGINS = [
    `https://${hostname}`,
    `https://${shortId}-srv.ellul.ai`,
    `https://${shortId}-dc.ellul.ai`,
  ];

  /**
   * Setup page - register first passkey
   */
  app.get('/_auth/setup', async (c) => {
    const credCount = db.prepare('SELECT COUNT(*) as count FROM credential').get() as { count: number };
    if (credCount && credCount.count > 0) {
      return c.text('Setup already completed. Sovereign Shield is active.', 403);
    }

    if (!validateSetupToken(c.req.query('token'))) {
      return c.html(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:-apple-system,system-ui,sans-serif;max-width:420px;margin:20px auto;padding:20px;background:#0a0a0a;color:#e0e0e0;text-align:center;}
.spinner{display:inline-block;width:24px;height:24px;border:3px solid #333;border-top-color:#7c3aed;border-radius:50%;animation:spin 1s linear infinite;margin-bottom:12px;}
@keyframes spin{to{transform:rotate(360deg)}}</style>
</head><body>
<div class="spinner"></div>
<p>Waiting for activation...</p>
<script>(function(){var a=parseInt(sessionStorage.getItem('shield-retry')||'0');if(a>15){sessionStorage.removeItem('shield-retry');document.body.innerHTML='<p>Setup token not found. Try again from the dashboard.</p>';return;}
sessionStorage.setItem('shield-retry',''+(a+1));setTimeout(function(){location.reload()},2000)})()</script>
</body></html>`, 200);
    }

    return c.html(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sovereign Shield Setup</title>
  <script src="/_auth/static/session-pop.js"></script>
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, system-ui, sans-serif; max-width: 420px; margin: 20px auto; padding: 20px; background: #0a0a0a; color: #e0e0e0; }
    h1 { font-size: 1.4rem; margin-bottom: 0.5rem; }
    .subtitle { color: #888; font-size: 0.9rem; margin-bottom: 24px; }
    .info { background: #1a1a2e; border: 1px solid #2a2a4e; border-radius: 8px; padding: 16px; margin-bottom: 24px; font-size: 0.85rem; color: #a0a0c0; }
    .info strong { color: #c0c0e0; }
    button { width: 100%; padding: 14px; border-radius: 8px; border: none; background: #7c3aed; color: white; font-size: 1rem; cursor: pointer; font-weight: 600; display: flex; align-items: center; justify-content: center; gap: 8px; }
    button:hover { background: #6d28d9; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .success { color: #22c55e; margin-top: 16px; display: none; text-align: center; }
    .error { color: #ef4444; margin-top: 12px; display: none; font-size: 0.85rem; text-align: center; }
    .fingerprint { font-size: 1.5rem; }
    .recovery-section { display: none; margin-top: 24px; }
    .recovery-warning { background: #7f1d1d; border: 1px solid #ef4444; padding: 12px; border-radius: 8px; margin-bottom: 16px; font-size: 0.85rem; color: #fca5a5; }
    .recovery-codes { background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 16px; font-family: monospace; font-size: 1rem; display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; }
    .recovery-code { background: #0a0a0a; padding: 8px; border-radius: 4px; text-align: center; letter-spacing: 2px; }
    .copy-btn { margin-top: 12px; background: #333; font-size: 0.85rem; }
    .copy-btn:hover { background: #444; }
  </style>
</head>
<body>
  <h1>Sovereign Shield Setup</h1>
  <p class="subtitle">Register a passkey to secure your server.</p>
  <div class="info">
    <strong>How it works:</strong> Your device's biometric (fingerprint or Face ID) becomes the key to your server. The credential is stored only on this machine &mdash; never sent to any cloud.
  </div>
  <button id="register-btn" onclick="doRegister()">
    <span class="fingerprint">&#9757;</span>
    Register Passkey
  </button>
  <p class="success" id="success-msg">Passkey registered! Sovereign Shield is active.</p>
  <p class="error" id="error-msg"></p>
  <div class="recovery-section" id="recovery-section">
    <h2 style="font-size:1.1rem;color:#ef4444;margin-bottom:8px;">&#9888; Recovery Codes</h2>
    <div class="recovery-warning">
      <strong>SAVE THESE CODES NOW!</strong><br>
      They will NOT be shown again. Use them to recover access if you lose your passkey device.
    </div>
    <div class="recovery-codes" id="recovery-codes"></div>
    <button class="copy-btn" onclick="copyRecoveryCodes()">Copy All Codes</button>
  </div>
  <script>sessionStorage.removeItem('shield-retry');</script>
  <script type="module">
    import { startRegistration } from '/_auth/static/simplewebauthn-browser.js';
    window.startRegistration = startRegistration;
  </script>
  <script>
    let recoveryCodes = [];

    function getParentOrigin() {
      try {
        const ref = document.referrer;
        if (!ref) return null;
        const origin = new URL(ref).origin;
        if (origin === 'https://ellul.ai' || (origin.startsWith('https://') && (origin.endsWith('.ellul.ai') || origin.endsWith('.ellul.app')))) return origin;
        return null;
      } catch { return null; }
    }

    function displayRecoveryCodes(codes) {
      recoveryCodes = codes;
      const container = document.getElementById('recovery-codes');
      container.innerHTML = codes.map(code =>
        '<div class="recovery-code">' + code + '</div>'
      ).join('');
      document.getElementById('recovery-section').style.display = 'block';
    }

    function copyRecoveryCodes() {
      const text = 'Sovereign Shield Recovery Codes\\n' +
        '================================\\n' +
        recoveryCodes.join('\\n') +
        '\\n================================\\n' +
        'Save these codes securely. Each can only be used once.';
      navigator.clipboard.writeText(text).then(() => {
        const btn = document.querySelector('.copy-btn');
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy All Codes'; }, 2000);
      });
    }

    async function doRegister() {
      const btn = document.getElementById('register-btn');
      const err = document.getElementById('error-msg');
      const success = document.getElementById('success-msg');
      btn.disabled = true;
      btn.textContent = 'Waiting for device...';
      err.style.display = 'none';
      try {
        const optRes = await fetch('/_auth/register/options', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: new URLSearchParams(window.location.search).get('token') }),
          credentials: 'include',
        });
        if (!optRes.ok) throw new Error((await optRes.json()).error || 'Failed to get options');
        const options = await optRes.json();
        const attResp = await window.startRegistration({ optionsJSON: options });
        const verRes = await fetch('/_auth/register/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: new URLSearchParams(window.location.search).get('token'), attestation: attResp }),
          credentials: 'include',
        });
        if (!verRes.ok) throw new Error((await verRes.json()).error || 'Verification failed');
        const result = await verRes.json();
        btn.style.display = 'none';
        success.style.display = 'block';

        // Initialize PoP (SSH-equivalent security) - MANDATORY
        try {
          if (typeof SESSION_POP === 'undefined') {
            throw new Error('Session security module unavailable');
          }
          await SESSION_POP.initialize();
          SESSION_POP.wrapFetch();
          console.log('[PoP] Session key bound after setup');
        } catch (popErr) {
          console.error('[PoP] Init failed:', popErr);
          err.textContent = 'Session security failed: ' + (popErr.message || 'Unknown error');
          err.style.display = 'block';
          // Don't block setup - PoP can be bound on next login
        }

        // Display recovery codes if returned (first passkey registration)
        if (result.recoveryCodes && result.recoveryCodes.length > 0) {
          displayRecoveryCodes(result.recoveryCodes);
        }

        // Notify parent iframe that registration is complete, include session for preview auth
        if (window.parent !== window) {
          const parentOrigin = getParentOrigin();
          if (parentOrigin) {
            window.parent.postMessage({ type: 'shield-registered', sessionId: result.sessionId }, parentOrigin);
          }
        }
      } catch (e) {
        err.textContent = e.message || 'Registration failed.';
        err.style.display = 'block';
        btn.disabled = false;
        btn.innerHTML = '<span class="fingerprint">&#9757;</span> Register Passkey';
      }
    }
    window.doRegister = doRegister;
    window.copyRecoveryCodes = copyRecoveryCodes;
  </script>
</body>
</html>`);
  });

  /**
   * Registration options
   */
  app.post('/_auth/register/options', async (c) => {
    const body = await c.req.json() as { token?: string; name?: string };

    if (!validateSetupToken(body.token)) {
      return c.json({ error: 'Invalid or expired setup token' }, 403);
    }

    // Prevent registration if credentials already exist (must use bridge to add more)
    const credCount = db.prepare('SELECT COUNT(*) as count FROM credential').get() as { count: number };
    if (credCount.count > 0) {
      return c.json({ error: 'Passkeys already registered. Use dashboard to add additional keys.' }, 403);
    }

    // Load attestation policy
    const attestationPolicy = loadAttestationPolicy();

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userName: 'owner',
      userDisplayName: 'Server Owner',
      // Request attestation based on policy (allows AAGUID verification)
      attestationType: attestationPolicy.mode === 'none' ? 'none' : 'direct',
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'preferred',
        userVerification: 'required', // Enforce biometric/PIN verification
      },
    });

    storeChallenge(options.challenge, { type: 'registration', createdAt: Date.now() });
    return c.json(options);
  });

  /**
   * Registration verify
   */
  app.post('/_auth/register/verify', async (c) => {
    const body = await c.req.json() as {
      token?: string;
      attestation?: {
        response?: { clientDataJSON?: string };
      };
      name?: string;
    };

    if (!validateSetupToken(body.token)) {
      return c.json({ error: 'Invalid or expired setup token' }, 403);
    }

    // Extract challenge from attestation response
    const clientDataJSON = body.attestation?.response?.clientDataJSON;
    if (!clientDataJSON) {
      return c.json({ error: 'Invalid attestation' }, 400);
    }
    const clientData = JSON.parse(Buffer.from(clientDataJSON, 'base64').toString());
    const expectedChallenge = clientData.challenge;

    const challengeData = getChallenge(expectedChallenge);
    if (!challengeData || challengeData.type !== 'registration') {
      return c.json({ error: 'No pending registration or challenge expired' }, 400);
    }

    const ip = getClientIp(c);
    const fingerprintData = getDeviceFingerprint(c);

    try {
      const verification = await verifyRegistrationResponse({
        response: body.attestation,
        expectedChallenge,
        expectedOrigin: ORIGINS,
        expectedRPID: RP_ID,
        requireUserVerification: true, // Enforce biometric/PIN was used
      });

      if (!verification.verified || !verification.registrationInfo) {
        return c.json({ error: 'Verification failed' }, 400);
      }

      const { credential, aaguid, credentialDeviceType, credentialBackedUp, attestationObject } = verification.registrationInfo;

      // Load attestation policy and verify AAGUID
      const attestationPolicy = loadAttestationPolicy();
      const aaguidStr = aaguid || '00000000-0000-0000-0000-000000000000';
      const authenticatorName = TRUSTED_AAGUIDS[aaguidStr] || 'Unknown Authenticator';

      // Check AAGUID against policy
      if (attestationPolicy.mode === 'strict') {
        if (!attestationPolicy.allowedAAGUIDs.includes(aaguidStr)) {
          logAuditEvent({
            type: 'attestation_rejected',
            ip,
            fingerprint: fingerprintData.hash,
            details: {
              aaguid: aaguidStr,
              reason: 'aaguid_not_in_allowlist',
              credentialDeviceType,
              credentialBackedUp
            }
          });
          return c.json({
            error: 'Authenticator not allowed',
            details: 'This authenticator type is not permitted by security policy. Use a hardware security key or platform authenticator.',
            aaguid: aaguidStr,
            authenticator: authenticatorName
          }, 403);
        }
      }

      // Log warning for unknown AAGUIDs in permissive mode
      if (attestationPolicy.mode === 'permissive' && attestationPolicy.warnUnknownAAGUID) {
        if (!attestationPolicy.allowedAAGUIDs.includes(aaguidStr)) {
          logAuditEvent({
            type: 'attestation_unknown_aaguid',
            ip,
            fingerprint: fingerprintData.hash,
            details: { aaguid: aaguidStr, credentialDeviceType, credentialBackedUp, authenticatorName }
          });
          console.log('[shield] WARNING: Unknown AAGUID registered:', aaguidStr);
        }
      }

      // Log attestation details for audit
      if (attestationPolicy.logAttestationDetails) {
        logAuditEvent({
          type: 'credential_attestation',
          ip,
          fingerprint: fingerprintData.hash,
          details: {
            aaguid: aaguidStr,
            authenticatorName,
            credentialDeviceType: credentialDeviceType || 'unknown',
            credentialBackedUp: !!credentialBackedUp,
            fmt: attestationObject?.fmt || 'unknown'
          }
        });
      }

      const credId = crypto.randomUUID();
      // credential.id may be Uint8Array (encode it) or already base64url string (use as-is)
      const credentialIdB64 = typeof credential.id === 'string'
        ? credential.id
        : Buffer.from(credential.id as Uint8Array).toString('base64url');

      // Store credential with attestation info
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
        body.name || authenticatorName || 'Passkey'
      );

      deleteChallenge(expectedChallenge);
      cleanupSetupToken();

      // If lock_web_only was requested, block SSH now that passkey is registered
      if (fs.existsSync(PENDING_SSH_BLOCK_FILE)) {
        try {
          execSync('ufw delete allow 22/tcp 2>/dev/null || true', { stdio: 'ignore' });
          execSync('ufw deny 22/tcp 2>/dev/null || true', { stdio: 'ignore' });
          fs.writeFileSync(SOVEREIGN_KEYS_FILE, '');
          fs.chmodSync(SOVEREIGN_KEYS_FILE, 0o400);
          execSync('chattr +i ' + SOVEREIGN_KEYS_FILE + ' 2>/dev/null || true', { stdio: 'ignore' });
          fs.unlinkSync(PENDING_SSH_BLOCK_FILE);
          console.log('[shield] SSH blocked permanently after passkey registration');
        } catch (e) {
          console.error('[shield] Error blocking SSH:', (e as Error).message);
        }
      }

      // If transitioning from SSH Only to Web Locked
      if (fs.existsSync(SSH_TRANSITION_MARKER)) {
        try {
          console.log('[shield] Completing SSH Only -> Web Locked transition');

          // CRITICAL: Remove any pending SSH block file
          if (fs.existsSync(PENDING_SSH_BLOCK_FILE)) {
            console.log('[shield] WARNING: Found unexpected pending-ssh-block file, removing it');
            fs.unlinkSync(PENDING_SSH_BLOCK_FILE);
          }

          // Check if SSH keys exist
          const hasSSHKeys = fs.existsSync('/home/dev/.ssh/authorized_keys') &&
            fs.readFileSync('/home/dev/.ssh/authorized_keys', 'utf8').trim().length > 0;

          // Ensure SSH remains enabled throughout this transition
          if (hasSSHKeys) {
            execSync('ufw allow 22/tcp comment SSH 2>/dev/null || true', { stdio: 'ignore' });
            console.log('[shield] SSH access preserved - keys present');
          } else {
            execSync('ufw allow 22/tcp comment SSH 2>/dev/null || true', { stdio: 'ignore' });
          }

          // Remove terminal disabled marker
          if (fs.existsSync(TERMINAL_DISABLED_FILE)) {
            fs.unlinkSync(TERMINAL_DISABLED_FILE);
            console.log('[shield] Removed terminal disabled marker');
          }

          // Create web_locked activation marker (fail-secure protection)
          const WEB_LOCKED_MARKER = '/etc/ellulai/.web_locked_activated';
          fs.writeFileSync(WEB_LOCKED_MARKER, Date.now().toString());
          fs.chmodSync(WEB_LOCKED_MARKER, 0o400);
          console.log('[shield] Web locked marker created');

          // Re-enable web terminal services (dynamic sessions via agent-bridge)
          execSync('systemctl start ellulai-agent-bridge ellulai-term-proxy 2>/dev/null || true', { stdio: 'ignore' });
          console.log('[shield] Terminal services (agent-bridge, term-proxy) started');

          // Re-verify SSH is still enabled
          execSync('ufw allow 22/tcp comment SSH 2>/dev/null || true', { stdio: 'ignore' });
          execSync('systemctl enable --now sshd 2>/dev/null || true', { stdio: 'ignore' });
          console.log('[shield] SSH access re-verified as enabled');

          // Update tier file
          fs.writeFileSync(TIER_FILE, 'web_locked');
          console.log('[shield] Tier updated to web_locked');

          // Notify platform
          const creds = getServerCredentials();
          if (creds && creds.token) {
            fetch(`${creds.apiUrl}/api/servers/${creds.serverId}/vps-event`, {
              method: 'POST',
              headers: {
                'Authorization': `Bearer ${creds.token}`,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                event: 'tier_changed',
                data: { fromTier: 'ssh_only', tier: 'web_locked', ipAddress: ip },
                timestamp: Date.now(),
                nonce: crypto.randomBytes(16).toString('hex'),
              }),
            }).catch(e => console.error('[shield] Failed to notify platform:', (e as Error).message));
          }

          // Clean up transition files
          fs.unlinkSync(SSH_TRANSITION_MARKER);
          try { fs.unlinkSync(SETUP_TOKEN_FILE); } catch {}
          try { fs.unlinkSync(SETUP_EXPIRY_FILE); } catch {}
          console.log('[shield] SSH Only -> Web Locked transition complete');
        } catch (e) {
          console.error('[shield] Error completing SSH -> Web Locked transition:', (e as Error).message);
        }
      }

      logAuditEvent({ type: 'credential_registered', ip, fingerprint: fingerprintData.hash, credentialId: credId });

      // Notify platform about passkey registration
      await notifyPlatformPasskeyRegistered(credentialIdB64, body.name || 'Passkey');

      // Create session with IP + fingerprint binding
      const session = createSession(credId, ip, fingerprintData);
      setSessionCookie(c, session.id, hostname);

      // Check if this is the first passkey - generate recovery codes
      const afterCount = db.prepare('SELECT COUNT(*) as count FROM credential').get() as { count: number };
      if (afterCount.count === 1) {
        // First passkey registered - generate recovery codes
        const codes = generateRecoveryCodes();
        const displayCodes = storeRecoveryCodes(codes);

        logAuditEvent({
          type: 'recovery_codes_generated',
          ip,
          fingerprint: fingerprintData.hash,
          credentialId: credId
        });

        return c.json({
          verified: true,
          sessionId: session.id,
          recoveryCodes: displayCodes,
          recoveryWarning: 'SAVE THESE RECOVERY CODES NOW. They will not be shown again. Use them to recover access if you lose your passkey device.'
        });
      }

      return c.json({ verified: true, sessionId: session.id });
    } catch (e) {
      return c.json({ error: (e as Error).message || 'Verification error' }, 400);
    }
  });

  /**
   * SSH Only -> Web Locked upgrade page (requires token from SSH command)
   */
  app.get('/_auth/ssh-only-upgrade', async (c) => {
    const { getCurrentTier } = await import('../services/tier.service');
    const currentTier = getCurrentTier();
    const token = c.req.query('token') || '';
    const isPopup = c.req.query('popup') === 'true';

    // Validate tier
    if (currentTier !== 'ssh_only') {
      return c.html(`<!DOCTYPE html><html><head><meta charset="utf-8">
        <style>body{font-family:system-ui;background:#0a0a0a;color:#e0e0e0;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;}</style>
      </head><body>
        <div style="text-align:center;padding:20px;">
          <p>This page is only for SSH Only -> Web Locked upgrades.</p>
          <p>Current tier: ${currentTier}</p>
          ${isPopup ? '<p><button onclick="window.close()" style="padding:8px 16px;cursor:pointer;">Close</button></p>' : ''}
        </div>
      </body></html>`, 400);
    }

    // Validate token before showing registration UI
    if (!token || !validateSetupToken(token)) {
      return c.html(`<!DOCTYPE html><html><head><meta charset="utf-8">
        <style>body{font-family:system-ui;background:#0a0a0a;color:#e0e0e0;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;}</style>
      </head><body>
        <div style="text-align:center;padding:20px;max-width:400px;">
          <h2 style="color:#ef4444;">Invalid or Expired Token</h2>
          <p>Run <code style="background:#222;padding:2px 6px;border-radius:4px;">ellulai-web-locked</code> in SSH to get a new setup link.</p>
          ${isPopup ? '<p><button onclick="window.close()" style="padding:8px 16px;cursor:pointer;">Close</button></p>' : ''}
        </div>
      </body></html>`, 403);
    }

    return c.html(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Upgrade to Web Locked</title>
  <script src="/_auth/static/session-pop.js"></script>
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, system-ui, sans-serif; max-width: 420px; margin: 20px auto; padding: 20px; background: #0a0a0a; color: #e0e0e0; }
    h1 { font-size: 1.4rem; margin-bottom: 0.5rem; }
    .subtitle { color: #888; font-size: 0.9rem; margin-bottom: 24px; }
    .info { background: #1a1a2e; border: 1px solid #2a2a4e; border-radius: 8px; padding: 16px; margin-bottom: 24px; font-size: 0.85rem; color: #a0a0c0; }
    button { width: 100%; padding: 14px; border-radius: 8px; border: none; background: #7c3aed; color: white; font-size: 1rem; cursor: pointer; font-weight: 600; display: flex; align-items: center; justify-content: center; gap: 8px; }
    button:hover { background: #6d28d9; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .success { color: #22c55e; margin-top: 16px; display: none; text-align: center; }
    .error { color: #ef4444; margin-top: 12px; display: none; font-size: 0.85rem; text-align: center; }
    .fingerprint { font-size: 1.5rem; }
    .recovery-section { display: none; margin-top: 24px; }
    .recovery-warning { background: #7f1d1d; border: 1px solid #ef4444; padding: 12px; border-radius: 8px; margin-bottom: 16px; font-size: 0.85rem; color: #fca5a5; }
    .recovery-codes { background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 16px; font-family: monospace; font-size: 1rem; display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; }
    .recovery-code { background: #0a0a0a; padding: 8px; border-radius: 4px; text-align: center; letter-spacing: 2px; }
    .copy-btn { margin-top: 12px; background: #333; font-size: 0.85rem; }
    .copy-btn:hover { background: #444; }
  </style>
</head>
<body>
  <h1>Upgrade to Web Locked</h1>
  <p class="subtitle">Register a passkey to enable Web Locked tier.</p>
  <div class="info">
    <strong>What happens:</strong> After registering a passkey, your server will require biometric authentication for web terminal access. SSH access will remain available.
  </div>
  <button id="register-btn" onclick="doRegister()">
    <span class="fingerprint">&#9757;</span>
    Register Passkey
  </button>
  <p class="success" id="success-msg">Passkey registered! Web Locked tier is now active.</p>
  <p class="error" id="error-msg"></p>
  <div class="recovery-section" id="recovery-section">
    <h2 style="font-size:1.1rem;color:#ef4444;margin-bottom:8px;">&#9888; Recovery Codes</h2>
    <div class="recovery-warning">
      <strong>SAVE THESE CODES NOW!</strong><br>
      They will NOT be shown again. Use them to recover access if you lose your passkey device.
    </div>
    <div class="recovery-codes" id="recovery-codes"></div>
    <button class="copy-btn" onclick="copyRecoveryCodes()">Copy All Codes</button>
  </div>
  <script type="module">
    import { startRegistration } from '/_auth/static/simplewebauthn-browser.js';
    window.startRegistration = startRegistration;
  </script>
  <script>
    const TOKEN = '${token}';
    const IS_POPUP = ${isPopup};
    let recoveryCodes = [];

    function displayRecoveryCodes(codes) {
      recoveryCodes = codes;
      const container = document.getElementById('recovery-codes');
      container.innerHTML = codes.map(code =>
        '<div class="recovery-code">' + code + '</div>'
      ).join('');
      document.getElementById('recovery-section').style.display = 'block';
    }

    function copyRecoveryCodes() {
      const text = 'Sovereign Shield Recovery Codes\\n' +
        '================================\\n' +
        recoveryCodes.join('\\n') +
        '\\n================================\\n' +
        'Save these codes securely. Each can only be used once.';
      navigator.clipboard.writeText(text).then(() => {
        const btn = document.querySelector('.copy-btn');
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy All Codes'; }, 2000);
      });
    }

    async function doRegister() {
      const btn = document.getElementById('register-btn');
      const err = document.getElementById('error-msg');
      const success = document.getElementById('success-msg');
      btn.disabled = true;
      btn.textContent = 'Waiting for device...';
      err.style.display = 'none';

      try {
        const optRes = await fetch('/_auth/register/options', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: TOKEN }),
          credentials: 'include',
        });
        if (!optRes.ok) throw new Error((await optRes.json()).error || 'Failed to get options');
        const options = await optRes.json();
        const attResp = await window.startRegistration({ optionsJSON: options });
        const verRes = await fetch('/_auth/register/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: TOKEN, attestation: attResp }),
          credentials: 'include',
        });
        if (!verRes.ok) throw new Error((await verRes.json()).error || 'Verification failed');
        const result = await verRes.json();

        btn.style.display = 'none';
        success.style.display = 'block';

        // Initialize PoP
        try {
          if (typeof SESSION_POP !== 'undefined') {
            await SESSION_POP.initialize();
            SESSION_POP.wrapFetch();
          }
        } catch {}

        // Display recovery codes if returned (first passkey registration)
        if (result.recoveryCodes && result.recoveryCodes.length > 0) {
          displayRecoveryCodes(result.recoveryCodes);
          // Don't auto-redirect if showing recovery codes - user needs to save them
          return;
        }

        // Notify opener and close if popup (only if no recovery codes to show)
        if (IS_POPUP && window.opener) {
          window.opener.postMessage({ type: 'upgrade-complete', tier: 'web_locked' }, '*');
          setTimeout(() => window.close(), 1500);
        } else {
          setTimeout(() => { window.location.href = '/'; }, 2000);
        }
      } catch (e) {
        err.textContent = e.message || 'Registration failed.';
        err.style.display = 'block';
        btn.disabled = false;
        btn.innerHTML = '<span class="fingerprint">&#9757;</span> Register Passkey';
      }
    }
    window.doRegister = doRegister;
    window.copyRecoveryCodes = copyRecoveryCodes;
  </script>
</body>
</html>`);
  });
}
