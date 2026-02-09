/**
 * Upgrade Routes
 *
 * Direct tier upgrade endpoints from Standard tier (JWT authenticated).
 * These endpoints allow users in Standard tier to upgrade directly
 * without going through the bridge.
 *
 * Endpoints:
 * - POST /_auth/upgrade-to-ssh-only         - Upgrade from Standard to SSH Only
 * - POST /_auth/upgrade-to-web-locked       - Initiate Web Locked upgrade
 * - POST /_auth/upgrade-to-web-locked/verify - Complete Web Locked upgrade
 * - GET  /_auth/bootstrap                   - Bootstrap SSH Only mode (DEPRECATED)
 * - POST /_auth/bootstrap/complete          - Complete bootstrap
 */

import type { Hono } from 'hono';
import crypto from 'crypto';
import fs from 'fs';
import { execSync } from 'child_process';
import { db } from '../database';
import {
  RP_NAME,
  SSH_AUTH_KEYS_PATH,
  TRUSTED_AAGUIDS,
} from '../config';
import { getDeviceFingerprint, getClientIp } from '../auth/fingerprint';
import { createSession, setSessionCookie } from '../auth/session';
import { verifyJwtToken } from '../auth/jwt';
import { logAuditEvent } from '../services/audit.service';
import {
  getCurrentTier,
  executeTierSwitch,
  notifyPlatformSshKeyChange,
  notifyPlatformPasskeyRegistered,
} from '../services/tier.service';
import { loadAttestationPolicy } from '../services/setup.service';
import { computeSshFingerprint } from './keys.routes';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  storeChallenge,
  getChallenge,
  deleteChallenge,
} from '../auth/webauthn';
import { generateRecoveryCodes, storeRecoveryCodes } from '../auth/recovery';

// Bootstrap session files
const BOOTSTRAP_SESSION_FILE = '/etc/ellulai/.bootstrap-session';
const BOOTSTRAP_TEMP_KEY_FILE = '/etc/ellulai/.bootstrap-temp-key';
const BOOTSTRAP_TOKEN_FILE = '/etc/ellulai/.bootstrap-token';
const BOOTSTRAP_EXPIRY_MS = 30 * 60 * 1000; // 30 minutes

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
   * Direct upgrade from Standard to SSH Only
   * Requires JWT authentication
   */
  app.post('/_auth/upgrade-to-ssh-only', async (c) => {
    // Only accept JWT cookie (must be in Standard tier)
    const decoded = verifyJwtToken(c.req);

    if (!decoded) {
      return c.json({ error: 'Authentication required' }, 401);
    }

    // Check current tier
    const currentTier = getCurrentTier();
    if (currentTier !== 'standard') {
      return c.json({ error: 'Can only upgrade to SSH Only from Standard tier', currentTier }, 400);
    }

    const ip = getClientIp(c);
    const body = await c.req.json() as { name?: string; publicKey?: string };
    const { name, publicKey } = body;

    if (!publicKey || typeof publicKey !== 'string') {
      return c.json({ error: 'Public key is required' }, 400);
    }

    const trimmedKey = publicKey.trim();

    // Validate key format
    if (!/^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d+)\s+/.test(trimmedKey)) {
      return c.json({ error: 'Invalid SSH public key format' }, 400);
    }

    if (trimmedKey.includes('PRIVATE KEY')) {
      return c.json({ error: 'You pasted a PRIVATE key! Only paste the PUBLIC key.' }, 400);
    }

    const keyFingerprint = computeSshFingerprint(trimmedKey);

    try {
      // Ensure .ssh directory exists
      execSync('mkdir -p /home/dev/.ssh && chmod 700 /home/dev/.ssh && chown dev:dev /home/dev/.ssh', { stdio: 'ignore' });

      // Check if key already exists (by fingerprint)
      let keyAlreadyExists = false;
      try {
        const existingContent = fs.readFileSync(SSH_AUTH_KEYS_PATH, 'utf8');
        const existingLines = existingContent.split('\n').filter(l => l.trim() && !l.startsWith('#'));
        keyAlreadyExists = existingLines.some(line => computeSshFingerprint(line) === keyFingerprint);
      } catch {
        // File doesn't exist yet, that's fine
      }

      // Only add if not already present
      if (!keyAlreadyExists) {
        const keyLine = name ? `${trimmedKey} ${name}` : trimmedKey;
        fs.appendFileSync(SSH_AUTH_KEYS_PATH, keyLine + '\n');
        notifyPlatformSshKeyChange('added', keyFingerprint, name || 'SSH Key', trimmedKey);
      }
      execSync(`chown dev:dev ${SSH_AUTH_KEYS_PATH} && chmod 600 ${SSH_AUTH_KEYS_PATH}`, { stdio: 'ignore' });

      // Execute tier switch to SSH Only
      await executeTierSwitch('ssh_only', ip, c.req.header('user-agent') || 'unknown');

      logAuditEvent({ type: 'tier_upgrade_ssh_only', ip, details: { keyFingerprint, name } });

      return c.json({
        success: true,
        tier: 'ssh_only',
        fingerprint: keyFingerprint,
        message: 'Upgraded to SSH Only. Web terminal is now disabled.',
      });
    } catch (e) {
      const err = e as Error;
      console.error('[shield] Error upgrading to SSH Only:', err.message, err.stack);
      return c.json({ error: 'Failed to upgrade to SSH Only', details: err.message }, 500);
    }
  });

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
   * DEPRECATED: Bootstrap SSH Only mode
   * Use /_auth/upgrade-to-ssh-only instead
   */
  app.get('/_auth/bootstrap', async (c) => {
    const token = c.req.query('token');

    // Read expected token
    let expectedToken: string | null = null;
    try {
      expectedToken = fs.readFileSync(BOOTSTRAP_TOKEN_FILE, 'utf8').trim();
    } catch {
      // Token file doesn't exist
    }

    // Check current tier
    const currentTier = getCurrentTier();

    // If no token provided or no expected token, show waiting page
    if (!token || !expectedToken) {
      return c.html(`<!DOCTYPE html>
<html><head><title>SSH Only Setup</title>
<style>
  body { font-family: system-ui; background: #0a0a0a; color: white; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
  .container { max-width: 400px; text-align: center; padding: 2rem; }
  .loader { width: 40px; height: 40px; border: 3px solid #333; border-top-color: #10b981; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 1rem; }
  @keyframes spin { to { transform: rotate(360deg); } }
  h2 { color: #10b981; margin-bottom: 0.5rem; }
  p { color: #888; font-size: 0.9rem; }
</style>
<meta http-equiv="refresh" content="3">
</head><body>
<div class="container">
  <div class="loader"></div>
  <h2>Setting Up SSH Only Mode</h2>
  <p>Please wait while we prepare your server...</p>
  <p style="font-size: 0.8rem; margin-top: 2rem;">This page will refresh automatically.</p>
</div>
</body></html>`);
    }

    // Verify token
    if (token !== expectedToken) {
      return c.html(`<!DOCTYPE html>
<html><head><title>Invalid Token</title>
<style>
  body { font-family: system-ui; background: #0a0a0a; color: white; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
  .container { max-width: 400px; text-align: center; padding: 2rem; }
  h2 { color: #ef4444; }
  p { color: #888; }
</style>
</head><body>
<div class="container">
  <h2>Invalid or Expired Token</h2>
  <p>Please start the SSH Only upgrade again from the dashboard.</p>
</div>
</body></html>`, 400);
    }

    // Check tier
    if (currentTier !== 'standard') {
      return c.html(`<!DOCTYPE html>
<html><head><title>Already Upgraded</title>
<style>
  body { font-family: system-ui; background: #0a0a0a; color: white; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
  .container { max-width: 400px; text-align: center; padding: 2rem; }
  h2 { color: #10b981; }
  p { color: #888; }
</style>
</head><body>
<div class="container">
  <h2>Already Upgraded</h2>
  <p>Your server is already in ${currentTier} mode.</p>
</div>
</body></html>`);
    }

    // Check if bootstrap already in progress
    if (fs.existsSync(BOOTSTRAP_SESSION_FILE)) {
      try {
        const session = JSON.parse(fs.readFileSync(BOOTSTRAP_SESSION_FILE, 'utf8'));
        if (Date.now() < session.expiresAt) {
          return c.html(`<!DOCTYPE html>
<html><head><title>Bootstrap In Progress</title>
<style>
  body { font-family: system-ui; background: #0a0a0a; color: white; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
  .container { max-width: 500px; text-align: center; padding: 2rem; }
  h2 { color: #f59e0b; }
  p { color: #888; margin: 1rem 0; }
  code { background: #1a1a1a; padding: 0.5rem 1rem; border-radius: 4px; display: block; margin: 1rem 0; color: #10b981; }
</style>
</head><body>
<div class="container">
  <h2>Bootstrap Already Started</h2>
  <p>A bootstrap session is already in progress. If you've lost the temporary key, wait for it to expire and try again.</p>
  <p>Expires: ${new Date(session.expiresAt).toLocaleString()}</p>
  <p>If you have the key, SSH in and run:</p>
  <code>ellulai-ssh-setup ~/.ssh/id_ed25519.pub</code>
</div>
</body></html>`);
        }
      } catch {}
      // Expired, clean up
      try { fs.unlinkSync(BOOTSTRAP_SESSION_FILE); } catch {}
      try { fs.unlinkSync(BOOTSTRAP_TEMP_KEY_FILE); } catch {}
    }

    // Generate temporary SSH keypair
    const sessionId = crypto.randomUUID();
    const tempKeyPath = '/tmp/bootstrap_key_' + sessionId;
    const serverIp = execSync('hostname -I 2>/dev/null || echo "your-server-ip"').toString().trim().split(' ')[0];

    try {
      execSync(`ssh-keygen -t ed25519 -f ${tempKeyPath} -N "" -C "ellulai-bootstrap-temp"`, { stdio: 'pipe' });

      const privateKey = fs.readFileSync(tempKeyPath, 'utf8');
      const publicKey = fs.readFileSync(tempKeyPath + '.pub', 'utf8').trim();

      // Clean up temp files
      fs.unlinkSync(tempKeyPath);
      fs.unlinkSync(tempKeyPath + '.pub');

      // Install temp key in authorized_keys
      execSync('mkdir -p /home/dev/.ssh && chmod 700 /home/dev/.ssh && chown dev:dev /home/dev/.ssh', { stdio: 'ignore' });
      fs.writeFileSync(SSH_AUTH_KEYS_PATH, publicKey + '\n');
      execSync(`chown dev:dev ${SSH_AUTH_KEYS_PATH} && chmod 600 ${SSH_AUTH_KEYS_PATH}`, { stdio: 'ignore' });

      // Enable SSH server
      execSync('ufw allow 22/tcp comment SSH 2>/dev/null || true', { stdio: 'pipe' });
      execSync('systemctl enable --now sshd 2>/dev/null || true', { stdio: 'pipe' });

      // Store bootstrap session
      const session = {
        id: sessionId,
        tempKeyFingerprint: computeSshFingerprint(publicKey),
        createdAt: Date.now(),
        expiresAt: Date.now() + BOOTSTRAP_EXPIRY_MS,
      };
      fs.writeFileSync(BOOTSTRAP_SESSION_FILE, JSON.stringify(session));
      fs.chmodSync(BOOTSTRAP_SESSION_FILE, 0o600);

      // Store temp key fingerprint for cleanup
      fs.writeFileSync(BOOTSTRAP_TEMP_KEY_FILE, session.tempKeyFingerprint);
      fs.chmodSync(BOOTSTRAP_TEMP_KEY_FILE, 0o600);

      // Clear the bootstrap token (one-time use)
      try { fs.unlinkSync(BOOTSTRAP_TOKEN_FILE); } catch {}

      logAuditEvent({
        type: 'bootstrap_initiated',
        ip: getClientIp(c),
        details: { sessionId, tempKeyFingerprint: session.tempKeyFingerprint }
      });

      console.log('[shield] SSH Only bootstrap initiated, temp key installed');

      // Show the private key to user - THIS IS SHOWN ONCE
      return c.html(`<!DOCTYPE html>
<html><head><title>SSH Only Setup - Save Your Key</title>
<style>
  body { font-family: system-ui; background: #0a0a0a; color: white; margin: 0; padding: 2rem; }
  .container { max-width: 700px; margin: 0 auto; }
  h1 { color: #10b981; margin-bottom: 0.5rem; }
  .warning { background: #7c2d12; border: 1px solid #ea580c; padding: 1rem; border-radius: 8px; margin: 1rem 0; }
  .warning h3 { color: #fb923c; margin: 0 0 0.5rem 0; }
  .step { background: #1a1a1a; padding: 1rem; border-radius: 8px; margin: 1rem 0; }
  .step h3 { color: #10b981; margin: 0 0 0.5rem 0; font-size: 0.9rem; }
  .step code { display: block; background: #0a0a0a; padding: 0.75rem; border-radius: 4px; margin: 0.5rem 0; font-size: 0.85rem; color: #4ade80; overflow-x: auto; }
  pre { background: #0a0a0a; border: 1px solid #333; padding: 1rem; border-radius: 8px; overflow-x: auto; font-size: 0.8rem; color: #888; margin: 1rem 0; white-space: pre-wrap; word-break: break-all; }
  .copy-btn { background: #10b981; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; font-size: 0.85rem; }
  .copy-btn:hover { background: #059669; }
  .expires { color: #888; font-size: 0.8rem; margin-top: 1rem; }
</style>
</head><body>
<div class="container">
  <h1>SSH Only Setup</h1>

  <div class="warning">
    <h3>Warning: Save This Key NOW</h3>
    <p style="margin:0;color:#fed7aa;">This temporary SSH key will NOT be shown again. Copy it before leaving this page.</p>
  </div>

  <div class="step">
    <h3>Step 1: Save the temporary private key to a file</h3>
    <p style="color:#888;font-size:0.85rem;">Copy this key and save it to a file on your computer:</p>
    <pre id="privateKey">${privateKey}</pre>
    <button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('privateKey').textContent);this.textContent='Copied!';">Copy Key</button>
  </div>

  <div class="step">
    <h3>Step 2: Set permissions on the key file</h3>
    <code>chmod 600 /tmp/ellulai_temp_key</code>
  </div>

  <div class="step">
    <h3>Step 3: SSH into your server</h3>
    <code>ssh -i /tmp/ellulai_temp_key dev@${serverIp}</code>
  </div>

  <div class="step">
    <h3>Step 4: Run the setup command with YOUR public key</h3>
    <code>ellulai-ssh-setup ~/.ssh/id_ed25519.pub</code>
    <p style="color:#888;font-size:0.8rem;margin:0.5rem 0 0 0;">This adds your permanent key and completes the upgrade.</p>
  </div>

  <div class="step">
    <h3>Step 5: Delete the temporary key file</h3>
    <code>rm /tmp/ellulai_temp_key</code>
  </div>

  <p class="expires">This temporary key expires in 30 minutes.</p>
</div>
</body></html>`);
    } catch (e) {
      console.error('[shield] Bootstrap initiate error:', e);
      return c.html(`<!DOCTYPE html>
<html><head><title>Error</title>
<style>
  body { font-family: system-ui; background: #0a0a0a; color: white; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
  .container { max-width: 400px; text-align: center; padding: 2rem; }
  h2 { color: #ef4444; }
</style>
</head><body>
<div class="container">
  <h2>Setup Failed</h2>
  <p>Failed to generate temporary SSH keypair. Please try again.</p>
</div>
</body></html>`, 500);
    }
  });

  /**
   * Complete bootstrap - called by ellulai-ssh-setup script
   */
  app.post('/_auth/bootstrap/complete', async (c) => {
    const body = await c.req.json() as { sessionId?: string; permanentKeyFingerprint?: string };
    const { sessionId, permanentKeyFingerprint } = body;

    // Verify bootstrap session exists and is valid
    if (!fs.existsSync(BOOTSTRAP_SESSION_FILE)) {
      return c.json({ error: 'No active bootstrap session' }, 400);
    }

    let session: { id: string; tempKeyFingerprint: string; expiresAt: number };
    try {
      session = JSON.parse(fs.readFileSync(BOOTSTRAP_SESSION_FILE, 'utf8'));
    } catch {
      return c.json({ error: 'Invalid bootstrap session' }, 400);
    }

    if (session.id !== sessionId) {
      return c.json({ error: 'Session ID mismatch' }, 400);
    }

    if (Date.now() > session.expiresAt) {
      // Clean up expired session
      try { fs.unlinkSync(BOOTSTRAP_SESSION_FILE); } catch {}
      try { fs.unlinkSync(BOOTSTRAP_TEMP_KEY_FILE); } catch {}
      return c.json({ error: 'Bootstrap session expired' }, 400);
    }

    // Remove temp key from authorized_keys
    const tempKeyFingerprint = session.tempKeyFingerprint;
    try {
      let content = fs.readFileSync(SSH_AUTH_KEYS_PATH, 'utf8');
      const lines = content.split('\n').filter(line => {
        if (!line.trim() || line.includes('ellulai-bootstrap-temp')) return false;
        return computeSshFingerprint(line) !== tempKeyFingerprint;
      });
      fs.writeFileSync(SSH_AUTH_KEYS_PATH, lines.join('\n') + '\n');
    } catch (e) {
      console.error('[shield] Error removing temp key:', e);
    }

    // Disable web terminal for SSH Only mode
    fs.writeFileSync('/etc/ellulai/.terminal-disabled', '');
    fs.chmodSync('/etc/ellulai/.terminal-disabled', 0o400);

    // Disable passkey gate if active
    execSync('/usr/local/bin/ellulai-unlock 2>&1 || true', { stdio: 'pipe' });

    // Stop terminal services (dynamic sessions via agent-bridge + legacy static services)
    execSync('systemctl stop ellulai-agent-bridge ellulai-term-proxy 2>/dev/null || true', { stdio: 'pipe' });
    execSync('systemctl stop ttyd@main ttyd@opencode ttyd@claude ttyd@codex ttyd@gemini ttyd@aider ttyd@git ttyd@branch ttyd@save ttyd@ship 2>/dev/null || true', { stdio: 'pipe' });
    execSync('systemctl disable ttyd@main ttyd@opencode ttyd@claude ttyd@codex ttyd@gemini ttyd@aider ttyd@git ttyd@branch ttyd@save ttyd@ship 2>/dev/null || true', { stdio: 'pipe' });

    // Update security tier
    fs.writeFileSync('/etc/ellulai/security-tier', 'ssh_only');

    // Clean up bootstrap session files
    try { fs.unlinkSync(BOOTSTRAP_SESSION_FILE); } catch {}
    try { fs.unlinkSync(BOOTSTRAP_TEMP_KEY_FILE); } catch {}

    logAuditEvent({
      type: 'bootstrap_completed',
      ip: getClientIp(c),
      details: { sessionId, permanentKeyFingerprint }
    });

    console.log('[shield] SSH Only bootstrap completed');

    return c.json({
      success: true,
      tier: 'ssh_only',
      message: 'SSH Only mode activated. Web terminal is now disabled.',
    });
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

  // SSH Only to Web Locked upgrade files
  const SSH_SETUP_TOKEN_FILE = '/etc/ellulai/.sovereign-setup-token';
  const SSH_SETUP_EXPIRY_FILE = '/etc/ellulai/.sovereign-setup-expiry';
  const SSH_TRANSITION_MARKER = '/etc/ellulai/.ssh-only-to-web-locked';

  /**
   * SSH Only to Web Locked upgrade - serve registration page
   * This is accessed via the link generated by ellulai-web-locked script
   */
  app.get('/_auth/ssh-only-upgrade', async (c) => {
    const token = c.req.query('token');

    if (!token) {
      return c.html(`<!DOCTYPE html>
<html><head><title>Missing Token</title>
<style>body{font-family:system-ui;background:#0a0a0a;color:white;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;}.container{max-width:400px;text-align:center;padding:2rem;}h2{color:#ef4444;}</style>
</head><body><div class="container"><h2>Missing Token</h2><p style="color:#888;">Run <code>sudo ellulai-web-locked</code> via SSH to generate a setup link.</p></div></body></html>`, 400);
    }

    // Verify token
    let expectedToken: string | null = null;
    let expiry: number | null = null;
    try {
      expectedToken = fs.readFileSync(SSH_SETUP_TOKEN_FILE, 'utf8').trim();
      expiry = parseInt(fs.readFileSync(SSH_SETUP_EXPIRY_FILE, 'utf8').trim(), 10);
    } catch {
      return c.html(`<!DOCTYPE html>
<html><head><title>No Setup Session</title>
<style>body{font-family:system-ui;background:#0a0a0a;color:white;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;}.container{max-width:400px;text-align:center;padding:2rem;}h2{color:#ef4444;}</style>
</head><body><div class="container"><h2>No Active Setup</h2><p style="color:#888;">Run <code>sudo ellulai-web-locked</code> via SSH to start the upgrade process.</p></div></body></html>`, 400);
    }

    if (token !== expectedToken) {
      return c.html(`<!DOCTYPE html>
<html><head><title>Invalid Token</title>
<style>body{font-family:system-ui;background:#0a0a0a;color:white;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;}.container{max-width:400px;text-align:center;padding:2rem;}h2{color:#ef4444;}</style>
</head><body><div class="container"><h2>Invalid Token</h2><p style="color:#888;">The token is invalid. Run <code>sudo ellulai-web-locked</code> again to generate a new link.</p></div></body></html>`, 400);
    }

    if (expiry && Date.now() / 1000 > expiry) {
      // Clean up expired files
      try { fs.unlinkSync(SSH_SETUP_TOKEN_FILE); } catch {}
      try { fs.unlinkSync(SSH_SETUP_EXPIRY_FILE); } catch {}
      try { fs.unlinkSync(SSH_TRANSITION_MARKER); } catch {}
      return c.html(`<!DOCTYPE html>
<html><head><title>Token Expired</title>
<style>body{font-family:system-ui;background:#0a0a0a;color:white;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;}.container{max-width:400px;text-align:center;padding:2rem;}h2{color:#f59e0b;}</style>
</head><body><div class="container"><h2>Token Expired</h2><p style="color:#888;">The setup link has expired. Run <code>sudo ellulai-web-locked</code> again via SSH.</p></div></body></html>`, 400);
    }

    // Serve the passkey registration page
    return c.html(`<!DOCTYPE html>
<html><head>
<title>Web Locked Setup - Register Passkey</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  * { box-sizing: border-box; }
  body { font-family: system-ui, -apple-system, sans-serif; background: #0a0a0a; color: white; margin: 0; padding: 1rem; min-height: 100vh; display: flex; justify-content: center; align-items: center; }
  .container { max-width: 420px; width: 100%; }
  h1 { color: #10b981; font-size: 1.5rem; margin: 0 0 0.5rem 0; text-align: center; }
  .subtitle { color: #888; font-size: 0.9rem; text-align: center; margin-bottom: 1.5rem; }
  .card { background: #1a1a1a; border: 1px solid #333; border-radius: 12px; padding: 1.5rem; }
  .info { background: #0c4a6e; border: 1px solid #0284c7; border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem; font-size: 0.85rem; color: #7dd3fc; }
  .info strong { color: #38bdf8; }
  label { display: block; color: #888; font-size: 0.85rem; margin-bottom: 0.5rem; }
  input { width: 100%; background: #0a0a0a; border: 1px solid #333; border-radius: 6px; padding: 0.75rem; color: white; font-size: 1rem; margin-bottom: 1rem; }
  input:focus { outline: none; border-color: #10b981; }
  button { width: 100%; background: #10b981; color: white; border: none; border-radius: 8px; padding: 1rem; font-size: 1rem; font-weight: 600; cursor: pointer; transition: background 0.2s; }
  button:hover { background: #059669; }
  button:disabled { background: #374151; cursor: not-allowed; }
  .error { background: #7f1d1d; border: 1px solid #dc2626; border-radius: 8px; padding: 1rem; margin-top: 1rem; color: #fca5a5; display: none; }
  .success { background: #14532d; border: 1px solid #22c55e; border-radius: 8px; padding: 1rem; margin-top: 1rem; color: #86efac; display: none; }
  .loader { display: none; width: 20px; height: 20px; border: 2px solid transparent; border-top-color: white; border-radius: 50%; animation: spin 0.8s linear infinite; margin: 0 auto; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="container">
  <h1>🔐 Web Locked Setup</h1>
  <p class="subtitle">Register a passkey to enable Web Locked mode</p>

  <div class="card">
    <div class="info">
      <strong>What is Web Locked?</strong><br>
      Web Locked mode requires passkey authentication for all web access. This is the highest security tier.
    </div>

    <label for="name">Passkey Name (optional)</label>
    <input type="text" id="name" placeholder="e.g., iPhone, MacBook" />

    <button id="registerBtn" onclick="startRegistration()">
      <span id="btnText">Register Passkey</span>
      <div class="loader" id="loader"></div>
    </button>

    <div class="error" id="error"></div>
    <div class="success" id="success"></div>
  </div>
</div>

<script>
const token = new URLSearchParams(window.location.search).get('token');

async function startRegistration() {
  const btn = document.getElementById('registerBtn');
  const btnText = document.getElementById('btnText');
  const loader = document.getElementById('loader');
  const errorDiv = document.getElementById('error');
  const successDiv = document.getElementById('success');
  const name = document.getElementById('name').value.trim() || 'Passkey';

  btn.disabled = true;
  btnText.style.display = 'none';
  loader.style.display = 'block';
  errorDiv.style.display = 'none';

  try {
    // Get registration options
    const optRes = await fetch('/_auth/ssh-only-upgrade/options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, name })
    });

    if (!optRes.ok) {
      const err = await optRes.json();
      throw new Error(err.error || 'Failed to get registration options');
    }

    const { options } = await optRes.json();

    // Decode challenge and user.id from base64url
    options.challenge = base64urlToBuffer(options.challenge);
    options.user.id = base64urlToBuffer(options.user.id);
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map(c => ({
        ...c,
        id: base64urlToBuffer(c.id)
      }));
    }

    // Create credential
    const credential = await navigator.credentials.create({ publicKey: options });

    // Encode response
    const attestation = {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
        attestationObject: bufferToBase64url(credential.response.attestationObject),
      },
      authenticatorAttachment: credential.authenticatorAttachment,
    };
    if (credential.response.getTransports) {
      attestation.response.transports = credential.response.getTransports();
    }

    // Verify and complete
    const verifyRes = await fetch('/_auth/ssh-only-upgrade/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, attestation, name })
    });

    if (!verifyRes.ok) {
      const err = await verifyRes.json();
      throw new Error(err.error || 'Verification failed');
    }

    const result = await verifyRes.json();

    successDiv.innerHTML = '<strong>✓ Web Locked Enabled!</strong><br>Passkey registered successfully. Redirecting...';
    successDiv.style.display = 'block';

    if (result.recoveryCodes) {
      successDiv.innerHTML += '<br><br><strong>Recovery Codes:</strong><br><code style="font-size:0.8rem;">' + result.recoveryCodes.join('<br>') + '</code><br><br><strong>SAVE THESE NOW!</strong>';
      setTimeout(() => { window.location.href = '/'; }, 15000);
    } else {
      setTimeout(() => { window.location.href = '/'; }, 2000);
    }

  } catch (e) {
    errorDiv.textContent = e.message || 'Registration failed';
    errorDiv.style.display = 'block';
    btn.disabled = false;
    btnText.style.display = 'block';
    loader.style.display = 'none';
  }
}

function base64urlToBuffer(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - base64.length % 4) % 4);
  const binary = atob(base64 + padding);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
}
</script>
</body>
</html>`);
  });

  /**
   * SSH Only to Web Locked - get registration options
   */
  app.post('/_auth/ssh-only-upgrade/options', async (c) => {
    const body = await c.req.json() as { token?: string; name?: string };
    const { token, name } = body;

    // Verify token
    let expectedToken: string | null = null;
    let expiry: number | null = null;
    try {
      expectedToken = fs.readFileSync(SSH_SETUP_TOKEN_FILE, 'utf8').trim();
      expiry = parseInt(fs.readFileSync(SSH_SETUP_EXPIRY_FILE, 'utf8').trim(), 10);
    } catch {
      return c.json({ error: 'No active setup session' }, 400);
    }

    if (token !== expectedToken) {
      return c.json({ error: 'Invalid token' }, 400);
    }

    if (expiry && Date.now() / 1000 > expiry) {
      return c.json({ error: 'Token expired' }, 400);
    }

    // Generate registration options
    const userName = name || 'ellul.ai User';
    const attestationPolicy = loadAttestationPolicy();

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userName,
      userDisplayName: userName,
      attestationType: attestationPolicy.mode === 'none' ? 'none' : 'direct',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required',
      },
    });

    // Store challenge
    storeChallenge(options.challenge, {
      type: 'registration',
      userId: crypto.randomBytes(16).toString('base64url'),
      createdAt: Date.now(),
    });

    return c.json({ options });
  });

  /**
   * SSH Only to Web Locked - verify registration and switch tier
   */
  app.post('/_auth/ssh-only-upgrade/verify', async (c) => {
    const body = await c.req.json() as {
      token?: string;
      attestation?: { response?: { clientDataJSON?: string } };
      name?: string;
    };
    const { token, attestation, name } = body;

    // Verify token
    let expectedToken: string | null = null;
    let expiry: number | null = null;
    try {
      expectedToken = fs.readFileSync(SSH_SETUP_TOKEN_FILE, 'utf8').trim();
      expiry = parseInt(fs.readFileSync(SSH_SETUP_EXPIRY_FILE, 'utf8').trim(), 10);
    } catch {
      return c.json({ error: 'No active setup session' }, 400);
    }

    if (token !== expectedToken) {
      return c.json({ error: 'Invalid token' }, 400);
    }

    if (expiry && Date.now() / 1000 > expiry) {
      return c.json({ error: 'Token expired' }, 400);
    }

    if (!attestation) {
      return c.json({ error: 'Attestation required' }, 400);
    }

    const ip = getClientIp(c);
    const fingerprintData = getDeviceFingerprint(c);

    // Extract challenge
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
        requireUserVerification: true,
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

      // Clean up setup files
      try { fs.unlinkSync(SSH_SETUP_TOKEN_FILE); } catch {}
      try { fs.unlinkSync(SSH_SETUP_EXPIRY_FILE); } catch {}

      logAuditEvent({
        type: 'tier_upgrade_web_locked_from_ssh',
        ip,
        fingerprint: fingerprintData.hash,
        credentialId: credId,
      });

      // Notify platform
      await notifyPlatformPasskeyRegistered(credentialIdB64, name || 'Passkey');

      // Create session
      const session = createSession(credId, ip, fingerprintData);
      setSessionCookie(c, session.id, hostname);

      console.log('[shield] SSH Only -> Web Locked upgrade completed');

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
      console.error('[shield] Error verifying SSH Only -> Web Locked upgrade:', e);
      return c.json({ error: (e as Error).message || 'Verification error' }, 400);
    }
  });
}
