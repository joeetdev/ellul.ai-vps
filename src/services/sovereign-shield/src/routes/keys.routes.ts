/**
 * SSH Keys Routes
 *
 * SSH key management endpoints (passkey or JWT protected).
 *
 * Endpoints:
 * - GET  /_auth/keys              - SSH key management UI (HTML)
 * - GET  /_auth/api/keys          - JSON API for SSH keys
 * - POST /_auth/keys              - Add SSH key
 * - DELETE /_auth/keys/:fingerprint - Remove SSH key
 */

import crypto from 'crypto';
import fs from 'fs';
import { execSync } from 'child_process';
import type { Hono, Context } from 'hono';
import { db } from '../database';
import { SSH_AUTH_KEYS_PATH } from '../config';
import type { SecurityTier } from '../config';
import { getDeviceFingerprint, getClientIp } from '../auth/fingerprint';
import { validateSession, refreshSession, setSessionCookie, clearSessionCookie } from '../auth/session';
import { verifyJwtToken } from '../auth/jwt';
import { getCurrentTier, notifyPlatformSshKeyChange } from '../services/tier.service';
import { logAuditEvent } from '../services/audit.service';
import { parseCookies } from '../utils/cookie';

interface SshKey {
  fingerprint: string;
  name: string;
  publicKey: string;
}

interface AuthResult {
  authenticated: boolean;
  error?: string;
  method?: 'passkey' | 'jwt';
  session?: unknown;
  decoded?: unknown;
  tier: SecurityTier;
}

/**
 * Compute SSH fingerprint from public key
 */
function computeSshFingerprint(publicKey: string): string {
  const parts = publicKey.trim().split(/\s+/);
  const keyPart = parts[1];
  if (parts.length < 2 || !keyPart) return 'unknown';
  try {
    const keyData = Buffer.from(keyPart, 'base64');
    const hash = crypto.createHash('sha256').update(keyData).digest('base64');
    return 'SHA256:' + hash.replace(/=+$/, '');
  } catch {
    return 'unknown';
  }
}

/**
 * Get all SSH keys from authorized_keys
 */
function getSshKeys(): SshKey[] {
  const keys: SshKey[] = [];
  try {
    const content = fs.readFileSync(SSH_AUTH_KEYS_PATH, 'utf8');
    const lines = content.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'));
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 2) {
        const fingerprint = computeSshFingerprint(line);
        const comment = parts.length > 2 ? parts.slice(2).join(' ') : 'SSH Key';
        keys.push({ fingerprint, name: comment, publicKey: line.trim() });
      }
    }
  } catch {}
  return keys;
}

/**
 * Check authentication for SSH key management
 * Only Web Locked tier can manage SSH keys via dashboard (passkey required)
 * SSH Only tier must use SSH directly
 * Standard tier has no SSH access
 */
function checkAuth(c: Context): AuthResult {
  const cookies = parseCookies(c.req.header('cookie'));
  const currentTier = getCurrentTier();
  const ip = getClientIp(c);
  const fingerprintData = getDeviceFingerprint(c);

  // Standard tier - no SSH key management via dashboard
  if (currentTier === 'standard') {
    return { authenticated: false, error: 'SSH key management not available in Standard tier. Upgrade to Web Locked for SSH access.', tier: currentTier };
  }

  // SSH Only tier - reject (must use SSH)
  if (currentTier === 'ssh_only') {
    return { authenticated: false, error: 'SSH Only mode - use SSH to manage keys', tier: currentTier };
  }

  // Web Locked tier - passkey required
  const sessionId = cookies.shield_session;
  if (sessionId) {
    const result = validateSession(sessionId, ip, fingerprintData, '/_auth/keys');
    if (result.valid) {
      return { authenticated: true, method: 'passkey', session: result.session, tier: currentTier };
    }
  }

  return { authenticated: false, error: 'Passkey authentication required', tier: currentTier };
}

/**
 * Escape HTML for safe rendering
 */
function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/**
 * Register SSH key routes on Hono app
 */
export function registerKeysRoutes(app: Hono, hostname: string): void {
  /**
   * SSH key management UI (HTML page)
   */
  app.get('/_auth/keys', async (c) => {
    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;

    // Check session
    if (!sessionId) {
      return c.redirect('/_auth/login?redirect=' + encodeURIComponent('/_auth/keys'), 302);
    }

    const ip = getClientIp(c);
    const fingerprintData = getDeviceFingerprint(c);
    const result = validateSession(sessionId, ip, fingerprintData, '/_auth/keys');

    if (!result.valid) {
      clearSessionCookie(c, hostname);
      return c.redirect('/_auth/login?redirect=' + encodeURIComponent('/_auth/keys'), 302);
    }

    // Refresh session
    const refresh = refreshSession(result.session!, ip, fingerprintData);
    if (refresh.rotated) {
      setSessionCookie(c, refresh.sessionId, hostname);
    }

    const keys = getSshKeys();

    return c.html(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SSH Keys - Sovereign Shield</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, system-ui, sans-serif; max-width: 520px; margin: 20px auto; padding: 20px; background: #0a0a0a; color: #e0e0e0; }
    h1 { font-size: 1.4rem; margin-bottom: 0.5rem; }
    .subtitle { color: #888; font-size: 0.9rem; margin-bottom: 24px; }
    .key-list { margin-bottom: 24px; }
    .key-item { display: flex; justify-content: space-between; align-items: center; padding: 12px; border: 1px solid #2a2a3e; border-radius: 8px; margin-bottom: 8px; background: #12121a; }
    .key-info { flex: 1; min-width: 0; }
    .key-name { font-weight: 500; color: #e0e0e0; margin-bottom: 4px; }
    .key-fingerprint { font-family: monospace; font-size: 11px; color: #888; overflow: hidden; text-overflow: ellipsis; }
    .btn { padding: 8px 16px; border-radius: 6px; border: none; cursor: pointer; font-size: 0.9rem; font-weight: 500; }
    .btn-danger { background: #3f1515; color: #ef4444; }
    .btn-danger:hover { background: #5f1f1f; }
    .btn-primary { background: #7c3aed; color: white; width: 100%; padding: 12px; margin-top: 8px; }
    .btn-primary:hover { background: #6d28d9; }
    .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
    .form { margin-top: 24px; padding-top: 24px; border-top: 1px solid #2a2a3e; }
    .form-group { margin-bottom: 12px; }
    .form-label { display: block; font-size: 0.85rem; color: #888; margin-bottom: 6px; }
    .form-input { width: 100%; padding: 10px; background: #12121a; border: 1px solid #2a2a3e; border-radius: 6px; color: #e0e0e0; font-size: 0.9rem; }
    .form-input:focus { outline: none; border-color: #7c3aed; }
    textarea.form-input { min-height: 80px; font-family: monospace; font-size: 12px; resize: vertical; }
    .empty { color: #888; text-align: center; padding: 40px 20px; }
    .error { color: #ef4444; font-size: 0.85rem; margin-top: 8px; display: none; }
    .success { color: #22c55e; font-size: 0.85rem; margin-top: 8px; display: none; }
    .note { font-size: 0.8rem; color: #666; margin-top: 16px; padding: 12px; background: #1a1a2e; border-radius: 6px; }
  </style>
</head>
<body>
  <h1>SSH Keys</h1>
  <p class="subtitle">Manage SSH access to your server (passkey protected)</p>

  <div class="key-list" id="key-list">
    ${keys.length === 0 ? `
      <div class="empty">
        <p>No SSH keys configured.</p>
        <p style="font-size: 0.85rem; margin-top: 8px;">SSH server will start when you add a key.</p>
      </div>
    ` : keys.map(key => `
      <div class="key-item" data-fingerprint="${key.fingerprint}">
        <div class="key-info">
          <div class="key-name">${escapeHtml(key.name)}</div>
          <div class="key-fingerprint">${key.fingerprint}</div>
        </div>
        <button class="btn btn-danger" onclick="removeKey('${key.fingerprint}')">Remove</button>
      </div>
    `).join('')}
  </div>

  <div class="form">
    <div class="form-group">
      <label class="form-label">Key Name (optional)</label>
      <input type="text" class="form-input" id="key-name" placeholder="MacBook Pro, Work Laptop, etc.">
    </div>
    <div class="form-group">
      <label class="form-label">Public Key</label>
      <textarea class="form-input" id="public-key" placeholder="ssh-ed25519 AAAA... or ssh-rsa AAAA..."></textarea>
    </div>
    <button class="btn btn-primary" id="add-btn" onclick="addKey()">Add SSH Key</button>
    <p class="error" id="error-msg"></p>
    <p class="success" id="success-msg"></p>
  </div>

  <div class="note">
    <strong>How it works:</strong> SSH keys added here are stored directly on your server.
    When keys are present, the SSH server runs. Remove all keys to disable SSH access.
  </div>

  <script>
    async function addKey() {
      const name = document.getElementById('key-name').value.trim();
      const publicKey = document.getElementById('public-key').value.trim();
      const btn = document.getElementById('add-btn');
      const errEl = document.getElementById('error-msg');
      const successEl = document.getElementById('success-msg');

      errEl.style.display = 'none';
      successEl.style.display = 'none';

      if (!publicKey) {
        errEl.textContent = 'Public key is required';
        errEl.style.display = 'block';
        return;
      }

      btn.disabled = true;
      btn.textContent = 'Adding...';

      try {
        const res = await fetch('/_auth/keys', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, publicKey }),
          credentials: 'include',
        });

        const data = await res.json();

        if (!res.ok) {
          throw new Error(data.error || 'Failed to add key');
        }

        successEl.textContent = 'SSH key added successfully!';
        successEl.style.display = 'block';
        setTimeout(() => location.reload(), 1000);
      } catch (e) {
        errEl.textContent = e.message;
        errEl.style.display = 'block';
        btn.disabled = false;
        btn.textContent = 'Add SSH Key';
      }
    }

    async function removeKey(fingerprint) {
      if (!confirm('Remove this SSH key?')) return;

      try {
        const res = await fetch('/_auth/keys/' + encodeURIComponent(fingerprint), {
          method: 'DELETE',
          credentials: 'include',
        });

        if (!res.ok) {
          const data = await res.json();
          throw new Error(data.error || 'Failed to remove key');
        }

        location.reload();
      } catch (e) {
        alert('Error: ' + e.message);
      }
    }
  </script>
</body>
</html>`);
  });

  /**
   * JSON API for SSH keys (JWT or passkey auth)
   */
  app.get('/_auth/api/keys', async (c) => {
    const auth = checkAuth(c);
    if (!auth.authenticated) {
      return c.json({ error: auth.error, tier: auth.tier }, 401);
    }

    const keys = getSshKeys();
    return c.json({
      keys,
      tier: auth.tier,
      authMethod: auth.method,
    });
  });

  /**
   * Add SSH key (JWT or passkey auth)
   */
  app.post('/_auth/keys', async (c) => {
    const auth = checkAuth(c);
    if (!auth.authenticated) {
      return c.json({ error: auth.error, tier: auth.tier }, 401);
    }

    const ip = getClientIp(c);
    const fingerprintData = getDeviceFingerprint(c);
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

    // Check for duplicate
    const existingKeys = getSshKeys();
    if (existingKeys.some(k => k.fingerprint === keyFingerprint)) {
      return c.json({ error: 'This key is already added' }, 400);
    }

    // Add key to authorized_keys (atomic: open port first for web_locked tier)
    const currentTier = getCurrentTier();
    const existingKeyCount = existingKeys.length;
    let portWasOpened = false;

    try {
      // Ensure .ssh directory exists
      execSync('mkdir -p /home/dev/.ssh && chmod 700 /home/dev/.ssh && chown dev:dev /home/dev/.ssh', { stdio: 'ignore' });

      // For web_locked tier: open SSH port FIRST (before adding key)
      // This ensures atomic behavior - port is open before key is written
      if (currentTier === 'web_locked' && existingKeyCount === 0) {
        console.log('[shield] Web Locked: Opening SSH port before adding first key...');
        execSync('ufw allow 22/tcp comment SSH 2>/dev/null || true', { stdio: 'pipe' });
        execSync('systemctl enable --now sshd 2>/dev/null || true', { stdio: 'pipe' });
        portWasOpened = true;
      }

      // Append key
      const keyLine = name ? `${trimmedKey} ${name}` : trimmedKey;
      fs.appendFileSync(SSH_AUTH_KEYS_PATH, keyLine + '\n');
      execSync(`chown dev:dev ${SSH_AUTH_KEYS_PATH} && chmod 600 ${SSH_AUTH_KEYS_PATH}`, { stdio: 'ignore' });

      // Verify key was actually added
      const newKeys = getSshKeys();
      const keyAdded = newKeys.some(k => k.fingerprint === keyFingerprint);
      if (!keyAdded) {
        throw new Error('Key was not written to authorized_keys');
      }

      // Notify platform
      notifyPlatformSshKeyChange('added', keyFingerprint, name || 'SSH Key', trimmedKey);

      logAuditEvent({ type: 'ssh_key_added', ip, fingerprint: fingerprintData.hash, details: { keyFingerprint, name, tier: currentTier } });

      return c.json({ success: true, fingerprint: keyFingerprint, sshEnabled: currentTier === 'web_locked' });
    } catch (e) {
      console.error('[shield] Error adding SSH key:', e);

      // Rollback: if we opened the port and there are no other keys, close it
      if (portWasOpened && existingKeyCount === 0) {
        console.log('[shield] Rolling back SSH port opening due to key add failure...');
        try {
          execSync('ufw delete allow 22/tcp 2>/dev/null || true', { stdio: 'ignore' });
          execSync('systemctl disable --now sshd 2>/dev/null || true', { stdio: 'ignore' });
        } catch (rollbackErr) {
          console.error('[shield] Rollback failed:', rollbackErr);
        }
      }
      // Note: Don't close port if other keys exist - only rollback what we changed

      return c.json({ error: 'Failed to add SSH key' }, 500);
    }
  });

  /**
   * Remove SSH key (JWT or passkey auth)
   */
  app.delete('/_auth/keys/:fingerprint', async (c) => {
    const auth = checkAuth(c);
    if (!auth.authenticated) {
      return c.json({ error: auth.error, tier: auth.tier }, 401);
    }

    const ip = getClientIp(c);
    const fingerprintData = getDeviceFingerprint(c);
    const keyFingerprint = decodeURIComponent(c.req.param('fingerprint'));

    try {
      // Read current keys
      let content = '';
      try {
        content = fs.readFileSync(SSH_AUTH_KEYS_PATH, 'utf8');
      } catch {
        return c.json({ error: 'No SSH keys found' }, 404);
      }

      // Filter out the key with matching fingerprint
      const lines = content.split('\n');
      const newLines = lines.filter(line => {
        if (!line.trim() || line.trim().startsWith('#')) return true;
        return computeSshFingerprint(line) !== keyFingerprint;
      });

      if (lines.length === newLines.length) {
        return c.json({ error: 'Key not found' }, 404);
      }

      // Write back
      fs.writeFileSync(SSH_AUTH_KEYS_PATH, newLines.join('\n'));
      execSync(`chown dev:dev ${SSH_AUTH_KEYS_PATH} && chmod 600 ${SSH_AUTH_KEYS_PATH}`, { stdio: 'ignore' });

      // Check if any keys remain
      const remainingKeys = getSshKeys();
      if (remainingKeys.length === 0) {
        console.log('[shield] No SSH keys remaining, stopping sshd...');
        execSync('systemctl disable --now sshd 2>/dev/null || true', { stdio: 'ignore' });
        execSync('ufw delete allow 22/tcp 2>/dev/null || true', { stdio: 'ignore' });
      }

      // Notify platform
      notifyPlatformSshKeyChange('removed', keyFingerprint, 'SSH Key');

      logAuditEvent({ type: 'ssh_key_removed', ip, fingerprint: fingerprintData.hash, details: { keyFingerprint } });

      return c.json({ success: true });
    } catch (e) {
      console.error('[shield] Error removing SSH key:', e);
      return c.json({ error: 'Failed to remove SSH key' }, 500);
    }
  });
}

// Export helpers for other modules
export { getSshKeys, computeSshFingerprint };
