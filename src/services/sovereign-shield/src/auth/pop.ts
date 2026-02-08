/**
 * Proof of Possession (PoP) Authentication
 *
 * Provides SSH-equivalent security for web sessions using ECDSA P-256.
 * Each browser session binds a non-extractable key pair to provide
 * cryptographic proof that requests originate from the same browser.
 */

import crypto from 'crypto';
import type { Context } from 'hono';

// CryptoKey is available globally in Node.js 18+ via Web Crypto API
type CryptoKey = Awaited<ReturnType<typeof crypto.subtle.importKey>>;
import { db } from '../database';
import { POP_TIMESTAMP_TOLERANCE_MS, SERVER_STARTUP_TIME } from '../config';
import { logAuditEvent } from '../services/audit.service';
import { getDeterministicBodyHash } from './body-hash';

export interface PopVerificationResult {
  valid: boolean;
  reason?: string;
}

export interface Session {
  id: string;
  pop_public_key?: string | null;
}

// Prepared statements for nonce operations
let checkNonceStmt: ReturnType<typeof db.prepare> | null = null;
let insertNonceStmt: ReturnType<typeof db.prepare> | null = null;
let cleanupNoncesStmt: ReturnType<typeof db.prepare> | null = null;

function initStatements() {
  if (!checkNonceStmt) {
    checkNonceStmt = db.prepare('SELECT 1 FROM pop_nonces WHERE nonce_key = ?');
    insertNonceStmt = db.prepare('INSERT OR IGNORE INTO pop_nonces (nonce_key, expires_at) VALUES (?, ?)');
    cleanupNoncesStmt = db.prepare('DELETE FROM pop_nonces WHERE expires_at < ?');
  }
}

/**
 * Import public key from base64 SPKI format
 */
export async function importPublicKey(base64Key: string): Promise<CryptoKey> {
  const binaryKey = Buffer.from(base64Key, 'base64');
  return crypto.subtle.importKey(
    'spki',
    binaryKey,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );
}

/**
 * Verify PoP signature
 */
export async function verifyPopSignature(
  publicKeyBase64: string,
  payload: string,
  signatureBase64: string
): Promise<boolean> {
  try {
    const publicKey = await importPublicKey(publicKeyBase64);
    const signature = Buffer.from(signatureBase64, 'base64');
    const data = new TextEncoder().encode(payload);
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      signature,
      data
    );
  } catch (e) {
    console.error('[shield] PoP verification error:', (e as Error).message);
    return false;
  }
}

/**
 * Verify PoP headers on a request
 * Returns valid: true if no PoP required or PoP verification passes
 */
export async function verifyRequestPoP(
  c: Context,
  session: Session
): Promise<PopVerificationResult> {
  if (!session.pop_public_key) {
    return { valid: true, reason: 'no_pop_required' };
  }

  initStatements();

  const timestamp = c.req.header('x-pop-timestamp');
  const nonce = c.req.header('x-pop-nonce');
  const signature = c.req.header('x-pop-signature');

  if (!timestamp || !nonce || !signature) {
    return { valid: false, reason: 'missing_pop_headers' };
  }

  const now = Date.now();
  const reqTime = parseInt(timestamp, 10);
  if (Math.abs(now - reqTime) > POP_TIMESTAMP_TOLERANCE_MS) {
    return { valid: false, reason: 'pop_timestamp_expired' };
  }

  // SECURITY: Startup grace period - reject requests with timestamps from before server started
  // This prevents replay attacks using captured requests from before a restart
  if (reqTime < SERVER_STARTUP_TIME) {
    console.log('[shield] PoP rejected - timestamp predates server startup');
    return { valid: false, reason: 'timestamp_before_startup' };
  }

  // SECURITY: Check for nonce replay attack using SQLite (persists across restarts)
  // Nonces must be unique per session within the timestamp window
  const nonceKey = session.id + ':' + nonce;
  try {
    const existing = checkNonceStmt!.get(nonceKey);
    if (existing) {
      console.log('[shield] PoP nonce replay detected for session:', session.id.substring(0, 8));
      return { valid: false, reason: 'nonce_reused' };
    }
  } catch (e) {
    console.error('[shield] Nonce check error:', (e as Error).message);
    return { valid: false, reason: 'nonce_check_failed' };
  }

  const method = c.req.method;
  const path = new URL(c.req.url).pathname;

  // SECURITY: Compute deterministic body hash for request body binding
  // This prevents bait-and-switch attacks where the body is modified after signing
  let rawBody: string | null = null;
  if (method !== 'GET' && method !== 'HEAD') {
    try {
      rawBody = await c.req.text();
    } catch {
      rawBody = null;
    }
  }
  const bodyHash = getDeterministicBodyHash(rawBody);

  const payload = timestamp + '|' + method + '|' + path + '|' + bodyHash + '|' + nonce;

  const valid = await verifyPopSignature(session.pop_public_key, payload, signature);
  if (!valid) {
    return { valid: false, reason: 'pop_signature_invalid' };
  }

  // Store nonce in SQLite to prevent replay - expires after 2x tolerance window
  try {
    insertNonceStmt!.run(nonceKey, now + (POP_TIMESTAMP_TOLERANCE_MS * 2));
  } catch (e) {
    console.error('[shield] Nonce insert error:', (e as Error).message);
    // Don't fail the request - nonce was already checked
  }

  return { valid: true };
}

/**
 * Bind PoP public key to a session
 */
export function bindPopKey(sessionId: string, publicKey: string, ip: string): void {
  const now = Date.now();
  db.prepare('UPDATE sessions SET pop_public_key = ?, pop_bound_at = ? WHERE id = ?')
    .run(publicKey, now, sessionId);

  logAuditEvent({
    type: 'pop_key_bound',
    ip,
    sessionId,
    details: { publicKeyPrefix: publicKey.substring(0, 20) + '...' }
  });
}

/**
 * Cleanup expired nonces periodically
 */
export function cleanupExpiredNonces(): void {
  initStatements();
  try {
    cleanupNoncesStmt!.run(Date.now());
  } catch (e) {
    console.error('[shield] Nonce cleanup error:', (e as Error).message);
  }
}

/**
 * Client-side PoP JavaScript
 * This script is served to browsers and handles key generation, storage, and signing.
 */
export const SESSION_POP_JS = `
const SESSION_POP = {
  DB_NAME: 'sovereign-shield',
  STORE_NAME: 'session-keys',
  KEY_ID: 'current',

  async openDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(this.DB_NAME, 1);
      req.onerror = () => reject(req.error);
      req.onsuccess = () => resolve(req.result);
      req.onupgradeneeded = (e) => {
        e.target.result.createObjectStore(this.STORE_NAME, { keyPath: 'id' });
      };
    });
  },

  async generateKeyPair() {
    return crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false, // NON-EXTRACTABLE
      ['sign', 'verify']
    );
  },

  async exportPublicKey(keyPair) {
    const exported = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    return btoa(String.fromCharCode(...new Uint8Array(exported)));
  },

  async storeKeyPair(keyPair) {
    const db = await this.openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this.STORE_NAME, 'readwrite');
      tx.objectStore(this.STORE_NAME).put({ id: this.KEY_ID, keyPair, createdAt: Date.now() });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  },

  async getKeyPair() {
    const db = await this.openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this.STORE_NAME, 'readonly');
      const req = tx.objectStore(this.STORE_NAME).get(this.KEY_ID);
      req.onsuccess = () => resolve(req.result?.keyPair || null);
      req.onerror = () => reject(req.error);
    });
  },

  async clearKeyPair() {
    const db = await this.openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this.STORE_NAME, 'readwrite');
      tx.objectStore(this.STORE_NAME).delete(this.KEY_ID);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  },

  // Deterministic body hashing — sort keys recursively for canonical JSON
  _sortKeys(obj) {
    if (obj === null || typeof obj !== 'object') return obj;
    if (Array.isArray(obj)) return obj.map(v => this._sortKeys(v));
    return Object.keys(obj).sort().reduce((s, k) => { s[k] = this._sortKeys(obj[k]); return s; }, {});
  },

  async hashBody(body) {
    let canonical = '';
    if (body !== undefined && body !== null && body !== '') {
      if (typeof body === 'string') {
        try {
          canonical = JSON.stringify(this._sortKeys(JSON.parse(body)));
        } catch { canonical = body; }
      } else {
        canonical = JSON.stringify(this._sortKeys(body));
      }
    }
    const data = new TextEncoder().encode(canonical);
    const buf = await crypto.subtle.digest('SHA-256', data);
    // base64url encode (matches Node.js base64url output)
    return btoa(String.fromCharCode(...new Uint8Array(buf)))
      .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  },

  async sign(data) {
    const keyPair = await this.getKeyPair();
    if (!keyPair) throw new Error('No session key');
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      keyPair.privateKey,
      new TextEncoder().encode(data)
    );
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
  },

  async signRequest(url, method = 'GET', body = null) {
    const timestamp = Date.now().toString();
    const nonce = crypto.randomUUID();
    const bodyHash = await this.hashBody(body);
    const payload = timestamp + '|' + method + '|' + url + '|' + bodyHash + '|' + nonce;
    const signature = await this.sign(payload);
    return {
      'X-PoP-Timestamp': timestamp,
      'X-PoP-Nonce': nonce,
      'X-PoP-Signature': signature,
    };
  },

  async initialize() {
    let keyPair = await this.getKeyPair();
    if (!keyPair) {
      keyPair = await this.generateKeyPair();
      await this.storeKeyPair(keyPair);
    }
    const publicKey = await this.exportPublicKey(keyPair);
    const timestamp = Date.now().toString();
    const bindPayload = 'bind|' + timestamp;
    const signature = await this.sign(bindPayload);

    const res = await fetch('/_auth/pop/bind', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ publicKey, timestamp, signature }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to bind session key');
    }
    return true;
  },

  wrapFetch() {
    const originalFetch = window.fetch;
    const self = this;
    window.fetch = async function(url, options = {}) {
      const urlObj = new URL(url, window.location.origin);
      if (urlObj.origin !== window.location.origin) return originalFetch(url, options);
      if (urlObj.pathname.startsWith('/_auth/pop/')) return originalFetch(url, options);
      try {
        const popHeaders = await self.signRequest(urlObj.pathname, options.method || 'GET', options.body || null);
        options.headers = { ...options.headers, ...popHeaders };
      } catch (e) { console.warn('[PoP] Sign failed:', e); }
      return originalFetch(url, options);
    };
  },

  createSignedWebSocket(url, protocols) {
    const ws = new WebSocket(url, protocols);
    const self = this;
    let userOnMessage = null;
    Object.defineProperty(ws, 'onmessage', {
      set(fn) { userOnMessage = fn; },
      get() { return userOnMessage; },
    });
    ws.addEventListener('message', async (event) => {
      if (typeof event.data === 'string' && event.data.startsWith('POP_CHALLENGE:')) {
        const challenge = event.data.slice('POP_CHALLENGE:'.length);
        try {
          const signature = await self.sign('challenge|' + challenge);
          ws.send('POP_RESPONSE:' + signature);
        } catch (e) {
          console.error('[PoP] Challenge failed:', e);
          ws.close(4001, 'PoP challenge failed');
        }
        return;
      }
      if (userOnMessage) userOnMessage(event);
    });
    return ws;
  },
};

// Auto-initialize PoP (cookie is HttpOnly so we can't check it, but if this script
// is loaded, we passed forward_auth so we have a valid session)
SESSION_POP.initialize()
  .then(() => { if (!window.__popFetchWrapped) { SESSION_POP.wrapFetch(); window.__popFetchWrapped = true; } console.log('[PoP] Session key bound'); })
  .catch((e) => { console.log('[PoP] Init skipped:', e.message); });
`;

/**
 * Terminal wrapper HTML - loads ttyd in iframe after PoP-authorized token
 */
export const TERMINAL_WRAPPER_HTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Terminal - Phone Stack</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body, html { margin: 0; padding: 0; height: 100%; overflow: hidden; background: #0a0a0a; }
    iframe { width: 100%; height: 100%; border: none; display: none; }
    .loading {
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      height: 100%; color: #888; font-family: -apple-system, BlinkMacSystemFont, sans-serif;
    }
    .loading .spinner {
      width: 32px; height: 32px; border: 3px solid #333; border-top-color: #3b82f6;
      border-radius: 50%; animation: spin 1s linear infinite; margin-bottom: 16px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .error { color: #ef4444; }
  </style>
</head>
<body>
  <div class="loading" id="loading">
    <div class="spinner"></div>
    <div id="status">Authorizing...</div>
  </div>
  <iframe id="terminal"></iframe>

  <script src="/_auth/static/session-pop.js"></script>
  <script>
    (async function() {
      const status = document.getElementById('status');
      const loading = document.getElementById('loading');
      const terminal = document.getElementById('terminal');

      // Helper function to get terminal token with retry for PoP binding race
      async function getTerminalToken(maxRetries = 3) {
        for (let attempt = 1; attempt <= maxRetries; attempt++) {
          const res = await fetch('/_auth/terminal/authorize', {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' }
          });

          if (res.ok) {
            return await res.json();
          }

          const err = await res.json().catch(() => ({}));

          // If PoP not bound yet, wait and retry
          if (err.reason === 'pop_not_bound' && attempt < maxRetries) {
            status.textContent = 'Initializing security (' + attempt + '/' + maxRetries + ')...';
            await new Promise(r => setTimeout(r, 500 * attempt)); // Exponential backoff
            continue;
          }

          throw new Error(err.error || err.reason || 'Authorization failed');
        }
        throw new Error('Authorization failed after retries');
      }

      try {
        // Initialize PoP if available (cookie is HttpOnly so we can't check it)
        if (typeof SESSION_POP !== 'undefined') {
          status.textContent = 'Initializing security...';
          try {
            await SESSION_POP.initialize();
            SESSION_POP.wrapFetch();
            console.log('[Terminal] PoP initialized');
          } catch (e) {
            // PoP init can fail if no session or no key - that's ok, authorize will handle it
            console.log('[Terminal] PoP init skipped:', e.message);
          }
        }

        status.textContent = 'Getting authorization...';

        // Request terminal token with retry logic for PoP binding race
        const { token } = await getTerminalToken();
        status.textContent = 'Loading terminal...';

        // Build iframe URL with token
        // Support redirect-based flow: /_auth/terminal/wrapper?target=/term/main/
        const wrapperParams = new URLSearchParams(window.location.search);
        const path = wrapperParams.get('target') || window.location.pathname;
        const params = new URLSearchParams();
        params.set('_term_token', token);
        params.set('_embedded', '1');

        // Load ttyd in iframe - completely untouched
        // Use & if path already has query params, otherwise use ?
        const separator = path.includes('?') ? '&' : '?';
        terminal.src = path + separator + params.toString();
        terminal.onload = function() {
          loading.style.display = 'none';
          terminal.style.display = 'block';
        };

        // Timeout fallback
        setTimeout(() => {
          if (loading.style.display !== 'none') {
            loading.style.display = 'none';
            terminal.style.display = 'block';
          }
        }, 3000);

      } catch (e) {
        console.error('Terminal auth error:', e);
        status.className = 'error';
        status.textContent = e.message || 'Authorization failed. Please refresh.';
        document.querySelector('.spinner').style.display = 'none';
      }
    })();
  </script>
</body>
</html>`;
