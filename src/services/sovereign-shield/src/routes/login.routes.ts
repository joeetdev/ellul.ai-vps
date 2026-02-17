/**
 * Login Routes
 *
 * Passkey authentication (WebAuthn) flow.
 *
 * Endpoints:
 * - GET  /_auth/login         - Login UI page
 * - POST /_auth/login/options - Generate authentication options
 * - POST /_auth/login/verify  - Verify authentication response
 * - POST /_auth/logout        - Logout (clear session)
 */

import type { Hono } from 'hono';
import { db } from '../database';
import { RP_NAME } from '../config';
import { getDeviceFingerprint, getClientIp } from '../auth/fingerprint';
import { createSession, clearSessionCookie, setSessionCookie, createSessionExchangeCode } from '../auth/session';
import { checkRateLimit, recordAuthAttempt } from '../services/rate-limiter';
import { logAuditEvent } from '../services/audit.service';
import { parseCookies } from '../utils/cookie';
import { generateCspNonce, getCspHeader } from '../utils/csp';
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  storeChallenge,
  getChallenge,
  buildAllowCredentials,
  type CredentialRecord,
} from '../auth/webauthn';

/**
 * Register login routes on Hono app
 */
export function registerLoginRoutes(app: Hono, hostname: string): void {
  const RP_ID = hostname;
  // Accept both deployment model domains (-srv for Cloudflare, -dc for Direct Connect)
  const shortId = hostname.replace(/-(?:srv|dc)\.ellul\.ai$/, '');
  const ORIGINS = [
    `https://${hostname}`,
    `https://${shortId}-srv.ellul.ai`,
    `https://${shortId}-dc.ellul.ai`,
  ];

  /**
   * Login UI page
   */
  app.get('/_auth/login', async (c) => {
    const nonce = generateCspNonce();
    c.header('Content-Security-Policy', getCspHeader(nonce));
    return c.html(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sovereign Shield</title>
  <script nonce="${nonce}" src="/_auth/static/session-pop.js"></script>
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, system-ui, sans-serif; max-width: 420px; margin: 20px auto; padding: 20px; background: #0a0a0a; color: #e0e0e0; }
    h1 { font-size: 1.4rem; margin-bottom: 0.5rem; }
    .subtitle { color: #888; font-size: 0.9rem; margin-bottom: 24px; }
    button { width: 100%; padding: 14px; border-radius: 8px; border: none; background: #7c3aed; color: white; font-size: 1rem; cursor: pointer; font-weight: 600; display: flex; align-items: center; justify-content: center; gap: 8px; }
    button:hover { background: #6d28d9; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .error { color: #ef4444; margin-top: 12px; display: none; font-size: 0.85rem; text-align: center; }
    .fingerprint { font-size: 1.5rem; }
  </style>
</head>
<body>
  <h1>Sovereign Shield</h1>
  <p class="subtitle">Authenticate with your passkey to access this server.</p>
  <button id="auth-btn" onclick="doAuth()">
    <span class="fingerprint">&#9757;</span>
    Authenticate
  </button>
  <p class="error" id="error-msg"></p>
  <script nonce="${nonce}" type="module">
    import { startAuthentication } from '/_auth/static/simplewebauthn-browser.js';
    window.startAuthentication = startAuthentication;
  </script>
  <script nonce="${nonce}">
    // Deduplicate auth across multiple login pages (terminal, code, context all redirect here)
    const AUTH_LOCK_KEY = 'shield_auth_lock';
    const AUTH_LOCK_TTL = 30000; // 30 seconds

    function acquireAuthLock() {
      try {
        const existing = localStorage.getItem(AUTH_LOCK_KEY);
        if (existing) {
          const lockTime = parseInt(existing, 10);
          if (Date.now() - lockTime < AUTH_LOCK_TTL) {
            return false; // Another page has the lock
          }
        }
        localStorage.setItem(AUTH_LOCK_KEY, Date.now().toString());
        return true;
      } catch { return true; } // If localStorage fails, proceed anyway
    }

    function releaseAuthLock() {
      try { localStorage.removeItem(AUTH_LOCK_KEY); } catch {}
    }

    // Listen for auth success from other pages
    window.addEventListener('storage', (e) => {
      if (e.key === 'shield_auth_success') {
        // Another page completed auth, reload to get the session
        window.location.reload();
      }
    });

    function getParentOrigin() {
      try {
        const ref = document.referrer;
        if (!ref) return null;
        const origin = new URL(ref).origin;
        if (origin === 'https://ellul.ai' || (origin.startsWith('https://') && (origin.endsWith('.ellul.ai') || origin.endsWith('.ellul.app')))) return origin;
        return null;
      } catch { return null; }
    }
    async function doAuth() {
      // Only one login page should show the passkey prompt at a time
      if (!acquireAuthLock()) {
        document.getElementById('auth-btn').textContent = 'Authenticating in another tab...';
        document.getElementById('auth-btn').disabled = true;
        return;
      }
      const btn = document.getElementById('auth-btn');
      const err = document.getElementById('error-msg');
      btn.disabled = true;
      btn.textContent = 'Waiting for device...';
      err.style.display = 'none';
      try {
        const optRes = await fetch('/_auth/login/options', { method: 'POST', credentials: 'include' });
        if (!optRes.ok) throw new Error((await optRes.json()).error || 'Failed');
        const options = await optRes.json();
        const assertionResp = await window.startAuthentication({ optionsJSON: options });
        const verRes = await fetch('/_auth/login/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ assertion: assertionResp }),
          credentials: 'include',
        });
        if (!verRes.ok) throw new Error((await verRes.json()).error || 'Auth failed');
        const result = await verRes.json();
        const params = new URLSearchParams(window.location.search);
        let redirectUrl = params.get('redirect') || '/';
        // SECURITY: Validate redirect URL to prevent open redirect attacks.
        // Only allow relative paths or URLs on *.ellul.ai / *.ellul.app domains.
        try {
          if (redirectUrl.startsWith('/') && !redirectUrl.startsWith('//')) {
            // Relative path — safe
          } else {
            const rUrl = new URL(redirectUrl);
            if (!rUrl.hostname.endsWith('.ellul.ai') && !rUrl.hostname.endsWith('.ellul.app') && rUrl.hostname !== 'ellul.ai') {
              redirectUrl = '/';
            }
            if (rUrl.protocol !== 'https:') {
              redirectUrl = '/';
            }
          }
        } catch {
          redirectUrl = '/';
        }
        // Handle cross-domain redirect for preview (*.ellul.app) vs same-domain (*.ellul.ai)
        // SECURITY: Use one-time exchange code instead of session ID in URL to prevent
        // session fixation via browser history, referer headers, or server logs.
        const exchangeCode = result.exchangeCode;
        if (exchangeCode) {
          try {
            const u = new URL(redirectUrl);
            if (u.hostname.endsWith('.ellul.app')) {
              // Cross-site redirect to dev domain: get a preview token
              const previewRes = await fetch('/_auth/preview/authorize', {
                method: 'POST',
                credentials: 'include',
              });
              if (previewRes.ok) {
                const previewData = await previewRes.json();
                u.searchParams.delete('_preview_token');
                u.searchParams.set('_preview_token', previewData.token);
                redirectUrl = u.toString();
              }
            } else {
              // Same-site redirect: append one-time exchange code (not session ID)
              u.searchParams.delete('_shield_code');
              redirectUrl = u.toString();
              const sep = redirectUrl.includes('?') ? '&' : '?';
              redirectUrl = redirectUrl + sep + '_shield_code=' + encodeURIComponent(exchangeCode);
            }
          } catch {
            // Fallback for relative URLs
            const sep = redirectUrl.includes('?') ? '&' : '?';
            redirectUrl = redirectUrl + sep + '_shield_code=' + encodeURIComponent(exchangeCode);
          }
          // Notify parent frame about the new session
          if (window.parent !== window) {
            const parentOrigin = getParentOrigin();
            if (parentOrigin) {
              window.parent.postMessage({ type: 'shield-authenticated', sessionId: result.sessionId }, parentOrigin);
            }
          }
        }
        // Initialize PoP (SSH-equivalent security) - MANDATORY, no fallback
        // This prevents downgrade attacks where attacker pretends IndexedDB is broken
        try {
          if (typeof SESSION_POP === 'undefined') {
            throw new Error('Session security module unavailable');
          }
          await SESSION_POP.initialize();
          SESSION_POP.wrapFetch();
        } catch (popErr) {
          // PoP failed - logout and show error. NO FALLBACK to cookie-only.
          await fetch('/_auth/logout', { method: 'POST', credentials: 'include' }).catch(() => {});
          throw new Error('Session security failed: ' + (popErr.message || 'Unknown error') + '. Requires a modern browser with IndexedDB support.');
        }
        // Register Service Worker for universal PoP (signs navigations + static assets)
        await SESSION_POP.registerServiceWorker();
        // Auth succeeded - release lock and notify other tabs
        releaseAuthLock();
        try { localStorage.setItem('shield_auth_success', Date.now().toString()); } catch {}
        window.location.href = redirectUrl;
      } catch (e) {
        releaseAuthLock();
        err.textContent = e.name === 'NotAllowedError' ? 'Authentication cancelled.' : (e.message || 'Authentication failed.');
        err.style.display = 'block';
        btn.disabled = false;
        btn.innerHTML = '<span class="fingerprint">&#9757;</span> Authenticate';
      }
    }
    window.doAuth = doAuth;
  </script>
</body>
</html>`);
  });

  /**
   * Generate authentication options (with rate limiting)
   */
  app.post('/_auth/login/options', async (c) => {
    const ip = getClientIp(c);
    const fingerprintData = getDeviceFingerprint(c);

    const rateLimit = checkRateLimit(ip);
    if (rateLimit.blocked) {
      logAuditEvent({ type: 'rate_limit_blocked', ip, fingerprint: fingerprintData.hash, details: { until: rateLimit.until } });
      return c.json({ error: 'Too many attempts. Try again later.', retryAfter: Math.ceil(rateLimit.remaining! / 1000) }, 429);
    }

    const creds = db.prepare('SELECT * FROM credential').all() as CredentialRecord[];
    if (!creds.length) {
      return c.json({ error: 'No passkeys registered' }, 400);
    }

    // Restrict to only registered credentials to prevent authenticator offering old/stale passkeys
    const allowCredentials = buildAllowCredentials(creds);

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      userVerification: 'required',
      allowCredentials,
    });

    storeChallenge(options.challenge, { type: 'authentication', createdAt: Date.now() });
    return c.json(options);
  });

  /**
   * Verify authentication response (with rate limiting, IP binding, fingerprint binding)
   */
  app.post('/_auth/login/verify', async (c) => {
    const ip = getClientIp(c);
    const fingerprintData = getDeviceFingerprint(c);

    const rateLimit = checkRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ error: 'Too many attempts. Try again later.' }, 429);
    }

    const body = await c.req.json() as {
      assertion?: {
        rawId?: string;
        response?: {
          clientDataJSON?: string;
        };
      };
    };

    // Extract challenge from assertion response
    const clientDataJSON = body.assertion?.response?.clientDataJSON;
    if (!clientDataJSON) {
      return c.json({ error: 'Invalid assertion' }, 400);
    }
    const clientData = JSON.parse(Buffer.from(clientDataJSON, 'base64').toString());
    const expectedChallenge = clientData.challenge;

    const challengeData = getChallenge(expectedChallenge);
    if (!challengeData || challengeData.type !== 'authentication') {
      return c.json({ error: 'No pending authentication or challenge expired' }, 400);
    }

    const credId = body.assertion!.rawId;
    const cred = db.prepare('SELECT * FROM credential WHERE credentialId = ?').get(credId) as CredentialRecord | undefined;
    if (!cred) {
      recordAuthAttempt(ip, false);
      logAuditEvent({ type: 'auth_failed', ip, fingerprint: fingerprintData.hash, details: { reason: 'unknown_credential' } });
      return c.json({ error: 'Unknown credential' }, 400);
    }

    try {
      const verification = await verifyAuthenticationResponse({
        response: body.assertion as any,
        expectedChallenge,
        expectedOrigin: ORIGINS,
        expectedRPID: RP_ID,
        credential: {
          id: cred.credentialId,
          publicKey: Buffer.from(cred.publicKey, 'base64url'),
          counter: cred.counter,
          transports: cred.transports ? JSON.parse(cred.transports) : [],
        },
      });

      if (!verification.verified) {
        recordAuthAttempt(ip, false);
        logAuditEvent({ type: 'auth_failed', ip, fingerprint: fingerprintData.hash, credentialId: cred.id, details: { reason: 'verification_failed' } });
        return c.json({ error: 'Verification failed' }, 400);
      }

      // Update counter
      db.prepare('UPDATE credential SET counter = ? WHERE id = ?')
        .run(verification.authenticationInfo.newCounter, cred.id);

      // Challenge already consumed by getChallenge (single-use)
      recordAuthAttempt(ip, true);

      // Create session bound to IP + fingerprint
      const session = createSession(cred.id, ip, fingerprintData);
      logAuditEvent({ type: 'auth_success', ip, fingerprint: fingerprintData.hash, credentialId: cred.id, sessionId: session.id });
      setSessionCookie(c, session.id, hostname);
      // Return one-time exchange code for URL redirect (never expose session ID in URLs)
      const exchangeCode = createSessionExchangeCode(session.id);
      return c.json({ verified: true, sessionId: session.id, exchangeCode });
    } catch (e) {
      recordAuthAttempt(ip, false);
      logAuditEvent({ type: 'auth_error', ip, fingerprint: fingerprintData.hash, details: { error: (e as Error).message } });
      return c.json({ error: (e as Error).message || 'Verification error' }, 400);
    }
  });

  /**
   * Logout - clear session
   */
  app.post('/_auth/logout', async (c) => {
    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;

    if (sessionId) {
      const ip = getClientIp(c);
      const fingerprintData = getDeviceFingerprint(c);

      // Delete session from database
      db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);

      logAuditEvent({
        type: 'logout',
        ip,
        fingerprint: fingerprintData.hash,
        sessionId,
      });
    }

    clearSessionCookie(c, hostname);
    return c.json({ success: true });
  });
}
