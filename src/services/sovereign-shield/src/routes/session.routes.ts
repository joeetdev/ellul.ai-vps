/**
 * Session Routes
 *
 * Forward auth endpoint (Caddy uses this), session management,
 * and Proof of Possession (PoP) binding.
 *
 * Endpoints:
 * - GET  /api/auth/session          - Forward auth for Caddy
 * - GET  /_auth/sessions            - List active sessions
 * - DELETE /_auth/sessions/:id      - Revoke a specific session
 * - POST /_auth/sessions/revoke-all - Revoke all except current
 * - POST /_auth/pop/bind            - Bind PoP public key
 * - GET  /_auth/pop/status          - Get PoP binding status
 * - GET  /_auth/static/session-pop.js - Client-side PoP library
 * - GET  /_auth/terminal/wrapper    - Terminal wrapper HTML
 */

import fs from 'fs';
import type { Hono } from 'hono';
import { db } from '../database';
import { getCurrentTier } from '../services/tier.service';
import { logAuditEvent } from '../services/audit.service';
import { verifyJwtToken } from '../auth/jwt';
import { getDeviceFingerprint, getClientIp, isNavigationRequest } from '../auth/fingerprint';
import {
  validateSession,
  refreshSession,
  setSessionCookie,
  clearSessionCookie,
  consumeSessionExchangeCode,
  type Session,
} from '../auth/session';
import {
  verifyRequestPoP,
  verifyPopSignature,
  SESSION_POP_JS,
  TERMINAL_WRAPPER_HTML,
} from '../auth/pop';
import { parseCookies } from '../utils/cookie';
import { validatePreviewCredentials } from './preview.routes';

/**
 * Register session routes on Hono app
 */
export function registerSessionRoutes(app: Hono, hostname: string): void {
  /**
   * Forward auth endpoint (Caddy uses this)
   * TIER-AWARE: Handles standard and web_locked differently
   */
  app.get('/api/auth/session', async (c) => {
    const tier = getCurrentTier();
    const forwardedUri = c.req.header('x-forwarded-uri') || '/';

    // Vibe chat WebSocket: Agent token is the sole credential.
    // Agent-bridge validates and consumes the token via verifyClient — forward_auth
    // just needs to confirm the token is present (not validate it, since tokens are single-use).
    if (forwardedUri.startsWith('/vibe')) {
      try {
        const uriParams = new URLSearchParams(forwardedUri.split('?')[1] || '');
        const agentToken = uriParams.get('_agent_token');
        if (agentToken && /^[a-f0-9]{64}$/.test(agentToken)) {
          c.header('X-Auth-User', 'agent-bridge');
          c.header('X-Auth-Tier', tier);
          c.header('X-Auth-Session', 'agent-token');
          return c.json({ authenticated: true, tier, method: 'agent_token' }, 200);
        }
      } catch {}
      return c.json({ error: 'Agent token required' }, 401);
    }

    // Terminal gate: term-proxy handles actual auth, but we require credential presence.
    // Requests must have either _term_token (initial page load) or _term_auth cookie (subsequent).
    // SSH-only tier is blocked above (never reaches here).
    // Also covers /terminal/ paths (sessions list, session close) for browser direct calls with _term_token
    if (forwardedUri.startsWith('/term/') || forwardedUri.startsWith('/ttyd/') || forwardedUri.startsWith('/terminal/')) {
      let hasTermToken = false;
      try {
        const uriParams = new URLSearchParams(forwardedUri.split('?')[1] || '');
        hasTermToken = uriParams.has('_term_token');
      } catch {}

      const reqCookies = parseCookies(c.req.header('cookie'));
      const hasTermAuth = !!reqCookies._term_auth;

      if (!hasTermToken && !hasTermAuth) {
        // Browser navigation: redirect to terminal wrapper (handles passkey auth + token)
        // API/WebSocket/ttyd internal: return 401 JSON
        const acceptHeader = c.req.header('accept') || '';
        const isWsUpgrade = c.req.header('upgrade')?.toLowerCase() === 'websocket';
        // ttyd's internal /token endpoint doesn't set Accept header, so detect it by path
        const isTtydTokenRefresh = forwardedUri.match(/\/term\/[^/]+\/token$/);
        const isApiRequest = isWsUpgrade ||
          isTtydTokenRefresh ||
          acceptHeader.includes('application/json') ||
          c.req.header('x-requested-with') === 'XMLHttpRequest';

        if (isApiRequest) {
          return c.json({ error: 'Terminal authentication required' }, 401);
        }

        // Redirect to wrapper which does PoP-authenticated token fetch then loads ttyd
        const wrapperUrl = `https://${hostname}/_auth/terminal/wrapper?target=${encodeURIComponent(forwardedUri)}`;
        return c.redirect(wrapperUrl, 302);
      }

      c.header('X-Auth-User', 'terminal-user');
      c.header('X-Auth-Tier', tier);
      c.header('X-Auth-Session', reqCookies.shield_session || 'term-proxy');
      return c.json({ authenticated: true, tier, method: 'terminal_gated' }, 200);
    }

    // Shared variables for all non-terminal paths
    const cookies = parseCookies(c.req.header('cookie'));
    const forwardedHost = c.req.header('x-forwarded-host') || hostname;
    const forwardedProto = c.req.header('x-forwarded-proto') || 'https';
    const originalUrl = `${forwardedProto}://${forwardedHost}${forwardedUri}`;

    // Dev domain (ellul.app): Preview token/session authentication
    // JWT cookies (.ellul.ai) don't flow cross-domain to .ellul.app,
    // so dev domains always use preview tokens regardless of tier.
    const isDevDomainRequest = forwardedHost.endsWith('.ellul.app');
    if (isDevDomainRequest) {
      // Check for __Host-preview_session cookie first (set after initial token validation)
      const previewSessionId = cookies['__Host-preview_session'];

      // Check for _preview_token URL param (initial access from dashboard iframe or redirect)
      let previewToken: string | undefined;
      try {
        const uriParams = new URLSearchParams(forwardedUri.split('?')[1] || '');
        previewToken = uriParams.get('_preview_token') || undefined;
      } catch {}

      if (previewSessionId || previewToken) {
        const validateData = validatePreviewCredentials({
          previewSessionId: previewSessionId || undefined,
          token: previewToken || undefined,
          ip: getClientIp(c),
        });

        if (validateData.valid) {
          // If this was a token (not cookie), set the __Host-preview_session cookie
          // and redirect to clean URL
          if (previewToken && validateData.previewSessionId) {
            const maxAge = Math.floor((validateData.expiresAt - Date.now()) / 1000);
            // __Host- prefix: origin-locked (Secure + Path=/ + no Domain attr)
            // SameSite=None: REQUIRED for cross-site iframe (parent console.ellul.ai, iframe *.ellul.app)
            //   SameSite=Lax only sends on top-level navigations, NOT iframe subresource loads
            // Partitioned (CHIPS): Cookie is keyed to (top-level-site, iframe-origin) pair.
            //   Exempt from Safari ITP and Chrome's third-party cookie deprecation.
            //   Supported: Safari 17+, Chrome 114+, Firefox 131+.
            //   Older browsers ignore the attribute and fall back to regular SameSite=None.
            c.header('Set-Cookie',
              `__Host-preview_session=${validateData.previewSessionId}; Path=/; Secure; HttpOnly; SameSite=None; Partitioned; Max-Age=${maxAge}`
            );

            // For navigation, redirect to clean URL (strips token from browser URL)
            const acceptHeader = c.req.header('accept') || '';
            const isApiRequest = acceptHeader.includes('application/json') ||
              c.req.header('x-requested-with') === 'XMLHttpRequest';

            if (!isApiRequest) {
              const urlObj = new URL(originalUrl);
              urlObj.searchParams.delete('_preview_token');
              return c.redirect(urlObj.toString(), 302);
            }
          }

          c.header('X-Auth-User', 'preview-user');
          c.header('X-Auth-Tier', tier);
          c.header('X-Auth-Session', previewSessionId || validateData.previewSessionId || 'preview');
          return c.json({ authenticated: true, tier, method: 'preview' }, 200);
        }
      }

      // No valid preview credentials — redirect to srv domain for login
      const acceptHeader = c.req.header('accept') || '';
      const isApiRequest = acceptHeader.includes('application/json') ||
        c.req.header('x-requested-with') === 'XMLHttpRequest' ||
        c.req.header('upgrade')?.toLowerCase() === 'websocket';

      if (isApiRequest) {
        return c.json({
          error: 'Preview authentication required',
          loginUrl: `https://${hostname}/_auth/login?redirect=${encodeURIComponent(originalUrl)}`,
        }, 401);
      }

      // Redirect to srv domain for passkey auth, which will redirect back with token
      return c.redirect(
        `https://${hostname}/_auth/login?redirect=${encodeURIComponent(originalUrl)}`,
        302
      );
    }

    // Standard tier: JWT-based authentication (for .ellul.ai domains only)
    if (tier === 'standard') {
      const jwtPayload = verifyJwtToken(c.req);
      if (!jwtPayload) {
        // Allow browser navigation to landing page without JWT (standard tier has
        // no VPS-side login page — the landing page is just a "privately managed" placeholder).
        // API/XHR requests still require JWT.
        // NOTE: Terminal/vibe/code/dev paths are handled by earlier checks and never reach here.
        const isNav = isNavigationRequest(c);
        if (isNav) {
          c.header('X-Auth-User', 'anonymous');
          c.header('X-Auth-Tier', 'standard');
          c.header('X-Auth-Session', 'none');
          return c.json({ authenticated: true, tier: 'standard', anonymous: true }, 200);
        }
        return c.json({ error: 'Authentication required' }, 401);
      }
      // Set auth headers for downstream services
      c.header('X-Auth-User', jwtPayload.sub || 'user');
      c.header('X-Auth-Tier', 'standard');
      c.header('X-Auth-Session', jwtPayload.jti || 'jwt');
      return c.json({ authenticated: true, tier: 'standard' }, 200);
    }

    // Web Locked tier: Passkey + PoP authentication

    // Check if this is a code subdomain request
    const isCodeSubdomain = forwardedHost.includes('-code.') || forwardedHost.startsWith('code.');

    // For code subdomain: Check for code_session OR X-Code-Token header
    if (isCodeSubdomain) {
      // First check for X-Code-Token header (used by dashboard's fetchWithCodeToken)
      const codeTokenHeader = c.req.header('x-code-token');
      if (codeTokenHeader) {
        // Validate the code token using existing endpoint
        try {
          const validateRes = await fetch('http://127.0.0.1:3005/_auth/code/validate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: codeTokenHeader })
          });
          const validateData = await validateRes.json() as { valid?: boolean; sessionId?: string; tier?: string };

          if (validateData.valid) {
            c.header('X-Auth-User', validateData.sessionId || 'code-user');
            c.header('X-Auth-Tier', validateData.tier || 'web_locked');
            c.header('X-Auth-Session', 'code-token');
            return c.json({ authenticated: true, tier: validateData.tier || 'web_locked' }, 200);
          }
        } catch (e) {
          console.log('[shield] Code token validation error:', (e as Error).message);
        }
        // If token invalid, fall through to check code_session
      }

      let codeSessionId = cookies.code_session;
      let codeSessionFromUrl = false;

      // Check URL param for initial code session setup
      if (!codeSessionId) {
        try {
          const uriParams = new URLSearchParams(forwardedUri.split('?')[1] || '');
          const urlCodeSession = uriParams.get('_code_session');
          if (urlCodeSession) {
            codeSessionId = urlCodeSession;
            codeSessionFromUrl = true;
          }
        } catch {}
      }

      if (codeSessionId) {
        // Validate code session via internal endpoint
        try {
          const validateRes = await fetch('http://127.0.0.1:3005/_auth/code/session/validate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ codeSessionId, ip: getClientIp(c) })
          });
          const validateData = await validateRes.json() as { valid?: boolean; credentialId?: string; tier?: string };

          if (validateData.valid) {
            // Code session is valid - set cookie if from URL
            if (codeSessionFromUrl) {
              // Set cookie for code subdomain
              c.header('Set-Cookie', `code_session=${codeSessionId}; Path=/; Domain=${forwardedHost}; HttpOnly; Secure; SameSite=Lax; Max-Age=1800`);

              // For API requests, don't redirect - just allow the request through
              // The cookie is now set for future requests
              const acceptHeader = c.req.header('accept') || '';
              const isApiRequest = acceptHeader.includes('application/json') ||
                c.req.header('x-requested-with') === 'XMLHttpRequest' ||
                forwardedUri.startsWith('/api/');

              if (!isApiRequest) {
                // Redirect browser navigation to clean URL without _code_session param
                const urlObj = new URL(originalUrl);
                urlObj.searchParams.delete('_code_session');
                return c.redirect(urlObj.toString(), 302);
              }
              // For API requests, fall through to allow the request
            }

            // Code session valid - allow request
            c.header('X-Auth-User', validateData.credentialId || 'code-user');
            c.header('X-Auth-Tier', validateData.tier || 'web_locked');
            c.header('X-Auth-Session', codeSessionId);
            return c.json({ authenticated: true, tier: validateData.tier || 'web_locked' }, 200);
          }
        } catch (e) {
          console.log('[shield] Code session validation error:', (e as Error).message);
        }
      }

      // No valid code session - redirect to get one
      // The dashboard should get a code session via bridge before accessing code subdomain
      const codeAuthUrl = `https://${hostname}/_auth/code/redirect?target=${encodeURIComponent(originalUrl)}`;

      const acceptHeader = c.req.header('accept') || '';
      const isWsUpgrade = c.req.header('upgrade')?.toLowerCase() === 'websocket';
      const isApiRequest = isWsUpgrade ||
        forwardedUri === '/ws' ||
        acceptHeader.includes('application/json') ||
        c.req.header('x-requested-with') === 'XMLHttpRequest' ||
        forwardedUri.startsWith('/api/') ||
        forwardedUri.includes('/apps') ||
        forwardedUri.includes('/status') ||
        forwardedUri.includes('/tree') ||
        forwardedUri.includes('/preview');

      if (isApiRequest) {
        return c.json({
          error: 'Code session required',
          codeAuthUrl,
          hint: 'Get a code session via /_auth/code/session endpoint first'
        }, 401);
      }
      return c.redirect(codeAuthUrl, 302);
    }

    // Main domain: Standard passkey + PoP flow
    let sessionId = cookies.shield_session;
    let sessionFromUrl = false;

    // Check for one-time exchange code in URL (replaces direct session ID exposure)
    // SECURITY: Exchange codes are single-use, 30s TTL, and map to session IDs server-side.
    // This prevents session fixation via browser history, referer headers, or server logs.
    if (!sessionId) {
      try {
        const uriParams = new URLSearchParams(forwardedUri.split('?')[1] || '');
        const exchangeCode = uriParams.get('_shield_code');
        if (exchangeCode) {
          const exchangedSessionId = consumeSessionExchangeCode(exchangeCode);
          if (exchangedSessionId) {
            sessionId = exchangedSessionId;
            sessionFromUrl = true;
          }
        }
      } catch {}
    }

    const loginUrl = `https://${hostname}/_auth/login?redirect=${encodeURIComponent(originalUrl)}`;

    // Check if this is an XHR/fetch request (not a browser navigation)
    const acceptHeader = c.req.header('accept') || '';
    const isApiRequest = acceptHeader.includes('application/json') ||
      c.req.header('x-requested-with') === 'XMLHttpRequest' ||
      forwardedUri.startsWith('/api/') ||
      forwardedUri.includes('/context') ||
      forwardedUri.includes('/apps') ||
      forwardedUri.includes('/status') ||
      forwardedUri.includes('/tree') ||
      forwardedUri.includes('/preview');

    if (!sessionId) {
      if (isApiRequest) {
        return c.json({ error: 'Authentication required', loginUrl }, 401);
      }
      return c.redirect(loginUrl, 302);
    }

    const ip = getClientIp(c);
    const fingerprintData = getDeviceFingerprint(c);
    const path = c.req.header('x-forwarded-uri') || '';

    const result = validateSession(sessionId, ip, fingerprintData, path);
    if (!result.valid) {
      if (result.reason === 'step_up_required') {
        if (isApiRequest) {
          return c.json({
            error: 'Step-up authentication required',
            loginUrl: `https://${hostname}/_auth/login?reason=step_up&redirect=${encodeURIComponent(originalUrl)}`
          }, 401);
        }
        return c.redirect(`https://${hostname}/_auth/login?reason=step_up&redirect=${encodeURIComponent(originalUrl)}`, 302);
      }

      // SECURITY FIX (H5): Handle session_not_ready - PoP binding incomplete in web_locked mode
      if (result.reason === 'session_not_ready') {
        // Don't clear the session - it's valid but not yet fully initialized
        if (isApiRequest) {
          return c.json({
            error: 'Session initializing',
            reason: 'pop_binding_required',
            hint: result.hint || 'Please wait for security initialization to complete',
            retry: true,
          }, 401);
        }
        // For navigation, allow the page load - PoP binding happens via session-pop.js
        return c.json({ authenticated: true }, 200);
      }

      clearSessionCookie(c, hostname);
      if (isApiRequest) {
        return c.json({ error: 'Session expired', loginUrl }, 401);
      }
      return c.redirect(loginUrl, 302);
    }

    // PoP verification - MANDATORY if session has PoP key bound (no downgrade attacks)
    // Skip for navigation requests, static assets, ttyd token, WebSocket upgrades,
    // and dev domain requests (iframe preview can't access main domain's PoP keys in IndexedDB)
    const isNav = isNavigationRequest(c);
    const fetchDest = c.req.header('sec-fetch-dest') || '';
    const isStaticAsset = ['style', 'script', 'image', 'font', 'manifest'].includes(fetchDest) ||
      /\.(css|js|map|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$/i.test(path);
    const isTtydToken = /\/term\/[^/]+\/token$/.test(path);
    const isWebSocketUpgrade = c.req.header('upgrade')?.toLowerCase() === 'websocket';
    const isDevDomain = forwardedHost !== hostname && forwardedHost.endsWith('.ellul.app');
    const skipPoP = isNav || isStaticAsset || isTtydToken || isWebSocketUpgrade || isDevDomain;

    if (result.session!.pop_public_key && !skipPoP) {
      const popResult = await verifyRequestPoP(c, result.session!);
      if (!popResult.valid) {
        logAuditEvent({
          type: 'pop_validation_failed',
          ip,
          fingerprint: fingerprintData.hash,
          sessionId,
          details: { reason: popResult.reason, path }
        });
        // Hard reject - delete session to prevent replay attempts
        db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
        clearSessionCookie(c, hostname);
        if (isApiRequest) {
          return c.json({ error: 'Session security verification failed', loginUrl }, 401);
        }
        return c.redirect(loginUrl, 302);
      }
    }

    // Refresh session (extend expiry, maybe rotate ID)
    const refresh = refreshSession(result.session!, ip, fingerprintData);

    // If session came from URL param and this is a navigation request (not API),
    // redirect to set the cookie. Caddy's forward_auth only passes Set-Cookie
    // on non-2xx responses, so we use a redirect to set the cookie.
    if (sessionFromUrl && !isApiRequest) {
      const cookieHost = forwardedHost || hostname;
      setSessionCookie(c, refresh.sessionId, cookieHost);

      // Build clean URL without exchange code param
      const urlObj = new URL(originalUrl);
      urlObj.searchParams.delete('_shield_code');
      const cleanUrl = urlObj.toString();

      return c.redirect(cleanUrl, 302);
    }

    // Set auth headers for downstream services (web_locked tier)
    c.header('X-Auth-User', result.session!.credential_id || 'passkey-user');
    c.header('X-Auth-Tier', 'web_locked');
    c.header('X-Auth-Session', refresh.sessionId);

    return c.json({ authenticated: true, tier: 'web_locked' }, 200);
  });

  /**
   * List all active sessions for current user
   */
  app.get('/_auth/sessions', async (c) => {
    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;

    if (!sessionId) {
      return c.json({ error: 'Authentication required' }, 401);
    }

    const ip = getClientIp(c);
    const fingerprintData = getDeviceFingerprint(c);
    const result = validateSession(sessionId, ip, fingerprintData, '/_auth/sessions');

    if (!result.valid) {
      return c.json({ error: 'Session invalid' }, 401);
    }

    // Get all sessions for this credential
    const sessions = db.prepare(`
      SELECT id, ip, created_at, last_activity, expires_at, absolute_expiry
      FROM sessions
      WHERE credential_id = ?
      ORDER BY last_activity DESC
    `).all(result.session!.credential_id) as Array<{
      id: string;
      ip: string;
      created_at: number;
      last_activity: number;
      expires_at: number;
      absolute_expiry: number;
    }>;

    return c.json({
      sessions: sessions.map(s => ({
        id: s.id.substring(0, 8) + '...',
        ip: s.ip,
        createdAt: s.created_at,
        lastActivity: s.last_activity,
        expiresAt: s.expires_at,
        absoluteExpiry: s.absolute_expiry,
        isCurrent: s.id === result.session!.id,
        isExpiringSoon: s.expires_at - Date.now() < 3600000
      })),
      currentSessionId: result.session!.id.substring(0, 8) + '...'
    });
  });

  /**
   * Revoke a specific session
   */
  app.delete('/_auth/sessions/:sessionId', async (c) => {
    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;

    if (!sessionId) {
      return c.json({ error: 'Authentication required' }, 401);
    }

    const ip = getClientIp(c);
    const fingerprintData = getDeviceFingerprint(c);
    const result = validateSession(sessionId, ip, fingerprintData, '/_auth/sessions');

    if (!result.valid) {
      return c.json({ error: 'Session invalid' }, 401);
    }

    const targetPrefix = c.req.param('sessionId');

    // Find session by prefix
    const targetSession = db.prepare(
      'SELECT id FROM sessions WHERE id LIKE ? AND credential_id = ?'
    ).get(targetPrefix + '%', result.session!.credential_id) as { id: string } | undefined;

    if (!targetSession) {
      return c.json({ error: 'Session not found' }, 404);
    }

    // Don't allow revoking current session via this endpoint
    if (targetSession.id === result.session!.id) {
      return c.json({
        error: 'Cannot revoke current session',
        details: 'Use logout to end your current session'
      }, 400);
    }

    db.prepare('DELETE FROM sessions WHERE id = ?').run(targetSession.id);

    logAuditEvent({
      type: 'session_revoked',
      ip,
      fingerprint: fingerprintData.hash,
      credentialId: result.session!.credential_id,
      sessionId: targetSession.id,
      details: { revokedBy: result.session!.id }
    });

    return c.json({
      success: true,
      revokedSession: targetPrefix + '...'
    });
  });

  /**
   * Revoke all sessions except current
   */
  app.post('/_auth/sessions/revoke-all', async (c) => {
    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;

    if (!sessionId) {
      return c.json({ error: 'Authentication required' }, 401);
    }

    const ip = getClientIp(c);
    const fingerprintData = getDeviceFingerprint(c);
    const result = validateSession(sessionId, ip, fingerprintData, '/_auth/sessions/revoke-all');

    if (!result.valid) {
      return c.json({ error: 'Session invalid' }, 401);
    }

    // Delete all sessions except current
    const deleteResult = db.prepare(
      'DELETE FROM sessions WHERE credential_id = ? AND id != ?'
    ).run(result.session!.credential_id, result.session!.id);

    logAuditEvent({
      type: 'all_sessions_revoked',
      ip,
      fingerprint: fingerprintData.hash,
      credentialId: result.session!.credential_id,
      sessionId: result.session!.id,
      details: { revokedCount: deleteResult.changes }
    });

    return c.json({
      success: true,
      revokedCount: deleteResult.changes
    });
  });

  /**
   * Bind PoP public key to session
   */
  app.post('/_auth/pop/bind', async (c) => {
    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;
    if (!sessionId) return c.json({ error: 'No session' }, 401);

    const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId) as Session | undefined;
    if (!session) return c.json({ error: 'Invalid session' }, 401);

    const body = await c.req.json() as {
      publicKey?: string;
      timestamp?: string;
      signature?: string;
    };
    const { publicKey, timestamp, signature } = body;
    if (!publicKey || !timestamp || !signature) {
      return c.json({ error: 'Missing required fields' }, 400);
    }

    // If already bound, verify the request is from same key
    if (session.pop_public_key) {
      const payload = 'bind|' + timestamp;
      const valid = await verifyPopSignature(session.pop_public_key, payload, signature);
      if (!valid) {
        return c.json({ error: 'Key mismatch - session bound to different key' }, 403);
      }
      return c.json({ bound: true, existing: true });
    }

    // Verify the client actually holds the private key
    const payload = 'bind|' + timestamp;
    const valid = await verifyPopSignature(publicKey, payload, signature);
    if (!valid) {
      return c.json({ error: 'Invalid signature - cannot prove key ownership' }, 400);
    }

    // Bind key to session
    const now = Date.now();
    db.prepare('UPDATE sessions SET pop_public_key = ?, pop_bound_at = ? WHERE id = ?')
      .run(publicKey, now, sessionId);

    const ip = getClientIp(c);
    logAuditEvent({
      type: 'pop_key_bound',
      ip,
      sessionId,
      details: { publicKeyPrefix: publicKey.substring(0, 20) + '...' }
    });

    return c.json({ bound: true, existing: false });
  });

  /**
   * Get PoP binding status
   */
  app.get('/_auth/pop/status', async (c) => {
    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;
    if (!sessionId) return c.json({ error: 'No session' }, 401);

    const session = db.prepare('SELECT pop_public_key, pop_bound_at FROM sessions WHERE id = ?')
      .get(sessionId) as { pop_public_key: string | null; pop_bound_at: number | null } | undefined;
    if (!session) return c.json({ error: 'Invalid session' }, 401);

    return c.json({ bound: !!session.pop_public_key, boundAt: session.pop_bound_at });
  });

  /**
   * Serve session-pop.js - Client-side PoP library
   */
  app.get('/_auth/static/session-pop.js', (c) => {
    c.header('Content-Type', 'application/javascript');
    c.header('Cache-Control', 'public, max-age=3600');
    return c.body(SESSION_POP_JS);
  });

  /**
   * Serve terminal wrapper HTML
   */
  app.get('/_auth/terminal/wrapper', (c) => {
    c.header('Content-Type', 'text/html; charset=utf-8');
    c.header('Cache-Control', 'no-store');
    return c.body(TERMINAL_WRAPPER_HTML);
  });

  /**
   * Ownership-verified forward_auth for free tier exposed apps.
   * Caddy's forward_auth directive calls this endpoint; if it returns 200
   * the request is allowed through, otherwise 403.
   *
   * Flow:
   * 1. Parse Cookie (term_session or shield_session)
   * 2. Standard tier → verifyJwtToken() → extract sub
   *    Web Locked   → validateSession() → extract credential_id
   * 3. Read /etc/ellulai/owner.lock → ownerId
   * 4. Compare user ID against ownerId
   * 5. Return 200 + X-Auth-User (match) or 403 (mismatch / no auth)
   */
  app.get('/api/auth/check', async (c) => {
    const tier = getCurrentTier();
    const cookies = parseCookies(c.req.header('cookie'));

    // Determine the authenticated user ID
    let userId: string | null = null;

    if (tier === 'standard') {
      // Standard tier: JWT-based
      const jwtPayload = verifyJwtToken(c.req);
      if (jwtPayload) {
        userId = jwtPayload.sub || null;
      }
    } else {
      // Web Locked tier: session-based
      const sessionId = cookies.shield_session;
      if (sessionId) {
        const ip = getClientIp(c);
        const fingerprintData = getDeviceFingerprint(c);
        const result = validateSession(sessionId, ip, fingerprintData, '/api/auth/check');
        if (result.valid && result.session) {
          userId = result.session.credential_id || null;
        }
      }
    }

    if (!userId) {
      return c.json({ error: 'Authentication required' }, 403);
    }

    // Read owner ID from immutable lock file
    let ownerId: string | null = null;
    try {
      ownerId = fs.readFileSync('/etc/ellulai/owner.lock', 'utf8').trim();
    } catch {
      // owner.lock missing — deny by default (fail secure)
    }

    if (!ownerId || userId !== ownerId) {
      return c.json({ error: 'Not the server owner' }, 403);
    }

    c.header('X-Auth-User', userId);
    return c.json({ authenticated: true, owner: true }, 200);
  });
}
