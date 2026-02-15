/**
 * Token Routes
 *
 * Short-lived token authorization and validation for:
 * - Terminal (ttyd) access
 * - Code browser (file-api) access
 * - Agent bridge (vibe chat) access
 *
 * Endpoints:
 * - POST /_auth/terminal/authorize - Get terminal token
 * - POST /_auth/terminal/validate  - Validate terminal token
 * - POST /_auth/code/authorize     - Get code browser token
 * - POST /_auth/code/validate      - Validate code browser token
 * - POST /_auth/agent/authorize    - Get agent bridge token
 * - POST /_auth/agent/validate     - Validate agent bridge token
 */

import crypto from 'crypto';
import type { Hono } from 'hono';
import { db } from '../database';
import { getCurrentTier } from '../services/tier.service';
import { verifyJwtToken } from '../auth/jwt';
import { getClientIp } from '../auth/fingerprint';
import { verifyRequestPoP } from '../auth/pop';
import { checkApiRateLimit } from '../services/rate-limiter';
import { parseCookies } from '../utils/cookie';
import type { Session } from '../auth/session';

interface TokenData {
  sessionId: string;
  ip: string;
  expiresAt: number;
  tier: string;
}

interface CodeTokenData {
  sessionId: string;
  ip: string;
  expiresAt: number;
  tier: string;
}

interface CodeSessionData {
  parentSessionId: string;
  credentialId: string;
  ip: string;
  createdAt: number;
  expiresAt: number;
  tier: string;
}

// In-memory token stores (short-lived, single-use)
const terminalTokens = new Map<string, TokenData>();
const codeTokens = new Map<string, CodeTokenData>();
const agentTokens = new Map<string, TokenData>();
const codeSessions = new Map<string, CodeSessionData>();

// Cleanup expired term sessions from SQLite every 60s
setInterval(() => {
  try {
    db.prepare('DELETE FROM term_sessions WHERE expires_at < ?').run(Date.now());
  } catch { /* ignore */ }
}, 60000);

// Token expiration times
const TERMINAL_TOKEN_TTL = 60 * 1000;  // 60 seconds (single-use for auth, allows slow iframe loads)
const TERM_SESSION_TTL = 30 * 60 * 1000; // 30 minutes (terminal session cookie)
const CODE_TOKEN_TTL = 5 * 60 * 1000;  // 5 minutes
const AGENT_TOKEN_TTL = 30 * 1000;     // 30 seconds
const CODE_SESSION_TTL = 30 * 60 * 1000;  // 30 minutes (code subdomain session)

// Cleanup expired tokens periodically
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of terminalTokens) {
    if (data.expiresAt < now) terminalTokens.delete(token);
  }
  for (const [token, data] of codeTokens) {
    if (data.expiresAt < now) codeTokens.delete(token);
  }
  for (const [token, data] of agentTokens) {
    if (data.expiresAt < now) agentTokens.delete(token);
  }
  for (const [sessionId, data] of codeSessions) {
    if (data.expiresAt < now) codeSessions.delete(sessionId);
  }
}, 10000);

/**
 * Register token routes on Hono app
 */
export function registerTokenRoutes(app: Hono): void {
  /**
   * Authorize terminal access - returns short-lived token
   * Tier-aware: standard (JWT), web_locked (passkey+PoP)
   */
  app.post('/_auth/terminal/authorize', async (c) => {
    const tier = getCurrentTier();
    const ip = getClientIp(c);

    // Standard tier: JWT-based authentication
    if (tier === 'standard') {
      const jwtPayload = verifyJwtToken(c.req);
      if (!jwtPayload) {
        return c.json({ error: 'Authentication required' }, 401);
      }

      // Generate short-lived token (30 seconds)
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = Date.now() + TERMINAL_TOKEN_TTL;
      const sessionId = 'jwt:' + (jwtPayload.jti || crypto.randomBytes(8).toString('hex'));

      terminalTokens.set(token, {
        sessionId,
        ip,
        expiresAt,
        tier: 'standard'
      });

      console.log('[shield] Terminal token issued for JWT session');
      return c.json({ token, expiresAt, tier: 'standard' });
    }

    // Web Locked tier: Passkey + PoP authentication
    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;
    if (!sessionId) return c.json({ error: 'No session' }, 401);

    const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId) as Session | undefined;
    if (!session) return c.json({ error: 'Invalid session' }, 401);

    // In web_locked mode, PoP is MANDATORY - no exceptions
    if (!session.pop_public_key) {
      console.log('[shield] Terminal auth denied - session not fully initialized (no PoP key)');
      return c.json({
        error: 'Session not fully initialized',
        reason: 'pop_not_bound',
        hint: 'PoP key binding in progress - retry in 1 second'
      }, 401);
    }

    const popResult = await verifyRequestPoP(c, session);
    if (!popResult.valid) {
      console.log('[shield] Terminal auth denied - PoP failed:', popResult.reason);
      return c.json({ error: 'PoP validation failed', reason: popResult.reason }, 401);
    }

    // Generate short-lived token (30 seconds)
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + TERMINAL_TOKEN_TTL;

    terminalTokens.set(token, {
      sessionId,
      ip,
      expiresAt,
      tier: 'web_locked'
    });

    console.log('[shield] Terminal token issued for session:', sessionId.substring(0, 8));
    return c.json({ token, expiresAt, tier: 'web_locked' });
  });

  /**
   * Validate terminal token (called by term-proxy)
   * Tier-aware: standard tokens don't require session binding
   *
   * Token is single-use - consumed on first WebSocket connection.
   * Once connected, the WebSocket stays authenticated for its lifetime.
   */
  app.post('/_auth/terminal/validate', async (c) => {
    const body = await c.req.json() as { token?: string; sessionId?: string };
    const { token, sessionId } = body;

    if (!token) {
      return c.json({ valid: false, reason: 'missing_token' }, 400);
    }

    // ATOMIC: Get and delete token immediately (single-use)
    const tokenData = terminalTokens.get(token);
    if (!tokenData) {
      return c.json({ valid: false, reason: 'token_not_found' });
    }

    // Delete immediately - token is single-use
    terminalTokens.delete(token);

    // Check expiration
    if (tokenData.expiresAt < Date.now()) {
      return c.json({ valid: false, reason: 'token_expired' });
    }

    // Session binding only required for web_locked tier
    // Standard tier tokens are bound to JWT, not shield_session
    if (tokenData.tier === 'web_locked') {
      if (!sessionId) {
        return c.json({ valid: false, reason: 'session_required_for_web_locked' });
      }
      if (tokenData.sessionId !== sessionId) {
        console.log('[shield] Terminal token session mismatch - potential attack:', {
          expectedSession: tokenData.sessionId.substring(0, 8),
          providedSession: sessionId.substring(0, 8)
        });
        return c.json({ valid: false, reason: 'session_mismatch' });
      }
    }

    console.log('[shield] Terminal token validated (tier: ' + tokenData.tier + ')');
    return c.json({ valid: true, ip: tokenData.ip, tier: tokenData.tier, sessionId: tokenData.sessionId });
  });

  /**
   * Check if a shield session is still valid (internal use by term-proxy)
   * Returns valid: true only if session exists and hasn't been revoked
   */
  app.post('/_auth/session/check', async (c) => {
    const body = await c.req.json() as { sessionId?: string };
    if (!body.sessionId) {
      return c.json({ valid: false, reason: 'missing_session_id' }, 400);
    }

    const session = db.prepare('SELECT id, expires_at, pop_public_key FROM sessions WHERE id = ?')
      .get(body.sessionId) as { id: string; expires_at: number; pop_public_key: string | null } | undefined;

    if (!session) {
      return c.json({ valid: false, reason: 'session_not_found' });
    }

    if (session.expires_at < Date.now()) {
      return c.json({ valid: false, reason: 'session_expired' });
    }

    const tier = getCurrentTier();

    // For web_locked tier, require PoP key to be bound
    if (tier === 'web_locked' && !session.pop_public_key) {
      return c.json({ valid: false, reason: 'pop_not_bound' });
    }

    return c.json({ valid: true, hasPoP: !!session.pop_public_key, tier });
  });

  /**
   * Create a terminal session (called by term-proxy after token validation).
   * Stores session in sovereign-shield's memory so it survives term-proxy restarts.
   */
  app.post('/_auth/terminal/session/create', async (c) => {
    const body = await c.req.json() as {
      ip?: string;
      shieldSessionId?: string;
      tier?: string;
    };

    const sessionId = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    db.prepare(
      'INSERT INTO term_sessions (id, ip, shield_session_id, tier, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(sessionId, body.ip || '', body.shieldSessionId || '', body.tier || '', now, now + TERM_SESSION_TTL);

    return c.json({ sessionId });
  });

  /**
   * Validate a terminal session (called by term-proxy on WebSocket upgrade).
   * Checks session exists, not expired, IP matches, and shield_session still valid.
   */
  app.post('/_auth/terminal/session/validate', async (c) => {
    const body = await c.req.json() as {
      termSessionId?: string;
      ip?: string;
      shieldSessionId?: string;
    };

    if (!body.termSessionId) {
      return c.json({ valid: false, reason: 'missing_session_id' }, 400);
    }

    const session = db.prepare('SELECT * FROM term_sessions WHERE id = ?')
      .get(body.termSessionId) as { id: string; ip: string; shield_session_id: string; tier: string; created_at: number; expires_at: number } | undefined;

    if (!session) {
      return c.json({ valid: false, reason: 'session_not_found' });
    }

    if (session.expires_at < Date.now()) {
      db.prepare('DELETE FROM term_sessions WHERE id = ?').run(body.termSessionId);
      return c.json({ valid: false, reason: 'session_expired' });
    }

    // IP binding: Log for security monitoring but don't reject
    // Users on mobile networks or VPNs may have IP changes mid-session
    if (session.ip && body.ip && session.ip !== body.ip) {
      console.log('[shield] Term session IP changed:', session.ip.substring(0, 10), '->', body.ip.substring(0, 10));
    }

    // Shield session binding removed: shield_session IDs rotate (every 15min) and
    // re-authentication deletes old sessions entirely, causing false rejections.
    // Term sessions already have 30-min expiry + IP binding which is sufficient.

    // Refresh session TTL on activity (sliding window) - keeps active terminals alive
    const newExpiresAt = Date.now() + TERM_SESSION_TTL;
    db.prepare('UPDATE term_sessions SET expires_at = ? WHERE id = ?').run(newExpiresAt, body.termSessionId);

    return c.json({ valid: true });
  });

  /**
   * Authorize code browser access - returns short-lived token
   * Tier-aware: standard (JWT), web_locked (passkey+PoP)
   */
  app.post('/_auth/code/authorize', async (c) => {
    const tier = getCurrentTier();
    const ip = getClientIp(c);

    // Standard tier: JWT-based authentication
    if (tier === 'standard') {
      const jwtPayload = verifyJwtToken(c.req);
      if (!jwtPayload) {
        return c.json({ error: 'Authentication required' }, 401);
      }

      // Generate short-lived token (5 minutes)
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = Date.now() + CODE_TOKEN_TTL;
      const sessionId = 'jwt:' + (jwtPayload.jti || crypto.randomBytes(8).toString('hex'));

      codeTokens.set(token, {
        sessionId,
        ip,
        expiresAt,
        tier: 'standard'
      });

      console.log('[shield] Code token issued for JWT session');
      return c.json({ token, expiresAt, tier: 'standard' });
    }

    // Web Locked tier: Passkey + PoP authentication
    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;
    if (!sessionId) return c.json({ error: 'No session' }, 401);

    const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId) as Session | undefined;
    if (!session) return c.json({ error: 'Invalid session' }, 401);

    // In web_locked mode, PoP is MANDATORY - no exceptions
    if (!session.pop_public_key) {
      console.log('[shield] Code auth denied - session not fully initialized (no PoP key)');
      return c.json({
        error: 'Session not fully initialized',
        reason: 'pop_not_bound',
        hint: 'PoP key binding in progress - retry in 1 second'
      }, 401);
    }

    const popResult = await verifyRequestPoP(c, session);
    if (!popResult.valid) {
      console.log('[shield] Code auth denied - PoP failed:', popResult.reason);
      return c.json({ error: 'PoP validation failed', reason: popResult.reason }, 401);
    }

    // Generate short-lived token (5 minutes)
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + CODE_TOKEN_TTL;

    codeTokens.set(token, {
      sessionId,
      ip,
      expiresAt,
      tier: 'web_locked'
    });

    // Clean up expired tokens periodically
    if (codeTokens.size > 100) {
      const now = Date.now();
      for (const [t, data] of codeTokens.entries()) {
        if (data.expiresAt < now) codeTokens.delete(t);
      }
    }

    console.log('[shield] Code token issued for session:', sessionId.substring(0, 8));
    return c.json({ token, expiresAt, tier: 'web_locked' });
  });

  /**
   * Validate code browser token (called by file-api)
   * SECURITY: Code tokens are now single-use to prevent token theft exploitation
   */
  app.post('/_auth/code/validate', async (c) => {
    const body = await c.req.json() as { token?: string };
    const { token } = body;

    if (!token) {
      return c.json({ valid: false, reason: 'missing_token' }, 400);
    }

    // ATOMIC: Get and delete token immediately to prevent reuse
    const tokenData = codeTokens.get(token);
    if (!tokenData) {
      return c.json({ valid: false, reason: 'token_not_found' });
    }

    // Single-use: delete immediately before validation
    codeTokens.delete(token);

    if (tokenData.expiresAt < Date.now()) {
      return c.json({ valid: false, reason: 'token_expired' });
    }

    // SECURITY: Code tokens are single-use for maximum security
    // Client pre-fetches next token in background after each use
    return c.json({ valid: true, sessionId: tokenData.sessionId, tier: tokenData.tier });
  });

  /**
   * Create a code session for the code subdomain.
   * This is a longer-lived session that allows access to the code browser
   * without requiring PoP on every request (PoP was verified when creating this session).
   *
   * SECURITY: Requires passkey + PoP authentication to create.
   * The code session is bound to the parent session and IP.
   */
  app.post('/_auth/code/session', async (c) => {
    const tier = getCurrentTier();
    const ip = getClientIp(c);

    // Standard tier: JWT-based authentication - create code session
    if (tier === 'standard') {
      const jwtPayload = verifyJwtToken(c.req);
      if (!jwtPayload) {
        return c.json({ error: 'Authentication required' }, 401);
      }

      const codeSessionId = crypto.randomBytes(32).toString('hex');
      const now = Date.now();
      const expiresAt = now + CODE_SESSION_TTL;

      codeSessions.set(codeSessionId, {
        parentSessionId: 'jwt:' + (jwtPayload.jti || 'unknown'),
        credentialId: jwtPayload.sub || 'jwt-user',
        ip,
        createdAt: now,
        expiresAt,
        tier: 'standard'
      });

      console.log('[shield] Code session created for JWT user');
      return c.json({ codeSessionId, expiresAt, tier: 'standard' });
    }

    // Web Locked tier: Passkey + PoP authentication required
    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;
    if (!sessionId) return c.json({ error: 'No session' }, 401);

    const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId) as Session | undefined;
    if (!session) return c.json({ error: 'Invalid session' }, 401);

    // In web_locked mode, PoP is MANDATORY for creating code session
    if (!session.pop_public_key) {
      console.log('[shield] Code session denied - no PoP key bound');
      return c.json({
        error: 'Session not fully initialized',
        reason: 'pop_not_bound',
        hint: 'PoP key binding in progress - retry in 1 second'
      }, 401);
    }

    const popResult = await verifyRequestPoP(c, session);
    if (!popResult.valid) {
      console.log('[shield] Code session denied - PoP failed:', popResult.reason);
      return c.json({ error: 'PoP validation failed', reason: popResult.reason }, 401);
    }

    // Create code session
    const codeSessionId = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    const expiresAt = now + CODE_SESSION_TTL;

    codeSessions.set(codeSessionId, {
      parentSessionId: sessionId,
      credentialId: session.credential_id,
      ip,
      createdAt: now,
      expiresAt,
      tier: 'web_locked'
    });

    // Cleanup old sessions if too many
    if (codeSessions.size > 100) {
      for (const [id, data] of codeSessions.entries()) {
        if (data.expiresAt < now) codeSessions.delete(id);
      }
    }

    console.log('[shield] Code session created for session:', sessionId.substring(0, 8));
    return c.json({ codeSessionId, expiresAt, tier: 'web_locked' });
  });

  /**
   * Validate a code session (used by forward_auth for code subdomain)
   */
  app.post('/_auth/code/session/validate', async (c) => {
    const body = await c.req.json() as { codeSessionId?: string; ip?: string };
    const { codeSessionId, ip: requestIp } = body;

    if (!codeSessionId) {
      return c.json({ valid: false, reason: 'missing_session_id' }, 400);
    }

    const sessionData = codeSessions.get(codeSessionId);
    if (!sessionData) {
      return c.json({ valid: false, reason: 'session_not_found' });
    }

    const now = Date.now();
    if (sessionData.expiresAt < now) {
      codeSessions.delete(codeSessionId);
      return c.json({ valid: false, reason: 'session_expired' });
    }

    // Optional IP binding check (log only, don't reject)
    if (requestIp && sessionData.ip !== requestIp) {
      console.log('[shield] Code session IP mismatch (logged):', {
        expected: sessionData.ip,
        actual: requestIp
      });
    }

    return c.json({
      valid: true,
      credentialId: sessionData.credentialId,
      tier: sessionData.tier
    });
  });

  /**
   * Authorize agent bridge access - returns short-lived token
   * Tier-aware: standard (JWT), web_locked (passkey+PoP)
   */
  app.post('/_auth/agent/authorize', async (c) => {
    const tier = getCurrentTier();
    const ip = getClientIp(c);

    // Standard tier: JWT-based authentication
    if (tier === 'standard') {
      const jwtPayload = verifyJwtToken(c.req);
      if (!jwtPayload) {
        return c.json({ error: 'Authentication required' }, 401);
      }

      // Generate short-lived token (30 seconds)
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = Date.now() + AGENT_TOKEN_TTL;
      const sessionId = 'jwt:' + (jwtPayload.jti || crypto.randomBytes(8).toString('hex'));

      agentTokens.set(token, {
        sessionId,
        ip,
        expiresAt,
        tier: 'standard'
      });

      console.log('[shield] Agent token issued for JWT session');
      return c.json({ token, expiresAt, tier: 'standard' });
    }

    // Web Locked tier: Passkey + PoP authentication
    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;
    if (!sessionId) return c.json({ error: 'No session' }, 401);

    const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId) as Session | undefined;
    if (!session) return c.json({ error: 'Invalid session' }, 401);

    // In web_locked mode, PoP is MANDATORY - no exceptions
    if (!session.pop_public_key) {
      console.log('[shield] Agent auth denied - session not fully initialized (no PoP key)');
      return c.json({
        error: 'Session not fully initialized',
        reason: 'pop_not_bound',
        hint: 'PoP key binding in progress - retry in 1 second'
      }, 401);
    }

    const popResult = await verifyRequestPoP(c, session);
    if (!popResult.valid) {
      console.log('[shield] Agent auth denied - PoP failed:', popResult.reason);
      return c.json({ error: 'PoP validation failed', reason: popResult.reason }, 401);
    }

    // Generate short-lived token (30 seconds)
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + AGENT_TOKEN_TTL;

    agentTokens.set(token, {
      sessionId,
      ip,
      expiresAt,
      tier: 'web_locked'
    });

    console.log('[shield] Agent token issued for session:', sessionId.substring(0, 8));
    return c.json({ token, expiresAt, tier: 'web_locked' });
  });

  /**
   * Validate agent bridge token (called by agent-bridge)
   */
  app.post('/_auth/agent/validate', async (c) => {
    const ip = getClientIp(c);
    const rateLimit = checkApiRateLimit(ip);
    if (rateLimit.blocked) {
      return c.json({ valid: false, reason: 'rate_limited' }, 429);
    }

    const body = await c.req.json() as { token?: string };
    const { token } = body;

    if (!token) {
      return c.json({ valid: false, reason: 'missing_token' }, 400);
    }

    // ATOMIC: Get and delete token immediately to prevent race condition
    const tokenData = agentTokens.get(token);
    if (!tokenData) {
      return c.json({ valid: false, reason: 'token_not_found' });
    }

    // Atomically remove from map BEFORE validation
    agentTokens.delete(token);

    if (tokenData.expiresAt < Date.now()) {
      return c.json({ valid: false, reason: 'token_expired' });
    }

    console.log('[shield] Agent token validated for session:', tokenData.sessionId.substring(0, 8));
    return c.json({ valid: true, sessionId: tokenData.sessionId });
  });

  /**
   * Code redirect page - helps users get a code session via passkey+PoP
   * This page loads the bridge, authenticates, gets a code session, and redirects
   */
  app.get('/_auth/code/redirect', async (c) => {
    const target = c.req.query('target') || '/';

    return c.html(`<!DOCTYPE html>
<html>
<head>
  <title>Authenticating...</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #0a0a0a;
      color: white;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .container {
      text-align: center;
      padding: 2rem;
    }
    .spinner {
      width: 48px;
      height: 48px;
      border: 3px solid #333;
      border-top-color: #7c3aed;
      border-radius: 50%;
      animation: spin 1s linear infinite;
      margin: 0 auto 1.5rem;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
    p { color: #888; font-size: 0.9rem; }
    .error { color: #ef4444; margin-top: 1rem; display: none; }
    button {
      margin-top: 1rem;
      padding: 0.75rem 1.5rem;
      background: #7c3aed;
      color: white;
      border: none;
      border-radius: 0.5rem;
      cursor: pointer;
      font-size: 1rem;
    }
    button:hover { background: #6d28d9; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .fingerprint { font-size: 1.2rem; margin-right: 0.5rem; }
  </style>
</head>
<body>
  <div class="container">
    <div class="spinner" id="spinner" style="display: none;"></div>
    <h1 id="status">Sovereign Shield</h1>
    <p id="message">Authenticate with your passkey to continue</p>
    <p class="error" id="error"></p>
    <button id="authBtn" onclick="startAuth()"><span class="fingerprint">&#9757;</span>Authenticate</button>
  </div>

  <!-- Load PoP script -->
  <script src="/_auth/static/session-pop.js"></script>
  <script type="module">
    import { startAuthentication } from '/_auth/static/simplewebauthn-browser.js';

    const TARGET_URL = ${JSON.stringify(target)};

    async function initPoP() {
      if (typeof SESSION_POP === 'undefined') {
        throw new Error('SESSION_POP not available');
      }
      await SESSION_POP.initialize();
      SESSION_POP.wrapFetch();
    }

    async function checkSession() {
      const res = await fetch('/_auth/bridge/session', { credentials: 'include' });
      return res.ok;
    }

    async function doPasskeyAuth() {
      document.getElementById('message').textContent = 'Waiting for passkey...';

      const optionsRes = await fetch('/_auth/login/options', {
        method: 'POST',
        credentials: 'include'
      });
      if (!optionsRes.ok) {
        const err = await optionsRes.json();
        throw new Error(err.error || 'Failed to get auth options');
      }

      const options = await optionsRes.json();
      const credential = await startAuthentication({ optionsJSON: options });

      const verifyRes = await fetch('/_auth/login/verify', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ assertion: credential })
      });

      if (!verifyRes.ok) {
        const err = await verifyRes.json();
        throw new Error(err.error || 'Passkey verification failed');
      }

      return await verifyRes.json();
    }

    async function getCodeSession() {
      document.getElementById('message').textContent = 'Getting code session...';

      const res = await fetch('/_auth/code/session', {
        method: 'POST',
        credentials: 'include'
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to get code session');
      }

      return await res.json();
    }

    window.startAuth = async function() {
      document.getElementById('spinner').style.display = 'block';
      document.getElementById('status').textContent = 'Authenticating...';
      document.getElementById('message').textContent = 'Please wait...';
      document.getElementById('error').style.display = 'none';
      document.getElementById('authBtn').disabled = true;
      document.getElementById('authBtn').innerHTML = 'Authenticating...';

      try {
        // Initialize PoP
        await initPoP();

        // Check if already authenticated
        const hasSession = await checkSession();

        if (!hasSession) {
          // Need to authenticate with passkey
          await doPasskeyAuth();
          // Re-init PoP after auth
          await initPoP();
        }

        // Get code session (requires PoP)
        const { codeSessionId } = await getCodeSession();

        // Redirect to target with code session
        document.getElementById('status').textContent = 'Success!';
        document.getElementById('message').textContent = 'Redirecting...';

        const targetUrl = new URL(TARGET_URL, window.location.origin);
        targetUrl.searchParams.set('_code_session', codeSessionId);
        window.location.href = targetUrl.toString();

      } catch (err) {
        console.error('Auth error:', err);
        document.getElementById('spinner').style.display = 'none';
        document.getElementById('status').textContent = 'Authentication Failed';
        document.getElementById('message').textContent = err.name === 'NotAllowedError' ? 'Authentication cancelled.' : '';
        document.getElementById('error').textContent = err.name === 'NotAllowedError' ? '' : (err.message || 'Unknown error');
        document.getElementById('error').style.display = err.name === 'NotAllowedError' ? 'none' : 'block';
        document.getElementById('authBtn').disabled = false;
        document.getElementById('authBtn').innerHTML = '<span class="fingerprint">&#9757;</span>Authenticate';
      }
    };
  </script>
</body>
</html>`);
  });
}

// Export token stores for cleanup interval setup in main
export { terminalTokens, codeTokens, agentTokens, codeSessions };
