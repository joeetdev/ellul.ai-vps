/**
 * Preview Auth Routes
 *
 * Token-based authentication for dev preview on ellul.app (cross-site from ellul.ai).
 *
 * Since dev preview domains (*.ellul.app) are cross-site from the srv domain (*.ellul.ai),
 * the shield_session cookie won't flow to the iframe. Instead:
 *
 * - Dashboard fetches a short-lived preview token from {id}-srv.ellul.ai (same-site, cookies work)
 * - Loads iframe as {id}-dev.ellul.app?_preview_token={token}
 * - Forward auth validates token, sets __Host-preview_session cookie (first-party on ellul.app)
 * - Subsequent requests use the cookie
 *
 * For direct access (user visits preview URL directly):
 * - No cookie → redirect to {id}-srv.ellul.ai/_auth/login?redirect={dev-url}
 * - After passkey auth, redirect back with one-time preview token
 * - Token validated, __Host-preview_session cookie set
 *
 * Endpoints:
 * - POST /_auth/preview/authorize  - Generate preview token (JWT or shield_session)
 * - POST /_auth/preview/validate   - Internal: validate preview token or session
 */

import crypto from 'crypto';
import type { Hono } from 'hono';
import { db } from '../database';
import { parseCookies } from '../utils/cookie';
import type { Session } from '../auth/session';
import { getClientIp } from '../auth/fingerprint';
import { verifyRequestPoP } from '../auth/pop';
import { logAuditEvent } from '../services/audit.service';
import { getCurrentTier } from '../services/tier.service';
import { verifyJwtToken } from '../auth/jwt';

const PREVIEW_TOKEN_TTL_MS = 60 * 1000; // 60 seconds — single-use, short-lived
const PREVIEW_SESSION_TTL_MS = 4 * 60 * 60 * 1000; // 4 hours — matches shield session

/**
 * Validate a preview token or preview session cookie.
 * Direct function call — avoids HTTP self-fetch from forward_auth handler.
 * Used by both the /_auth/preview/validate endpoint and session.routes.ts forward_auth.
 */
export function validatePreviewCredentials(opts: {
  token?: string;
  previewSessionId?: string;
  ip?: string;
}): { valid: true; previewSessionId: string; expiresAt: number } | { valid: false; reason: string } {
  // Validate preview session cookie
  if (opts.previewSessionId) {
    const session = db.prepare(`
      SELECT id, ip, created_at, expires_at FROM preview_sessions
      WHERE id = ? AND expires_at > ?
    `).get(opts.previewSessionId, Date.now()) as {
      id: string; ip: string; created_at: number; expires_at: number;
    } | undefined;

    if (session) {
      return { valid: true, previewSessionId: session.id, expiresAt: session.expires_at };
    }
    return { valid: false, reason: 'session_expired' };
  }

  // Validate single-use preview token
  if (opts.token) {
    const tokenRow = db.prepare(`
      SELECT token, session_id, expires_at, used FROM preview_tokens
      WHERE token = ?
    `).get(opts.token) as {
      token: string; session_id: string; expires_at: number; used: number;
    } | undefined;

    if (!tokenRow) {
      return { valid: false, reason: 'token_not_found' };
    }

    if (tokenRow.used) {
      return { valid: false, reason: 'token_already_used' };
    }

    if (tokenRow.expires_at < Date.now()) {
      db.prepare('DELETE FROM preview_tokens WHERE token = ?').run(opts.token);
      return { valid: false, reason: 'token_expired' };
    }

    // Mark as used (single-use)
    db.prepare('UPDATE preview_tokens SET used = 1 WHERE token = ?').run(opts.token);

    // Create a preview session for subsequent requests
    const previewSessionId = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    const expiresAt = now + PREVIEW_SESSION_TTL_MS;

    db.prepare(`
      INSERT INTO preview_sessions (id, ip, shield_session_id, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(previewSessionId, opts.ip || '', tokenRow.session_id, now, expiresAt);

    logAuditEvent({
      type: 'preview_session_created',
      ip: opts.ip || 'unknown',
      details: { previewSessionId: previewSessionId.slice(0, 8) + '...' }
    });

    return { valid: true, previewSessionId, expiresAt };
  }

  return { valid: false, reason: 'no_credentials' };
}

/**
 * Register preview auth routes
 */
export function registerPreviewRoutes(app: Hono, hostname: string): void {
  /**
   * POST /_auth/preview/authorize
   *
   * Called by the dashboard (from console.ellul.ai → {id}-srv.ellul.ai, same-site).
   * Tier-aware: standard uses JWT, web_locked uses shield_session.
   * Returns a short-lived single-use preview token.
   */
  app.post('/_auth/preview/authorize', async (c) => {
    const tier = getCurrentTier();
    const ip = getClientIp(c);

    let sessionId: string;

    if (tier === 'web_locked') {
      // Web Locked: shield_session + PoP (matches terminal authorize)
      const cookies = parseCookies(c.req.header('cookie'));
      const shieldSession = cookies.shield_session;

      if (!shieldSession) {
        return c.json({ error: 'Authentication required' }, 401);
      }

      const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(shieldSession) as Session | undefined;
      if (!session) {
        return c.json({ error: 'Invalid session' }, 401);
      }

      // PoP is MANDATORY for web_locked — no exceptions
      if (!session.pop_public_key) {
        return c.json({
          error: 'Session not fully initialized',
          reason: 'pop_not_bound',
          hint: 'PoP key binding in progress - retry in 1 second'
        }, 401);
      }

      const popResult = await verifyRequestPoP(c, session);
      if (!popResult.valid) {
        return c.json({ error: 'PoP validation failed', reason: popResult.reason }, 401);
      }

      sessionId = shieldSession;
    } else {
      // Standard: JWT authentication
      const jwtPayload = verifyJwtToken(c.req);
      if (!jwtPayload) {
        return c.json({ error: 'Authentication required' }, 401);
      }

      sessionId = 'jwt:' + (jwtPayload.jti || crypto.randomBytes(8).toString('hex'));
    }

    // Generate single-use preview token
    const token = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    const expiresAt = now + PREVIEW_TOKEN_TTL_MS;

    db.prepare(`
      INSERT INTO preview_tokens (token, session_id, created_at, expires_at, used)
      VALUES (?, ?, ?, ?, 0)
    `).run(token, sessionId, now, expiresAt);

    logAuditEvent({
      type: 'preview_token_issued',
      ip,
      sessionId,
      details: { expiresIn: '60s' }
    });

    return c.json({
      token,
      expiresAt: new Date(expiresAt).toISOString(),
    });
  });

  /**
   * POST /_auth/preview/validate
   *
   * Internal endpoint called by forward_auth to validate a preview token
   * or preview session cookie. Not called directly by clients.
   */
  app.post('/_auth/preview/validate', async (c) => {
    const body = await c.req.json() as {
      token?: string;
      previewSessionId?: string;
      ip?: string;
    };

    const result = validatePreviewCredentials(body);
    return c.json(result);
  });

  /**
   * GET /api/preview-url
   *
   * Localhost-only endpoint for the AI agent to get a tokenized preview URL.
   * Returns a one-time URL with an embedded preview token (60s TTL).
   * No auth required — only accessible from localhost (127.0.0.1).
   */
  app.get('/api/preview-url', (c) => {
    // Localhost guard: external requests always arrive via Caddy/CF with proxy headers.
    // Direct localhost curl from the AI agent won't have these headers.
    const hasProxyHeaders = !!(c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || c.req.header('x-real-ip'));
    if (hasProxyHeaders) {
      return c.json({ error: 'Localhost only' }, 403);
    }

    const token = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    const expiresAt = now + PREVIEW_TOKEN_TTL_MS;

    db.prepare(`
      INSERT INTO preview_tokens (token, session_id, created_at, expires_at, used)
      VALUES (?, ?, ?, ?, 0)
    `).run(token, 'agent:local', now, expiresAt);

    // Build dev preview URL
    const shortId = (hostname.match(/^([a-f0-9]{8})-/) || [])[1] || hostname.split('.')[0];
    const devDomain = `${shortId}-dev.ellul.app`;
    const url = `https://${devDomain}?_preview_token=${token}`;

    return c.json({ url, expiresIn: 60 });
  });
}

/**
 * Clean up expired preview tokens and sessions.
 * Called periodically from main.
 */
export function cleanupPreviewData(): void {
  const now = Date.now();
  db.prepare('DELETE FROM preview_tokens WHERE expires_at < ?').run(now);
  db.prepare('DELETE FROM preview_sessions WHERE expires_at < ?').run(now);
}
