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
 * - POST /_auth/preview/authorize  - Generate preview token (requires shield_session)
 * - POST /_auth/preview/validate   - Internal: validate preview token or session
 */

import crypto from 'crypto';
import type { Hono } from 'hono';
import { db } from '../database';
import { parseCookies } from '../utils/cookie';
import { validateSession } from '../auth/session';
import { getDeviceFingerprint, getClientIp } from '../auth/fingerprint';
import { logAuditEvent } from '../services/audit.service';

const PREVIEW_TOKEN_TTL_MS = 60 * 1000; // 60 seconds — single-use, short-lived
const PREVIEW_SESSION_TTL_MS = 4 * 60 * 60 * 1000; // 4 hours — matches shield session

/**
 * Register preview auth routes
 */
export function registerPreviewRoutes(app: Hono, hostname: string): void {
  /**
   * POST /_auth/preview/authorize
   *
   * Called by the dashboard (from console.ellul.ai → {id}-srv.ellul.ai, same-site).
   * Validates shield_session cookie, returns a short-lived single-use preview token.
   */
  app.post('/_auth/preview/authorize', async (c) => {
    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;

    if (!sessionId) {
      return c.json({ error: 'Authentication required' }, 401);
    }

    const ip = getClientIp(c);
    const fingerprintData = getDeviceFingerprint(c);
    const result = validateSession(sessionId, ip, fingerprintData, '/_auth/preview/authorize');

    if (!result.valid) {
      return c.json({ error: 'Session invalid' }, 401);
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

    // Validate preview session cookie
    if (body.previewSessionId) {
      const session = db.prepare(`
        SELECT id, ip, created_at, expires_at FROM preview_sessions
        WHERE id = ? AND expires_at > ?
      `).get(body.previewSessionId, Date.now()) as {
        id: string; ip: string; created_at: number; expires_at: number;
      } | undefined;

      if (session) {
        return c.json({ valid: true, sessionId: session.id });
      }
      return c.json({ valid: false, reason: 'session_expired' });
    }

    // Validate single-use preview token
    if (body.token) {
      const tokenRow = db.prepare(`
        SELECT token, session_id, expires_at, used FROM preview_tokens
        WHERE token = ?
      `).get(body.token) as {
        token: string; session_id: string; expires_at: number; used: number;
      } | undefined;

      if (!tokenRow) {
        return c.json({ valid: false, reason: 'token_not_found' });
      }

      if (tokenRow.used) {
        return c.json({ valid: false, reason: 'token_already_used' });
      }

      if (tokenRow.expires_at < Date.now()) {
        // Clean up expired token
        db.prepare('DELETE FROM preview_tokens WHERE token = ?').run(body.token);
        return c.json({ valid: false, reason: 'token_expired' });
      }

      // Mark as used (single-use)
      db.prepare('UPDATE preview_tokens SET used = 1 WHERE token = ?').run(body.token);

      // Create a preview session for subsequent requests
      const previewSessionId = crypto.randomBytes(32).toString('hex');
      const now = Date.now();

      db.prepare(`
        INSERT INTO preview_sessions (id, ip, shield_session_id, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(previewSessionId, body.ip || '', tokenRow.session_id, now, now + PREVIEW_SESSION_TTL_MS);

      logAuditEvent({
        type: 'preview_session_created',
        ip: body.ip || 'unknown',
        details: { previewSessionId: previewSessionId.slice(0, 8) + '...' }
      });

      return c.json({
        valid: true,
        previewSessionId,
        expiresAt: now + PREVIEW_SESSION_TTL_MS,
      });
    }

    return c.json({ valid: false, reason: 'no_credentials' });
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
