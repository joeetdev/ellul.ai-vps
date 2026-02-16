/**
 * Session Management
 *
 * Passkey session creation, validation, and refresh with
 * deferred fingerprint binding and PoP support.
 */

import crypto from 'crypto';
import type { Context } from 'hono';
import { db } from '../database';
import {
  SESSION_TTL_MS,
  ABSOLUTE_MAX_MS,
  ROTATION_INTERVAL_MS,
  STEP_UP_THRESHOLD_MS,
  SENSITIVE_ACTIONS,
} from '../config';
import { logAuditEvent } from '../services/audit.service';
import { getCurrentTier } from '../services/tier.service';
import { compareFingerprints, type FingerprintData } from './fingerprint';

export interface Session {
  id: string;
  credential_id: string;
  ip: string;
  fingerprint: string | null;
  fingerprint_status: 'pending' | 'bound';
  fingerprint_components: string | null;
  fingerprint_bound_at: number | null;
  country_code: string | null;
  created_at: number;
  last_activity: number;
  last_rotation: number;
  expires_at: number;
  absolute_expiry: number;
  pop_public_key?: string | null;
  pop_bound_at?: number | null;
}

export interface SessionValidationResult {
  valid: boolean;
  reason?: string;
  hint?: string;
  session?: Session;
}

export interface SessionRefreshResult {
  sessionId: string;
  rotated: boolean;
}

/**
 * Create session with DEFERRED fingerprint binding.
 * Fingerprint is captured on first navigation request, not during auth (fetch/XHR).
 */
export function createSession(
  credentialId: string,
  ip: string,
  fingerprintData: FingerprintData | null
): Session {
  // Single active session: invalidate existing sessions for this credential
  const oldSessions = db.prepare('SELECT id FROM sessions WHERE credential_id = ?').all(credentialId) as { id: string }[];
  for (const old of oldSessions) {
    logAuditEvent({
      type: 'session_invalidated',
      ip,
      fingerprint: fingerprintData?.hash,
      credentialId,
      sessionId: old.id,
      details: { reason: 'new_session_created' }
    });
  }
  db.prepare('DELETE FROM sessions WHERE credential_id = ?').run(credentialId);

  const now = Date.now();
  const session: Session = {
    id: crypto.randomUUID(),
    credential_id: credentialId,
    ip,
    // DEFERRED BINDING: fingerprint starts as NULL, bound on first navigation
    fingerprint: null,
    fingerprint_status: 'pending',
    fingerprint_components: null,
    fingerprint_bound_at: null,
    country_code: null,
    created_at: now,
    last_activity: now,
    last_rotation: now,
    expires_at: now + SESSION_TTL_MS,
    absolute_expiry: now + ABSOLUTE_MAX_MS,
  };

  db.prepare(
    `INSERT INTO sessions (id, credential_id, ip, fingerprint, fingerprint_status, fingerprint_components, fingerprint_bound_at, country_code, created_at, last_activity, last_rotation, expires_at, absolute_expiry)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    session.id, session.credential_id, session.ip, session.fingerprint,
    session.fingerprint_status, session.fingerprint_components, session.fingerprint_bound_at,
    session.country_code, session.created_at, session.last_activity, session.last_rotation,
    session.expires_at, session.absolute_expiry
  );

  logAuditEvent({
    type: 'session_created',
    ip,
    fingerprint: fingerprintData?.hash,
    credentialId,
    sessionId: session.id,
    details: { fingerprint_status: 'pending' }
  });

  return session;
}

/**
 * Validate session with DEFERRED FINGERPRINT BINDING and HARD REJECT.
 */
export function validateSession(
  sessionId: string,
  ip: string,
  fingerprintData: FingerprintData,
  path: string
): SessionValidationResult {
  const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId) as Session | undefined;
  if (!session) return { valid: false, reason: 'not_found' };

  const now = Date.now();

  // Check absolute expiry
  if (now > session.absolute_expiry) {
    db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
    logAuditEvent({
      type: 'session_expired',
      ip,
      fingerprint: fingerprintData.hash,
      sessionId,
      details: { reason: 'absolute_expiry' }
    });
    return { valid: false, reason: 'absolute_expiry' };
  }

  // Check idle timeout
  if (now > session.expires_at) {
    db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
    logAuditEvent({
      type: 'session_expired',
      ip,
      fingerprint: fingerprintData.hash,
      sessionId,
      details: { reason: 'idle_timeout' }
    });
    return { valid: false, reason: 'idle_timeout' };
  }

  // === DEFERRED FINGERPRINT BINDING ===
  if (session.fingerprint_status === 'pending') {
    // Only bind fingerprint on NAVIGATION requests (not fetch/XHR)
    if (fingerprintData.isNavigation) {
      // Bind the fingerprint now
      db.prepare(
        `UPDATE sessions SET fingerprint = ?, fingerprint_status = ?, fingerprint_components = ?,
         fingerprint_bound_at = ?, country_code = ?, last_activity = ? WHERE id = ?`
      ).run(
        fingerprintData.hash, 'bound', JSON.stringify(fingerprintData.components),
        now, fingerprintData.countryCode, now, sessionId
      );

      logAuditEvent({
        type: 'fingerprint_bound',
        ip,
        fingerprint: fingerprintData.hash,
        sessionId,
        details: {
          country_code: fingerprintData.countryCode,
          component_count: Object.keys(fingerprintData.components).length,
          components_preview: Object.keys(fingerprintData.components).join(', '),
        }
      });

      // Update local session object for subsequent checks
      session.fingerprint = fingerprintData.hash;
      session.fingerprint_status = 'bound';
      session.fingerprint_components = JSON.stringify(fingerprintData.components);
      session.country_code = fingerprintData.countryCode;
    } else {
      // Non-navigation request while fingerprint pending
      const tier = getCurrentTier();
      const hasPoP = !!session.pop_public_key;
      const isPopBindingPath = path === '/_auth/pop/bind' || path === '/_auth/pop/status' ||
                               path === '/_auth/static/session-pop.js';

      if (tier === 'web_locked' && !hasPoP && !isPopBindingPath) {
        // In web_locked mode, require PoP binding before allowing API access
        logAuditEvent({
          type: 'session_not_ready',
          ip,
          fingerprint: fingerprintData.hash,
          sessionId,
          details: {
            reason: 'web_locked_requires_pop_binding',
            path,
            tier,
          }
        });
        return { valid: false, reason: 'session_not_ready', hint: 'PoP binding required' };
      }

      // Allow it but don't bind (will bind on first navigation)
      db.prepare('UPDATE sessions SET last_activity = ? WHERE id = ?').run(now, sessionId);
      return { valid: true, session };
    }
  }

  // === FINGERPRINT/COUNTRY/UA VALIDATION ===
  const hasPoP = !!session.pop_public_key;

  // Fingerprint validation (navigation requests only)
  if (session.fingerprint_status === 'bound' && session.fingerprint && fingerprintData.isNavigation) {
    if (fingerprintData.hash !== session.fingerprint) {
      const storedComponents = JSON.parse(session.fingerprint_components || '{}');
      const comparison = compareFingerprints(storedComponents, fingerprintData.components);

      if (hasPoP) {
        // PoP bound - log anomaly only
        logAuditEvent({
          type: 'fingerprint_anomaly',
          ip,
          fingerprint: fingerprintData.hash,
          sessionId,
          details: {
            stored_hash: session.fingerprint.substring(0, 16),
            current_hash: fingerprintData.hash.substring(0, 16),
            mismatches: comparison.mismatches,
            note: 'PoP bound - anomaly logged, not rejected',
          }
        });
      } else {
        // No PoP - hard reject
        logAuditEvent({
          type: 'fingerprint_mismatch_rejected',
          ip,
          fingerprint: fingerprintData.hash,
          sessionId,
          details: {
            stored_hash: session.fingerprint.substring(0, 16),
            current_hash: fingerprintData.hash.substring(0, 16),
            mismatches: comparison.mismatches,
          }
        });
        db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
        return { valid: false, reason: 'fingerprint_mismatch' };
      }
    }
  }

  // Country binding validation
  if (session.country_code && fingerprintData.countryCode) {
    if (session.country_code !== fingerprintData.countryCode) {
      if (hasPoP) {
        logAuditEvent({
          type: 'country_anomaly',
          ip,
          fingerprint: fingerprintData.hash,
          sessionId,
          details: {
            stored_country: session.country_code,
            current_country: fingerprintData.countryCode,
            note: 'PoP bound - anomaly logged, not rejected',
          }
        });
      } else {
        logAuditEvent({
          type: 'country_mismatch_rejected',
          ip,
          fingerprint: fingerprintData.hash,
          sessionId,
          details: {
            stored_country: session.country_code,
            current_country: fingerprintData.countryCode,
          }
        });
        db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
        return { valid: false, reason: 'country_mismatch' };
      }
    }
  }

  // User-Agent validation (all requests)
  if (session.fingerprint_status === 'bound' && session.fingerprint_components) {
    const storedComponents = JSON.parse(session.fingerprint_components);
    const currentUA = fingerprintData.components['user-agent'] || '';
    const storedUA = storedComponents['user-agent'] || '';

    if (storedUA && currentUA && currentUA !== storedUA) {
      if (hasPoP) {
        logAuditEvent({
          type: 'useragent_anomaly',
          ip,
          fingerprint: fingerprintData.hash,
          sessionId,
          details: {
            stored_ua: storedUA.substring(0, 50),
            current_ua: currentUA.substring(0, 50),
            note: 'PoP bound - anomaly logged, not rejected',
          }
        });
      } else {
        logAuditEvent({
          type: 'useragent_mismatch_rejected',
          ip,
          fingerprint: fingerprintData.hash,
          sessionId,
          details: {
            stored_ua: storedUA.substring(0, 50),
            current_ua: currentUA.substring(0, 50),
          }
        });
        db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
        return { valid: false, reason: 'useragent_mismatch' };
      }
    }
  }

  // IP binding - LOG ONLY (can legitimately change with mobile/VPN)
  if (session.ip !== ip) {
    logAuditEvent({
      type: 'ip_mismatch_logged',
      ip,
      fingerprint: fingerprintData.hash,
      sessionId,
      details: { expected: session.ip, actual: ip }
    });
    // Update stored IP to current (allows legitimate network changes)
    db.prepare('UPDATE sessions SET ip = ? WHERE id = ?').run(ip, sessionId);
  }

  // Step-up authentication for sensitive actions
  if (SENSITIVE_ACTIONS.some(action => path && path.startsWith(action))) {
    const timeSinceAuth = now - session.created_at;
    if (timeSinceAuth > STEP_UP_THRESHOLD_MS) {
      return { valid: false, reason: 'step_up_required', session };
    }
  }

  // Update last activity
  db.prepare('UPDATE sessions SET last_activity = ? WHERE id = ?').run(now, sessionId);

  return { valid: true, session };
}

/**
 * Refresh session (update expiry and optionally rotate ID)
 */
export function refreshSession(
  session: Session,
  ip: string,
  fingerprintData: FingerprintData
): SessionRefreshResult {
  const now = Date.now();
  let newSessionId = session.id;
  let rotated = false;

  if (now - session.last_rotation > ROTATION_INTERVAL_MS) {
    newSessionId = crypto.randomUUID();
    rotated = true;
    logAuditEvent({
      type: 'session_rotated',
      ip,
      fingerprint: fingerprintData.hash,
      sessionId: newSessionId,
      details: { old_id: session.id }
    });
  }

  const newExpiry = Math.min(now + SESSION_TTL_MS, session.absolute_expiry);
  db.prepare('UPDATE sessions SET id = ?, last_activity = ?, last_rotation = ?, expires_at = ? WHERE id = ?')
    .run(newSessionId, now, rotated ? now : session.last_rotation, newExpiry, session.id);

  // Cascade session ID change to terminal sessions bound to this shield session
  if (rotated) {
    db.prepare('UPDATE term_sessions SET shield_session_id = ? WHERE shield_session_id = ?')
      .run(newSessionId, session.id);
  }

  return { sessionId: newSessionId, rotated };
}

/**
 * Set session cookie on response
 */
export function setSessionCookie(c: Context, sessionId: string, _hostname: string): void {
  // __Host- prefix: browser enforces Secure + Path=/ + no Domain (origin-locked)
  // Prevents cross-subdomain cookie tossing between different VPS instances
  // SameSite=Lax: srv domains are on ellul.ai (same-site as console.ellul.ai)
  c.header('Set-Cookie', `__Host-shield_session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${Math.floor(ABSOLUTE_MAX_MS / 1000)}`);
}

/**
 * Clear session cookie
 */
export function clearSessionCookie(c: Context, _hostname: string): void {
  c.header('Set-Cookie', `__Host-shield_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
}

/**
 * Get session by ID
 */
export function getSession(sessionId: string): Session | null {
  return db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId) as Session | null;
}

/**
 * Delete session
 */
export function deleteSession(sessionId: string): void {
  db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
}

/**
 * Get all sessions for a credential
 */
export function getSessionsByCredential(credentialId: string): Session[] {
  return db.prepare('SELECT * FROM sessions WHERE credential_id = ?').all(credentialId) as Session[];
}

/**
 * Delete all sessions for a credential
 */
export function deleteSessionsByCredential(credentialId: string): void {
  db.prepare('DELETE FROM sessions WHERE credential_id = ?').run(credentialId);
}

/**
 * Bind PoP public key to session
 */
export function bindPopKey(sessionId: string, publicKey: string): void {
  const now = Date.now();
  db.prepare('UPDATE sessions SET pop_public_key = ?, pop_bound_at = ? WHERE id = ?')
    .run(publicKey, now, sessionId);
}

// ── Session Exchange Codes ──
// SECURITY: One-time codes that map to session IDs, used to avoid exposing
// session IDs directly in URL parameters (browser history, referer headers, logs).
// Codes are single-use and expire after 30 seconds.

const EXCHANGE_CODE_TTL_MS = 30_000;
const exchangeCodes = new Map<string, { sessionId: string; expiresAt: number }>();

// Cleanup expired codes every 30s
setInterval(() => {
  const now = Date.now();
  for (const [code, data] of exchangeCodes) {
    if (data.expiresAt < now) exchangeCodes.delete(code);
  }
}, 30_000);

/**
 * Create a one-time exchange code for a session ID.
 * The code can be safely placed in URL parameters.
 */
export function createSessionExchangeCode(sessionId: string): string {
  const code = crypto.randomBytes(32).toString('hex');
  exchangeCodes.set(code, {
    sessionId,
    expiresAt: Date.now() + EXCHANGE_CODE_TTL_MS,
  });
  return code;
}

/**
 * Consume a one-time exchange code, returning the session ID.
 * Returns null if the code is invalid, expired, or already used.
 */
export function consumeSessionExchangeCode(code: string): string | null {
  const data = exchangeCodes.get(code);
  if (!data) return null;

  // Always delete immediately (single-use)
  exchangeCodes.delete(code);

  if (data.expiresAt < Date.now()) return null;
  return data.sessionId;
}
