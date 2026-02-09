/**
 * Confirm Routes
 *
 * Operation confirmation with tier-driven enforcement.
 * The VPS is the sole authority — even if the platform is compromised,
 * the VPS refuses to issue confirmation tokens unless the tier's full
 * security requirements are met.
 *
 * Tier enforcement:
 * - Standard:   Session sufficient
 * - Web Locked: Session + PoP required (same as token routes)
 * - SSH Only:   Hard reject — no web operations allowed
 *
 * Endpoints:
 * - POST /_auth/confirm-operation   - Confirm a destructive operation (tier-enforced)
 * - POST /_auth/verify-confirmation - Verify a confirmation token (called by platform)
 */

import type { Hono } from 'hono';
import crypto from 'crypto';
import fs from 'fs';
import { SERVER_ID_FILE } from '../config';
import { getDeviceFingerprint, getClientIp } from '../auth/fingerprint';
import { validateSession } from '../auth/session';
import type { Session } from '../auth/session';
import { logAuditEvent } from '../services/audit.service';
import { signPayload, verifyAuthSignature } from '../auth/secrets';
import { parseCookies } from '../utils/cookie';
import { db } from '../database';
import { getCurrentTier } from '../services/tier.service';
import { verifyRequestPoP } from '../auth/pop';


// SECURITY: Confirmation nonce graveyard — ensures every confirmation token is strictly single-use.
// Nonces are persisted in SQLite so they survive service restarts.
// TTL matches token expiry (5 minutes).
let checkConfirmNonceStmt: ReturnType<typeof db.prepare> | null = null;
let insertConfirmNonceStmt: ReturnType<typeof db.prepare> | null = null;
let cleanupConfirmNoncesStmt: ReturnType<typeof db.prepare> | null = null;

function initConfirmNonceStatements() {
  if (!checkConfirmNonceStmt) {
    checkConfirmNonceStmt = db.prepare('SELECT 1 FROM confirmation_nonces WHERE nonce = ?');
    insertConfirmNonceStmt = db.prepare('INSERT OR IGNORE INTO confirmation_nonces (nonce, expires_at) VALUES (?, ?)');
    cleanupConfirmNoncesStmt = db.prepare('DELETE FROM confirmation_nonces WHERE expires_at < ?');
  }
}

// Cleanup expired nonces every 60 seconds
setInterval(() => {
  try {
    initConfirmNonceStatements();
    cleanupConfirmNoncesStmt!.run(Date.now());
  } catch (e) {
    console.error('[shield] Confirmation nonce cleanup error:', (e as Error).message);
  }
}, 60000);

/**
 * Register confirm routes on Hono app
 */
export function registerConfirmRoutes(app: Hono): void {

  /**
   * Confirm a destructive operation with passkey
   * Used by dashboard for Web Locked tier to authorize delete/rebuild
   */
  app.post('/_auth/confirm-operation', async (c) => {
    const cookies = parseCookies(c.req.header('cookie'));
    const sessionId = cookies.shield_session;

    if (!sessionId) {
      return c.json({ error: 'Authentication required', needsAuth: true }, 401);
    }

    const ip = getClientIp(c);
    const fingerprintData = getDeviceFingerprint(c);
    const result = validateSession(sessionId, ip, fingerprintData, '/_auth/confirm-operation');

    if (!result.valid) {
      return c.json({ error: 'Session invalid or expired', needsAuth: true }, 401);
    }

    // Parse the operation from request body
    const body = await c.req.json() as { operation?: string };
    const operation = body.operation;

    const VALID_OPERATIONS = ['delete', 'rebuild', 'update', 'rollback', 'deployment', 'change-tier', 'settings'];
    if (!operation || !VALID_OPERATIONS.includes(operation)) {
      return c.json({ error: `Invalid operation. Must be one of: ${VALID_OPERATIONS.join(', ')}` }, 400);
    }

    // Get server ID
    let serverId = 'unknown';
    try {
      serverId = fs.readFileSync(SERVER_ID_FILE, 'utf8').trim();
    } catch {}

    // =================================================================
    // TIER ENFORCEMENT: VPS is the sole authority
    // Even if the platform API is fully compromised, the VPS refuses
    // to issue confirmation tokens unless tier requirements are met.
    // =================================================================
    const tier = getCurrentTier();

    // SSH Only: Hard reject ALL web-initiated operations
    if (tier === 'ssh_only') {
      logAuditEvent({
        type: 'confirm_rejected_ssh_only',
        ip,
        fingerprint: fingerprintData.hash,
        sessionId: result.session?.id,
        details: { operation, tier },
      });
      return c.json({ error: 'Web operations disabled', tier: 'ssh_only' }, 403);
    }

    // Web Locked: Require Proof-of-Possession (same pattern as token.routes.ts)
    if (tier === 'web_locked') {
      const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId) as Session | undefined;

      if (!session) {
        return c.json({ error: 'Invalid session' }, 401);
      }

      // PoP is MANDATORY for web_locked — no exceptions
      if (!session.pop_public_key) {
        console.log('[shield] Confirm denied - session not fully initialized (no PoP key)');
        return c.json({
          error: 'Session not fully initialized',
          reason: 'pop_not_bound',
          hint: 'PoP key binding in progress - retry in 1 second'
        }, 401);
      }

      const popResult = await verifyRequestPoP(c, session);
      if (!popResult.valid) {
        console.log('[shield] Confirm denied - PoP failed:', popResult.reason);
        logAuditEvent({
          type: 'confirm_pop_failed',
          ip,
          fingerprint: fingerprintData.hash,
          sessionId: session.id,
          details: { operation, reason: popResult.reason },
        });
        return c.json({ error: 'PoP validation failed', reason: popResult.reason }, 401);
      }
    }

    // Standard: Session already validated above — no additional checks

    // HARDWARE NON-REPUDIATION (P2 security enhancement)
    // Capture the raw PoP signature headers for the audit log. For destructive actions,
    // this creates a cryptographic proof that only the holder of the session's non-extractable
    // private key could have authorized this specific request. A third-party auditor can
    // verify: PoP_Verify(session.pop_public_key, payload, popSignature) === true.
    const popSignatureRaw = c.req.header('x-pop-signature') || null;
    const popTimestampRaw = c.req.header('x-pop-timestamp') || null;
    const popNonceRaw = c.req.header('x-pop-nonce') || null;

    // NOTE: Body hash is omitted because the confirm-operation body ({ operation })
    // differs from the execution body sent to the platform API. The operation name
    // in the signed token is sufficient to prevent bait-and-switch attacks.

    // Generate a signed confirmation token
    const timestamp = Date.now();
    const nonce = crypto.randomBytes(16).toString('hex');
    const payload = {
      operation,
      serverId,
      timestamp,
      nonce,
      credentialId: result.session?.credential_id,
      ip,
      tier,
    };

    // Sign the payload with versioned auth secret (P1 security enhancement)
    const { signature, keyVersion } = signPayload(payload);

    // Base64 encode the confirmation (includes key version for rotation support)
    const confirmation = Buffer.from(JSON.stringify({
      payload,
      signature,
      keyVersion, // Include version so verify can use correct secret
    })).toString('base64url');

    // Log the confirmation with hardware non-repudiation data
    logAuditEvent({
      type: 'operation_confirmed',
      ip,
      fingerprint: fingerprintData.hash,
      credentialId: result.session?.credential_id,
      sessionId: result.session?.id,
      details: {
        operation,
        serverId,
        timestamp,
        tier,
        nonce,
        // Hardware non-repudiation: raw PoP signature proving device possession.
        // A third-party auditor can reconstruct the signed payload from the fields above
        // and verify against the session's pop_public_key to prove hardware provenance.
        popSignature: popSignatureRaw,
        popTimestamp: popTimestampRaw,
        popNonce: popNonceRaw,
      },
    });

    return c.json({
      confirmed: true,
      operation,
      confirmation,
      expiresAt: timestamp + 300000, // 5 minute expiry
    });
  });

  /**
   * Verify a confirmation token (called by platform)
   * This is for the platform to verify the confirmation came from this VPS
   * SECURITY: Now includes IP binding verification to prevent token interception attacks
   */
  app.post('/_auth/verify-confirmation', async (c) => {
    const body = await c.req.json() as {
      confirmation?: string;
      operation?: string;
      expectedServerId?: string;
      verifierIp?: string;
    };
    const { confirmation, operation, expectedServerId, verifierIp } = body;

    if (!confirmation || !operation) {
      return c.json({ error: 'Missing confirmation or operation' }, 400);
    }

    // Verify caller is authorized (localhost or platform)
    const callerIp = getClientIp(c);
    const isLocalCall = callerIp === '127.0.0.1' || callerIp === '::1' || callerIp === 'localhost';

    // Platform IP ranges (ellul.ai infrastructure)
    // In production, this should be configured via environment or file
    const isPlatformCall = isLocalCall || (
      // Cloudflare ranges or known platform IPs can be added here
      // For now, we trust the caller if they provide verifierIp (platform-only param)
      verifierIp !== undefined
    );

    if (!isLocalCall && !isPlatformCall) {
      logAuditEvent({
        type: 'confirmation_unauthorized_caller',
        ip: callerIp,
        details: { operation }
      });
      return c.json({ error: 'Unauthorized caller' }, 403);
    }

    try {
      // Decode the confirmation
      const decoded = JSON.parse(Buffer.from(confirmation, 'base64url').toString()) as {
        payload: {
          operation: string;
          serverId: string;
          timestamp: number;
          nonce?: string;
          ip?: string;
          bodyHash?: string;
        };
        signature: string;
        keyVersion?: number;
      };
      const { payload, signature, keyVersion } = decoded;

      // Verify signature using versioned secrets (P1 security enhancement)
      // This supports secret rotation with grace period
      const verifyResult = verifyAuthSignature(payload, signature, keyVersion);

      if (!verifyResult.valid) {
        logAuditEvent({
          type: 'confirmation_signature_invalid',
          ip: verifierIp || callerIp,
          details: {
            reason: verifyResult.reason,
            keyVersion,
            operation
          }
        });
        return c.json({ error: 'Invalid signature', reason: verifyResult.reason }, 401);
      }

      // Check operation matches
      if (payload.operation !== operation) {
        return c.json({ error: 'Operation mismatch' }, 400);
      }

      // Check server ID if provided
      if (expectedServerId && payload.serverId !== expectedServerId) {
        return c.json({ error: 'Server ID mismatch' }, 400);
      }

      // Check expiry (5 minutes)
      if (Date.now() - payload.timestamp > 300000) {
        return c.json({ error: 'Confirmation expired' }, 410);
      }

      // NONCE GRAVEYARD (P0 security enhancement — SQLite-persisted)
      // Every confirmation token is strictly single-use. The nonce embedded in the
      // signed payload is checked against the graveyard — if it has been seen before,
      // the token is rejected even if it is otherwise valid and unexpired.
      // Persisted in SQLite so nonces survive service restarts within the 5-minute TTL.
      const tokenNonce = (payload as { nonce?: string }).nonce;
      if (tokenNonce) {
        initConfirmNonceStatements();
        const existing = checkConfirmNonceStmt!.get(tokenNonce);
        if (existing) {
          logAuditEvent({
            type: 'confirmation_replay_blocked',
            ip: verifierIp || callerIp,
            details: {
              operation: payload.operation,
              serverId: payload.serverId,
              nonce: tokenNonce,
            }
          });
          return c.json({ error: 'Confirmation already used', reason: 'nonce_reused' }, 409);
        }
        // Bury the nonce — TTL matches the 5-minute token window
        try {
          insertConfirmNonceStmt!.run(tokenNonce, payload.timestamp + 300000);
        } catch (e) {
          console.error('[shield] Confirmation nonce insert error:', (e as Error).message);
        }
      }

      // IP BINDING VERIFICATION (P0 security enhancement)
      // If platform provides verifierIp, ensure it matches the IP in the token
      // This prevents stolen tokens from being used from different locations
      if (verifierIp && payload.ip && payload.ip !== verifierIp) {
        logAuditEvent({
          type: 'confirmation_ip_mismatch',
          ip: verifierIp,
          details: {
            expectedIp: payload.ip,
            actualIp: verifierIp,
            operation: payload.operation,
            serverId: payload.serverId
          }
        });
        return c.json({
          error: 'IP address mismatch',
          details: 'Confirmation must be verified from the same IP where it was created'
        }, 403);
      }

      // Log successful verification
      logAuditEvent({
        type: 'confirmation_verified',
        ip: verifierIp || callerIp,
        details: {
          operation: payload.operation,
          serverId: payload.serverId,
          ipVerified: !!verifierIp
        }
      });

      return c.json({
        valid: true,
        verified: true,
        operation: payload.operation,
        serverId: payload.serverId,
        timestamp: payload.timestamp,
        ipVerified: !!verifierIp,
        bodyHash: payload.bodyHash ?? null,
      });
    } catch (e) {
      return c.json({ error: 'Invalid confirmation format', details: (e as Error).message }, 400);
    }
  });
}
