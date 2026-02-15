/**
 * Tier Routes
 *
 * Security tier management endpoints.
 * All tier changes MUST go through executeTierSwitch() which has:
 * - Pre-flight safety checks (verify new access works before closing old)
 * - Tier file updates with verification
 * - Rollback on failure
 * - Platform notification
 *
 * Endpoints:
 * - POST /_auth/tier/switch  - Switch to a different tier (localhost only)
 * - GET  /_auth/tier/current - Get current tier and capabilities (localhost only)
 */

import fs from 'fs';
import type { Hono } from 'hono';
import { db } from '../database';
import { SSH_AUTH_KEYS_PATH } from '../config';
import type { SecurityTier } from '../config';
import { getClientIp } from '../auth/fingerprint';
import { getCurrentTier, executeTierSwitch } from '../services/tier.service';

/**
 * Register tier routes on Hono app
 */
export function registerTierRoutes(app: Hono): void {
  /**
   * Switch to a different tier (localhost only)
   *
   * This endpoint is called by:
   * - enforcer.ts (bash script via curl to localhost)
   * - file-api.ts (Node.js via fetch to localhost)
   * - ellulai-downgrade (bash script via curl to localhost)
   * - Bridge endpoints (via internal function call)
   */
  app.post('/_auth/tier/switch', async (c) => {
    const ip = getClientIp(c);

    // SECURITY: Only accept requests from localhost
    // This prevents external callers from bypassing the bridge auth
    // Note: For direct curl requests from localhost, headers won't be set,
    // so getClientIp returns 'unknown' - we accept that for internal calls
    // The X-Internal-Request header provides additional verification
    const internalHeader = c.req.header('x-internal-request');
    const isLocalhost = ip === '127.0.0.1' || ip === '::1' || ip === 'localhost' ||
                        (ip === 'unknown' && internalHeader === 'enforcer');

    if (!isLocalhost) {
      console.error('[shield] Rejected tier switch from non-localhost:', ip, 'internal:', internalHeader);
      return c.json({ error: 'Forbidden - internal endpoint' }, 403);
    }

    const body = await c.req.json().catch(() => ({})) as {
      targetTier?: string;
      tier?: string;  // alias for backwards compatibility
      source?: string;
      ipAddress?: string;
      userAgent?: string;
    };
    const { source, ipAddress, userAgent } = body;
    const targetTier = body.targetTier || body.tier;  // accept both names

    const validTiers: SecurityTier[] = ['standard', 'web_locked'];
    if (!targetTier || !validTiers.includes(targetTier as SecurityTier)) {
      return c.json({ error: 'Invalid target tier', validTiers }, 400);
    }

    const currentTier = getCurrentTier();

    // Log the source for audit trail
    console.log(`[shield] Tier switch requested: ${currentTier} -> ${targetTier} (source: ${source || 'unknown'})`);

    // Pre-flight checks based on target tier
    if (targetTier === 'web_locked') {
      // Web Locked requires passkey registration (handled by separate upgrade flow)
      // This endpoint is mainly for internal transitions, not initial web_locked setup
      const hasPasskey = (db.prepare('SELECT COUNT(*) as c FROM credential').get() as { c: number }).c > 0;
      if (!hasPasskey) {
        return c.json({
          error: 'Web Locked requires a passkey',
          message: 'Register a passkey first via the upgrade flow'
        }, 400);
      }
    }

    try {
      await executeTierSwitch(targetTier as SecurityTier, ipAddress || ip, userAgent || 'internal');

      console.log(`[shield] Tier switch completed: ${currentTier} -> ${targetTier}`);

      return c.json({
        success: true,
        previousTier: currentTier,
        tier: targetTier,
        message: `Successfully switched from ${currentTier} to ${targetTier}`
      });
    } catch (e) {
      console.error('[shield] Tier switch failed:', (e as Error).message);
      return c.json({
        error: (e as Error).message || 'Tier switch failed',
        previousTier: currentTier,
        targetTier,
        hint: 'Check sovereign-shield logs for details'
      }, 500);
    }
  });

  /**
   * Get current tier and capabilities (localhost only)
   */
  app.get('/_auth/tier/current', (c) => {
    const ip = getClientIp(c);
    const internalHeader = c.req.header('x-internal-request');

    // Only localhost can query this (same logic as tier/switch)
    const isLocalhost = ip === '127.0.0.1' || ip === '::1' || ip === 'localhost' ||
                        (ip === 'unknown' && internalHeader === 'enforcer');
    if (!isLocalhost) {
      return c.json({ error: 'Forbidden' }, 403);
    }

    const tier = getCurrentTier();
    const hasPasskeys = (db.prepare('SELECT COUNT(*) as c FROM credential').get() as { c: number }).c > 0;
    const hasSshKeys = fs.existsSync(SSH_AUTH_KEYS_PATH) &&
                       fs.readFileSync(SSH_AUTH_KEYS_PATH, 'utf8').trim().length > 0;

    return c.json({
      tier,
      hasPasskeys,
      hasSshKeys,
      canSwitchTo: {
        standard: tier !== 'standard',
        web_locked: tier !== 'web_locked' && hasPasskeys,
      }
    });
  });
}
