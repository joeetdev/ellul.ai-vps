/**
 * Capabilities Routes
 *
 * Declares what this VPS version supports.
 * No authentication required — must work before session exists.
 * Dashboard fetches this on connect to adapt UI for the VPS version.
 *
 * SECURITY: In SSH-Only mode, returns an empty object to minimize the server's
 * fingerprint. An attacker scanning the system sees no advertised features,
 * endpoints, or version — the server looks like a standard hardened Linux box.
 */

import type { Hono } from 'hono';
import { VERSION, CAPABILITIES } from '../../../../version';
import { getCurrentTier } from '../services/tier.service';

/**
 * Register capabilities routes on Hono app
 */
export function registerCapabilitiesRoutes(app: Hono): void {
  app.get('/_auth/capabilities', (c) => {
    // DARK MODE (P3 security enhancement): SSH-Only servers reveal nothing.
    // This prevents fingerprinting and API surface enumeration by attackers.
    if (getCurrentTier() === 'ssh_only') {
      return c.json({});
    }

    return c.json({
      version: VERSION.release,
      endpoints: CAPABILITIES.endpoints,
      features: [...CAPABILITIES.features],
    });
  });
}
