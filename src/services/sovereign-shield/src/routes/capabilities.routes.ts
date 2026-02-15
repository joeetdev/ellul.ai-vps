/**
 * Capabilities Routes
 *
 * Declares what this VPS version supports.
 * No authentication required — must work before session exists.
 * Dashboard fetches this on connect to adapt UI for the VPS version.
 */

import type { Hono } from 'hono';
import { VERSION, CAPABILITIES } from '../../../../version';

/**
 * Register capabilities routes on Hono app
 */
export function registerCapabilitiesRoutes(app: Hono): void {
  app.get('/_auth/capabilities', (c) => {
    return c.json({
      version: VERSION.release,
      endpoints: CAPABILITIES.endpoints,
      features: [...CAPABILITIES.features],
    });
  });
}
