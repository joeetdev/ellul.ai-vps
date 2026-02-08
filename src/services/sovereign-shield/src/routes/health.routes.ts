/**
 * Health Routes
 *
 * Service health check endpoint.
 */

import type { Hono } from 'hono';

/**
 * Register health routes on Hono app
 */
export function registerHealthRoutes(app: Hono): void {
  app.get('/health', (c) => {
    return c.json({
      status: 'ok',
      service: 'sovereign-shield',
      timestamp: Date.now(),
    });
  });
}
