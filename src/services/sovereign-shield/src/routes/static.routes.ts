/**
 * Static Routes
 *
 * Serves static assets like session-pop.js and vendored libraries.
 *
 * Endpoints:
 * - GET /_auth/static/session-pop.js         - PoP client library
 * - GET /_auth/static/simplewebauthn-browser.js - Vendored @simplewebauthn/browser@11.0.0
 */

import type { Hono } from 'hono';
import { SESSION_POP_JS } from '../auth/pop';
import { SIMPLEWEBAUTHN_BROWSER_JS } from '../vendor/simplewebauthn-browser-content';
import BRIDGE_CLIENT_JS from '../static/bridge-client.js';

/**
 * Register static asset routes on Hono app
 */
export function registerStaticRoutes(app: Hono): void {
  /**
   * Serve session-pop.js - client-side PoP library
   */
  app.get('/_auth/static/session-pop.js', (c) => {
    c.header('Content-Type', 'application/javascript');
    c.header('Cache-Control', 'public, max-age=3600');
    return c.body(SESSION_POP_JS);
  });

  /**
   * Serve vendored @simplewebauthn/browser — eliminates CDN supply-chain risk
   * Content is embedded at build time via TypeScript import (no runtime file reading)
   */
  app.get('/_auth/static/simplewebauthn-browser.js', (c) => {
    c.header('Content-Type', 'application/javascript');
    c.header('Cache-Control', 'public, max-age=86400');
    return c.body(SIMPLEWEBAUTHN_BROWSER_JS);
  });

  /**
   * Serve bridge-client.js - bridge iframe client-side module
   */
  app.get('/_auth/static/bridge-client.js', (c) => {
    c.header('Content-Type', 'application/javascript');
    c.header('Cache-Control', 'no-store');
    return c.body(BRIDGE_CLIENT_JS);
  });
}
