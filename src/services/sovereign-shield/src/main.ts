/**
 * Sovereign Shield - Main Entry Point
 *
 * WebAuthn/Passkey authentication service for Phone Stack VPS.
 * Runs on port 3005 and provides:
 *
 * - Passkey registration and authentication
 * - Session management with PoP (Proof of Possession)
 * - Forward auth for Caddy reverse proxy
 * - Security tier management (standard, ssh_only, web_locked)
 * - SSH key management
 * - Break-glass recovery system
 * - Platform bridge API for dashboard integration
 */

import fs from 'fs';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { serve } from '@hono/node-server';
import { PORT, RP_NAME, DOMAIN_FILE } from './config';
import { registerAllRoutes } from './routes';
import { getCurrentTier } from './services/tier.service';
// Import database to ensure initialization and migrations run
import './database';

// Read domain from file or use default
let hostname = 'localhost';
try {
  const domainFromFile = fs.readFileSync(DOMAIN_FILE, 'utf8').trim();
  if (domainFromFile) {
    hostname = domainFromFile;
  }
} catch {
  console.log('[shield] No domain file found, using localhost');
}

const app = new Hono();

// CORS middleware for cross-origin iframe communication
app.use('*', cors({
  origin: (origin) => {
    // Allow dashboard origins
    if (!origin) return origin;
    if (origin === 'https://phone-stack.app') return origin;
    if (origin === 'https://console.phone-stack.app') return origin;
    if (origin.endsWith('.phone-stack.app')) return origin;
    // Allow same-origin
    if (origin === `https://${hostname}`) return origin;
    return null;
  },
  credentials: true,
  allowMethods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'X-PoP-Signature', 'X-PoP-Timestamp', 'X-PoP-Nonce'],
  exposeHeaders: ['Set-Cookie'],
}));

// DARK MODE (P3 security enhancement): In SSH-Only mode, immediately reject all
// web bridge and dashboard requests before they reach any route handler.
// Only health, capabilities (returns {}), tier, and forward-auth endpoints are allowed
// so the system can still report its status and enforce the SSH-only gate at Caddy level.
const SSH_ONLY_ALLOWED_PATHS = new Set([
  '/health',
  '/_auth/capabilities',
  '/_auth/tier/current',
  '/_auth/tier/switch',
  '/_auth/bridge/tier',
  '/api/auth/session',
  '/api/auth/check',
  '/api/workflow/expose',
]);

const SSH_ONLY_ALLOWED_PREFIXES = [
  '/_auth/ssh-only-upgrade',
  '/_auth/register',
];

app.use('*', async (c, next) => {
  if (getCurrentTier() === 'ssh_only') {
    const path = new URL(c.req.url).pathname;
    if (!SSH_ONLY_ALLOWED_PATHS.has(path) && !SSH_ONLY_ALLOWED_PREFIXES.some(p => path.startsWith(p))) {
      return c.json({ error: 'Web access disabled', tier: 'ssh_only' }, 403);
    }
  }
  return next();
});

// Register all routes
registerAllRoutes(app, {
  hostname,
  rpName: RP_NAME,
});

// Start server
console.log(`[shield] Starting Sovereign Shield on port ${PORT}...`);
console.log(`[shield] Hostname: ${hostname}`);
console.log(`[shield] RP Name: ${RP_NAME}`);

serve({
  fetch: app.fetch,
  port: PORT,
  hostname: '127.0.0.1',
}, (info) => {
  console.log(`[shield] Sovereign Shield running on http://127.0.0.1:${info.port}`);
});

// Cleanup on exit
process.on('SIGINT', () => {
  console.log('[shield] Shutting down...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('[shield] Shutting down...');
  process.exit(0);
});
