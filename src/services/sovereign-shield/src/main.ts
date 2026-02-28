/**
 * Sovereign Shield - Main Entry Point
 *
 * WebAuthn/Passkey authentication service for ellul.ai VPS.
 * Runs on port 3005 and provides:
 *
 * - Passkey registration and authentication
 * - Session management with PoP (Proof of Possession)
 * - Forward auth for Caddy reverse proxy
 * - Security tier management (standard, web_locked)
 * - SSH key management
 * - Break-glass recovery system
 * - Platform bridge API for dashboard integration
 */

import fs from 'fs';
import { Hono } from 'hono';

import { serve } from '@hono/node-server';
import { PORT, RP_NAME, DOMAIN_FILE, API_URL_FILE, SVC_HOME } from './config';
import { registerAllRoutes } from './routes';
import { cleanupPreviewData } from './routes/preview.routes';
import { cleanupExpiredNonces } from './auth/pop';
import { getCurrentTier } from './services/tier.service';
import { decryptEnvelope, setSecret, deleteSecret } from './services/secrets.service';
import { initSettings } from './services/settings.service';
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

// NOTE: No Hono CORS middleware here — Caddy handles all CORS headers for external
// requests. Adding CORS at both layers causes duplicate Access-Control-Allow-Origin
// headers, which browsers reject (breaking cookie-based auth flows).

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

  // Initialize local settings file on boot (tier-based defaults)
  initSettings();

  // Periodic cleanup of expired preview tokens/sessions (every 5 minutes)
  setInterval(cleanupPreviewData, 5 * 60 * 1000);

  // Periodic cleanup of expired PoP nonces (every 60 seconds)
  setInterval(cleanupExpiredNonces, 60 * 1000);

  // Git token refresh — pull encrypted token from API every 30 minutes
  setTimeout(refreshGitToken, 10_000); // Initial pull after 10s startup delay
  setInterval(refreshGitToken, 30 * 60 * 1000);
});

// ── Git Token Refresh ──

/**
 * Pull encrypted GitHub installation token from API and write to env file.
 * The VPS initiates this — no secrets flow through the heartbeat.
 */
async function refreshGitToken(): Promise<void> {
  try {
    // Read API URL and bearer token
    let apiUrl: string;
    let bearerToken: string | null = null;

    try {
      apiUrl = fs.readFileSync(API_URL_FILE, 'utf8').trim();
    } catch {
      return; // No API URL configured — skip silently
    }

    // Read ELLULAI_AI_TOKEN from file (bashrc sources this via $(cat ...) which regex can't parse)
    try {
      bearerToken = fs.readFileSync('/etc/ellulai/ai-proxy-token', 'utf8').trim();
    } catch {}

    if (!bearerToken) return; // No token — skip

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);

    try {
      const res = await fetch(`${apiUrl}/api/servers/git-token`, {
        headers: { Authorization: `Bearer ${bearerToken}` },
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (!res.ok) return;

      const data = await res.json() as any;

      if (data.noToken) {
        // No linked repo — remove stale git token if present
        deleteSecret('__GIT_TOKEN');
        return;
      }

      if (data.encryptedKey && data.iv && data.encryptedData) {
        setSecret('__GIT_TOKEN', {
          encryptedKey: data.encryptedKey,
          iv: data.iv,
          encryptedData: data.encryptedData,
        });
        console.log('[shield] Git token refreshed');
      }
    } catch (err: any) {
      clearTimeout(timeout);
      if (err.name !== 'AbortError') {
        console.warn('[shield] Git token refresh failed:', err.message);
      }
    }
  } catch (err: any) {
    console.warn('[shield] Git token refresh error:', err.message);
  }
}

// Cleanup on exit
process.on('SIGINT', () => {
  console.log('[shield] Shutting down...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('[shield] Shutting down...');
  process.exit(0);
});
