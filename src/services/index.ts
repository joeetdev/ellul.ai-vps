/**
 * VPS Services Index
 *
 * Unified exports for all VPS service bundles.
 * These are the production-ready implementations with exact feature parity
 * to the original template literal scripts.
 *
 * Usage:
 *   import {
 *     getEnforcerScript,
 *     getSovereignShieldScript,
 *     getFileApiScript,
 *     getAgentBridgeScript,
 *   } from './services';
 */

// Enforcer (state enforcement daemon)
export {
  getEnforcerScript,
  getEnforcerService,
  getEnforcerVersion,
} from './enforcer/bundle';

// Sovereign Shield (authentication service)
export {
  getSovereignShieldScript,
  getSovereignShieldService,
  getSovereignShieldVersion,
} from './sovereign-shield/bundle';

// File API (code browser)
export {
  getFileApiScript,
  getFileApiService,
  getFileApiVersion,
} from './file-api/bundle';

// Agent Bridge (Vibe Mode WebSocket)
export {
  getAgentBridgeScript,
  getAgentBridgeService,
  getAgentBridgeVersion,
} from './agent-bridge/bundle';

// Caddy Generator (Caddyfile generation CLI)
export { getCaddyGenScript } from './caddy-gen/bundle';
export { generateCaddyfileContent, type CaddyfileOptions } from './caddy-gen/caddyfile';

// Watchdog (container lifecycle daemon)
export {
  getWatchdogService,
} from './watchdog/index';
