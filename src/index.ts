/**
 * @ellul.ai/vps
 *
 * VPS utilities, scripts, and service bundles for ellul.ai servers.
 *
 * This package provides:
 * - Version management for coordinated updates
 * - VPS service bundles (sovereign-shield, file-api, agent-bridge, enforcer)
 * - Configuration templates and scripts
 *
 * Usage:
 *   import { VERSION } from '@ellul.ai/vps';
 *   import { getEnforcerScript } from '@ellul.ai/vps/services/enforcer';
 */

// Version utilities
export {
  VERSION,
  isVersionCompatible,
  needsUpdate,
  compareVersions,
  getUpdateStatus,
  type VersionManifest,
  type ComponentVersions,
} from './version';

// Service bundles
export {
  // Enforcer (state enforcement daemon)
  getEnforcerScript,
  getEnforcerService,
  getEnforcerVersion,
} from './services/enforcer/bundle';

export {
  // Sovereign Shield (authentication service)
  getSovereignShieldScript,
  getSovereignShieldService,
  getSovereignShieldVersion,
  getVpsAuthScript,
  getVpsAuthService,
  getDowngradeScript,
  getWebLockedSwitchScript,
  getResetAuthScript,
  getTierSwitchHelperScript,
} from './services/sovereign-shield/bundle';

export {
  // File API (code browser)
  getFileApiScript,
  getFileApiService,
  getFileApiVersion,
} from './services/file-api/bundle';

export {
  // Agent Bridge (Vibe Mode WebSocket)
  getAgentBridgeScript,
  getAgentBridgeService,
  getAgentBridgeVersion,
} from './services/agent-bridge/bundle';
