/**
 * Shared utilities for VPS services.
 *
 * These utilities eliminate code duplication across:
 * - sovereign-shield
 * - file-api
 * - enforcer
 * - agent-bridge
 * - term-proxy
 */

// Constants
export * from './constants';

// Tier utilities
export {
  getCurrentTier,
  setTier,
  isStandardTier,
  isWebLockedTier,
  isPasskeyRequired,
} from './tier';

// Credential utilities
export {
  getServerId,
  getApiUrl,
  getDomain,
  getOwnerId,
  setOwnerId,
  getJwtSecret,
  getServerCredentials,
  type ServerCredentials,
} from './credentials';
