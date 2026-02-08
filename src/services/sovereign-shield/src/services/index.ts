/**
 * Services Module Index
 *
 * Re-exports all service-related functions.
 */

// Re-export with unique names for setDatabase
export {
  setDatabase as setAuditDatabase,
  logAuditEvent,
  getAuditLog,
  verifyAuditIntegrity,
  getAuditCount,
} from './audit.service';

export {
  setDatabase as setRateLimiterDatabase,
  checkRateLimit,
  recordAuthAttempt,
  checkApiRateLimit,
  checkRecoveryRateLimit,
  recordRecoveryAttempt,
} from './rate-limiter';

export {
  setDatabase as setTierDatabase,
  getCurrentTier,
  setTier,
  canActivateTier,
  getServerCredentials,
  notifyPlatformTierChange,
  notifyPlatformSshKeyChange,
  notifyPlatformPasskeyRegistered,
  notifyPlatformPasskeyRemoved,
  executeTierSwitch,
} from './tier.service';
