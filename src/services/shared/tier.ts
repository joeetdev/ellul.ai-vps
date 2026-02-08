/**
 * Security tier utilities for VPS services.
 * Reads and writes the current security tier from the filesystem.
 */

import fs from 'fs';
import { TIER_FILE, TIERS, type SecurityTier } from './constants';

/**
 * Get the current security tier.
 * Defaults to 'standard' if file doesn't exist.
 */
export function getCurrentTier(): SecurityTier {
  try {
    const tier = fs.readFileSync(TIER_FILE, 'utf8').trim();
    const validTiers = Object.values(TIERS) as string[];
    if (validTiers.includes(tier)) {
      return tier as SecurityTier;
    }
  } catch {
    // File doesn't exist or unreadable
  }
  return TIERS.STANDARD;
}

/**
 * Set the security tier.
 */
export function setTier(tier: SecurityTier): void {
  const validTiers = Object.values(TIERS) as string[];
  if (!validTiers.includes(tier)) {
    throw new Error(`Invalid tier: ${tier}`);
  }
  fs.writeFileSync(TIER_FILE, tier, 'utf8');
}

/**
 * Check if current tier is Standard.
 */
export function isStandardTier(): boolean {
  return getCurrentTier() === TIERS.STANDARD;
}

/**
 * Check if current tier is SSH Only.
 */
export function isSshOnlyTier(): boolean {
  return getCurrentTier() === TIERS.SSH_ONLY;
}

/**
 * Check if current tier is Web Locked.
 */
export function isWebLockedTier(): boolean {
  return getCurrentTier() === TIERS.WEB_LOCKED;
}

/**
 * Check if dashboard control is allowed for current tier.
 */
export function isDashboardControlAllowed(): boolean {
  const tier = getCurrentTier();
  return tier !== TIERS.SSH_ONLY;
}

/**
 * Check if passkey is required for current tier.
 */
export function isPasskeyRequired(): boolean {
  return getCurrentTier() === TIERS.WEB_LOCKED;
}
