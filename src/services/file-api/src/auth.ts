/**
 * File API Authentication
 *
 * All authentication is handled by sovereign-shield (port 3005) via Caddy forward_auth.
 * file-api trusts X-Auth-User / X-Auth-Tier headers set by the forward_auth layer.
 */

import * as fs from 'fs';
import { PATHS, TIERS, type SecurityTier } from './config';

/**
 * Get the current security tier.
 */
export function getCurrentTier(): SecurityTier {
  try {
    const tier = fs.readFileSync(PATHS.TIER, 'utf8').trim();
    if (tier === 'standard' || tier === 'ssh_only' || tier === 'web_locked') {
      return tier;
    }
  } catch {}
  return TIERS.STANDARD;
}

/**
 * Get server ID from file.
 */
export function getServerId(): string | null {
  try {
    return fs.readFileSync(PATHS.SERVER_ID, 'utf8').trim() || null;
  } catch {
    return null;
  }
}
