/**
 * Shared constants for VPS services.
 * Used by sovereign-shield, file-api, enforcer, and other VPS components.
 */

import * as fs from 'fs';

// Derive service user from /etc/default/ellulai (set during provisioning)
function getServiceUser(): string {
  try {
    const content = fs.readFileSync('/etc/default/ellulai', 'utf8');
    const match = content.match(/PS_USER=(\w+)/);
    if (match?.[1]) return match[1];
  } catch {}
  return 'dev';
}

export const SVC_USER = getServiceUser();
export const SVC_HOME = `/home/${SVC_USER}`;

// File paths
export const TIER_FILE = '/etc/ellulai/security-tier';
export const SERVER_ID_FILE = '/etc/ellulai/server-id';
export const API_URL_FILE = '/etc/ellulai/api-url';
export const DOMAIN_FILE = '/etc/ellulai/domain';
export const OWNER_LOCK_FILE = '/etc/ellulai/owner.lock';
export const JWT_SECRET_FILE = '/etc/ellulai/jwt-secret';
export const SHIELD_MARKER = '/etc/ellulai/.sovereign-shield-active';
export const TERMINAL_DISABLED_FILE = '/etc/ellulai/.terminal-disabled';
export const SSH_AUTH_KEYS_PATH = `${SVC_HOME}/.ssh/authorized_keys`;

// Mutable data lives in shield-data/ (owned by $SVC_USER, isolated from root config)
export const SHIELD_DATA_DIR = '/etc/ellulai/shield-data';
export const DB_PATH = `${SHIELD_DATA_DIR}/local-auth.db`;
export const AUTH_SECRET_FILE = `${SHIELD_DATA_DIR}/.sovereign-auth-secret`;
export const AUTH_SECRETS_FILE = `${SHIELD_DATA_DIR}/auth-secrets.json`;
export const SETUP_TOKEN_FILE = `${SHIELD_DATA_DIR}/.sovereign-setup-token`;
export const SETUP_EXPIRY_FILE = `${SHIELD_DATA_DIR}/.sovereign-setup-expiry`;

// Security tiers
export const TIERS = {
  STANDARD: 'standard',
  WEB_LOCKED: 'web_locked',
} as const;

export type SecurityTier = typeof TIERS[keyof typeof TIERS];

// Ports
export const PORTS = {
  SOVEREIGN_SHIELD: 3005,
  FILE_API: 3002,
  AGENT_BRIDGE: 7700,
  TERM_PROXY: 7701,
} as const;

// Session/Token TTLs
export const SESSION_TTL_MS = 4 * 60 * 60 * 1000;        // 4 hours idle timeout
export const ABSOLUTE_MAX_MS = 24 * 60 * 60 * 1000;      // 24 hours absolute expiry
export const ROTATION_INTERVAL_MS = 15 * 60 * 1000;      // 15 minutes session rotation
export const STEP_UP_THRESHOLD_MS = 5 * 60 * 1000;       // 5 minutes step-up
export const TERMINAL_TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours for terminal tokens
export const CODE_TOKEN_TTL_MS = 24 * 60 * 60 * 1000;    // 24 hours for code tokens
export const AGENT_TOKEN_TTL_MS = 24 * 60 * 60 * 1000;   // 24 hours for agent tokens

// Rate limiting
export const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;      // 15 minutes
export const RATE_LIMIT_MAX_ATTEMPTS = 5;
export const LOCKOUT_DURATION_MS = 60 * 60 * 1000;       // 1 hour lockout
