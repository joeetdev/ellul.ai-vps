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
export const SSH_AUTH_KEYS_PATH = `${SVC_HOME}/.ssh/authorized_keys`;

// Mutable data lives in shield-data/ (owned by $SVC_USER, isolated from root config)
export const SHIELD_DATA_DIR = '/etc/ellulai/shield-data';
export const DB_PATH = `${SHIELD_DATA_DIR}/local-auth.db`;
export const AUTH_SECRET_FILE = `${SHIELD_DATA_DIR}/.sovereign-auth-secret`;
export const AUTH_SECRETS_FILE = `${SHIELD_DATA_DIR}/auth-secrets.json`;
export const SETUP_TOKEN_FILE = `${SHIELD_DATA_DIR}/.sovereign-setup-token`;
export const SETUP_EXPIRY_FILE = `${SHIELD_DATA_DIR}/.sovereign-setup-expiry`;
export const TERMINAL_DISABLED_FILE = `${SHIELD_DATA_DIR}/.terminal-disabled`;

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

// Per-project preview port range (each project gets a dedicated port)
export const PREVIEW_PORT_MIN = 4000;
export const PREVIEW_PORT_MAX = 4099;

// Session/Token TTLs
export const SESSION_TTL_MS = 4 * 60 * 60 * 1000;        // 4 hours idle timeout
export const ABSOLUTE_MAX_MS = 24 * 60 * 60 * 1000;      // 24 hours absolute expiry
export const ROTATION_INTERVAL_MS = 15 * 60 * 1000;      // 15 minutes session rotation
export const STEP_UP_THRESHOLD_MS = 5 * 60 * 1000;       // 5 minutes step-up
export const TERMINAL_TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours for terminal tokens
export const CODE_TOKEN_TTL_MS = 24 * 60 * 60 * 1000;    // 24 hours for code tokens
export const AGENT_TOKEN_TTL_MS = 24 * 60 * 60 * 1000;   // 24 hours for agent tokens

// Ports reserved for ellul.ai internal services — never assign to user apps
export const RESERVED_PORTS = new Set([
  22, 80, 443, 2019, 3000, 3002, 3005, 3006,
  7681, 7682, 7683, 7684, 7685, 7686, 7687, 7688, 7689, 7690, 7700, 7701,
  // Preview port range (4000-4099) — reserved for per-project preview ports
  ...Array.from({ length: PREVIEW_PORT_MAX - PREVIEW_PORT_MIN + 1 }, (_, i) => PREVIEW_PORT_MIN + i),
]);

// Preview resource limits
export const PREVIEW_LIMITS = {
  MAX_CONCURRENT: 3,           // max simultaneous preview-* PM2 processes
  MAX_MEMORY_MB: 256,          // PM2 max_memory_restart per preview
  MAX_RESTARTS: 10,            // PM2 max restarts before errored
  RESTART_DELAY_MS: 1000,      // base delay between PM2 restarts
  MAX_REPAIR_ATTEMPTS: 3,      // background auto-repair cap
  RAM_THRESHOLD: 0.85,         // refuse new preview if RAM > 85%
  LOAD_MULTIPLIER: 1.5,        // refuse if loadavg > nCPU * 1.5
  HEALTH_CACHE_TTL_MS: 2000,   // don't re-check health within 2s
  ANCESTOR_DEPTH: 16,          // isDescendantOf max proc tree depth
} as const;

// Rate limiting
export const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;      // 15 minutes
export const RATE_LIMIT_MAX_ATTEMPTS = 5;
export const LOCKOUT_DURATION_MS = 60 * 60 * 1000;       // 1 hour lockout
