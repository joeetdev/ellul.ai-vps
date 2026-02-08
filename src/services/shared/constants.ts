/**
 * Shared constants for VPS services.
 * Used by sovereign-shield, file-api, enforcer, and other VPS components.
 */

// File paths
export const TIER_FILE = '/etc/phonestack/security-tier';
export const SERVER_ID_FILE = '/etc/phonestack/server-id';
export const API_URL_FILE = '/etc/phonestack/api-url';
export const DOMAIN_FILE = '/etc/phonestack/domain';
export const OWNER_LOCK_FILE = '/etc/phonestack/owner.lock';
export const JWT_SECRET_FILE = '/etc/phonestack/jwt-secret';
export const AUTH_SECRET_FILE = '/etc/phonestack/.sovereign-auth-secret';
export const AUTH_SECRETS_FILE = '/etc/phonestack/auth-secrets.json';
export const SETUP_TOKEN_FILE = '/etc/phonestack/.sovereign-setup-token';
export const SETUP_EXPIRY_FILE = '/etc/phonestack/.sovereign-setup-expiry';
export const SHIELD_MARKER = '/etc/phonestack/.sovereign-shield-active';
export const TERMINAL_DISABLED_FILE = '/etc/phonestack/.terminal-disabled';
export const SSH_AUTH_KEYS_PATH = '/home/dev/.ssh/authorized_keys';
export const DB_PATH = '/etc/phonestack/local-auth.db';

// Security tiers
export const TIERS = {
  STANDARD: 'standard',
  SSH_ONLY: 'ssh_only',
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
