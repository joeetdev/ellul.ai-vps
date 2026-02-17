/**
 * Sovereign Shield Configuration
 *
 * All constants, file paths, and security configuration.
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
// Mutable data lives in shield-data/ (owned by $SVC_USER, isolated from root config)
export const SHIELD_DATA_DIR = '/etc/ellulai/shield-data';
export const DB_PATH = `${SHIELD_DATA_DIR}/local-auth.db`;
export const SETUP_TOKEN_FILE = `${SHIELD_DATA_DIR}/.sovereign-setup-token`;
export const AUTH_SECRET_FILE = `${SHIELD_DATA_DIR}/.sovereign-auth-secret`;
export const AUTH_SECRETS_FILE = `${SHIELD_DATA_DIR}/auth-secrets.json`;
export const PENDING_SSH_BLOCK_FILE = `${SHIELD_DATA_DIR}/.pending-ssh-block`;
export const SOVEREIGN_KEYS_FILE = `${SHIELD_DATA_DIR}/.sovereign-keys`;
export const DOMAIN_FILE = '/etc/ellulai/domain';
export const SSH_TRANSITION_MARKER = `${SHIELD_DATA_DIR}/.ssh-only-to-web-locked`;
export const SETUP_EXPIRY_FILE = `${SHIELD_DATA_DIR}/.sovereign-setup-expiry`;
export const TERMINAL_DISABLED_FILE = '/etc/ellulai/.terminal-disabled'; // Read by enforcer (root), stays in root dir
export const TIER_FILE = '/etc/ellulai/security-tier';
export const SHIELD_MARKER = '/etc/ellulai/.sovereign-shield-active';
export const ATTESTATION_POLICY_FILE = '/etc/ellulai/attestation-policy.json';
export const JWT_SECRET_FILE = '/etc/ellulai/jwt-secret';
export const SSH_AUTH_KEYS_PATH = `${SVC_HOME}/.ssh/authorized_keys`;
export const SERVER_ID_FILE = '/etc/ellulai/server-id';
export const API_URL_FILE = '/etc/ellulai/api-url';

// Service configuration
export const PORT = 3005;
export const RP_NAME = 'ellul.ai';

// Session security constants
export const SESSION_TTL_MS = 4 * 60 * 60 * 1000;        // 4 hours idle timeout
export const ABSOLUTE_MAX_MS = 24 * 60 * 60 * 1000;      // 24 hours absolute expiry
export const ROTATION_INTERVAL_MS = 15 * 60 * 1000;      // 15 minutes session rotation
export const STEP_UP_THRESHOLD_MS = 5 * 60 * 1000;       // 5 minutes for step-up auth
export const CHALLENGE_TTL_MS = 60 * 1000;                // 60 second challenge expiry

// Rate limiting
export const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
export const RATE_LIMIT_MAX_ATTEMPTS = 5;
export const LOCKOUT_DURATION_MS = 60 * 60 * 1000;

// PoP (Proof of Possession) constants
export const POP_TIMESTAMP_TOLERANCE_MS = 30 * 1000; // 30 seconds clock drift tolerance
export const SERVER_STARTUP_TIME = Date.now();       // Track server startup for replay attack prevention

// Sensitive actions requiring step-up auth
export const SENSITIVE_ACTIONS = [
  '/_auth/delete-credential',
  '/_auth/add-credential',
  '/_auth/bridge/switch-tier',
  '/_auth/bridge/downgrade-to-standard',
  '/_auth/bridge/upgrade-to-web-locked',
  '/_auth/recovery/regenerate',
  '/_auth/confirm-operation',
] as const;

// Known trusted authenticator AAGUIDs (hardware-backed or reputable password managers)
export const TRUSTED_AAGUIDS: Record<string, string> = {
  // Apple
  'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'Apple Passwords',
  'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': 'iCloud Keychain (Managed)',
  '00000000-0000-0000-0000-000000000000': 'Apple Platform Authenticator',
  // Google
  'adce0002-35bc-c60a-648b-0b25f1f05503': 'Chrome on Mac',
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager',
  // YubiKey (FW 5.1)
  'cb69481e-8ff7-4039-93ec-0a2729a154a8': 'YubiKey 5 Series',
  'fa2b99dc-9e39-4257-8f92-4a30d23c4118': 'YubiKey 5 NFC',
  // YubiKey (FW 5.2+)
  'ee882879-721c-4913-9775-3dfcce97072a': 'YubiKey 5 Series',
  '2fc0579f-8113-47ea-b116-bb5a8db9202a': 'YubiKey 5 NFC',
  'c5ef55ff-ad9a-4b9f-b580-adebafe026d0': 'YubiKey 5Ci',
  // YubiKey FIPS
  '73bb0cd4-e502-49b8-9c6f-b59445bf720b': 'YubiKey 5 FIPS Series',
  'c1f9a0bc-1dd2-404a-b27f-8e29047a43fd': 'YubiKey 5 NFC FIPS',
  '85203421-48f9-4355-9bc8-8a53846e5083': 'YubiKey 5Ci FIPS',
  // Password Managers
  'bada5566-a7aa-401f-bd96-45619a55120d': '1Password',
  'd548826e-79b4-db40-a3d8-11116f7e8349': 'Bitwarden',
  '531126d6-e717-415c-9320-3d9aa6981239': 'Dashlane',
  'b84e4048-15dc-4dd0-8640-f4f60813c8af': 'NordPass',
  '0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6': 'Keeper',
  // Windows Hello
  '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello',
  '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': 'Windows Hello',
  '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello',
};

// Headers used for stable device fingerprinting (low-entropy, always sent)
export const STABLE_FINGERPRINT_HEADERS = [
  'user-agent',
  'sec-ch-ua',           // Always sent (low-entropy)
  'sec-ch-ua-mobile',    // Always sent (low-entropy)
  'sec-ch-ua-platform',  // Always sent (low-entropy)
] as const;

// Security tiers
export type SecurityTier = 'standard' | 'web_locked';
