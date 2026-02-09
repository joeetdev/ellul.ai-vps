/**
 * Setup Service
 *
 * Setup token validation and attestation policy management.
 */

import crypto from 'crypto';
import fs from 'fs';
import {
  SETUP_TOKEN_FILE,
  SETUP_EXPIRY_FILE,
  SSH_TRANSITION_MARKER,
  ATTESTATION_POLICY_FILE,
  TRUSTED_AAGUIDS,
} from '../config';

export interface AttestationPolicy {
  mode: 'strict' | 'permissive' | 'none';
  allowedAAGUIDs: string[];
  warnUnknownAAGUID: boolean;
  logAttestationDetails: boolean;
}

/**
 * Load attestation policy (default: strict mode)
 */
export function loadAttestationPolicy(): AttestationPolicy {
  try {
    if (fs.existsSync(ATTESTATION_POLICY_FILE)) {
      return JSON.parse(fs.readFileSync(ATTESTATION_POLICY_FILE, 'utf8'));
    }
  } catch {}
  // Default strict policy - only allow known hardware authenticators
  // This prevents software-based authenticator attacks where keys can be exported
  return {
    mode: 'strict',
    allowedAAGUIDs: Object.keys(TRUSTED_AAGUIDS),
    warnUnknownAAGUID: true,
    logAttestationDetails: true,
  };
}

/**
 * Validate setup token with timing-safe comparison
 */
export function validateSetupToken(token: string | undefined | null): boolean {
  if (!token) return false;
  try {
    const validToken = fs.readFileSync(SETUP_TOKEN_FILE, 'utf8').trim();

    // Constant-time comparison to prevent timing attacks
    // Handle different lengths by padding shorter string (still rejects but without length leak)
    const tokenBuf = Buffer.from(token);
    const validBuf = Buffer.from(validToken);
    const maxLen = Math.max(tokenBuf.length, validBuf.length);
    const paddedToken = Buffer.alloc(maxLen);
    const paddedValid = Buffer.alloc(maxLen);
    tokenBuf.copy(paddedToken);
    validBuf.copy(paddedValid);

    if (!crypto.timingSafeEqual(paddedToken, paddedValid) || tokenBuf.length !== validBuf.length) {
      return false;
    }

    // Check expiry if expiry file exists (used by ellulai-web-locked)
    if (fs.existsSync(SETUP_EXPIRY_FILE)) {
      const expiry = parseInt(fs.readFileSync(SETUP_EXPIRY_FILE, 'utf8').trim(), 10);
      if (Date.now() / 1000 > expiry) {
        // Token expired - clean up
        try { fs.unlinkSync(SETUP_TOKEN_FILE); } catch {}
        try { fs.unlinkSync(SETUP_EXPIRY_FILE); } catch {}
        try { fs.unlinkSync(SSH_TRANSITION_MARKER); } catch {}
        return false;
      }
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Clean up setup token files
 */
export function cleanupSetupToken(): void {
  try { fs.unlinkSync(SETUP_TOKEN_FILE); } catch {}
  try { fs.unlinkSync(SETUP_EXPIRY_FILE); } catch {}
  try { fs.unlinkSync(SSH_TRANSITION_MARKER); } catch {}
}
