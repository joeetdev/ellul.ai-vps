/**
 * WebAuthn Authentication
 *
 * Passkey registration and authentication using @simplewebauthn/server.
 * This module handles challenge management and credential verification.
 *
 * Note: @simplewebauthn/server is installed on the VPS, not in this monorepo.
 * TypeScript errors for this import are expected during local development.
 */

// VPS dependency stubs - these will be overwritten at runtime on VPS
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let generateRegistrationOptions: (opts: any) => Promise<any> = async () => { throw new Error('Not implemented'); };
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let verifyRegistrationResponse: (opts: any) => Promise<any> = async () => { throw new Error('Not implemented'); };
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let generateAuthenticationOptions: (opts: any) => Promise<any> = async () => { throw new Error('Not implemented'); };
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let verifyAuthenticationResponse: (opts: any) => Promise<any> = async () => { throw new Error('Not implemented'); };

// Try to load actual module at runtime (VPS only)
try {
  // @ts-ignore - VPS runtime dependency
  const webauthn = require('@simplewebauthn/server');
  generateRegistrationOptions = webauthn.generateRegistrationOptions;
  verifyRegistrationResponse = webauthn.verifyRegistrationResponse;
  generateAuthenticationOptions = webauthn.generateAuthenticationOptions;
  verifyAuthenticationResponse = webauthn.verifyAuthenticationResponse;
} catch {
  // Module not available - stubs will throw when called
}
import { CHALLENGE_TTL_MS, TRUSTED_AAGUIDS } from '../config';

// Type definitions for WebAuthn (matches @simplewebauthn/server types)
export type AuthenticatorTransport = 'usb' | 'ble' | 'nfc' | 'internal' | 'hybrid';

export interface GenerateRegistrationOptionsOpts {
  rpName: string;
  rpID: string;
  userName: string;
  userDisplayName?: string;
  attestationType?: 'none' | 'direct' | 'indirect' | 'enterprise';
  authenticatorSelection?: {
    authenticatorAttachment?: 'platform' | 'cross-platform';
    residentKey?: 'required' | 'preferred' | 'discouraged';
    userVerification?: 'required' | 'preferred' | 'discouraged';
  };
  excludeCredentials?: Array<{ id: string; type: 'public-key'; transports?: AuthenticatorTransport[] }>;
}

export interface VerifyRegistrationResponseOpts {
  response: unknown;
  expectedChallenge: string;
  expectedOrigin: string | string[];
  expectedRPID: string;
  requireUserVerification?: boolean;
}

export interface GenerateAuthenticationOptionsOpts {
  rpID: string;
  userVerification?: 'required' | 'preferred' | 'discouraged';
  allowCredentials?: Array<{ id: string; type: 'public-key'; transports?: AuthenticatorTransport[] }>;
}

export interface VerifyAuthenticationResponseOpts {
  response: unknown;
  expectedChallenge: string;
  expectedOrigin: string | string[];
  expectedRPID: string;
  credential: {
    id: string;
    publicKey: Uint8Array;
    counter: number;
    transports?: AuthenticatorTransport[];
  };
}

export interface VerifiedRegistrationResponse {
  verified: boolean;
  registrationInfo?: {
    credential: {
      id: string | Uint8Array;
      publicKey: Uint8Array;
      counter: number;
      transports?: AuthenticatorTransport[];
    };
    aaguid?: string;
    credentialDeviceType?: string;
    credentialBackedUp?: boolean;
    attestationObject?: { fmt?: string };
  };
}

export interface VerifiedAuthenticationResponse {
  verified: boolean;
  authenticationInfo: {
    newCounter: number;
    credentialID: string | Uint8Array;
  };
}

// Re-export functions for convenience
export {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
};

export interface ChallengeData {
  type: 'registration' | 'authentication' | 'recovery_registration';
  createdAt: number;
  userId?: string;
  recoveryToken?: string;
}

// In-memory challenge storage
const challenges = new Map<string, ChallengeData>();

// Cleanup expired challenges periodically
setInterval(() => {
  const now = Date.now();
  for (const [challenge, data] of challenges) {
    if (now - data.createdAt > CHALLENGE_TTL_MS) {
      challenges.delete(challenge);
    }
  }
}, 60000);

/**
 * Store a challenge for later verification
 */
export function storeChallenge(challenge: string, data: ChallengeData): void {
  challenges.set(challenge, data);
}

/**
 * Get, validate, and consume a challenge (single-use).
 * SECURITY: Challenge is deleted immediately on retrieval to prevent reuse
 * on verification failure or exception. This is critical because challenges
 * that survive failed attempts can be retried by an attacker.
 */
export function getChallenge(challenge: string): ChallengeData | null {
  const data = challenges.get(challenge);
  if (!data) return null;

  // Always delete immediately - challenges are single-use
  challenges.delete(challenge);

  // Check if expired
  if (Date.now() - data.createdAt > CHALLENGE_TTL_MS) {
    return null;
  }

  return data;
}

/**
 * Delete a challenge after use
 */
export function deleteChallenge(challenge: string): void {
  challenges.delete(challenge);
}

/**
 * Check if an AAGUID is a known trusted authenticator
 */
export function isTrustedAuthenticator(aaguid: string): boolean {
  return aaguid in TRUSTED_AAGUIDS;
}

/**
 * Get the name of a trusted authenticator by AAGUID
 */
export function getAuthenticatorName(aaguid: string): string | null {
  return TRUSTED_AAGUIDS[aaguid] || null;
}

/**
 * Parse AAGUID from attestation data
 */
export function parseAaguid(authData: Uint8Array): string {
  // AAGUID is at bytes 37-52 (16 bytes) in the authenticator data
  if (authData.length < 53) return '00000000-0000-0000-0000-000000000000';

  const aaguidBytes = authData.slice(37, 53);
  const hex = Array.from(aaguidBytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export interface CredentialRecord {
  id: string;
  credentialId: string;
  publicKey: string;
  counter: number;
  transports?: string;
  aaguid?: string;
  device_type?: string;
  backed_up?: number;
  attestation_fmt?: string;
  name?: string;
}

/**
 * Build credential descriptor for allowCredentials
 */
export function buildAllowCredentials(credentials: CredentialRecord[]): Array<{
  id: string;
  type: 'public-key';
  transports?: AuthenticatorTransport[];
}> {
  return credentials.map(c => ({
    id: c.credentialId,
    type: 'public-key' as const,
    transports: c.transports ? JSON.parse(c.transports) : undefined,
  }));
}
