/**
 * Recovery Code Management
 *
 * Break-glass recovery system to prevent permanent lockout
 * if user loses all passkey devices.
 */

import crypto from 'crypto';
import { db } from '../database';

export interface RecoverySession {
  token: string;
  created_at: number;
  expires_at: number;
  ip: string;
  fingerprint: string | null;
  used: number;
}

/**
 * Generate 10 recovery codes (8 characters each, alphanumeric)
 */
export function generateRecoveryCodes(): string[] {
  const codes: string[] = [];
  for (let i = 0; i < 10; i++) {
    // Generate random bytes and convert to readable code
    const bytes = crypto.randomBytes(5);
    const code = bytes.toString('base64')
      .replace(/[+/=]/g, '') // Remove non-alphanumeric
      .substring(0, 8)
      .toUpperCase();
    codes.push(code);
  }
  return codes;
}

/**
 * Store recovery codes (hashed with individual salts)
 */
export function storeRecoveryCodes(codes: string[]): string[] {
  const salt = crypto.randomBytes(16).toString('hex');

  // Clear any existing codes
  db.prepare('DELETE FROM recovery_codes').run();

  const stmt = db.prepare(
    'INSERT INTO recovery_codes (hash, salt, used, created_at) VALUES (?, ?, 0, ?)'
  );

  const now = Date.now();
  for (const code of codes) {
    const hash = crypto.scryptSync(code, salt, 64).toString('hex');
    stmt.run(hash, salt, now);
  }

  return codes; // Return plaintext codes for user to save
}

/**
 * Verify a recovery code (returns code id if valid)
 */
export function verifyRecoveryCode(code: string, _ip: string): number | null {
  // Get all unused codes
  const codes = db.prepare(
    'SELECT id, hash, salt FROM recovery_codes WHERE used = 0'
  ).all() as { id: number; hash: string; salt: string }[];

  for (const c of codes) {
    const testHash = crypto.scryptSync(code.toUpperCase(), c.salt, 64).toString('hex');
    if (crypto.timingSafeEqual(Buffer.from(testHash, 'hex'), Buffer.from(c.hash, 'hex'))) {
      return c.id;
    }
  }
  return null;
}

/**
 * Mark recovery code as used
 */
export function markRecoveryCodeUsed(codeId: number, ip: string): void {
  db.prepare(
    'UPDATE recovery_codes SET used = 1, used_at = ?, used_ip = ? WHERE id = ?'
  ).run(Date.now(), ip, codeId);
}

/**
 * Get remaining recovery codes count
 */
export function getRemainingRecoveryCodes(): number {
  const result = db.prepare(
    'SELECT COUNT(*) as count FROM recovery_codes WHERE used = 0'
  ).get() as { count: number };
  return result.count;
}

/**
 * Check if recovery codes exist
 */
export function hasRecoveryCodes(): boolean {
  const result = db.prepare(
    'SELECT COUNT(*) as count FROM recovery_codes'
  ).get() as { count: number };
  return result.count > 0;
}

/**
 * Create a recovery session token
 */
export function createRecoverySession(ip: string, fingerprint: string | null): string {
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  const expiresAt = now + 10 * 60 * 1000; // 10 minutes

  db.prepare(
    'INSERT INTO recovery_sessions (token, created_at, expires_at, ip, fingerprint, used) VALUES (?, ?, ?, ?, ?, 0)'
  ).run(token, now, expiresAt, ip, fingerprint);

  return token;
}

/**
 * Validate and consume a recovery session token
 */
export function consumeRecoverySession(token: string, _ip: string): RecoverySession | null {
  const session = db.prepare(
    'SELECT * FROM recovery_sessions WHERE token = ? AND used = 0'
  ).get(token) as RecoverySession | undefined;

  if (!session) return null;

  // Check expiry
  if (Date.now() > session.expires_at) {
    db.prepare('DELETE FROM recovery_sessions WHERE token = ?').run(token);
    return null;
  }

  // Mark as used
  db.prepare('UPDATE recovery_sessions SET used = 1 WHERE token = ?').run(token);

  return session;
}

/**
 * Clean up expired recovery sessions
 */
export function cleanupRecoverySessions(): void {
  const now = Date.now();
  db.prepare('DELETE FROM recovery_sessions WHERE expires_at < ?').run(now);
}
