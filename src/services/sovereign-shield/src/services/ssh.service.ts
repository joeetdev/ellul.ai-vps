/**
 * SSH Key Service
 *
 * SSH key management utilities.
 */

import crypto from 'crypto';
import fs from 'fs';
import { execSync } from 'child_process';
import { SSH_AUTH_KEYS_PATH, SVC_USER, SVC_HOME } from '../config';

export interface SshKey {
  fingerprint: string;
  name: string;
  publicKey: string;
}

/**
 * Compute SSH fingerprint from public key
 */
export function computeSshFingerprint(publicKey: string): string {
  const parts = publicKey.trim().split(/\s+/);
  if (parts.length < 2 || !parts[1]) return 'unknown';
  try {
    const keyData = Buffer.from(parts[1], 'base64');
    const hash = crypto.createHash('sha256').update(keyData).digest('base64');
    return 'SHA256:' + hash.replace(/=+$/, '');
  } catch {
    return 'unknown';
  }
}

/**
 * Get all SSH keys from authorized_keys
 */
export function getSshKeys(): SshKey[] {
  const keys: SshKey[] = [];
  try {
    const content = fs.readFileSync(SSH_AUTH_KEYS_PATH, 'utf8');
    const lines = content.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'));
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 2) {
        const fingerprint = computeSshFingerprint(line);
        const comment = parts.length > 2 ? parts.slice(2).join(' ') : 'SSH Key';
        keys.push({ fingerprint, name: comment, publicKey: line.trim() });
      }
    }
  } catch {}
  return keys;
}

/**
 * Add an SSH key to authorized_keys
 */
export function addSshKey(publicKey: string): { fingerprint: string; success: boolean; error?: string } {
  const fingerprint = computeSshFingerprint(publicKey);

  if (fingerprint === 'unknown') {
    return { fingerprint: '', success: false, error: 'Invalid SSH key format' };
  }

  // Check if key already exists
  const existingKeys = getSshKeys();
  if (existingKeys.some(k => k.fingerprint === fingerprint)) {
    return { fingerprint, success: false, error: 'SSH key already exists' };
  }

  try {
    // Ensure .ssh directory exists
    const sshDir = `${SVC_HOME}/.ssh`;
    if (!fs.existsSync(sshDir)) {
      fs.mkdirSync(sshDir, { mode: 0o700 });
      execSync(`chown ${SVC_USER}:${SVC_USER} ${sshDir}`, { stdio: 'ignore' });
    }

    // Append key to authorized_keys
    const keyLine = publicKey.trim() + '\n';
    fs.appendFileSync(SSH_AUTH_KEYS_PATH, keyLine);

    // Ensure correct permissions
    fs.chmodSync(SSH_AUTH_KEYS_PATH, 0o600);
    execSync(`chown ${SVC_USER}:${SVC_USER} ${SSH_AUTH_KEYS_PATH}`, { stdio: 'ignore' });

    return { fingerprint, success: true };
  } catch (e) {
    return { fingerprint, success: false, error: (e as Error).message };
  }
}

/**
 * Remove an SSH key from authorized_keys
 */
export function removeSshKey(fingerprint: string): { success: boolean; error?: string } {
  try {
    const keys = getSshKeys();
    const filteredKeys = keys.filter(k => k.fingerprint !== fingerprint);

    if (filteredKeys.length === keys.length) {
      return { success: false, error: 'SSH key not found' };
    }

    // Write back filtered keys
    const content = filteredKeys.map(k => k.publicKey).join('\n') + (filteredKeys.length > 0 ? '\n' : '');
    fs.writeFileSync(SSH_AUTH_KEYS_PATH, content);
    fs.chmodSync(SSH_AUTH_KEYS_PATH, 0o600);
    execSync(`chown ${SVC_USER}:${SVC_USER} ${SSH_AUTH_KEYS_PATH}`, { stdio: 'ignore' });

    return { success: true };
  } catch (e) {
    return { success: false, error: (e as Error).message };
  }
}

/**
 * Check if SSHD needs to be restarted
 */
export function restartSshd(): void {
  try {
    execSync('systemctl restart sshd 2>/dev/null || true', { stdio: 'ignore' });
  } catch {}
}
