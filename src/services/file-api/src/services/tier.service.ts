/**
 * Tier Service
 *
 * Security tier management for the file API.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as crypto from 'crypto';
import { execSync } from 'child_process';
import { PATHS, HOME } from '../config';

/**
 * Get current security tier.
 */
export function getCurrentTier(): 'standard' | 'web_locked' {
  try {
    const tier = fs.readFileSync(PATHS.TIER, 'utf8').trim();
    if (tier === 'standard' || tier === 'web_locked') {
      return tier;
    }
  } catch {
    // Detect from state
    if (fs.existsSync('/etc/ellulai/.sovereign-shield-active')) return 'web_locked';
  }
  return 'standard';
}

/**
 * Get server credentials for platform communication.
 */
export function getServerCredentials(): {
  serverId: string;
  apiUrl: string;
  token: string | null;
} | null {
  try {
    const serverId = fs.readFileSync(PATHS.SERVER_ID, 'utf8').trim();
    const apiUrl = fs.existsSync(PATHS.API_URL)
      ? fs.readFileSync(PATHS.API_URL, 'utf8').trim()
      : 'https://api.ellul.ai';
    const bashrc = fs.readFileSync(`${os.homedir()}/.bashrc`, 'utf8');
    const tokenMatch = bashrc.match(/ELLULAI_AI_TOKEN="([^"]+)"/);
    const token = tokenMatch && tokenMatch[1] ? tokenMatch[1] : null;
    return { serverId, apiUrl, token };
  } catch {
    return null;
  }
}

/**
 * Get server ID.
 */
export function getServerId(): string | null {
  try {
    return fs.readFileSync(PATHS.SERVER_ID, 'utf8').trim() || null;
  } catch {
    return null;
  }
}

/**
 * Compute SSH key fingerprint.
 */
export function computeSshFingerprint(publicKey: string): string {
  const parts = publicKey.trim().split(/\s+/);
  if (parts.length < 2) return 'unknown';
  try {
    const keyData = Buffer.from(parts[1] as string, 'base64');
    const hash = crypto.createHash('sha256').update(keyData).digest('base64');
    return 'SHA256:' + hash.replace(/=+$/, '');
  } catch {
    return 'unknown';
  }
}

/**
 * SSH key info.
 */
export interface SshKeyInfo {
  fingerprint: string;
  name: string;
  publicKey: string;
}

/**
 * Get all SSH keys from authorized_keys.
 */
export function getSshKeys(): SshKeyInfo[] {
  const keys: SshKeyInfo[] = [];
  try {
    const content = fs.readFileSync(PATHS.SSH_AUTH_KEYS, 'utf8');
    const lines = content.split('\n').filter((l) => l.trim() && !l.trim().startsWith('#'));
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
 * Add an SSH key.
 */
export function addSshKey(
  publicKey: string,
  name?: string
): { success: boolean; fingerprint?: string; error?: string } {
  const trimmedKey = publicKey.trim();

  // Validate format
  if (!/^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d+)\s+/.test(trimmedKey)) {
    return { success: false, error: 'Invalid SSH public key format' };
  }

  // Check for private key
  if (trimmedKey.includes('PRIVATE KEY')) {
    return { success: false, error: 'You pasted a PRIVATE key! Only paste the PUBLIC key.' };
  }

  const fingerprint = computeSshFingerprint(trimmedKey);

  try {
    execSync(`mkdir -p ${HOME}/.ssh && chmod 700 ${HOME}/.ssh`, { stdio: 'ignore' });

    // Check for duplicate
    const keyData = trimmedKey.split(' ')[1];
    let existingKeys = '';
    try {
      existingKeys = fs.readFileSync(PATHS.SSH_AUTH_KEYS, 'utf8');
    } catch {}
    const keyExists = existingKeys.split('\n').some((line) => line.includes(keyData || ''));

    if (keyExists) {
      return { success: false, error: 'This SSH key is already added', fingerprint };
    }

    const keyLine = name ? `${trimmedKey} ${name}` : trimmedKey;
    fs.appendFileSync(PATHS.SSH_AUTH_KEYS, keyLine + '\n');
    execSync(`chmod 600 ${PATHS.SSH_AUTH_KEYS}`, { stdio: 'ignore' });

    return { success: true, fingerprint };
  } catch (e) {
    return { success: false, error: 'Failed to add SSH key' };
  }
}

/**
 * Remove an SSH key by fingerprint.
 */
export function removeSshKey(fingerprint: string): { success: boolean; error?: string } {
  try {
    const content = fs.readFileSync(PATHS.SSH_AUTH_KEYS, 'utf8');
    const lines = content.split('\n');
    const newLines = lines.filter((line) => {
      if (!line.trim() || line.trim().startsWith('#')) return true;
      const lineFingerprint = computeSshFingerprint(line);
      return lineFingerprint !== fingerprint;
    });

    fs.writeFileSync(PATHS.SSH_AUTH_KEYS, newLines.join('\n'));
    execSync(`chmod 600 ${PATHS.SSH_AUTH_KEYS}`, { stdio: 'ignore' });

    return { success: true };
  } catch (e) {
    return { success: false, error: 'Failed to remove SSH key' };
  }
}

/**
 * Notify platform of an event.
 */
export async function notifyPlatform(
  event: string,
  data: Record<string, unknown>,
  retries: number = 2
): Promise<void> {
  const creds = getServerCredentials();
  if (!creds || !creds.token) return;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);

      const res = await fetch(`${creds.apiUrl}/api/servers/${creds.serverId}/vps-event`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${creds.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          event,
          data,
          timestamp: Date.now(),
          nonce: crypto.randomBytes(16).toString('hex'),
        }),
        signal: controller.signal,
      });

      clearTimeout(timeout);
      console.log(`[file-api] Platform notified: ${event} -> ${res.status}`);
      return;
    } catch (e) {
      const error = e as Error;
      console.error(
        `[file-api] Failed to notify platform (attempt ${attempt + 1}/${retries + 1}):`,
        error.message
      );
      if (attempt < retries) {
        await new Promise((resolve) => setTimeout(resolve, 1000 * (attempt + 1)));
      }
    }
  }
}

/**
 * Execute tier switch via sovereign-shield unified endpoint.
 */
export async function executeTierSwitch(
  targetTier: 'standard' | 'web_locked',
  ipAddress: string,
  userAgent: string
): Promise<void> {
  const currentTier = getCurrentTier();

  console.log(`[file-api] Delegating tier switch to unified endpoint: ${currentTier} -> ${targetTier}`);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 60000);

  const response = await fetch('http://localhost:3005/_auth/tier/switch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      targetTier,
      source: 'file-api',
      ipAddress: ipAddress || 'unknown',
      userAgent: userAgent || 'unknown',
    }),
    signal: controller.signal,
  });

  clearTimeout(timeout);

  const result = (await response.json()) as { success?: boolean; error?: string };

  if (!response.ok || !result.success) {
    throw new Error(result.error || 'Tier switch failed');
  }

  console.log(`[file-api] Tier switch completed via unified endpoint: ${currentTier} -> ${targetTier}`);
}
