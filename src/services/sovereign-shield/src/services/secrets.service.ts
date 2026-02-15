/**
 * Secrets Service
 *
 * Handles encrypted secret decryption and environment file management.
 * Secrets are encrypted browser-side (RSA-4096 OAEP + AES-256-GCM) and
 * decrypted here using the VPS private key.
 *
 * The .ellulai-env file format:
 *   # ellul.ai Environment
 *   # Updated: <ISO timestamp>
 *   export NAME="VALUE"
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

import { SVC_USER, SVC_HOME } from '../config';

const PRIVATE_KEY_PATH = '/etc/ellulai/node.key';
const ENV_FILE = `${SVC_HOME}/.ellulai-env`;
const ENV_FILE_TMP = ENV_FILE + '.tmp';

export interface EncryptedEnvelope {
  encryptedKey: string;   // Base64 RSA-OAEP encrypted AES key
  iv: string;             // Base64 12-byte IV
  encryptedData: string;  // Base64 AES-GCM ciphertext + 16-byte auth tag
}

// ── Decryption ──

let privateKeyCache: string | null = null;

function getPrivateKey(): string {
  if (!privateKeyCache) {
    privateKeyCache = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
  }
  return privateKeyCache;
}

/**
 * Decrypt an encrypted envelope using the VPS private key.
 * Matches the browser's RSA-OAEP + AES-256-GCM format.
 */
export function decryptEnvelope(envelope: EncryptedEnvelope): string {
  const privateKey = getPrivateKey();

  // Step 1: RSA-OAEP decrypt the AES key
  const aesKey = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(envelope.encryptedKey, 'base64'),
  );

  // Step 2: AES-256-GCM decrypt the data
  const data = Buffer.from(envelope.encryptedData, 'base64');
  // Browser's SubtleCrypto appends 16-byte auth tag to ciphertext
  const authTag = data.subarray(-16);
  const ciphertext = data.subarray(0, -16);

  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    aesKey,
    Buffer.from(envelope.iv, 'base64'),
  );
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

// ── Env File I/O ──

/**
 * Parse .ellulai-env into a Map of name → value.
 * Handles the `export NAME="VALUE"` format.
 */
export function readEnvFile(): Map<string, string> {
  const secrets = new Map<string, string>();

  try {
    const content = fs.readFileSync(ENV_FILE, 'utf8');
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      // Match: export NAME="VALUE" or export NAME='VALUE'
      const match = trimmed.match(/^export\s+([A-Z_][A-Z0-9_]*)=["'](.*)["']$/);
      if (match) {
        secrets.set(match[1]!, match[2]!);
      }
    }
  } catch (err: any) {
    if (err.code !== 'ENOENT') throw err;
    // File doesn't exist yet — return empty map
  }

  return secrets;
}

/**
 * Write secrets map to .ellulai-env atomically.
 * Uses tmp file + rename for crash safety.
 */
export function writeEnvFile(secrets: Map<string, string>): void {
  const lines = [
    '# ellul.ai Environment',
    `# Updated: ${new Date().toISOString()}`,
    '',
  ];

  for (const [name, value] of secrets) {
    // Escape double quotes and backslashes in values
    const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    lines.push(`export ${name}="${escaped}"`);
  }

  // Ensure parent directory exists
  const dir = path.dirname(ENV_FILE);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  // Atomic write: write to tmp, then rename
  fs.writeFileSync(ENV_FILE_TMP, lines.join('\n') + '\n', { mode: 0o600 });

  // chown to dev user (sovereign-shield runs as root or service user)
  try {
    const { execSync } = require('child_process');
    execSync(`chown ${SVC_USER}:${SVC_USER} ${ENV_FILE_TMP}`, { stdio: 'ignore' });
  } catch {
    // Best effort — may fail in test environments
  }

  fs.renameSync(ENV_FILE_TMP, ENV_FILE);
}

// ── Public API ──

/**
 * Set a secret: decrypt the envelope and merge into env file.
 */
export function setSecret(name: string, envelope: EncryptedEnvelope): void {
  const value = decryptEnvelope(envelope);
  const secrets = readEnvFile();
  secrets.set(name, value);
  writeEnvFile(secrets);
}

/**
 * Set multiple secrets atomically.
 */
export function setSecretsBulk(items: Array<{ name: string; envelope: EncryptedEnvelope }>): void {
  const secrets = readEnvFile();
  for (const item of items) {
    const value = decryptEnvelope(item.envelope);
    secrets.set(item.name, value);
  }
  writeEnvFile(secrets);
}

/**
 * Delete a secret from the env file.
 */
export function deleteSecret(name: string): boolean {
  const secrets = readEnvFile();
  const existed = secrets.delete(name);
  if (existed) {
    writeEnvFile(secrets);
  }
  return existed;
}

/**
 * List all secret names (no values exposed).
 */
export function listSecrets(): string[] {
  const secrets = readEnvFile();
  return Array.from(secrets.keys());
}
