/**
 * Cryptographic Hash-Chained Audit Service
 *
 * Tamper-evident audit log using Ed25519-signed, hash-chained entries.
 * Each entry includes the hash of the previous entry, creating an
 * immutable chain. The chain head is reported in heartbeat for
 * remote verification by the platform API.
 *
 * SEPARATE from audit.service.ts (SQLite-based audit log).
 * This is a file-based JSONL audit trail with cryptographic guarantees.
 */

import fs from 'fs';
import crypto from 'crypto';

const AUDIT_LOG = '/var/log/ellulai/audit.jsonl';
const CHAIN_HEAD_FILE = '/etc/ellulai/audit-chain-head';
const SIGNING_KEY = '/etc/ellulai/heartbeat.key'; // Reuse Ed25519 key

interface AuditEntry {
  seq: number;
  timestamp: string;
  action: string;
  actor: 'passkey' | 'system' | 'enforcer';
  details: Record<string, unknown>;
  prevHash: string;
  hash: string;
  signature: string;
}

interface ChainHead {
  seq: number;
  hash: string;
}

function loadChainHead(): ChainHead {
  try {
    const data = fs.readFileSync(CHAIN_HEAD_FILE, 'utf8');
    return JSON.parse(data);
  } catch {
    return { seq: 0, hash: 'genesis' };
  }
}

let chainHead = loadChainHead();

export function cryptoAudit(action: string, actor: AuditEntry['actor'], details: Record<string, unknown>): void {
  const entry: Partial<AuditEntry> = {
    seq: chainHead.seq + 1,
    timestamp: new Date().toISOString(),
    action,
    actor,
    details,
    prevHash: chainHead.hash,
  };

  // Hash: SHA-256(prevHash + seq + timestamp + action + details)
  const hashInput = `${entry.prevHash}:${entry.seq}:${entry.timestamp}:${entry.action}:${JSON.stringify(entry.details)}`;
  entry.hash = crypto.createHash('sha256').update(hashInput).digest('hex');

  // Sign with Ed25519 private key (if available)
  try {
    const privateKey = fs.readFileSync(SIGNING_KEY, 'utf8');
    entry.signature = crypto.sign(null, Buffer.from(entry.hash), privateKey).toString('base64');
  } catch {
    entry.signature = ''; // Key not available yet (pre-provisioning)
  }

  // Ensure log directory exists
  const logDir = '/var/log/ellulai';
  if (!fs.existsSync(logDir)) {
    try { fs.mkdirSync(logDir, { recursive: true }); } catch {}
  }

  // Append to log
  fs.appendFileSync(AUDIT_LOG, JSON.stringify(entry) + '\n');

  // Update chain head
  chainHead = { seq: entry.seq!, hash: entry.hash };
  fs.writeFileSync(CHAIN_HEAD_FILE, JSON.stringify(chainHead));
}

export function getChainHead(): ChainHead {
  return { ...chainHead };
}

/**
 * Read audit log entries with seq > since.
 * Returns at most `limit` entries (default 100).
 */
export function readAuditLog(since: number = 0, limit: number = 100): AuditEntry[] {
  try {
    const data = fs.readFileSync(AUDIT_LOG, 'utf8');
    const lines = data.trim().split('\n').filter(Boolean);
    const entries: AuditEntry[] = [];

    for (const line of lines) {
      try {
        const entry = JSON.parse(line) as AuditEntry;
        if (entry.seq > since) {
          entries.push(entry);
        }
      } catch {
        // Skip malformed lines
      }
    }

    // Return the last `limit` entries (most recent)
    return entries.slice(-limit);
  } catch {
    return [];
  }
}
