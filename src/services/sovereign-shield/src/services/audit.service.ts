/**
 * Audit Service
 *
 * Tamper-evident audit logging with hash chain integrity.
 */

import crypto from 'crypto';
import type Database from 'better-sqlite3';

// Database will be injected to avoid circular dependencies
let db: Database;

export function setDatabase(database: Database): void {
  db = database;
}

export interface AuditEvent {
  type: string;
  ip?: string | null;
  fingerprint?: string | null;
  credentialId?: string | null;
  sessionId?: string | null;
  details?: Record<string, unknown> | null;
}

export interface AuditEntry {
  timestamp: number;
  event: string;
  ip: string | null;
  fingerprint: string | null;
  credential_id: string | null;
  session_id: string | null;
  details: string | null;
  prev_hash: string;
  hash: string;
}

export interface IntegrityResult {
  valid: boolean;
  total: number;
  errors: Array<{
    id: number;
    error: string;
    expected_prev?: string;
    actual_prev?: string;
    expected?: string;
    actual?: string;
  }>;
}

/**
 * Log an audit event with hash chain integrity
 */
export function logAuditEvent(event: AuditEvent): AuditEntry {
  const lastLog = db.prepare('SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1').get() as { hash: string } | undefined;
  const prevHash = lastLog ? lastLog.hash : '0';

  const entry: AuditEntry = {
    timestamp: Date.now(),
    event: event.type,
    ip: event.ip || null,
    fingerprint: event.fingerprint || null,
    credential_id: event.credentialId || null,
    session_id: event.sessionId || null,
    details: event.details ? JSON.stringify(event.details) : null,
    prev_hash: prevHash,
    hash: '', // Will be computed below
  };

  entry.hash = crypto.createHash('sha256').update(JSON.stringify(entry)).digest('hex');

  db.prepare(
    'INSERT INTO audit_log (timestamp, event, ip, fingerprint, credential_id, session_id, details, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(
    entry.timestamp,
    entry.event,
    entry.ip,
    entry.fingerprint,
    entry.credential_id,
    entry.session_id,
    entry.details,
    entry.prev_hash,
    entry.hash
  );

  return entry;
}

/**
 * Get recent audit log entries
 */
export function getAuditLog(limit = 100, offset = 0): AuditEntry[] {
  return db.prepare(
    'SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?'
  ).all(limit, offset) as AuditEntry[];
}

/**
 * Verify audit log integrity (hash chain)
 */
export function verifyAuditIntegrity(): IntegrityResult {
  const logs = db.prepare('SELECT * FROM audit_log ORDER BY id ASC').all() as (AuditEntry & { id: number })[];

  let prevHash = '0';
  const errors: IntegrityResult['errors'] = [];

  for (const log of logs) {
    // Verify prev_hash links correctly
    if (log.prev_hash !== prevHash) {
      errors.push({
        id: log.id,
        error: 'chain_broken',
        expected_prev: prevHash,
        actual_prev: log.prev_hash,
      });
    }

    // Verify hash is correct
    const entry = {
      timestamp: log.timestamp,
      event: log.event,
      ip: log.ip,
      fingerprint: log.fingerprint,
      credential_id: log.credential_id,
      session_id: log.session_id,
      details: log.details,
      prev_hash: log.prev_hash,
      hash: '', // Exclude hash from computation
    };
    const computedHash = crypto.createHash('sha256').update(JSON.stringify(entry)).digest('hex');

    if (computedHash !== log.hash) {
      errors.push({
        id: log.id,
        error: 'hash_mismatch',
        expected: computedHash,
        actual: log.hash,
      });
    }

    prevHash = log.hash;
  }

  return {
    valid: errors.length === 0,
    total: logs.length,
    errors,
  };
}

/**
 * Get audit log count
 */
export function getAuditCount(): number {
  const result = db.prepare('SELECT COUNT(*) as count FROM audit_log').get() as { count: number };
  return result.count;
}
