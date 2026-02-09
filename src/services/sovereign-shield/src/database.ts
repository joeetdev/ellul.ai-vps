/**
 * Sovereign Shield Database
 *
 * SQLite initialization, schema creation, and migrations.
 */

import Database from 'better-sqlite3';
import { DB_PATH } from './config';
import { setDatabase as setAuditDb } from './services/audit.service';
import { setDatabase as setRateLimiterDb } from './services/rate-limiter';
import { setDatabase as setTierDb } from './services/tier.service';

// Initialize SQLite with WAL mode for better concurrency
export const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');

// Inject database into services
setAuditDb(db);
setRateLimiterDb(db);
setTierDb(db);

// Create core tables
db.exec(`
  CREATE TABLE IF NOT EXISTS credential (
    id TEXT PRIMARY KEY,
    credentialId TEXT NOT NULL UNIQUE,
    publicKey TEXT NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    transports TEXT,
    createdAt TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL,
    ip TEXT NOT NULL,
    fingerprint TEXT,
    fingerprint_status TEXT DEFAULT 'pending',
    fingerprint_components TEXT,
    fingerprint_bound_at INTEGER,
    country_code TEXT,
    created_at INTEGER NOT NULL,
    last_activity INTEGER NOT NULL,
    last_rotation INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    absolute_expiry INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_credential ON sessions(credential_id);

  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    event TEXT NOT NULL,
    ip TEXT,
    fingerprint TEXT,
    credential_id TEXT,
    session_id TEXT,
    details TEXT,
    prev_hash TEXT,
    hash TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);

  CREATE TABLE IF NOT EXISTS auth_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    success INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_attempts_ip_time ON auth_attempts(ip, timestamp);

  -- Recovery codes table
  CREATE TABLE IF NOT EXISTS recovery_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    used INTEGER DEFAULT 0,
    used_at INTEGER,
    used_ip TEXT,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS recovery_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    success INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_recovery_attempts_ip ON recovery_attempts(ip, timestamp);

  CREATE TABLE IF NOT EXISTS recovery_sessions (
    token TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ip TEXT NOT NULL,
    fingerprint TEXT,
    used INTEGER DEFAULT 0
  );

  -- PoP nonces table for replay attack prevention (persisted across restarts)
  CREATE TABLE IF NOT EXISTS pop_nonces (
    nonce_key TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_pop_nonces_expires ON pop_nonces(expires_at);

  -- Confirmation nonces graveyard — ensures single-use confirmation tokens
  -- survive service restarts (previously in-memory Map, now persisted)
  CREATE TABLE IF NOT EXISTS confirmation_nonces (
    nonce TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_confirmation_nonces_expires ON confirmation_nonces(expires_at);

  -- Terminal sessions (persisted so they survive service restarts)
  CREATE TABLE IF NOT EXISTS term_sessions (
    id TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    shield_session_id TEXT NOT NULL,
    tier TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_term_sessions_expires ON term_sessions(expires_at);

  -- Preview tokens (short-lived, single-use, for cross-site dev preview auth)
  CREATE TABLE IF NOT EXISTS preview_tokens (
    token TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_preview_tokens_expires ON preview_tokens(expires_at);

  -- Preview sessions (longer-lived, set as __Host-preview_session cookie on ellul.app)
  CREATE TABLE IF NOT EXISTS preview_sessions (
    id TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    shield_session_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_preview_sessions_expires ON preview_sessions(expires_at);
`);

// Drop old session table if it exists (migration from v1)
try { db.exec('DROP TABLE IF EXISTS session'); } catch { /* ignore */ }

// Schema migration: Add attestation columns to credential table
function migrateCredentialTable(): void {
  try {
    const cols = (db.prepare("PRAGMA table_info(credential)").all() as { name: string }[]).map(c => c.name);
    if (!cols.includes('aaguid')) {
      db.exec("ALTER TABLE credential ADD COLUMN aaguid TEXT");
    }
    if (!cols.includes('device_type')) {
      db.exec("ALTER TABLE credential ADD COLUMN device_type TEXT");
    }
    if (!cols.includes('backed_up')) {
      db.exec("ALTER TABLE credential ADD COLUMN backed_up INTEGER DEFAULT 0");
    }
    if (!cols.includes('attestation_fmt')) {
      db.exec("ALTER TABLE credential ADD COLUMN attestation_fmt TEXT");
    }
    if (!cols.includes('name')) {
      db.exec("ALTER TABLE credential ADD COLUMN name TEXT DEFAULT 'Passkey'");
    }
  } catch (e) {
    console.error('[shield] Credential migration error (non-fatal):', (e as Error).message);
  }
}

// Schema migration: Add fingerprint binding columns to sessions table
function migrateSessionsTable(): void {
  try {
    const cols = (db.prepare("PRAGMA table_info(sessions)").all() as { name: string }[]).map(c => c.name);
    if (!cols.includes('fingerprint_status')) {
      db.exec("ALTER TABLE sessions ADD COLUMN fingerprint_status TEXT DEFAULT 'pending'");
      db.exec("UPDATE sessions SET fingerprint_status = 'bound' WHERE fingerprint IS NOT NULL");
    }
    if (!cols.includes('fingerprint_components')) {
      db.exec("ALTER TABLE sessions ADD COLUMN fingerprint_components TEXT");
    }
    if (!cols.includes('fingerprint_bound_at')) {
      db.exec("ALTER TABLE sessions ADD COLUMN fingerprint_bound_at INTEGER");
    }
    if (!cols.includes('country_code')) {
      db.exec("ALTER TABLE sessions ADD COLUMN country_code TEXT");
    }
    try { db.exec("CREATE INDEX IF NOT EXISTS idx_sessions_fingerprint_status ON sessions(fingerprint_status)"); } catch { /* ignore */ }
  } catch (e) {
    console.error('[shield] Sessions migration error (non-fatal):', (e as Error).message);
  }
}

// Schema migration: Add PoP columns to sessions table
function migratePopColumns(): void {
  try {
    const cols = (db.prepare("PRAGMA table_info(sessions)").all() as { name: string }[]).map(c => c.name);
    if (!cols.includes('pop_public_key')) {
      db.exec("ALTER TABLE sessions ADD COLUMN pop_public_key TEXT");
    }
    if (!cols.includes('pop_bound_at')) {
      db.exec("ALTER TABLE sessions ADD COLUMN pop_bound_at INTEGER");
    }
  } catch (e) {
    console.error('[shield] PoP migration error (non-fatal):', (e as Error).message);
  }
}

// Run all migrations
migrateCredentialTable();
migrateSessionsTable();
migratePopColumns();
