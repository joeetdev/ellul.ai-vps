/**
 * Vibe Chat Database
 *
 * SQLite initialization for persistent chat threads and messages.
 * Data lives solely on VPS for full sovereignty.
 */

import Database from 'better-sqlite3';
import * as fs from 'fs';
import * as path from 'path';
import { CHAT_DB_PATH } from './config';
import { setDatabase as setThreadDb } from './services/thread.service';

// Ensure directory exists
const dbDir = path.dirname(CHAT_DB_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

// Initialize SQLite with WAL mode for better concurrency
export const db = new Database(CHAT_DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');
db.pragma('foreign_keys = ON');

// Inject database into services
setThreadDb(db);

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS threads (
    id TEXT PRIMARY KEY,
    title TEXT,
    project TEXT,
    last_session TEXT NOT NULL DEFAULT 'opencode',
    last_model TEXT,
    opencode_session_id TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_threads_updated ON threads(updated_at DESC);
  CREATE INDEX IF NOT EXISTS idx_threads_project ON threads(project, updated_at DESC);

  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    thread_id TEXT NOT NULL,
    type TEXT NOT NULL,
    content TEXT NOT NULL,
    session TEXT,
    model TEXT,
    thinking TEXT,
    metadata TEXT,
    created_at INTEGER NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (thread_id) REFERENCES threads(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(thread_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_messages_thread_seq ON messages(thread_id, seq);

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS processing_ledger (
    thread_id TEXT PRIMARY KEY,
    session TEXT NOT NULL,
    project TEXT,
    prompt TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    pid INTEGER NOT NULL,
    FOREIGN KEY (thread_id) REFERENCES threads(id) ON DELETE CASCADE
  );
`);

// Schema migration: add thinking_steps + streamed_text to processing_ledger for crash recovery.
// These columns persist in-flight state so thinking steps survive a mid-stream crash.
try {
  const cols = db.prepare("PRAGMA table_info(processing_ledger)").all() as { name: string }[];
  const colNames = new Set(cols.map(c => c.name));
  if (!colNames.has('thinking_steps')) {
    db.exec("ALTER TABLE processing_ledger ADD COLUMN thinking_steps TEXT DEFAULT '[]'");
  }
  if (!colNames.has('streamed_text')) {
    db.exec("ALTER TABLE processing_ledger ADD COLUMN streamed_text TEXT DEFAULT ''");
  }
} catch (e) {
  console.warn('[vibe-chat] processing_ledger migration warning:', (e as Error).message);
}

console.log('[vibe-chat] Database initialized at', CHAT_DB_PATH);

// Ensure thread state directory exists
import * as os from 'os';
import * as threadFs from 'fs';
const THREAD_STATE_DIR = `${os.homedir()}/.ellulai/threads`;
if (!threadFs.existsSync(THREAD_STATE_DIR)) {
  threadFs.mkdirSync(THREAD_STATE_DIR, { recursive: true });
  console.log('[vibe-chat] Created thread state directory at', THREAD_STATE_DIR);
}
