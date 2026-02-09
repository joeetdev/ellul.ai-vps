/**
 * Thread Service
 *
 * CRUD operations for chat threads and messages.
 * Data stored in VPS SQLite for full sovereignty.
 *
 * Each thread has isolated CLI state - separate OpenCode sessions
 * and isolated HOME directories for Claude/Codex/Gemini.
 *
 * Thread isolation ensures:
 * - Independent conversation history per thread
 * - No context leakage between threads
 * - Clean resource cleanup on thread deletion
 */

import crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import type Database from 'better-sqlite3';

// Database will be injected to avoid circular dependencies
let db: Database;

// Base directory for per-thread isolated state
import * as os from 'os';
const THREAD_STATE_DIR = `${os.homedir()}/.ellulai/threads`;

// Simple mutex for thread operations to prevent race conditions
const threadLocks = new Map<string, Promise<void>>();

/**
 * Acquire a lock for a thread operation.
 * Ensures sequential access to thread resources.
 */
export async function withThreadLock<T>(threadId: string, operation: () => Promise<T>): Promise<T> {
  // Wait for any existing operation on this thread
  const existingLock = threadLocks.get(threadId);
  if (existingLock) {
    await existingLock;
  }

  // Create new lock
  let releaseLock: () => void;
  const lockPromise = new Promise<void>((resolve) => {
    releaseLock = resolve;
  });
  threadLocks.set(threadId, lockPromise);

  try {
    return await operation();
  } finally {
    releaseLock!();
    threadLocks.delete(threadId);
  }
}

export function setDatabase(database: Database): void {
  db = database;
}

// Types
export interface Thread {
  id: string;
  title: string | null;
  project: string | null; // App/project scope (null = global/unscoped)
  lastSession: string;
  lastModel: string | null;
  opencodeSessionId: string | null; // Per-thread OpenCode session
  createdAt: number;
  updatedAt: number;
}

export interface Message {
  id: string;
  threadId: string;
  type: 'user' | 'assistant' | 'error' | 'system' | 'cli_prompt' | 'cli_input';
  content: string;
  session: string | null;
  model: string | null;
  thinking: string[] | null;
  metadata: Record<string, unknown> | null;
  createdAt: number;
}

// Internal row types (snake_case from SQLite)
interface ThreadRow {
  id: string;
  title: string | null;
  project: string | null;
  last_session: string;
  last_model: string | null;
  opencode_session_id: string | null;
  created_at: number;
  updated_at: number;
}

interface MessageRow {
  id: string;
  thread_id: string;
  type: string;
  content: string;
  session: string | null;
  model: string | null;
  thinking: string | null;
  metadata: string | null;
  created_at: number;
}

// Helper to generate IDs
function generateId(): string {
  return crypto.randomBytes(12).toString('hex');
}

// Convert DB row to Thread
function rowToThread(row: ThreadRow): Thread {
  return {
    id: row.id,
    title: row.title,
    project: row.project,
    lastSession: row.last_session,
    lastModel: row.last_model,
    opencodeSessionId: row.opencode_session_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// Convert DB row to Message
function rowToMessage(row: MessageRow): Message {
  return {
    id: row.id,
    threadId: row.thread_id,
    type: row.type as Message['type'],
    content: row.content,
    session: row.session,
    model: row.model,
    thinking: row.thinking ? JSON.parse(row.thinking) : null,
    metadata: row.metadata ? JSON.parse(row.metadata) : null,
    createdAt: row.created_at,
  };
}

/**
 * Create a new thread
 * @param title - Optional thread title
 * @param session - Session type (default: opencode)
 * @param project - Project/app scope (null = global)
 */
export function createThread(title?: string, session: string = 'opencode', project?: string | null): Thread {
  const now = Date.now();
  const id = generateId();

  db.prepare(`
    INSERT INTO threads (id, title, project, last_session, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, title || null, project || null, session, now, now);

  // Create isolated state directory for this thread
  ensureThreadStateDir(id);

  return {
    id,
    title: title || null,
    project: project || null,
    lastSession: session,
    lastModel: null,
    opencodeSessionId: null,
    createdAt: now,
    updatedAt: now,
  };
}

/**
 * Ensure per-thread state directory exists with proper structure.
 * Creates isolated directories for each CLI tool.
 */
export function ensureThreadStateDir(threadId: string): string {
  const threadDir = path.join(THREAD_STATE_DIR, threadId);

  try {
    if (!fs.existsSync(threadDir)) {
      fs.mkdirSync(threadDir, { recursive: true, mode: 0o700 });
      console.log(`[Thread] Created state directory for ${threadId.substring(0, 8)}...`);

      // Create subdirectories for CLI state isolation
      const subDirs = ['.claude', '.codex', '.gemini', '.cache'];
      for (const subDir of subDirs) {
        fs.mkdirSync(path.join(threadDir, subDir), { recursive: true, mode: 0o700 });
      }
    }
  } catch (err) {
    console.error(`[Thread] Failed to create state directory for ${threadId.substring(0, 8)}...:`, (err as Error).message);
    // Return the path anyway - let caller handle the error
  }

  return threadDir;
}

/**
 * Get the isolated state directory for a thread
 */
export function getThreadStateDir(threadId: string): string {
  return path.join(THREAD_STATE_DIR, threadId);
}

/**
 * Clean up thread state directory.
 * Removes all CLI state associated with the thread.
 */
export function cleanupThreadStateDir(threadId: string): void {
  const threadDir = path.join(THREAD_STATE_DIR, threadId);

  try {
    if (fs.existsSync(threadDir)) {
      fs.rmSync(threadDir, { recursive: true, force: true });
      console.log(`[Thread] Cleaned up state directory for ${threadId.substring(0, 8)}...`);
    }
  } catch (err) {
    // Log but don't throw - cleanup failure is non-fatal
    console.error(`[Thread] Failed to cleanup state directory for ${threadId.substring(0, 8)}...:`, (err as Error).message);
  }
}

/**
 * Set OpenCode session ID for a thread
 */
export function setThreadOpencodeSession(threadId: string, sessionId: string): boolean {
  const result = db.prepare(`
    UPDATE threads SET opencode_session_id = ?, updated_at = ? WHERE id = ?
  `).run(sessionId, Date.now(), threadId);
  return result.changes > 0;
}

/**
 * Get OpenCode session ID for a thread
 */
export function getThreadOpencodeSession(threadId: string): string | null {
  const row = db.prepare('SELECT opencode_session_id FROM threads WHERE id = ?').get(threadId) as { opencode_session_id: string | null } | undefined;
  return row?.opencode_session_id || null;
}

/**
 * List threads for a project, ordered by most recent first
 * @param project - Project scope (null = only unscoped threads)
 * @param limit - Max threads to return
 */
export function listThreads(project?: string | null, limit: number = 100): Thread[] {
  let rows: ThreadRow[];

  if (project) {
    // Filter by specific project
    rows = db.prepare(`
      SELECT * FROM threads
      WHERE project = ?
      ORDER BY updated_at DESC
      LIMIT ?
    `).all(project, limit) as ThreadRow[];
  } else {
    // Only unscoped threads (project IS NULL)
    rows = db.prepare(`
      SELECT * FROM threads
      WHERE project IS NULL
      ORDER BY updated_at DESC
      LIMIT ?
    `).all(limit) as ThreadRow[];
  }

  return rows.map(rowToThread);
}

/**
 * Get a thread by ID
 */
export function getThread(id: string): Thread | null {
  const row = db.prepare('SELECT * FROM threads WHERE id = ?').get(id) as ThreadRow | undefined;
  return row ? rowToThread(row) : null;
}

/**
 * Delete a thread (messages cascade delete via foreign key).
 * Also cleans up associated resources (state directory, OpenCode session).
 */
export function deleteThread(id: string): boolean {
  const result = db.prepare('DELETE FROM threads WHERE id = ?').run(id);

  if (result.changes > 0) {
    console.log(`[Thread] Deleted thread ${id.substring(0, 8)}...`);

    // Clean up isolated state directory
    cleanupThreadStateDir(id);

    // Note: OpenCode session cleanup is handled async by caller if needed
    // We return the session ID via getThread() before deletion

    return true;
  }

  return false;
}

/**
 * Get OpenCode session ID before deleting a thread (for cleanup).
 */
export function getThreadForCleanup(id: string): { opencodeSessionId: string | null } | null {
  const row = db.prepare('SELECT opencode_session_id FROM threads WHERE id = ?').get(id) as { opencode_session_id: string | null } | undefined;
  return row ? { opencodeSessionId: row.opencode_session_id } : null;
}

/**
 * Rename a thread
 */
export function renameThread(id: string, title: string): boolean {
  const result = db.prepare(`
    UPDATE threads SET title = ?, updated_at = ? WHERE id = ?
  `).run(title, Date.now(), id);
  return result.changes > 0;
}

/**
 * Update thread's last session
 */
export function updateThreadSession(id: string, session: string): boolean {
  const result = db.prepare(`
    UPDATE threads SET last_session = ?, updated_at = ? WHERE id = ?
  `).run(session, Date.now(), id);
  return result.changes > 0;
}

/**
 * Update thread's last model
 */
export function updateThreadModel(id: string, model: string): boolean {
  const result = db.prepare(`
    UPDATE threads SET last_model = ?, updated_at = ? WHERE id = ?
  `).run(model, Date.now(), id);
  return result.changes > 0;
}

/**
 * Touch thread's updated_at timestamp
 */
export function touchThread(id: string): void {
  db.prepare('UPDATE threads SET updated_at = ? WHERE id = ?').run(Date.now(), id);
}

/**
 * Add a message to a thread
 */
export function addMessage(
  threadId: string,
  message: Omit<Message, 'id' | 'threadId' | 'createdAt'>
): Message {
  const now = Date.now();
  const id = generateId();

  db.prepare(`
    INSERT INTO messages (id, thread_id, type, content, session, model, thinking, metadata, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    threadId,
    message.type,
    message.content,
    message.session || null,
    message.model || null,
    message.thinking ? JSON.stringify(message.thinking) : null,
    message.metadata ? JSON.stringify(message.metadata) : null,
    now
  );

  // Touch thread's updated_at
  touchThread(threadId);

  return {
    id,
    threadId,
    type: message.type,
    content: message.content,
    session: message.session || null,
    model: message.model || null,
    thinking: message.thinking || null,
    metadata: message.metadata || null,
    createdAt: now,
  };
}

/**
 * Get messages for a thread
 */
export function getMessages(threadId: string, limit: number = 200): Message[] {
  const rows = db.prepare(`
    SELECT * FROM messages
    WHERE thread_id = ?
    ORDER BY created_at ASC
    LIMIT ?
  `).all(threadId, limit) as MessageRow[];

  return rows.map(rowToMessage);
}

/**
 * Get thread with messages
 */
export function getThreadWithMessages(
  threadId: string,
  messageLimit: number = 200
): { thread: Thread; messages: Message[] } | null {
  const thread = getThread(threadId);
  if (!thread) return null;

  const messages = getMessages(threadId, messageLimit);
  return { thread, messages };
}

/**
 * Get message count for a thread
 */
export function getMessageCount(threadId: string): number {
  const result = db.prepare('SELECT COUNT(*) as count FROM messages WHERE thread_id = ?').get(threadId) as { count: number };
  return result.count;
}

/**
 * Delete all threads and messages (for testing/cleanup)
 */
export function deleteAllThreads(): void {
  db.prepare('DELETE FROM threads').run();
}

/**
 * Get the last active thread ID for a project (persisted across sessions/devices)
 * @param project - Project scope (null = global setting)
 */
export function getActiveThreadId(project?: string | null): string | null {
  const settingKey = project ? `active_thread_id:${project}` : 'active_thread_id';
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(settingKey) as { value: string } | undefined;
  if (!row) return null;

  // Verify the thread still exists
  const thread = getThread(row.value);
  if (!thread) {
    // Thread was deleted, clear the setting
    db.prepare('DELETE FROM settings WHERE key = ?').run(settingKey);
    return null;
  }

  return row.value;
}

/**
 * Set the active thread ID for a project (persists across sessions/devices)
 * @param threadId - Thread ID or null to clear
 * @param project - Project scope (null = global setting)
 */
export function setActiveThreadId(threadId: string | null, project?: string | null): void {
  const now = Date.now();
  const settingKey = project ? `active_thread_id:${project}` : 'active_thread_id';

  if (threadId === null) {
    db.prepare('DELETE FROM settings WHERE key = ?').run(settingKey);
  } else {
    db.prepare(`
      INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    `).run(settingKey, threadId, now);
  }
}
