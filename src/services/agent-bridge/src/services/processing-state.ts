/**
 * Processing State Service
 *
 * In-memory buffer for in-progress thread processing state.
 * When AI is processing a command, thinking steps are buffered here
 * so that clients reconnecting mid-processing can catch up.
 *
 * Subscribers receive forwarded thinking_step messages in real-time.
 *
 * Processing Ledger (SQLite):
 * Persists in-flight {thread_id, session, project, prompt} for crash recovery.
 * On startup, the bridge re-dispatches interrupted prompts from the ledger.
 */

import type Database from 'better-sqlite3';

// Database handle for persistent ledger (injected from main.ts)
let processingDb: Database | null = null;

export function setProcessingDb(database: Database): void {
  processingDb = database;
}

// WebSocket interface (minimal, matches both ws and native WebSocket)
interface WsClient {
  readyState: number;
  send(data: string): void;
}

interface ProcessingEntry {
  isProcessing: boolean;
  thinkingSteps: string[];
  streamedText: string;
  startedAt: number;
  session: string;
  subscribers: Set<WsClient>;
}

// Module-level store: threadId -> processing state
const processingStore = new Map<string, ProcessingEntry>();

// Stale entry cleanup interval (safety net)
const STALE_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes

/**
 * Initialize processing state when a command starts.
 * Optionally persists to the processing ledger for crash recovery.
 */
export function startProcessing(threadId: string, session: string, project?: string, prompt?: string): void {
  const existing = processingStore.get(threadId);
  const now = Date.now();

  // If this thread is already actively processing, preserve the original startedAt
  // and accumulated state. This prevents the timer from resetting when auth auto-start
  // or other subsystems call startProcessing on an already-running thread.
  if (existing?.isProcessing) {
    existing.session = session;
    // Still update the ledger with the new prompt if provided
    if (processingDb && prompt) {
      try {
        processingDb.prepare(
          'INSERT OR REPLACE INTO processing_ledger (thread_id, session, project, prompt, started_at, pid) VALUES (?, ?, ?, ?, ?, ?)'
        ).run(threadId, session, project ?? null, prompt, existing.startedAt, process.pid);
      } catch {}
    }
    return;
  }

  const entry: ProcessingEntry = {
    isProcessing: true,
    thinkingSteps: [],
    streamedText: '',
    startedAt: now,
    session,
    subscribers: existing?.subscribers ?? new Set(),
  };
  processingStore.set(threadId, entry);

  // Persist to ledger for crash recovery
  if (processingDb && prompt) {
    try {
      processingDb.prepare(
        'INSERT OR REPLACE INTO processing_ledger (thread_id, session, project, prompt, started_at, pid) VALUES (?, ?, ?, ?, ?, ?)'
      ).run(threadId, session, project ?? null, prompt, now, process.pid);
    } catch {}
  }

  console.log(`[ProcessingState] Started processing for thread ${threadId.substring(0, 8)}...`);
}

// Batch thinking step persistence — flush to SQLite at most every 2s to avoid
// write amplification while still surviving mid-stream crashes.
const THINKING_FLUSH_INTERVAL_MS = 2000;
const dirtyThinkingThreads = new Set<string>();

function flushThinkingSteps(): void {
  if (!processingDb || dirtyThinkingThreads.size === 0) return;
  for (const threadId of dirtyThinkingThreads) {
    const entry = processingStore.get(threadId);
    if (!entry || !entry.isProcessing) continue;
    try {
      processingDb.prepare(
        'UPDATE processing_ledger SET thinking_steps = ?, streamed_text = ? WHERE thread_id = ?'
      ).run(JSON.stringify(entry.thinkingSteps), entry.streamedText, threadId);
    } catch {}
  }
  dirtyThinkingThreads.clear();
}

const thinkingFlushTimer = setInterval(flushThinkingSteps, THINKING_FLUSH_INTERVAL_MS);
// Don't keep process alive just for this timer
if (thinkingFlushTimer.unref) thinkingFlushTimer.unref();

/**
 * Buffer a thinking step AND forward to all subscribers.
 * Marks the thread as dirty for batched persistence to the processing ledger.
 */
export function addThinkingStep(threadId: string, step: string): void {
  const entry = processingStore.get(threadId);
  if (!entry || !entry.isProcessing) return;

  entry.thinkingSteps.push(step);
  dirtyThinkingThreads.add(threadId);

  // Forward to all subscribers
  const message = JSON.stringify({
    type: 'thinking_step',
    content: step,
    threadId,
    timestamp: Date.now(),
  });

  for (const ws of entry.subscribers) {
    try {
      if (ws.readyState === 1) { // OPEN
        ws.send(message);
      }
    } catch {
      // Connection might be closing, will be cleaned up
    }
  }
}

/**
 * Broadcast an arbitrary JSON message to all subscribers of a thread.
 * Used for final output/ack delivery to all connected clients (not just the original sender).
 */
export function broadcastToSubscribers(threadId: string, msg: Record<string, unknown>): void {
  const entry = processingStore.get(threadId);
  if (!entry) return;

  const message = JSON.stringify(msg);
  for (const ws of entry.subscribers) {
    try {
      if (ws.readyState === 1) { // OPEN
        ws.send(message);
      }
    } catch {
      // Connection might be closing
    }
  }
}

/**
 * Update accumulated streamed text and broadcast output to all subscribers.
 * Ensures reconnecting clients see in-progress streamed content.
 * Marks thread as dirty for batched ledger persistence.
 */
export function updateStreamedText(threadId: string, text: string): void {
  const entry = processingStore.get(threadId);
  if (!entry || !entry.isProcessing) return;

  entry.streamedText = text;
  dirtyThinkingThreads.add(threadId);
}

/**
 * End processing for a thread. Notifies subscribers that processing is done.
 * Includes lastSeq so clients can detect missed messages.
 */
export function endProcessing(threadId: string, lastSeq?: number): void {
  const entry = processingStore.get(threadId);
  if (!entry) return;

  // Flush any pending thinking steps before removing from ledger
  dirtyThinkingThreads.delete(threadId);
  // Remove from persistent ledger (crash recovery no longer needed for this request)
  if (processingDb) {
    try { processingDb.prepare('DELETE FROM processing_ledger WHERE thread_id = ?').run(threadId); } catch {}
  }

  // Notify subscribers that processing ended (with lastSeq for gap detection)
  const message = JSON.stringify({
    type: 'processing_done',
    threadId,
    lastSeq: lastSeq ?? null,
    timestamp: Date.now(),
  });

  for (const ws of entry.subscribers) {
    try {
      if (ws.readyState === 1) {
        ws.send(message);
      }
    } catch {
      // Ignore send errors
    }
  }

  // Clean up the entry (keep subscribers in case of rapid re-processing)
  processingStore.delete(threadId);
  console.log(`[ProcessingState] Ended processing for thread ${threadId.substring(0, 8)}...`);
}

/**
 * Get current processing state for a thread (used by get_thread handler).
 * Returns null if thread is not currently processing.
 */
export function getProcessingState(threadId: string): {
  isProcessing: boolean;
  thinkingSteps: string[];
  streamedText: string;
  session: string;
  startedAt: number;
} | null {
  const entry = processingStore.get(threadId);
  if (!entry || !entry.isProcessing) return null;

  return {
    isProcessing: entry.isProcessing,
    thinkingSteps: [...entry.thinkingSteps],
    streamedText: entry.streamedText,
    session: entry.session,
    startedAt: entry.startedAt,
  };
}

/**
 * Subscribe a WebSocket connection to receive thinking_step forwards for a thread.
 */
export function subscribe(threadId: string, ws: WsClient): void {
  let entry = processingStore.get(threadId);
  if (!entry) {
    // Create a placeholder entry just for the subscriber set
    entry = {
      isProcessing: false,
      thinkingSteps: [],
      streamedText: '',
      startedAt: 0,
      session: '',
      subscribers: new Set(),
    };
    processingStore.set(threadId, entry);
  }
  entry.subscribers.add(ws);
}

/**
 * Unsubscribe a WebSocket from a specific thread.
 */
export function unsubscribe(threadId: string, ws: WsClient): void {
  const entry = processingStore.get(threadId);
  if (!entry) return;
  entry.subscribers.delete(ws);

  // Clean up empty non-processing entries
  if (!entry.isProcessing && entry.subscribers.size === 0) {
    processingStore.delete(threadId);
  }
}

/**
 * Remove a WebSocket from all thread subscriptions (called on ws close).
 */
export function unsubscribeAll(ws: WsClient): void {
  for (const [threadId, entry] of processingStore) {
    entry.subscribers.delete(ws);
    // Clean up empty non-processing entries
    if (!entry.isProcessing && entry.subscribers.size === 0) {
      processingStore.delete(threadId);
    }
  }
}

/**
 * Get thread IDs that are currently being processed (in-memory).
 * Used by graceful shutdown to add interruption messages.
 */
export function getActiveProcessingThreadIds(): string[] {
  const ids: string[] = [];
  for (const [threadId, entry] of processingStore) {
    if (entry.isProcessing) ids.push(threadId);
  }
  return ids;
}

// Periodic cleanup of stale entries (safety net for crashed processes)
setInterval(() => {
  const now = Date.now();
  for (const [threadId, entry] of processingStore) {
    if (entry.isProcessing && now - entry.startedAt > STALE_TIMEOUT_MS) {
      console.warn(`[ProcessingState] Cleaning up stale entry for thread ${threadId.substring(0, 8)}... (${Math.round((now - entry.startedAt) / 1000)}s old)`);
      processingStore.delete(threadId);
      // Also clean ledger
      if (processingDb) {
        try { processingDb.prepare('DELETE FROM processing_ledger WHERE thread_id = ?').run(threadId); } catch {}
      }
    }
  }
}, 60 * 1000); // Check every minute
