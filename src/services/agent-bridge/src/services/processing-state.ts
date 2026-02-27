/**
 * Processing State Service
 *
 * In-memory buffer for in-progress thread processing state.
 * When AI is processing a command, thinking steps are buffered here
 * so that clients reconnecting mid-processing can catch up.
 *
 * Subscribers receive forwarded thinking_step messages in real-time.
 */

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
 */
export function startProcessing(threadId: string, session: string): void {
  const existing = processingStore.get(threadId);
  const entry: ProcessingEntry = {
    isProcessing: true,
    thinkingSteps: [],
    streamedText: '',
    startedAt: Date.now(),
    session,
    subscribers: existing?.subscribers ?? new Set(),
  };
  processingStore.set(threadId, entry);
  console.log(`[ProcessingState] Started processing for thread ${threadId.substring(0, 8)}...`);
}

/**
 * Buffer a thinking step AND forward to all subscribers.
 */
export function addThinkingStep(threadId: string, step: string): void {
  const entry = processingStore.get(threadId);
  if (!entry || !entry.isProcessing) return;

  entry.thinkingSteps.push(step);

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
 */
export function updateStreamedText(threadId: string, text: string): void {
  const entry = processingStore.get(threadId);
  if (!entry || !entry.isProcessing) return;

  entry.streamedText = text;
}

/**
 * End processing for a thread. Notifies subscribers that processing is done.
 * Includes lastSeq so clients can detect missed messages.
 */
export function endProcessing(threadId: string, lastSeq?: number): void {
  const entry = processingStore.get(threadId);
  if (!entry) return;

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

// Periodic cleanup of stale entries (safety net for crashed processes)
setInterval(() => {
  const now = Date.now();
  for (const [threadId, entry] of processingStore) {
    if (entry.isProcessing && now - entry.startedAt > STALE_TIMEOUT_MS) {
      console.warn(`[ProcessingState] Cleaning up stale entry for thread ${threadId.substring(0, 8)}... (${Math.round((now - entry.startedAt) / 1000)}s old)`);
      processingStore.delete(threadId);
    }
  }
}, 60 * 1000); // Check every minute
