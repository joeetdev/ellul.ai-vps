/**
 * WebSocket Service
 *
 * Real-time file system updates via WebSocket.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { exec } from 'child_process';
import { ROOT_DIR, DEBOUNCE_MS, IGNORED_PATTERNS } from '../config';
import { safeReadFile, safeStat, safeReadDir } from '../utils';
// UNIFIED AUTH: sovereign-shield handles all tier logic at token issuance
import { getTree, getActiveProject } from './files.service';
import { getPreviewStatus } from './preview.service';

// WebSocket types (ws is external runtime dependency)
interface WsClient {
  readyState: number;
  send(data: string): void;
  close(): void;
  ping(data?: unknown, mask?: boolean, cb?: (err: Error) => void): void;
  on(event: string, listener: (...args: unknown[]) => void): void;
}

interface WsServer {
  on(event: string, listener: (...args: unknown[]) => void): void;
}

// WebSocket.OPEN constant
const WS_OPEN = 1;

// State
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const clients = new Set<WsClient>();
let debounceTimer: NodeJS.Timeout | null = null;
let lastTreeHash = '';
let lastStatusHash = '';
let lastAppsHash = '';
let lastServerStatusHash = '';
let lastPreviewHash = '';

const SERVER_STATUS_FILE = `${os.homedir()}/.ellulai/server-status.json`;

/**
 * Simple hash for change detection.
 */
function simpleHash(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash;
  }
  return hash.toString(36);
}

/**
 * Run shell command and return result.
 */
function run(
  cmd: string,
  cwd: string
): Promise<{ stdout?: string; error?: string; stderr?: string }> {
  return new Promise((resolve) => {
    exec(cmd, { cwd, timeout: 5000 }, (err, stdout, stderr) => {
      if (err) resolve({ error: err.message, stderr });
      else resolve({ stdout: stdout.trim() });
    });
  });
}

/**
 * Broadcast message to all connected clients.
 */
export function broadcast(type: string, data: unknown): void {
  const message = JSON.stringify({ type, data, timestamp: Date.now() });
  for (const client of clients) {
    if (client.readyState === WS_OPEN) {
      client.send(message);
    }
  }
}

/**
 * Broadcast server status if changed.
 */
function broadcastServerStatus(): void {
  try {
    if (!fs.existsSync(SERVER_STATUS_FILE)) return;
    const statusJson = fs.readFileSync(SERVER_STATUS_FILE, 'utf8');
    const statusHash = simpleHash(statusJson);
    if (statusHash !== lastServerStatusHash) {
      lastServerStatusHash = statusHash;
      const status = JSON.parse(statusJson);
      broadcast('server_status', status);
    }
  } catch {
    // Status file might not exist or be mid-write
  }
}

/**
 * Compute current state and broadcast if changed.
 */
async function computeAndBroadcast(): Promise<void> {
  try {
    const activeProject = getActiveProject();
    const projectPath = path.join(ROOT_DIR, activeProject);

    // Tree
    try {
      const tree = getTree(projectPath);
      if (tree && !tree.error) {
        const treeJson = JSON.stringify({ project: activeProject, tree });
        const treeHash = simpleHash(treeJson);
        if (treeHash !== lastTreeHash) {
          lastTreeHash = treeHash;
          broadcast('tree', { project: activeProject, tree });
        }
      }
    } catch (e) {
      const error = e as Error;
      console.error('[file-api] Error computing tree:', error.message);
    }

    // Git status
    try {
      const status = await run('git status --porcelain', projectPath);
      const modified: Array<{ status: string; file: string }> = [];
      if (status.stdout) {
        for (const line of status.stdout.split('\n')) {
          if (line.trim()) {
            const statusCode = line.substring(0, 2);
            const file = line.substring(3);
            modified.push({ status: statusCode.trim() || 'M', file });
          }
        }
      }
      const statusJson = JSON.stringify(modified);
      const statusHash = simpleHash(statusJson);
      if (statusHash !== lastStatusHash) {
        lastStatusHash = statusHash;
        broadcast('status', { project: activeProject, modified });
      }
    } catch (e) {
      const error = e as Error;
      console.error('[file-api] Error computing git status:', error.message);
    }

    // Apps (detect changes)
    try {
      const configPath = path.join(ROOT_DIR, '.ellulai.json');
      const configContent = safeReadFile(configPath);
      const config = configContent
        ? (JSON.parse(configContent) as { hidden?: string[] })
        : { hidden: [] };
      const hiddenApps = new Set(config.hidden || []);
      const entries = safeReadDir(ROOT_DIR);
      const appNames = entries.filter((name) => {
        const stat = safeStat(path.join(ROOT_DIR, name));
        return stat && stat.isDirectory() && !hiddenApps.has(name);
      });
      const appsJson = JSON.stringify(appNames);
      const appsHash = simpleHash(appsJson);
      if (appsHash !== lastAppsHash) {
        lastAppsHash = appsHash;
        broadcast('apps_changed', { hint: 'refetch' });
      }
    } catch (e) {
      const error = e as Error;
      console.error('[file-api] Error computing apps:', error.message);
    }

    // Preview status — broadcast when preview state changes (app starts/stops)
    try {
      const preview = getPreviewStatus();
      const previewJson = JSON.stringify(preview);
      const previewHash = simpleHash(previewJson);
      if (previewHash !== lastPreviewHash) {
        lastPreviewHash = previewHash;
        broadcast('preview_status', preview);
      }
    } catch {}

    // Server status
    broadcastServerStatus();
  } catch (e) {
    const error = e as Error;
    console.error('[file-api] Error in computeAndBroadcast:', error.message);
  }
}

/**
 * Debounced file change handler.
 */
function onFileChange(): void {
  if (debounceTimer) clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    computeAndBroadcast();
  }, DEBOUNCE_MS);
}

/**
 * Check if path should be ignored.
 */
function shouldIgnorePath(filepath: string): boolean {
  return IGNORED_PATTERNS.some(
    (p) => filepath.includes('/' + p + '/') || filepath.endsWith('/' + p)
  );
}

// Watcher state
const watchedDirs = new Set<string>();
const watcherInstances = new Map<string, fs.FSWatcher>();
let serverStatusWatcher: fs.FSWatcher | null = null;

/**
 * Watch a directory for changes.
 */
function watchDir(dir: string): void {
  if (watchedDirs.has(dir) || shouldIgnorePath(dir)) return;

  const stat = safeStat(dir);
  if (!stat || !stat.isDirectory()) return;

  try {
    const watcher = fs.watch(dir, { persistent: true }, (_eventType, filename) => {
      if (filename && !shouldIgnorePath(filename)) {
        onFileChange();
      }
    });

    watcher.on('error', (err) => {
      console.error(`[Watch] Error on ${dir}:`, err.message);
      watchedDirs.delete(dir);
      watcherInstances.delete(dir);
      setTimeout(() => watchDir(dir), 5000);
    });

    watcher.on('close', () => {
      watchedDirs.delete(dir);
      watcherInstances.delete(dir);
    });

    watchedDirs.add(dir);
    watcherInstances.set(dir, watcher);
  } catch (e) {
    const error = e as Error;
    console.error(`[Watch] Failed to watch ${dir}:`, error.message);
  }
}

/**
 * Initialize file watchers.
 */
export function initWatchers(): void {
  const rootStat = safeStat(ROOT_DIR);
  if (!rootStat || !rootStat.isDirectory()) {
    console.error('[Watch] ROOT_DIR does not exist:', ROOT_DIR);
    return;
  }

  watchDir(ROOT_DIR);

  const entries = safeReadDir(ROOT_DIR);
  for (const entry of entries) {
    const subPath = path.join(ROOT_DIR, entry);
    const stat = safeStat(subPath);
    if (stat && stat.isDirectory() && !shouldIgnorePath(entry)) {
      watchDir(subPath);

      // Watch common source directories
      for (const srcDir of ['src', 'app', 'pages', 'components', 'lib', 'packages', 'apps']) {
        const deepPath = path.join(subPath, srcDir);
        const deepStat = safeStat(deepPath);
        if (deepStat && deepStat.isDirectory()) {
          watchDir(deepPath);
        }
      }
    }
  }

  console.log(`[Watch] Watching ${watchedDirs.size} directories`);
}

/**
 * Periodically check preview status and broadcast changes.
 * This detects when the AI agent starts/stops a preview process.
 */
export function initPreviewStatusWatcher(): void {
  setInterval(() => {
    if (clients.size === 0) return; // No clients — skip
    try {
      const preview = getPreviewStatus();
      const previewJson = JSON.stringify(preview);
      const previewHash = simpleHash(previewJson);
      if (previewHash !== lastPreviewHash) {
        lastPreviewHash = previewHash;
        broadcast('preview_status', preview);
      }
    } catch {}
  }, 3000);
}

/**
 * Initialize server status watcher.
 */
export function initServerStatusWatcher(): void {
  const statusDir = path.dirname(SERVER_STATUS_FILE);

  if (serverStatusWatcher) {
    try {
      serverStatusWatcher.close();
    } catch {}
    serverStatusWatcher = null;
  }

  try {
    const stat = safeStat(statusDir);
    if (!stat || !stat.isDirectory()) {
      try {
        fs.mkdirSync(statusDir, { recursive: true });
      } catch {}
    }

    serverStatusWatcher = fs.watch(statusDir, { persistent: true }, (_eventType, filename) => {
      if (filename === 'server-status.json') {
        setTimeout(broadcastServerStatus, 100);
      }
    });

    serverStatusWatcher.on('error', (err) => {
      console.error('[Watch] Server status watcher error:', err.message);
      setTimeout(initServerStatusWatcher, 5000);
    });

    serverStatusWatcher.on('close', () => {
      serverStatusWatcher = null;
    });

    console.log('[Watch] Watching server status file');
  } catch (e) {
    const error = e as Error;
    console.error('[Watch] Failed to watch server status:', error.message);
    setTimeout(initServerStatusWatcher, 5000);
  }
}

/**
 * Polling fallback for file change detection.
 * fs.watch is unreliable on Linux VPS (inotify issues on some virtualized
 * filesystems). This polls the tree when clients are connected to ensure
 * changes are always detected.
 */
const POLL_INTERVAL_MS = 1000;
let pollTimer: NodeJS.Timeout | null = null;

export function startPollingFallback(): void {
  if (pollTimer) return;
  pollTimer = setInterval(() => {
    if (clients.size > 0) {
      computeAndBroadcast();
    }
  }, POLL_INTERVAL_MS);
}

/**
 * Set up WebSocket server on existing HTTP server.
 * Note: ws package is an external runtime dependency, dynamically required.
 */
export function setupWebSocket(server: import('http').Server): WsServer {
  // Dynamic require since ws is external
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { WebSocketServer } = require('ws') as { WebSocketServer: new (opts: { server: unknown; path: string }) => WsServer };
  const wss = new WebSocketServer({ server, path: '/ws' });

  wss.on('error', ((err: Error) => {
    console.error('[WS] Server error:', err.message);
  }) as (...args: unknown[]) => void);

  // Keepalive: ping all clients every 30s to prevent Cloudflare/proxy idle timeout.
  // Cloudflare closes WebSocket connections after ~100s of inactivity.
  const PING_INTERVAL_MS = 30_000;
  const pingInterval = setInterval(() => {
    for (const client of clients) {
      if (client.readyState === WS_OPEN) {
        try {
          client.ping();
        } catch {
          clients.delete(client);
        }
      }
    }
  }, PING_INTERVAL_MS);

  wss.on('connection', ((ws: WsClient, req: { headers?: Record<string, string | string[] | undefined> }) => {
    // UNIFIED AUTH: If client has valid code token, they're authorized
    // Tier enforcement happens at token issuance in sovereign-shield
    clients.add(ws);
    console.log(`[WS] Client connected. Total: ${clients.size}`);

    // Extract code_session from upgrade request cookies for periodic validation
    let codeSessionId: string | null = null;
    try {
      const cookieHeader = req?.headers?.cookie;
      if (typeof cookieHeader === 'string') {
        const match = cookieHeader.match(/(?:^|;\s*)__Host-code_session=([^;]+)/);
        if (match?.[1]) codeSessionId = match[1];
      }
    } catch { /* ignore parse errors */ }

    // Send initial state
    ws.send(JSON.stringify({ type: 'connected', timestamp: Date.now() }));

    // Immediate initial data push
    setTimeout(() => computeAndBroadcast(), 100);

    // Absolute timeout: force re-authentication after 24 hours (matches shield session max)
    const ABSOLUTE_TIMEOUT_MS = 24 * 60 * 60 * 1000;
    const absoluteTimer = setTimeout(() => {
      console.log('[WS] Absolute timeout (24h) — closing connection');
      ws.close();
    }, ABSOLUTE_TIMEOUT_MS);

    // Periodic session validation: verify code_session is still valid every 5 minutes
    // Catches revoked sessions without requiring PoP (different origin, no PoP key)
    const SESSION_CHECK_INTERVAL_MS = 5 * 60 * 1000;
    const sessionCheckInterval = codeSessionId ? setInterval(async () => {
      if (ws.readyState !== WS_OPEN) return;
      try {
        const res = await fetch('http://127.0.0.1:3005/_auth/code/session/validate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ codeSessionId }),
        });
        const data = (await res.json()) as { valid?: boolean };
        if (!data.valid) {
          console.log('[WS] Code session no longer valid — closing connection');
          ws.close();
        }
      } catch {
        // Shield temporarily unavailable — don't close, retry next interval
      }
    }, SESSION_CHECK_INTERVAL_MS) : null;

    // Track liveness via pong responses
    let isAlive = true;
    ws.on('pong', () => { isAlive = true; });

    const aliveCheck = setInterval(() => {
      if (!isAlive) {
        clearInterval(aliveCheck);
        ws.close();
        return;
      }
      isAlive = false;
    }, PING_INTERVAL_MS);

    ws.on('close', () => {
      clearTimeout(absoluteTimer);
      clearInterval(aliveCheck);
      if (sessionCheckInterval) clearInterval(sessionCheckInterval);
      clients.delete(ws);
      console.log(`[WS] Client disconnected. Total: ${clients.size}`);
    });

    ws.on('error', (err: unknown) => {
      const error = err as Error;
      console.error('[WS] Error:', error.message);
      clearInterval(aliveCheck);
      if (sessionCheckInterval) clearInterval(sessionCheckInterval);
      clients.delete(ws);
    });
  }) as (...args: unknown[]) => void);

  console.log('[WS] WebSocket server ready on /ws');

  return wss;
}
