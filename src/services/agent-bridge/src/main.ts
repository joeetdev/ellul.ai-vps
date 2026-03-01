/**
 * Agent Bridge Main Entry Point
 *
 * WebSocket bridge for Vibe Mode chat UI running on port 7700.
 * Provides multi-session AI CLI routing with context injection.
 *
 * Sessions: opencode, claude, codex, gemini
 *
 * Message Types:
 * - switch_session   - Switch between AI sessions
 * - set_project      - Set active project for context
 * - get_providers    - Get available AI providers
 * - set_api_key      - Set provider API key
 * - set_model        - Set AI model
 * - get_current_model - Get current model
 * - get_cli_keys     - Get CLI environment keys
 * - set_cli_key      - Set a CLI key
 * - remove_cli_key   - Remove a CLI key
 * - cli_auth         - Start interactive CLI auth
 * - cli_response     - Respond to interactive CLI prompt
 * - command          - Send command to current session
 * - ping             - Keep-alive
 *
 * Thread Management (persistent chat):
 * - create_thread    - Create new chat thread
 * - list_threads     - List all threads
 * - get_thread       - Get thread with messages
 * - delete_thread    - Delete a thread
 * - set_thread       - Set active thread
 * - rename_thread    - Rename a thread
 * - add_message      - Add message to thread
 */

import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import {
  PORT,
  PROJECTS_DIR,
  DEFAULT_SESSION,
  VALID_SESSIONS,
  CONTEXT_CACHE_MS,
  type SessionType,
} from './config';
import { startZenModelRefresh, getZenModelList } from './services/zen-models.service';
import { validateAgentToken, extractAgentToken, verifyPopChallenge } from './auth';
import * as crypto from 'crypto';
import {
  loadCliEnv,
  saveCliKey,
  removeCliKey,
  CLI_KEY_MAP,
} from './services/cli-env.service';
import {
  loadGlobalContext,
  loadProjectContext,
  buildClawSystemPrompt,
  getActiveProject,
} from './services/context.service';
import { sendToOpenClaw, closeOpenClawConnection, type OpenClawChunk } from './services/openclaw-client.service';
import { ensureProjectAgent, refreshProjectContext } from './services/openclaw-agent.service';
import {
  getProviders,
  setApiKey,
  setModel,
  getCurrentModel,
  ensureOpencodeServer,
  sendToOpencodeStreaming,
  sendToClaudeStreaming,
  sendToCodexStreaming,
  sendToGeminiStreaming,
  hasPendingQuestion,
  respondToPendingQuestion,
  abortThreadCommand,
  type CliResponse,
} from './services/cli-streaming.service';
import {
  checkCliNeedsSetup,
  startInteractiveCli,
  respondToInteractiveCli,
  killInteractiveSession,
  startCliAuthInChat,
  hasCliAuthInChat,
  hasCliAuthForThread,
  getCliAuthThreadId,
  respondToCliAuthInChat,
  cancelCliAuthInChat,
  detachCliAuth,
  reattachCliAuth,
} from './services/interactive.service';

// Display labels for session model names (used in welcome messages and get_current_model)
const SESSION_MODEL_LABELS: Record<string, string> = {
  claude: 'Claude Code',
  codex: 'Codex',
  gemini: 'Gemini',
  opencode: 'OpenCode',
  main: 'OpenCode',
  claw: 'Claw',
};

// Processing state for in-progress thread operations (thinking step buffer)
import {
  startProcessing,
  endProcessing,
  addThinkingStep,
  getProcessingState,
  broadcastToSubscribers,
  updateStreamedText,
  subscribe as subscribeProcessing,
  unsubscribe as unsubscribeProcessing,
  unsubscribeAll as unsubscribeAllProcessing,
  setProcessingDb,
  getActiveProcessingThreadIds,
} from './services/processing-state';

// Initialize chat database (must import before thread service)
import { db } from './database';

// Inject database into processing state for persistent ledger
setProcessingDb(db);

import {
  createThread,
  listThreads,
  getThread,
  getThreadWithMessages,
  deleteThread,
  deleteThreadsByProject,
  renameThread,
  updateThreadModel,
  updateThreadSession,
  clearThreadOpencodeSession,
  addMessage,
  getMessagesSince,
  getLastSeq,
  getActiveThreadId,
  setActiveThreadId,
  type Message,
} from './services/thread.service';

// WebSocket types
interface WsClient {
  readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  on(event: string, listener: (...args: unknown[]) => void): void;
}

interface WsServer {
  on(event: string, listener: (...args: unknown[]) => void): void;
  close(): void;
}

// Connection state per WebSocket
interface ConnectionState {
  currentSession: SessionType;
  currentProject: string | null;
  currentThreadId: string | null;
}

// In-flight request tracking for graceful shutdown drain
const inflightRequests = new Set<Promise<void>>();

/**
 * Try to send a JSON message over WebSocket. Silently swallows errors
 * (e.g. connection already closed by Chrome tab suspension).
 */
function trySend(ws: WsClient, msg: Record<string, unknown>): void {
  try {
    if (ws.readyState === 1) ws.send(JSON.stringify(msg));
  } catch {}
}

/**
 * Send a message to all subscribers of a thread (broadcast), falling back
 * to direct send if no threadId. This ensures final output/ack reaches
 * all connected clients — not just the original (possibly dead) ws.
 */
function sendToThread(ws: WsClient, threadId: string | null, msg: Record<string, unknown>): void {
  if (threadId) {
    broadcastToSubscribers(threadId, msg);
  } else {
    trySend(ws, msg);
  }
}

// ---------------------------------------------------------------------------
// Preview Health Gate — polls file-api for preview readiness
// ---------------------------------------------------------------------------

import { execSync } from 'child_process';
import { PREVIEW_PORT_MIN, PREVIEW_PORT_MAX } from '../../shared/constants';
import {
  FILE_API_PORT,
  HEALTH_GATE_TOTAL_MS,
  HEALTH_GATE_INITIAL_DELAY_MS,
  HEALTH_GATE_MAX_INTERVAL_MS,
  HEALTH_GATE_BACKOFF_FACTOR,
} from './config';

const bridgeSleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms));

/**
 * Check if a project is a previewable web app (has ellulai.json with previewable: true,
 * or has package.json with a dev script).
 */
function isPreviewableProject(project: string | null): boolean {
  if (!project) return false;
  const projectPath = path.join(PROJECTS_DIR, project);
  // Check ellulai.json
  try {
    const meta = JSON.parse(fs.readFileSync(path.join(projectPath, 'ellulai.json'), 'utf8'));
    if (meta.previewable === true || meta.type === 'frontend') return true;
  } catch {}
  // Check package.json for dev scripts
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(projectPath, 'package.json'), 'utf8'));
    const scripts = pkg.scripts || {};
    if (scripts.dev || scripts.start) return true;
  } catch {}
  return false;
}

/** Result from file-api /api/preview/health */
interface PreviewHealthResponse {
  app: string | null;
  phase: 'idle' | 'installing' | 'starting' | 'ready' | 'error' | 'crashed';
  active: boolean;
  port: number;
  error?: string;
  logTail?: string;
  healAttempts?: number;
  healStatus?: 'healing' | 'exhausted' | null;
}

/** Outcome of the preview health polling loop */
interface PreviewPollOutcome {
  passed: boolean;
  needsCodeFix: boolean;
  error?: string;
  phase?: string;
}

// Patterns that indicate code errors (fixable by the agent)
const CODE_ERROR_PATTERNS = [
  /SyntaxError/i,
  /Module not found/i,
  /Cannot resolve/i,
  /Cannot find module/i,
  /TypeError.*is not/i,
  /ReferenceError/i,
  /Unexpected token/i,
  /Cannot read propert/i,
  /is not defined/i,
  /ModuleBuildError/i,
];

// Patterns that indicate infrastructure errors (auto-recoverable by daemon)
const INFRA_ERROR_PATTERNS = [
  /EADDRINUSE/i,
  /text\/jsx/i,
  /text\/tsx/i,
  /missing.*plugin/i,
  /MIME type/i,
];

/**
 * Fetch preview health from file-api (non-blocking HTTP GET).
 */
async function fetchPreviewHealth(project?: string | null): Promise<PreviewHealthResponse | null> {
  try {
    const qs = project ? `?project=${encodeURIComponent(project)}` : '';
    const url = `http://localhost:${FILE_API_PORT}/api/preview/health${qs}`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(3000) });
    if (!resp.ok) return null;
    return await resp.json() as PreviewHealthResponse;
  } catch {
    return null;
  }
}

/**
 * Poll file-api for preview health with exponential backoff.
 * Returns whether the preview is ready, and if not, whether the agent can fix it.
 */
async function pollPreviewHealth(project: string | null): Promise<PreviewPollOutcome> {
  const start = Date.now();
  let interval = HEALTH_GATE_INITIAL_DELAY_MS;

  while (Date.now() - start < HEALTH_GATE_TOTAL_MS) {
    await bridgeSleep(interval);
    interval = Math.min(interval * HEALTH_GATE_BACKOFF_FACTOR, HEALTH_GATE_MAX_INTERVAL_MS);

    const health = await fetchPreviewHealth(project);
    if (!health) continue; // file-api not responding, keep trying

    if (health.phase === 'ready') {
      return { passed: true, needsCodeFix: false };
    }

    if (health.phase === 'installing' || health.phase === 'starting') {
      continue; // still booting, keep waiting
    }

    if (health.phase === 'idle') {
      // No preview active — treat as passed (nothing to gate on)
      return { passed: true, needsCodeFix: false };
    }

    // error or crashed — classify the error
    const errorText = (health.error || '') + '\n' + (health.logTail || '');

    const isInfra = INFRA_ERROR_PATTERNS.some(p => p.test(errorText));
    if (isInfra) {
      // Wait 5s for daemon auto-fix, then re-check once
      await bridgeSleep(5000);
      const recheck = await fetchPreviewHealth(project);
      if (recheck?.phase === 'ready') {
        return { passed: true, needsCodeFix: false };
      }
      return { passed: false, needsCodeFix: false, error: health.error, phase: health.phase };
    }

    const isCodeError = CODE_ERROR_PATTERNS.some(p => p.test(errorText));
    if (isCodeError) {
      return { passed: false, needsCodeFix: true, error: health.error, phase: health.phase };
    }

    // Unknown error — wait for daemon to try fixing
    await bridgeSleep(5000);
    const recheck = await fetchPreviewHealth(project);
    if (recheck?.phase === 'ready') {
      return { passed: true, needsCodeFix: false };
    }
    return { passed: false, needsCodeFix: true, error: health.error, phase: health.phase };
  }

  // Timeout while still installing/starting — treat as passed (don't retry CLI for timing)
  return { passed: true, needsCodeFix: false };
}

// ---------------------------------------------------------------------------
// Deployment Health Gate — ensures deployed apps actually work
// ---------------------------------------------------------------------------

const APPS_DIR = path.join(path.dirname(PROJECTS_DIR), '.ellulai', 'apps');

interface DeploymentHealthResult {
  healthy: boolean;
  appName: string;
  port: number;
  httpStatus?: number;
  error?: string;
}

/**
 * Check if any recently deployed apps are broken.
 * Scans ~/.ellulai/apps/ for app metadata, checks each app's port.
 * Returns the first broken deployment found, or null if all healthy.
 */
function checkDeploymentHealth(): DeploymentHealthResult | null {
  try {
    if (!fs.existsSync(APPS_DIR)) return null;
    const files = fs.readdirSync(APPS_DIR).filter(f => f.endsWith('.json'));
    if (files.length === 0) return null;

    // Check all deployed apps — find the first broken one
    for (const file of files) {
      try {
        const meta = JSON.parse(fs.readFileSync(path.join(APPS_DIR, file), 'utf8'));
        if (!meta.port || !meta.name) continue;
        // Skip preview ports — handled by preview health gate
        if (meta.port >= PREVIEW_PORT_MIN && meta.port <= PREVIEW_PORT_MAX) continue;

        const statusOut = execSync(
          `curl -s -o /dev/null -w '%{http_code}' -m 3 http://localhost:${meta.port}/`,
          { encoding: 'utf8', timeout: 5000 }
        ).trim();
        const httpStatus = parseInt(statusOut, 10);

        if (isNaN(httpStatus) || httpStatus >= 500) {
          let error = `Deployed app "${meta.name}" returned HTTP ${httpStatus || 'no response'} on port ${meta.port}`;
          // Extract error from pm2 logs
          try {
            const logs = execSync(`pm2 logs ${JSON.stringify(meta.name)} --nostream --lines 30 2>&1`, {
              encoding: 'utf8', timeout: 5000,
            });
            const errorLines = logs.split('\n').filter(l =>
              /error|Error|ERR|SyntaxError|TypeError|Cannot find|Module not found/i.test(l)
            );
            if (errorLines.length > 0) {
              error += '\n\npm2 logs:\n' + errorLines.slice(0, 10).join('\n');
            }
          } catch {}
          return { healthy: false, appName: meta.name, port: meta.port, httpStatus, error };
        }
      } catch {}
    }
  } catch {}
  return null; // All healthy or no deployments
}

/**
 * Check if any deployment happened by looking for recently modified app metadata.
 * Returns true if an app was deployed in the last 2 minutes.
 */
function hasRecentDeployment(): boolean {
  try {
    if (!fs.existsSync(APPS_DIR)) return false;
    const files = fs.readdirSync(APPS_DIR).filter(f => f.endsWith('.json'));
    const twoMinutesAgo = Date.now() - 120000;
    for (const file of files) {
      try {
        const stat = fs.statSync(path.join(APPS_DIR, file));
        if (stat.mtimeMs > twoMinutesAgo) return true;
      } catch {}
    }
  } catch {}
  return false;
}

// Context cache
let cachedGlobalContext = '';
let globalContextLastRead = 0;

/**
 * Refresh global context if stale.
 */
function refreshGlobalContext(): string {
  const now = Date.now();
  if (now - globalContextLastRead > CONTEXT_CACHE_MS) {
    cachedGlobalContext = loadGlobalContext();
    globalContextLastRead = now;
  }
  return cachedGlobalContext;
}

/**
 * Get welcome message for a session (connection-level, shown on session switch).
 */
function getWelcomeMessage(session: SessionType): string {
  const model = SESSION_MODEL_LABELS[session] || 'AI';
  return `${model} ready.`;
}

// Create HTTP server with health endpoint
const httpServer = http.createServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://localhost`);

  // Health check
  if (url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        status: 'ok',
        defaultSession: DEFAULT_SESSION,
        validSessions: VALID_SESSIONS,
        activeProject: getActiveProject(),
        contextLoaded: !!refreshGlobalContext(),
      })
    );
    return;
  }

  // POST /api/cleanup-project - Delete all threads for a project (called by file-api on app delete)
  if (req.method === 'POST' && url.pathname === '/api/cleanup-project') {
    let body = '';
    req.on('data', (chunk: Buffer) => (body += chunk.toString()));
    req.on('end', () => {
      try {
        const { project } = JSON.parse(body) as { project?: string };
        if (!project) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: 'Missing project' }));
          return;
        }
        const deleted = deleteThreadsByProject(project);
        console.log(`[Bridge] Cleaned up ${deleted} threads for project "${project}"`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, deleted }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: (err as Error).message }));
      }
    });
    return;
  }

  // POST /api/internal/preview-error - Self-healing: inject build error into agent thread
  // Localhost-only — called by file-api's preview.service.ts when a dev server fails
  if (req.method === 'POST' && url.pathname === '/api/internal/preview-error') {
    // Reject non-localhost requests
    const remoteAddr = req.socket.remoteAddress;
    if (remoteAddr !== '127.0.0.1' && remoteAddr !== '::1' && remoteAddr !== '::ffff:127.0.0.1') {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, reason: 'Localhost only' }));
      return;
    }

    let body = '';
    req.on('data', (chunk: Buffer) => (body += chunk.toString()));
    req.on('end', () => {
      try {
        const { projectName, error, logTail } = JSON.parse(body) as {
          projectName?: string;
          threadId?: string;
          error?: string;
          logTail?: string;
        };

        if (!projectName || !error) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, reason: 'Missing projectName or error' }));
          return;
        }

        // Find the latest thread for this project
        const threads = listThreads(projectName);
        if (threads.length === 0) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, reason: 'No active thread for project' }));
          return;
        }

        // Use the most recent thread
        const targetThread = threads[0]!;

        // Inject a system message with the build error
        const logSection = logTail ? `\n\nRelevant logs:\n${logTail.slice(-2048)}` : '';
        const message = addMessage(targetThread.id, {
          type: 'system',
          content: `[Preview Build Error]\nThe dev server for this project failed to start. Here is the error output:\n\n${error}${logSection}\n\nPlease fix the code issue causing this build failure. After fixing, the dev server will automatically restart.`,
          session: 'system',
          model: null,
          thinking: null,
          metadata: { source: 'preview-self-heal' },
        });

        console.log(`[Bridge] Preview error injected into thread ${targetThread.id.substring(0, 8)} for project "${projectName}"`);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, messageId: message.id, threadId: targetThread.id }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, reason: (err as Error).message }));
      }
    });
    return;
  }

  // Not found
  res.writeHead(404);
  res.end();
});

// Set up WebSocket server with unified auth
// Token validation is the ONLY check - sovereign-shield handles all tier logic at token issuance
const WebSocketModule = require('ws');
const wss: WsServer = new WebSocketModule.WebSocketServer({
  server: httpServer,
  // 1 MB max payload — prevents OOM from oversized messages.
  // Chat messages are typically <100KB; anything larger is malformed or malicious.
  maxPayload: 1 * 1024 * 1024,
  verifyClient: async (
    info: { req: { url?: string; _shieldSessionId?: string } },
    cb: (result: boolean, code?: number, message?: string) => void
  ) => {
    // UNIFIED AUTH: Valid token = authorized (sovereign-shield enforced tier at issuance)
    const agentToken = extractAgentToken(info.req.url);
    if (!agentToken) {
      console.log('[Bridge] No agent token provided');
      cb(false, 401, 'Agent token required');
      return;
    }
    const result = await validateAgentToken(agentToken);
    if (!result.valid) {
      console.log('[Bridge] Agent token validation failed');
      cb(false, 401, 'Invalid agent token');
      return;
    }
    // Store sessionId on request for PoP challenge-response
    if (result.sessionId) {
      info.req._shieldSessionId = result.sessionId;
    }
    console.log('[Bridge] Agent token validated');
    cb(true);
  },
});

// Extract project from URL parameters
function extractProjectFromUrl(url?: string): string | null {
  if (!url) return null;
  try {
    const urlObj = new URL(url, 'http://localhost');
    const project = urlObj.searchParams.get('_project');
    return project || null;
  } catch {
    return null;
  }
}

wss.on('connection', ((ws: WsClient, req: { url?: string; _shieldSessionId?: string }) => {
  console.log('[Bridge] Connection URL:', req?.url);

  // Extract project from URL for per-connection state
  const urlProject = extractProjectFromUrl(req?.url);
  console.log('[Bridge] Extracted project from URL:', urlProject);

  // Shield session ID for PoP challenge-response
  const shieldSessionId = req?._shieldSessionId || null;

  // Per-connection state (project is scoped to this connection, not shared globally)
  const state: ConnectionState = {
    currentSession: DEFAULT_SESSION as SessionType,
    currentProject: urlProject,
    currentThreadId: null,
  };

  console.log('[Bridge] New connection (authenticated), project:', state.currentProject);

  // Absolute timeout: force re-authentication after 24 hours (matches shield session max)
  const ABSOLUTE_TIMEOUT_MS = 24 * 60 * 60 * 1000;
  const absoluteTimer = setTimeout(() => {
    console.log('[Bridge] Absolute timeout (24h) — closing connection');
    ws.close(4004, 'Session expired');
  }, ABSOLUTE_TIMEOUT_MS);

  // PoP challenge-response: verify session liveness every 5 minutes
  // Mirrors SSH's per-packet authentication — server challenges, client proves key possession
  let popFailCount = 0;
  let pendingChallenge: string | null = null;
  let challengeTimer: ReturnType<typeof setTimeout> | null = null;
  const POP_CHALLENGE_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
  const POP_RESPONSE_TIMEOUT_MS = 30 * 1000; // 30 seconds to respond
  const POP_MAX_FAILURES = 2;

  function sendPopChallenge() {
    if (!shieldSessionId || ws.readyState !== 1) return;
    pendingChallenge = crypto.randomBytes(32).toString('base64');
    try {
      ws.send('POP_CHALLENGE:' + pendingChallenge);
    } catch {
      return; // Connection closing
    }
    // Timeout if no response within 30s
    challengeTimer = setTimeout(() => {
      popFailCount++;
      console.log(`[Bridge] PoP challenge timeout (failures: ${popFailCount}/${POP_MAX_FAILURES})`);
      pendingChallenge = null;
      if (popFailCount >= POP_MAX_FAILURES) {
        console.log('[Bridge] PoP max failures — closing connection');
        ws.close(4003, 'PoP challenge failed');
      }
    }, POP_RESPONSE_TIMEOUT_MS);
  }

  const popInterval = shieldSessionId
    ? setInterval(sendPopChallenge, POP_CHALLENGE_INTERVAL_MS)
    : null;

  // Heartbeat to keep connection alive through Cloudflare (100s timeout)
  // Send ping every 30 seconds
  const heartbeatInterval = setInterval(() => {
    if (ws.readyState === 1) { // OPEN
      try {
        ws.send(JSON.stringify({ type: 'heartbeat', timestamp: Date.now() }));
      } catch {
        // Connection might be closing
      }
    }
  }, 30000);

  // Send initial session_switched message
  ws.send(
    JSON.stringify({
      type: 'session_switched',
      session: state.currentSession,
      content: getWelcomeMessage(state.currentSession as SessionType),
      timestamp: Date.now(),
    })
  );

  ws.on('message', (async (data: Buffer | string) => {
    const raw = data.toString();

    // Intercept PoP challenge responses (raw text, not JSON)
    if (raw.startsWith('POP_RESPONSE:') && pendingChallenge) {
      const signature = raw.slice('POP_RESPONSE:'.length);
      if (challengeTimer) {
        clearTimeout(challengeTimer);
        challengeTimer = null;
      }
      const challenge = pendingChallenge;
      pendingChallenge = null;

      if (shieldSessionId) {
        const valid = await verifyPopChallenge(shieldSessionId, challenge, signature);
        if (valid) {
          popFailCount = 0; // Reset on success
        } else {
          popFailCount++;
          console.log(`[Bridge] PoP challenge failed (failures: ${popFailCount}/${POP_MAX_FAILURES})`);
          if (popFailCount >= POP_MAX_FAILURES) {
            console.log('[Bridge] PoP max failures — closing connection');
            ws.close(4003, 'PoP challenge failed');
          }
        }
      }
      return;
    }

    try {
      const msg = JSON.parse(raw) as Record<string, unknown>;
      const msgType = msg.type as string;

      // ============ Session Management ============
      if (msgType === 'switch_session' && VALID_SESSIONS.includes(msg.session as SessionType)) {
        const prevSession = state.currentSession;
        let requestedSession = msg.session as SessionType;

        // When switching session within an active thread, update the thread's stored session
        // so the skin stays correct on reconnect / tab switch.
        if (state.currentThreadId) {
          updateThreadSession(state.currentThreadId, requestedSession);
        }

        state.currentSession = requestedSession;

        ws.send(
          JSON.stringify({
            type: 'session_switched',
            session: state.currentSession,
            content: getWelcomeMessage(state.currentSession),
            timestamp: Date.now(),
          })
        );

        // Cancel auth only when actually changing sessions.
        // When selecting a thread, set_thread fires first (starts auth), then
        // the frontend sends switch_session with the same session (from useEffect).
        // Canceling unconditionally would kill the auth that set_thread just started.
        if (prevSession !== state.currentSession) {
          cancelCliAuthInChat(ws);
        }
        return;
      }

      // ============ Project Management ============
      if (msgType === 'set_project') {
        const newProject = (msg.project as string) || null;
        const oldProject = state.currentProject;
        state.currentProject = newProject;

        if (newProject !== oldProject) {
          console.log('[Bridge] Project changed from', oldProject, 'to', newProject);

          // Ensure CLI context files exist for the project (CLAUDE.md, AGENTS.md, GEMINI.md).
          // These are read by OpenCode, Claude, Gemini etc. for platform context.
          if (newProject) {
            const projectDir = path.join(PROJECTS_DIR, newProject);
            const claudeMdPath = path.join(projectDir, 'CLAUDE.md');
            if (!fs.existsSync(claudeMdPath)) {
              refreshProjectContext(projectDir);
            }
          }
        }
        ws.send(
          JSON.stringify({
            type: 'project_set',
            project: newProject,
            success: true,
            timestamp: Date.now(),
          })
        );

        // Auto-send threads list when project changes (so frontend doesn't need to request it)
        const threads = listThreads(state.currentProject);
        const activeThreadId = getActiveThreadId(state.currentProject);
        console.log(`[Bridge] Auto-sending ${threads.length} threads for project ${state.currentProject}`);
        ws.send(JSON.stringify({ type: 'threads_list', threads, activeThreadId, timestamp: Date.now() }));
        return;
      }

      // ============ Provider/Model Management ============
      if (msgType === 'get_providers') {
        try {
          const result = await getProviders();
          ws.send(
            JSON.stringify({
              type: 'providers',
              providers: result.providers,
              connected: result.connected,
              currentModel: result.currentModel,
              zenModels: result.zenModels,
              timestamp: Date.now(),
            })
          );
        } catch (err) {
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to get providers: ' + (err as Error).message, timestamp: Date.now() }));
        }
        return;
      }

      if (msgType === 'set_api_key' && msg.provider && msg.key) {
        try {
          const success = await setApiKey(msg.provider as string, msg.key as string);
          // Persist to env file so key survives VPS restarts
          const envVar = CLI_KEY_MAP[msg.provider as string];
          if (envVar) {
            saveCliKey(envVar, msg.key as string);
          }
          ws.send(
            JSON.stringify({
              type: 'api_key_set',
              provider: msg.provider,
              success,
              timestamp: Date.now(),
            })
          );
        } catch (err) {
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to set API key: ' + (err as Error).message, timestamp: Date.now() }));
        }
        return;
      }

      if (msgType === 'set_model' && msg.model) {
        try {
          const success = await setModel(msg.model as string);
          // Update thread's last model and clear its OpenCode session.
          // OpenCode locks model per-session, so we must force a new session
          // for the thread to pick up the new model.
          if (state.currentThreadId && success) {
            updateThreadModel(state.currentThreadId, msg.model as string);
            clearThreadOpencodeSession(state.currentThreadId);
          }
          ws.send(
            JSON.stringify({
              type: 'model_set',
              model: msg.model,
              success,
              timestamp: Date.now(),
            })
          );
        } catch (err) {
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to set model: ' + (err as Error).message, timestamp: Date.now() }));
        }
        return;
      }

      if (msgType === 'get_current_model') {
        try {
          const model = await getCurrentModel();
          ws.send(JSON.stringify({ type: 'current_model', model, timestamp: Date.now() }));
        } catch {
          ws.send(JSON.stringify({ type: 'current_model', model: null, timestamp: Date.now() }));
        }
        return;
      }

      // ============ CLI API Key Management ============
      if (msgType === 'get_cli_keys') {
        const env = loadCliEnv();
        const keys: Record<string, { set: boolean; masked?: string }> = {};
        for (const [provider, varName] of Object.entries(CLI_KEY_MAP)) {
          const value = env[varName];
          keys[provider] = value
            ? { set: true, masked: '***' + (value.slice(-4) || '') }
            : { set: false };
        }
        ws.send(JSON.stringify({ type: 'cli_keys', keys, timestamp: Date.now() }));
        return;
      }

      if (msgType === 'set_cli_key' && msg.provider && msg.key) {
        const varName = CLI_KEY_MAP[msg.provider as string];
        if (!varName) {
          ws.send(JSON.stringify({ type: 'error', message: 'Unknown provider: ' + msg.provider, timestamp: Date.now() }));
        } else {
          saveCliKey(varName, msg.key as string);
          ws.send(JSON.stringify({ type: 'cli_key_set', provider: msg.provider, success: true, timestamp: Date.now() }));
        }
        return;
      }

      if (msgType === 'remove_cli_key' && msg.provider) {
        const varName = CLI_KEY_MAP[msg.provider as string];
        if (varName) {
          removeCliKey(varName);
          ws.send(JSON.stringify({ type: 'cli_key_removed', provider: msg.provider, success: true, timestamp: Date.now() }));
        }
        return;
      }

      // ============ Interactive CLI Auth ============
      if (msgType === 'cli_auth' && msg.session) {
        startInteractiveCli(msg.session as string, ws, msg.command as string | undefined, state.currentThreadId);
        return;
      }

      if (msgType === 'cli_response' && msg.value !== undefined) {
        // If there's an active in-chat auth session, route there instead
        // (handles case where frontend sent cli_response instead of cli_auth_response)
        if (hasCliAuthInChat(ws)) {
          console.log(`[Bridge] cli_response redirected to cli_auth_response (active auth session exists)`);
          respondToCliAuthInChat(ws, msg.value as string, (msg.selectionType as 'number' | 'arrow' | 'text') || 'text');
          return;
        }
        // Check for pending OpenCode question (forwarded from question.asked SSE event)
        if (state.currentThreadId && hasPendingQuestion(state.currentThreadId)) {
          console.log(`[Bridge] cli_response routed to pending OpenCode question: ${msg.value}`);
          respondToPendingQuestion(state.currentThreadId, msg.value as string);
          return;
        }
        respondToInteractiveCli(ws, msg.value as string, (msg.selectionType as 'number' | 'arrow') || 'number');
        return;
      }

      // In-chat CLI auth option selection (from cli_prompt sent during chat auth flow)
      if (msgType === 'cli_auth_response' && msg.value !== undefined) {
        console.log(`[Bridge] cli_auth_response received: value=${msg.value}, selectionType=${msg.selectionType}`);
        respondToCliAuthInChat(
          ws,
          msg.value as string,
          (msg.selectionType as 'number' | 'arrow') || 'number',
        );
        return;
      }

      // ============ Abort Command ============
      if (msgType === 'abort_command') {
        const threadId = state.currentThreadId;
        if (threadId) {
          // Abort all session types: OpenCode SSE, CLI processes, and OpenClaw
          const abortedCli = abortThreadCommand(threadId);
          closeOpenClawConnection(threadId);
          console.log(`[Bridge] Abort requested for thread ${threadId.substring(0, 8)}: cli=${abortedCli}`);
          // End processing state so frontend clears the thinking spinner
          endProcessing(threadId, getLastSeq(threadId));
        }
        ws.send(JSON.stringify({ type: 'abort_ack', threadId, timestamp: Date.now() }));
        return;
      }

      // ============ Command Execution ============
      if (msgType === 'command' && msg.content) {
        const userMessage = (msg.content as string).trim();

        // If auth is in progress, try to route the user's input to the auth session.
        // Users often paste auth codes into the main chat input instead of the dedicated field.
        if (hasCliAuthInChat(ws)) {
          // If it looks like an auth code (short, no spaces or very few words), route to auth
          const isLikelyAuthCode = userMessage.length < 200 && userMessage.split(/\s+/).length <= 3;
          if (isLikelyAuthCode) {
            console.log(`[Bridge] Routing command to auth session (looks like auth code): ${userMessage.substring(0, 30)}`);
            respondToCliAuthInChat(ws, userMessage, 'text');
            ws.send(JSON.stringify({ type: 'ack', command: msg.content, session: state.currentSession, project: state.currentProject, threadId: state.currentThreadId, timestamp: Date.now() }));
            return;
          }
          console.log(`[Bridge] User typed during auth, blocking command until auth completes`);
          ws.send(JSON.stringify({
            type: 'output',
            content: `Please complete ${state.currentSession} authentication first using the prompt above, then try again.`,
            threadId: state.currentThreadId,
            timestamp: Date.now(),
          }));
          ws.send(JSON.stringify({ type: 'ack', command: msg.content, session: state.currentSession, project: state.currentProject, threadId: state.currentThreadId, timestamp: Date.now() }));
          return;
        }

        // Capture thread context at start - prevents race condition when user switches threads during processing
        const commandThreadId = state.currentThreadId;
        let commandSession = state.currentSession;
        const commandProject = state.currentProject;

        // Fix session desync: thread's lastSession is the source of truth.
        // switch_session race conditions can leave state.currentSession mismatched.
        if (commandThreadId) {
          const thread = getThread(commandThreadId);
          if (thread && VALID_SESSIONS.includes(thread.lastSession as SessionType) && thread.lastSession !== commandSession) {
            console.log(`[Bridge] Session desync corrected: state=${commandSession}, thread=${thread.lastSession}`);
            commandSession = thread.lastSession as SessionType;
            state.currentSession = commandSession;
          }
        }

        console.log(`[Bridge] Command received, threadId=${commandThreadId?.substring(0, 8) || 'null'}, session=${commandSession}`);
        ws.send(JSON.stringify({ type: 'thinking', session: commandSession, threadId: commandThreadId, timestamp: Date.now() }));

        // Track processing state so reconnecting clients can catch up on thinking steps
        if (commandThreadId) {
          startProcessing(commandThreadId, commandSession, commandProject ?? undefined, (msg.content as string));
          // Ensure the sending ws receives thinking_step updates (belt-and-suspenders:
          // also subscribed on create_thread and set_thread, but this covers edge cases)
          subscribeProcessing(commandThreadId, ws);
        }

        // Save user message to thread immediately (before CLI dispatch).
        // This ensures the user's message is persisted even if the CLI takes
        // a long time and the WS drops before the response completes.
        const saveUserMessage = (content: string) => {
          if (!commandThreadId) return;
          try {
            const saved = addMessage(commandThreadId, {
              type: 'user',
              content,
              session: commandSession,
              model: null,
              thinking: null,
              metadata: null,
            });
            // Broadcast so client can replace its optimistic local- message with server ID
            sendToThread(ws, commandThreadId, { type: 'message_added', message: saved, timestamp: Date.now() });
            console.log(`[Bridge] Saved user message to thread ${commandThreadId.substring(0, 8)}...`);
          } catch (err) {
            console.error('[Bridge] Failed to save user message:', (err as Error).message);
          }
        };

        // Save assistant message to thread BEFORE sending over WS.
        // DB is the source of truth; WS is just a notification channel.
        const saveAssistantMessage = (content: string, thinking?: string[]) => {
          if (!commandThreadId) return;
          try {
            const saved = addMessage(commandThreadId, {
              type: 'assistant',
              content,
              session: commandSession,
              model: null,
              thinking: thinking || null,
              metadata: null,
            });
            // Broadcast message_added so the client can replace its streaming
            // placeholder with the server-generated ID (prevents doubling on sync)
            sendToThread(ws, commandThreadId, { type: 'message_added', message: saved, timestamp: Date.now() });
            console.log(`[Bridge] Saved assistant message to thread ${commandThreadId.substring(0, 8)}...`);
          } catch (err) {
            console.error('[Bridge] Failed to save assistant message:', (err as Error).message);
          }
        };

        // Save user message to DB immediately (survives WS drops during long CLI responses)
        saveUserMessage(msg.content as string);

        // Wrap the entire CLI dispatch in a tracked promise for graceful drain
        const requestPromise = (async () => {
        try {
          const project = (msg.project as string) || commandProject;

          if (commandSession === 'claw') {
            // Claw mode: direct to OpenClaw agent, no CLI middleman
            if (project) {
              await ensureProjectAgent(project);
            }

            const globalCtx = refreshGlobalContext();
            const projectCtx = loadProjectContext(project);
            const systemPrompt = buildClawSystemPrompt(globalCtx, projectCtx, project);

            let streamedText = '';
            const openclawResponse = await sendToOpenClaw(
              commandThreadId || `claw-${Date.now()}`,
              userMessage,
              'claw',
              (chunk: OpenClawChunk) => {
                if (chunk.type === 'text' && chunk.content) {
                  streamedText += chunk.content;
                  // Track streamed text for mid-stream reconnection recovery
                  if (commandThreadId) updateStreamedText(commandThreadId, streamedText);
                  sendToThread(ws, commandThreadId, {
                    type: 'output',
                    content: streamedText,
                    threadId: commandThreadId,
                    timestamp: Date.now(),
                  });
                } else if (chunk.type === 'tool_use' && chunk.tool) {
                  if (commandThreadId) {
                    addThinkingStep(commandThreadId, `Using ${chunk.tool}...`);
                  }
                }
              },
              null,
              project,
              systemPrompt,
            );

            let clawOutput = openclawResponse.text.trim() || 'Done';

            // Preview health gate: poll file-api for readiness
            if (isPreviewableProject(project)) {
              const outcome = await pollPreviewHealth(project);
              if (!outcome.passed && outcome.needsCodeFix) {
                sendToThread(ws, commandThreadId, {
                  type: 'output',
                  content: 'Preview has a code error. Auto-fixing...',
                  threadId: commandThreadId,
                  timestamp: Date.now(),
                });

                const fixMessage = `The preview has a code error. Fix it so the app starts correctly.\n\nError: ${outcome.error}\n\nDo NOT run pm2, npm run dev, or any process management commands. Just fix the code. The preview system will auto-restart.`;

                try {
                  const fixResponse = await sendToOpenClaw(
                    commandThreadId || `claw-${Date.now()}`,
                    fixMessage,
                    'claw',
                    (chunk: OpenClawChunk) => {
                      if (chunk.type === 'text' && chunk.content) {
                        streamedText += chunk.content;
                        if (commandThreadId) updateStreamedText(commandThreadId, streamedText);
                        sendToThread(ws, commandThreadId, {
                          type: 'output',
                          content: streamedText,
                          threadId: commandThreadId,
                          timestamp: Date.now(),
                        });
                      }
                    },
                    null,
                    project,
                    systemPrompt,
                  );
                  const fixOutput = fixResponse.text.trim();
                  if (fixOutput) clawOutput += '\n\n' + fixOutput;

                  // Re-poll after fix
                  const recheck = await pollPreviewHealth(project);
                  if (!recheck.passed) {
                    clawOutput += `\n\n⚠️ Preview still has an error after fix attempt: ${recheck.error || 'unknown'}`;
                  } else {
                    console.log(`[Bridge] Claw health gate passed after fix for project ${project}`);
                  }
                } catch (fixErr) {
                  console.error(`[Bridge] Claw health gate fix failed:`, (fixErr as Error).message);
                }
              } else if (!outcome.passed) {
                clawOutput += '\n\nPreview is recovering automatically — the system is fixing an infrastructure issue.';
              } else {
                console.log(`[Bridge] Claw health gate passed for project ${project}`);
              }
            }

            // Deployment health gate: if a deployment happened, verify it works
            if (hasRecentDeployment()) {
              const MAX_DEPLOY_RETRIES = 3;
              for (let attempt = 0; attempt < MAX_DEPLOY_RETRIES; attempt++) {
                await bridgeSleep(4000);
                const deployHealth = checkDeploymentHealth();
                if (!deployHealth) {
                  console.log(`[Bridge] Claw deployment health gate passed — all deployed apps healthy`);
                  break;
                }

                console.log(`[Bridge] Claw deployment health gate FAILED (attempt ${attempt + 1}/${MAX_DEPLOY_RETRIES}): ${deployHealth.error}`);
                if (attempt >= MAX_DEPLOY_RETRIES - 1) {
                  clawOutput += `\n\n⚠️ Deployment health check failed after ${MAX_DEPLOY_RETRIES} attempts. Error: ${deployHealth.error}`;
                  break;
                }

                sendToThread(ws, commandThreadId, {
                  type: 'output',
                  content: `Deployed app "${deployHealth.appName}" returned HTTP ${deployHealth.httpStatus || 'no response'}. Auto-fixing... (attempt ${attempt + 2}/${MAX_DEPLOY_RETRIES})`,
                  threadId: commandThreadId,
                  timestamp: Date.now(),
                });

                const fixMessage = `The deployed app "${deployHealth.appName}" is broken on port ${deployHealth.port}. Fix this error and redeploy.\n\nError details:\n${deployHealth.error}\n\nSteps:\n1. Read the error above carefully\n2. Fix the code in the project\n3. Run ellulai-expose again to redeploy\n4. Verify the deployed app returns HTTP 200`;

                try {
                  const fixResponse = await sendToOpenClaw(
                    commandThreadId || `claw-${Date.now()}`,
                    fixMessage,
                    'claw',
                    (chunk: OpenClawChunk) => {
                      if (chunk.type === 'text' && chunk.content) {
                        streamedText += chunk.content;
                        if (commandThreadId) updateStreamedText(commandThreadId, streamedText);
                        sendToThread(ws, commandThreadId, {
                          type: 'output',
                          content: streamedText,
                          threadId: commandThreadId,
                          timestamp: Date.now(),
                        });
                      }
                    },
                    null,
                    project,
                    systemPrompt,
                  );
                  const fixOutput = fixResponse.text.trim();
                  if (fixOutput) clawOutput += '\n\n' + fixOutput;
                } catch (fixErr) {
                  console.error(`[Bridge] Claw deployment health gate fix attempt ${attempt + 1} failed:`, (fixErr as Error).message);
                }
              }
            }

            // Save to DB first (source of truth) — message_added broadcast replaces streaming placeholder
            saveAssistantMessage(clawOutput, openclawResponse.reasoning);
            // No redundant output send — message_added already has the final content
            sendToThread(ws, commandThreadId, { type: 'ack', command: msg.content, session: commandSession, project: commandProject, threadId: commandThreadId, timestamp: Date.now() });
          } else {
          // Auth pre-flight: check if CLI needs setup before invoking
          // opencode/main don't need external auth (uses free models)
          const sessionNeedsAuth = commandSession !== 'opencode' && commandSession !== 'main';
          if (sessionNeedsAuth && checkCliNeedsSetup(commandSession)) {
            // If auth is already in progress (auto-started on thread select), don't restart it
            if (!hasCliAuthInChat(ws)) {
              console.log(`[Bridge] ${commandSession} needs auth setup, starting in-chat auth`);
              startCliAuthInChat(commandSession, ws, commandThreadId);
            }
            // Tell the user their message can't be processed yet
            ws.send(JSON.stringify({
              type: 'output',
              content: `${commandSession} needs to be authenticated before it can process messages. Please complete the authentication above.`,
              threadId: commandThreadId,
              timestamp: Date.now(),
            }));
            ws.send(JSON.stringify({ type: 'ack', command: msg.content, session: commandSession, project: commandProject, threadId: commandThreadId, timestamp: Date.now() }));
            return;
          }

          // Dispatch to CLI with health check gate — retry loop ensures preview works
          const dispatchToCli = async (message: string): Promise<CliResponse> => {
            switch (commandSession) {
              case 'claude':
                return sendToClaudeStreaming(message, ws, true, commandThreadId, project);
              case 'codex':
                return sendToCodexStreaming(message, ws, true, commandThreadId, project);
              case 'gemini':
                return sendToGeminiStreaming(message, ws, true, commandThreadId, project);
              case 'opencode':
              case 'main':
              default:
                return sendToOpencodeStreaming(message, ws, commandThreadId, project);
            }
          };

          let cliResponse = await dispatchToCli(userMessage);
          let finalOutput = cliResponse.text.filter(t => t.trim()).join('\n\n').trim()
            || (cliResponse.tools.length > 0 ? 'Done (' + cliResponse.tools.join(', ') + ')' : 'Done');

          // Echo detection: if the model just repeated the user's message back, retry once
          const isEcho = finalOutput.trim().toLowerCase() === userMessage.trim().toLowerCase()
            && cliResponse.tools.length === 0;
          if (isEcho) {
            console.log(`[Bridge] Echo detected — model repeated user input, retrying with explicit instruction`);
            const retryMessage = `The user said: "${userMessage}"\n\nPlease actually execute this request. Do NOT just repeat it back. Use the appropriate tools (Bash, Read, Write, Edit) to accomplish the task. If they asked to deploy, run: sudo ellulai-expose <app_name> <port>`;
            cliResponse = await dispatchToCli(retryMessage);
            finalOutput = cliResponse.text.filter(t => t.trim()).join('\n\n').trim()
              || (cliResponse.tools.length > 0 ? 'Done (' + cliResponse.tools.join(', ') + ')' : 'Done');
            // If still echoing after retry, give a helpful fallback
            if (finalOutput.trim().toLowerCase() === retryMessage.trim().toLowerCase() || finalOutput.trim().toLowerCase() === userMessage.trim().toLowerCase()) {
              finalOutput = 'I wasn\'t able to process that request. Please try being more specific, or try switching to a different model.';
            }
          }

          // Preview health gate: poll file-api for readiness
          if (isPreviewableProject(project)) {
            const outcome = await pollPreviewHealth(project);
            if (!outcome.passed && outcome.needsCodeFix) {
              sendToThread(ws, commandThreadId, {
                type: 'output',
                content: 'Preview has a code error. Auto-fixing...',
                threadId: commandThreadId,
                timestamp: Date.now(),
              });

              const fixMessage = `The preview has a code error. Fix it so the app starts correctly.\n\nError: ${outcome.error}\n\nDo NOT run pm2, npm run dev, or any process management commands. Just fix the code. The preview system will auto-restart.`;

              try {
                cliResponse = await dispatchToCli(fixMessage);
                const fixOutput = cliResponse.text.filter(t => t.trim()).join('\n\n').trim();
                if (fixOutput) finalOutput += '\n\n' + fixOutput;

                // Re-poll after fix
                const recheck = await pollPreviewHealth(project);
                if (!recheck.passed) {
                  finalOutput += `\n\n⚠️ Preview still has an error after fix attempt: ${recheck.error || 'unknown'}`;
                } else {
                  console.log(`[Bridge] Health gate passed after fix for project ${project}`);
                }
              } catch (fixErr) {
                console.error(`[Bridge] Health gate fix failed:`, (fixErr as Error).message);
              }
            } else if (!outcome.passed) {
              finalOutput += '\n\nPreview is recovering automatically — the system is fixing an infrastructure issue.';
            } else {
              console.log(`[Bridge] Health gate passed for project ${project}`);
            }
          }

          // Deployment health gate: if a deployment happened, verify it works
          if (hasRecentDeployment()) {
            const MAX_DEPLOY_RETRIES = 3;
            for (let attempt = 0; attempt < MAX_DEPLOY_RETRIES; attempt++) {
              await bridgeSleep(4000);
              const deployHealth = checkDeploymentHealth();
              if (!deployHealth) {
                console.log(`[Bridge] Deployment health gate passed — all deployed apps healthy`);
                break;
              }

              console.log(`[Bridge] Deployment health gate FAILED (attempt ${attempt + 1}/${MAX_DEPLOY_RETRIES}): ${deployHealth.error}`);
              if (attempt >= MAX_DEPLOY_RETRIES - 1) {
                finalOutput += `\n\n⚠️ Deployment health check failed after ${MAX_DEPLOY_RETRIES} attempts. Error: ${deployHealth.error}`;
                break;
              }

              sendToThread(ws, commandThreadId, {
                type: 'output',
                content: `Deployed app "${deployHealth.appName}" returned HTTP ${deployHealth.httpStatus || 'no response'}. Auto-fixing... (attempt ${attempt + 2}/${MAX_DEPLOY_RETRIES})`,
                threadId: commandThreadId,
                timestamp: Date.now(),
              });

              const fixMessage = `The deployed app "${deployHealth.appName}" is broken on port ${deployHealth.port}. Fix this error and redeploy.\n\nError details:\n${deployHealth.error}\n\nSteps:\n1. Read the error above carefully\n2. Fix the code in the project\n3. Run ellulai-expose again to redeploy\n4. Verify the deployed app returns HTTP 200`;

              try {
                cliResponse = await dispatchToCli(fixMessage);
                const fixOutput = cliResponse.text.filter(t => t.trim()).join('\n\n').trim();
                if (fixOutput) finalOutput += '\n\n' + fixOutput;
              } catch (fixErr) {
                console.error(`[Bridge] Deployment health gate fix attempt ${attempt + 1} failed:`, (fixErr as Error).message);
              }
            }
          }

          // Save to DB first (source of truth) — message_added broadcast replaces streaming placeholder
          saveAssistantMessage(finalOutput, cliResponse.reasoning);
          // No redundant output send — message_added already has the final content
          sendToThread(ws, commandThreadId, { type: 'ack', command: msg.content, session: commandSession, project: commandProject, threadId: commandThreadId, timestamp: Date.now() });
          }
        } catch (err) {
          const rawMsg = (err as Error).message;
          const errMsg = typeof rawMsg === 'string' ? rawMsg : (rawMsg ? String(rawMsg) : 'Unknown error');
          console.error(`[Bridge] CLI error: ${errMsg}`);
          try {
            // Reactive auth fallback: if CLI throws auth error, start in-chat auth
            if (errMsg.match(/unauthori|authenticate|login|api.key|not.logged|credential|permission|forbidden|401|403/i)
              && ['claude', 'codex', 'gemini'].includes(commandSession)) {
              startCliAuthInChat(commandSession, ws, commandThreadId);
            } else {
              // Surface meaningful errors to the user instead of swallowing them
              let userMsg: string;
              if (errMsg.includes('installing') || errMsg.includes('not installed')) {
                userMsg = errMsg;
              } else if (/rate.?limit|429|too many requests/i.test(errMsg)) {
                userMsg = 'Rate limit reached for the current model. Try switching to a different model or wait a moment.';
              } else if (/timeout|timed out/i.test(errMsg)) {
                userMsg = 'Request timed out. Please try again.';
              } else if (/opencode:/i.test(errMsg)) {
                // Pass through OpenCode session errors (they contain useful info)
                userMsg = errMsg.replace(/^OpenCode:\s*/i, '');
              } else {
                userMsg = 'Something went wrong. Please try again.';
              }
              // Save error response to DB so user sees their failed attempt in history
              saveAssistantMessage(userMsg);
              sendToThread(ws, commandThreadId, { type: 'error', message: userMsg, threadId: commandThreadId, timestamp: Date.now() });
            }
            sendToThread(ws, commandThreadId, { type: 'ack', command: msg.content, session: commandSession, project: commandProject, threadId: commandThreadId, timestamp: Date.now() });
          } catch {
            // WebSocket already closed
          }
        } finally {
          // ALWAYS end processing — stops thinking spinner on frontend
          // Include lastSeq so clients can detect missed messages via gap detection
          if (commandThreadId) {
            endProcessing(commandThreadId, getLastSeq(commandThreadId));
          }
        }
        })();
        inflightRequests.add(requestPromise);
        requestPromise.finally(() => inflightRequests.delete(requestPromise));
        return;
      }

      // ============ Thread Management ============
      if (msgType === 'create_thread') {
        try {
          // Use session from message if provided, otherwise use current session
          const session = (msg.session as SessionType) || state.currentSession;

          // Scope thread to current project (per-connection, not global)
          const thread = createThread(msg.title as string | undefined, session, state.currentProject);
          state.currentThreadId = thread.id;
          // Persist as active thread for this project (survives refresh/device switch)
          setActiveThreadId(thread.id, state.currentProject);
          // Subscribe to processing updates (thinking steps) for the new thread
          subscribeProcessing(thread.id, ws);
          // Also switch connection to that session
          state.currentSession = session;
          console.log(`[Bridge] Created thread ${thread.id.substring(0, 8)}... for project ${state.currentProject}, session ${session}`);

          ws.send(JSON.stringify({ type: 'thread_created', thread, timestamp: Date.now() }));

          // Auth is NOT started here — set_thread (which always follows create_thread)
          // handles auth. Starting it here would be wasted since set_thread cancels + restarts it.
        } catch (err) {
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to create thread: ' + (err as Error).message, timestamp: Date.now() }));
        }
        return;
      }

      if (msgType === 'list_threads') {
        try {
          // Accept project from message (for initial load before set_project arrives)
          // This also updates state.currentProject if provided
          if (msg.project !== undefined) {
            state.currentProject = (msg.project as string) || null;
          }
          console.log(`[Bridge] list_threads called, project=${state.currentProject}`);
          const threads = listThreads(state.currentProject, msg.limit as number | undefined);
          const activeThreadId = getActiveThreadId(state.currentProject);
          console.log(`[Bridge] Returning ${threads.length} threads, activeThreadId=${activeThreadId?.substring(0, 8) || 'null'}`);
          ws.send(JSON.stringify({ type: 'threads_list', threads, activeThreadId, timestamp: Date.now() }));
        } catch (err) {
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to list threads: ' + (err as Error).message, timestamp: Date.now() }));
        }
        return;
      }

      if (msgType === 'get_thread' && msg.threadId) {
        try {
          const result = getThreadWithMessages(msg.threadId as string, msg.limit as number | undefined);
          if (result) {
            // Include in-progress processing state if this thread is currently being processed
            const processingState = getProcessingState(msg.threadId as string);
            const lastMsg = result.messages[result.messages.length - 1];
            const lastSeq = lastMsg ? lastMsg.seq : 0;
            ws.send(JSON.stringify({
              type: 'thread_data',
              thread: result.thread,
              messages: result.messages,
              processingState: processingState || null,
              lastSeq,
              timestamp: Date.now(),
            }));
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Thread not found', timestamp: Date.now() }));
          }
        } catch (err) {
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to get thread: ' + (err as Error).message, timestamp: Date.now() }));
        }
        return;
      }

      if (msgType === 'delete_thread' && msg.threadId) {
        try {
          const threadId = msg.threadId as string;

          // Delete thread (cascades to messages, cleans up state dir)
          const success = deleteThread(threadId);

          if (success) {
            // Clear current thread if it was the deleted one
            if (state.currentThreadId === threadId) {
              state.currentThreadId = null;
              setActiveThreadId(null, state.currentProject);
            }
          }

          ws.send(JSON.stringify({ type: 'thread_deleted', threadId, success, timestamp: Date.now() }));
        } catch (err) {
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to delete thread: ' + (err as Error).message, timestamp: Date.now() }));
        }
        return;
      }

      if (msgType === 'set_thread') {
        const threadId = msg.threadId as string | null;
        console.log(`[Bridge] set_thread called: threadId=${threadId?.substring(0, 8) || 'null'}, project=${state.currentProject}`);

        // Unsubscribe from previous thread's processing updates
        if (state.currentThreadId) {
          unsubscribeProcessing(state.currentThreadId, ws);
        }

        // If the target thread already has an active auth running, just reattach
        // instead of canceling + restarting (prevents duplicate auth prompts).
        // But always cancel auth on the current ws if it belongs to a different thread.
        const targetHasAuth = threadId ? hasCliAuthForThread(threadId) : false;
        const currentAuthThread = getCliAuthThreadId(ws);
        if (!targetHasAuth) {
          cancelCliAuthInChat(ws);
        } else if (currentAuthThread && currentAuthThread !== threadId) {
          // This ws has auth for a different thread — cancel it before reattaching target's auth
          cancelCliAuthInChat(ws);
        }

        if (threadId) {
          const thread = getThread(threadId);
          if (thread) {
            state.currentThreadId = threadId;
            // Persist active thread for this project (survives refresh/device switch)
            setActiveThreadId(threadId, state.currentProject);
            // Restore session from thread
            if (VALID_SESSIONS.includes(thread.lastSession as SessionType)) {
              state.currentSession = thread.lastSession as SessionType;
            }
            // Subscribe to processing state updates for this thread
            subscribeProcessing(threadId, ws);
            console.log(`[Bridge] Thread set to ${threadId.substring(0, 8)}..., session=${state.currentSession}`);
            ws.send(JSON.stringify({ type: 'thread_set', threadId, session: state.currentSession, timestamp: Date.now() }));

            // If this thread is currently processing, re-send the thinking signal
            // with the original startedAt so the frontend timer resumes accurately
            // instead of resetting to 0 on thread switch.
            const activeProcessing = getProcessingState(threadId);
            if (activeProcessing) {
              ws.send(JSON.stringify({
                type: 'thinking',
                session: activeProcessing.session,
                threadId,
                startedAt: activeProcessing.startedAt,
                timestamp: Date.now(),
              }));
              // Replay buffered thinking steps so the client catches up
              for (const step of activeProcessing.thinkingSteps) {
                ws.send(JSON.stringify({
                  type: 'thinking_step',
                  content: step,
                  threadId,
                  timestamp: Date.now(),
                }));
              }
              // Replay accumulated streamed text
              if (activeProcessing.streamedText) {
                ws.send(JSON.stringify({
                  type: 'output',
                  content: activeProcessing.streamedText,
                  threadId,
                  isReplay: true,
                  timestamp: Date.now(),
                }));
              }
            }

            // Try to reattach an auth session from a dropped ws (reconnect scenario)
            // Pass thread session to prevent cross-session reattach (e.g., claude auth on opencode thread)
            const reattached = targetHasAuth ? reattachCliAuth(ws, threadId, state.currentSession) : false;

            // Auto-start auth setup if this CLI session needs it (don't wait for first message)
            const sessionNeedsAuth = state.currentSession !== 'opencode' && state.currentSession !== 'main' && state.currentSession !== 'claw';
            if (!reattached && sessionNeedsAuth && checkCliNeedsSetup(state.currentSession)) {
              console.log(`[Bridge] Auto-starting ${state.currentSession} auth on thread select`);
              // Signal "thinking" so the frontend shows a loading spinner while PTY starts up
              startProcessing(threadId, state.currentSession);
              subscribeProcessing(threadId, ws);
              ws.send(JSON.stringify({ type: 'thinking', session: state.currentSession, threadId, timestamp: Date.now() }));
              startCliAuthInChat(state.currentSession, ws, threadId);
            }
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Thread not found', timestamp: Date.now() }));
          }
        } else {
          state.currentThreadId = null;
          setActiveThreadId(null, state.currentProject);
          console.log('[Bridge] Thread cleared');
          ws.send(JSON.stringify({ type: 'thread_set', threadId: null, session: state.currentSession, timestamp: Date.now() }));
        }
        return;
      }

      if (msgType === 'rename_thread' && msg.threadId && msg.title) {
        try {
          const success = renameThread(msg.threadId as string, msg.title as string);
          ws.send(JSON.stringify({ type: 'thread_renamed', threadId: msg.threadId, title: msg.title, success, timestamp: Date.now() }));
        } catch (err) {
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to rename thread: ' + (err as Error).message, timestamp: Date.now() }));
        }
        return;
      }

      if (msgType === 'add_message' && msg.threadId && msg.message) {
        try {
          const msgData = msg.message as Omit<Message, 'id' | 'threadId' | 'createdAt'>;
          const message = addMessage(msg.threadId as string, msgData);
          ws.send(JSON.stringify({ type: 'message_added', message, timestamp: Date.now() }));
        } catch (err) {
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to add message: ' + (err as Error).message, timestamp: Date.now() }));
        }
        return;
      }

      // ============ Delta Sync ============
      if (msgType === 'sync_messages' && msg.threadId && msg.afterSeq !== undefined) {
        const messages = getMessagesSince(msg.threadId as string, msg.afterSeq as number);
        const lastSeq = getLastSeq(msg.threadId as string);
        ws.send(JSON.stringify({
          type: 'sync_messages',
          messages,
          lastSeq,
          threadId: msg.threadId,
          timestamp: Date.now(),
        }));
        return;
      }

      // ============ Ping/Pong ============
      if (msgType === 'ping') {
        ws.send(JSON.stringify({ type: 'pong', session: state.currentSession, project: state.currentProject, timestamp: Date.now() }));
        return;
      }
    } catch (err) {
      console.error('[Bridge] Error:', (err as Error).message);
    }
  }) as (...args: unknown[]) => void);

  ws.on('close', () => {
    clearTimeout(absoluteTimer);
    clearInterval(heartbeatInterval);
    if (popInterval) clearInterval(popInterval);
    if (challengeTimer) clearTimeout(challengeTimer);
    killInteractiveSession(ws);
    // Don't cancel auth — detach so it survives reconnection
    detachCliAuth(ws);
    unsubscribeAllProcessing(ws);
    console.log('[Bridge] Connection closed');
  });

  ws.on('error', ((err: Error) => {
    console.error('[Bridge] WebSocket error:', err.message);
  }) as (...args: unknown[]) => void);
}) as (...args: unknown[]) => void);

// Startup
httpServer.listen(PORT, '127.0.0.1', async () => {
  console.log(`[Bridge] Running on http://127.0.0.1:${PORT}`);

  // Ensure OpenCode server is running (needed for opencode/main sessions)
  ensureOpencodeServer().then((ready) => {
    console.log(`[Bridge] OpenCode server: ${ready ? 'running' : 'unavailable (will retry on first message)'}`);
    // Start Zen model discovery after OpenCode is ready (needs /config PATCH endpoint)
    if (ready) {
      startZenModelRefresh();
      console.log('[Bridge] Zen model refresh started');
    }
  }).catch((err) => {
    console.error('[Bridge] OpenCode server startup error:', (err as Error).message);
  });

  console.log('[Bridge] Ready');

  // Recover any interrupted requests from the processing ledger (crash recovery)
  recoverInterruptedRequests().catch(err => console.error('[Bridge] Recovery error:', (err as Error).message));
});

// ============ Crash Recovery ============

/**
 * Recover interrupted requests from the processing ledger.
 * Called on startup — re-dispatches prompts that were in-flight when the bridge died.
 */
async function recoverInterruptedRequests(): Promise<void> {
  const orphans = db.prepare(
    'SELECT thread_id, session, project, prompt, thinking_steps, streamed_text FROM processing_ledger'
  ).all() as Array<{
    thread_id: string; session: string; project: string | null; prompt: string;
    thinking_steps: string | null; streamed_text: string | null;
  }>;
  if (orphans.length === 0) return;

  console.log(`[Bridge] Recovering ${orphans.length} interrupted request(s)`);
  db.prepare('DELETE FROM processing_ledger').run();

  for (const orphan of orphans) {
    // Skip if thread already has a response (e.g. drain completed before crash)
    const lastMsg = db.prepare(
      'SELECT type FROM messages WHERE thread_id = ? ORDER BY seq DESC LIMIT 1'
    ).get(orphan.thread_id) as { type: string } | undefined;
    if (lastMsg && lastMsg.type !== 'user') continue;

    // Persist any partial thinking steps that were captured before the crash
    let recoveredThinking: string[] = [];
    try {
      recoveredThinking = orphan.thinking_steps ? JSON.parse(orphan.thinking_steps) : [];
    } catch {}

    if (recoveredThinking.length > 0 || orphan.streamed_text) {
      // Save partial response as a system message so the user sees what was delivered pre-crash
      addMessage(orphan.thread_id, {
        type: 'system',
        content: orphan.streamed_text
          ? `Partial response recovered after restart:\n\n${orphan.streamed_text}`
          : 'Service restarted during processing — partial thinking recovered.',
        session: null, model: null,
        thinking: recoveredThinking.length > 0 ? recoveredThinking : null,
        metadata: { recovery: true, partial: true },
      });
    }

    addMessage(orphan.thread_id, {
      type: 'system',
      content: 'Retrying your last request after a service restart...',
      session: null, model: null, thinking: null,
      metadata: { recovery: true },
    });

    retryPrompt(orphan.thread_id, orphan.session as SessionType, orphan.project, orphan.prompt);
  }
}

/**
 * Retry a prompt for a specific thread. Dispatches to the correct CLI
 * based on the session type stored in the ledger.
 */
async function retryPrompt(threadId: string, session: SessionType, project: string | null, prompt: string): Promise<void> {
  // Noop WS for recovery — no active frontend connection, results saved to DB
  const noopWs = { readyState: 0, send() {} } as any;
  startProcessing(threadId, session, project ?? undefined, prompt);

  const requestPromise = (async () => {
    try {
      let cliResponse: CliResponse;
      const proj = project || '';

      if (session === 'claw') {
        if (proj) await ensureProjectAgent(proj);
        const globalCtx = refreshGlobalContext();
        const projectCtx = loadProjectContext(proj);
        const systemPrompt = buildClawSystemPrompt(globalCtx, projectCtx, proj);
        const openclawResponse = await sendToOpenClaw(threadId, prompt, 'claw', () => {}, null, proj, systemPrompt);
        cliResponse = { reasoning: openclawResponse.reasoning || [], text: [openclawResponse.text || ''], tools: [] };
      } else {
        switch (session) {
          case 'claude': cliResponse = await sendToClaudeStreaming(prompt, noopWs, true, threadId, proj); break;
          case 'codex': cliResponse = await sendToCodexStreaming(prompt, noopWs, true, threadId, proj); break;
          case 'gemini': cliResponse = await sendToGeminiStreaming(prompt, noopWs, true, threadId, proj); break;
          default: cliResponse = await sendToOpencodeStreaming(prompt, noopWs, threadId, proj); break;
        }
      }

      const output = cliResponse.text.filter(t => t.trim()).join('\n\n').trim()
        || (cliResponse.tools.length > 0 ? 'Done (' + cliResponse.tools.join(', ') + ')' : 'Done');
      addMessage(threadId, {
        type: 'assistant', content: output, session, model: null,
        thinking: cliResponse.reasoning || null,
        metadata: { recovered: true },
      });
      console.log(`[Bridge] Recovery complete: thread=${threadId.substring(0, 8)}, session=${session}`);
    } catch (err) {
      console.error(`[Bridge] Recovery failed: thread=${threadId.substring(0, 8)}: ${(err as Error).message}`);
      addMessage(threadId, {
        type: 'system',
        content: 'Could not complete your previous request after a service restart. Please try again.',
        session: null, model: null, thinking: null,
        metadata: { recoveryFailed: true },
      });
    } finally {
      endProcessing(threadId, getLastSeq(threadId));
    }
  })();
  inflightRequests.add(requestPromise);
  requestPromise.finally(() => inflightRequests.delete(requestPromise));
}

// Graceful shutdown with drain for in-flight requests
let shuttingDown = false;

async function gracefulShutdown(signal: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`[Bridge] ${signal}: draining ${inflightRequests.size} in-flight request(s)...`);
  wss.close();

  if (inflightRequests.size > 0) {
    const DRAIN_TIMEOUT = 60_000;
    await Promise.race([
      Promise.allSettled([...inflightRequests]),
      new Promise(r => setTimeout(r, DRAIN_TIMEOUT)),
    ]);
    console.log(`[Bridge] Drain complete, ${inflightRequests.size} remaining`);
  }

  // Add interruption messages for any still-processing threads
  for (const threadId of getActiveProcessingThreadIds()) {
    try {
      addMessage(threadId, {
        type: 'system',
        content: 'Your request was interrupted by a service restart. It will be retried automatically.',
        session: null,
        model: null,
        thinking: null,
        metadata: { interrupted: true, interruptedAt: Date.now() },
      });
    } catch {}
  }

  httpServer.close();
  process.exit(0);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

process.on('uncaughtException', (err) => {
  console.error('[Bridge] Uncaught exception:', err.message);
});

process.on('unhandledRejection', (reason) => {
  console.error('[Bridge] Unhandled rejection:', reason);
});
