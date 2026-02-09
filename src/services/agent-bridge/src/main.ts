/**
 * Agent Bridge Main Entry Point
 *
 * WebSocket bridge for Vibe Mode chat UI running on port 7700.
 * Provides multi-session AI CLI routing with context injection.
 *
 * Sessions: opencode, claude, codex, gemini, main
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
import {
  PORT,
  DEFAULT_SESSION,
  VALID_SESSIONS,
  CONTEXT_CACHE_MS,
  ELLULAI_MODELS,
  type SessionType,
} from './config';
import { validateAgentToken, extractAgentToken } from './auth';
import {
  loadCliEnv,
  saveCliKey,
  removeCliKey,
  CLI_KEY_MAP,
} from './services/cli-env.service';
import {
  loadGlobalContext,
  loadProjectContext,
  withContext,
  getActiveProject,
} from './services/context.service';
import { ensureTmuxSession, sendToTmux, captureTmuxPane } from './services/tmux.service';
import {
  ensureOpencodeServer,
  getOpencodeSession,
  resetOpencodeSession,
  opencodeReady,
  sendToOpencodeStreaming,
  sendToClaudeStreaming,
  sendToCodexStreaming,
  sendToGeminiStreaming,
  getProviders,
  setApiKey,
  setModel,
  getCurrentModel,
  closeVibeSession,
  closeAllVibeSessions,
} from './services/cli-streaming.service';
import {
  checkCliNeedsSetup,
  startInteractiveCli,
  respondToInteractiveCli,
  killInteractiveSession,
} from './services/interactive.service';

// Processing state for in-progress thread operations (thinking step buffer)
import {
  startProcessing,
  endProcessing,
  getProcessingState,
  subscribe as subscribeProcessing,
  unsubscribe as unsubscribeProcessing,
  unsubscribeAll as unsubscribeAllProcessing,
} from './services/processing-state';

// Initialize chat database (must import before thread service)
import './database';
import {
  createThread,
  listThreads,
  getThread,
  getThreadWithMessages,
  deleteThread,
  getThreadForCleanup,
  renameThread,
  updateThreadSession,
  updateThreadModel,
  addMessage,
  getActiveThreadId,
  setActiveThreadId,
  type Message,
} from './services/thread.service';
import { deleteOpencodeSession } from './services/cli-streaming.service';

// WebSocket types
interface WsClient {
  readyState: number;
  send(data: string): void;
  close(): void;
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
  pollTimer: NodeJS.Timeout | null;
  lastContent: string;
  // Track which threads have had context injected (per-thread isolation)
  claudeActiveThreads: Set<string>;
  codexActiveThreads: Set<string>;
  geminiActiveThreads: Set<string>;
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
 * Get welcome message for a session
 */
function getWelcomeMessage(session: SessionType): string {
  if (['claude', 'codex', 'gemini'].includes(session) && checkCliNeedsSetup(session)) {
    return session.charAt(0).toUpperCase() + session.slice(1) + ' needs setup. Starting configuration...';
  }
  const messages: Record<string, string> = {
    opencode: opencodeReady ? 'OpenCode ready. Ask me anything!' : 'Starting OpenCode...',
    claude: 'Claude Code ready. What would you like to build?',
    codex: 'Codex ready. What code should I write?',
    gemini: 'Gemini ready. How can I help?',
    main: 'Shell ready. Enter commands to execute.',
  };
  return messages[session] || 'Ready.';
}

/**
 * Send command to main tmux session.
 */
async function sendToMain(command: string): Promise<void> {
  ensureTmuxSession('main');
  sendToTmux('main', command);
}

// Import terminal session manager
import {
  createTerminalSession,
  getTerminalSessionPort,
  closeTerminalSession,
  listTerminalSessions,
  shutdownAllSessions,
  cleanupOrphanedSessions,
  type TerminalSessionType,
} from './services/terminal.service';
import { cleanupOrphanedVibeSessions } from './services/vibe-cli.service';

// Parse JSON body from request
function parseJsonBody(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

// Create HTTP server with health and terminal session endpoints
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
        opencodeReady,
        activeProject: getActiveProject(),
        contextLoaded: !!refreshGlobalContext(),
      })
    );
    return;
  }

  // Terminal session API (used by term-proxy)
  // POST /terminal/session - Create new terminal session
  if (url.pathname === '/terminal/session' && req.method === 'POST') {
    try {
      const body = await parseJsonBody(req);
      const type = body.type as TerminalSessionType;
      const instanceId = body.instanceId as string | undefined;
      // Use project from body or fall back to active project
      const project = (body.project as string | undefined) || getActiveProject() || undefined;

      if (!type || !VALID_SESSIONS.includes(type)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid session type' }));
        return;
      }

      const session = await createTerminalSession(type, instanceId, project);
      if (session) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(session));
      } else {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Failed to create session' }));
      }
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: (err as Error).message }));
    }
    return;
  }

  // GET /terminal/session/:instanceId/port - Get port for session (used by term-proxy routing)
  if (url.pathname.startsWith('/terminal/session/') && url.pathname.endsWith('/port') && req.method === 'GET') {
    const parts = url.pathname.split('/');
    const instanceId = parts[3];

    if (!instanceId) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Missing instance ID' }));
      return;
    }

    const port = getTerminalSessionPort(instanceId);

    if (port) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ port }));
    } else {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Session not found' }));
    }
    return;
  }

  // GET /terminal/session/:instanceId/capture - Capture terminal pane content (for mobile select mode)
  if (url.pathname.startsWith('/terminal/session/') && url.pathname.endsWith('/capture') && req.method === 'GET') {
    const parts = url.pathname.split('/');
    const instanceId = parts[3];

    if (!instanceId) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Missing instance ID' }));
      return;
    }

    // Try dynamic session first (term-<id>), then systemd session (just <id>)
    const dynamicTmux = `term-${instanceId}`;
    let capturedPaneContent = captureTmuxPane(dynamicTmux);
    if (capturedPaneContent === null) {
      capturedPaneContent = captureTmuxPane(instanceId);
    }
    if (capturedPaneContent === null) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Session not found or no content' }));
      return;
    }

    // Strip ANSI escape codes for clean text
    const clean = capturedPaneContent.replace(/\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g, '');

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ content: clean, sessionId: instanceId }));
    return;
  }

  // DELETE /terminal/session/:instanceId - Close terminal session
  if (url.pathname.startsWith('/terminal/session/') && req.method === 'DELETE') {
    const parts = url.pathname.split('/');
    const instanceId = parts[3];

    if (!instanceId) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Missing instance ID' }));
      return;
    }

    const success = await closeTerminalSession(instanceId);

    res.writeHead(success ? 200 : 404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success }));
    return;
  }

  // GET /terminal/sessions - List active sessions (optionally filtered by project)
  if (url.pathname === '/terminal/sessions' && req.method === 'GET') {
    // project query param: string = filter by project, empty string = unscoped only, absent = all
    const projectParam = url.searchParams.get('project');
    const project = projectParam === '' ? null : projectParam === null ? undefined : projectParam;
    const sessions = listTerminalSessions(project);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ sessions }));
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
  verifyClient: async (
    info: { req: { url?: string } },
    cb: (result: boolean, code?: number, message?: string) => void
  ) => {
    // UNIFIED AUTH: Valid token = authorized (sovereign-shield enforced tier at issuance)
    const agentToken = extractAgentToken(info.req.url);
    if (!agentToken) {
      console.log('[Bridge] No agent token provided');
      cb(false, 401, 'Agent token required');
      return;
    }
    const valid = await validateAgentToken(agentToken);
    if (!valid) {
      console.log('[Bridge] Agent token validation failed');
      cb(false, 401, 'Invalid agent token');
      return;
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

wss.on('connection', ((ws: WsClient, req: { url?: string }) => {
  console.log('[Bridge] Connection URL:', req?.url);

  // Extract project from URL for per-connection state
  const urlProject = extractProjectFromUrl(req?.url);
  console.log('[Bridge] Extracted project from URL:', urlProject);

  // Per-connection state (project is scoped to this connection, not shared globally)
  const state: ConnectionState = {
    currentSession: DEFAULT_SESSION as SessionType,
    currentProject: urlProject,
    currentThreadId: null,
    pollTimer: null,
    lastContent: '',
    // Track per-thread CLI session activation (for context injection)
    claudeActiveThreads: new Set(),
    codexActiveThreads: new Set(),
    geminiActiveThreads: new Set(),
  };

  console.log('[Bridge] New connection (authenticated), project:', state.currentProject);

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

  // Polling for main shell output
  function startPolling() {
    if (state.pollTimer) clearInterval(state.pollTimer);
    if (state.currentSession !== 'main') return;

    state.pollTimer = setInterval(() => {
      const content = captureTmuxPane('main');
      if (content && content !== state.lastContent) {
        state.lastContent = content;
        ws.send(JSON.stringify({ type: 'output', content, timestamp: Date.now() }));
      }
    }, 100);
  }

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
    try {
      const msg = JSON.parse(data.toString()) as Record<string, unknown>;
      const msgType = msg.type as string;

      // ============ Session Management ============
      if (msgType === 'switch_session' && VALID_SESSIONS.includes(msg.session as SessionType)) {
        if (state.pollTimer) clearInterval(state.pollTimer);
        state.currentSession = msg.session as SessionType;
        state.lastContent = '';
        // Note: Per-thread CLI activation is tracked separately, no need to reset here

        // Update thread's last session if there's an active thread
        if (state.currentThreadId) {
          updateThreadSession(state.currentThreadId, state.currentSession);
        }

        ws.send(
          JSON.stringify({
            type: 'session_switched',
            session: state.currentSession,
            content: getWelcomeMessage(state.currentSession),
            timestamp: Date.now(),
          })
        );

        if (state.currentSession === 'main') {
          ensureTmuxSession('main');
          startPolling();
        }

        // Auto-start interactive setup if CLI needs first-time configuration
        if (['claude', 'codex', 'gemini'].includes(state.currentSession)) {
          const needsSetup = checkCliNeedsSetup(state.currentSession);
          if (needsSetup) {
            console.log('[Bridge] ' + state.currentSession + ' needs setup, starting interactive CLI');
            startInteractiveCli(state.currentSession, ws, undefined, state.currentThreadId);
          }
        }
        return;
      }

      // ============ Project Management ============
      if (msgType === 'set_project') {
        const newProject = (msg.project as string) || null;
        const oldProject = state.currentProject;
        state.currentProject = newProject;

        if (newProject !== oldProject) {
          // Reset OpenCode session so next command creates one with correct project
          resetOpencodeSession();
          console.log('[Bridge] Project changed from', oldProject, 'to', newProject);
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
              ellulaiModels: ELLULAI_MODELS,
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
          // Update thread's last model if there's an active thread
          if (state.currentThreadId && success) {
            updateThreadModel(state.currentThreadId, msg.model as string);
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
          ws.send(
            JSON.stringify({
              type: 'current_model',
              model,
              timestamp: Date.now(),
            })
          );
        } catch (err) {
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to get model: ' + (err as Error).message, timestamp: Date.now() }));
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
        respondToInteractiveCli(ws, msg.value as string, (msg.selectionType as 'number' | 'arrow') || 'number');
        return;
      }

      // ============ Command Execution ============
      if (msgType === 'command' && msg.content) {
        // Capture thread context at start - prevents race condition when user switches threads during processing
        const commandThreadId = state.currentThreadId;
        const commandSession = state.currentSession;
        const commandProject = state.currentProject;

        console.log(`[Bridge] Command received, threadId=${commandThreadId?.substring(0, 8) || 'null'}, session=${commandSession}`);
        ws.send(JSON.stringify({ type: 'thinking', session: commandSession, threadId: commandThreadId, timestamp: Date.now() }));

        // Track processing state so reconnecting clients can catch up on thinking steps
        if (commandThreadId) {
          startProcessing(commandThreadId, commandSession);
        }

        // Helper to save messages to thread (uses captured threadId)
        const saveToThread = (userContent: string, assistantContent: string, thinking?: string[]) => {
          if (!commandThreadId) {
            console.log('[Bridge] No thread ID, skipping message save');
            return;
          }
          try {
            // Save user message
            addMessage(commandThreadId, {
              type: 'user',
              content: userContent,
              session: commandSession,
              model: null,
              thinking: null,
              metadata: null,
            });
            // Save assistant message
            addMessage(commandThreadId, {
              type: 'assistant',
              content: assistantContent,
              session: commandSession,
              model: null,
              thinking: thinking || null,
              metadata: null,
            });
            console.log(`[Bridge] Saved 2 messages to thread ${commandThreadId.substring(0, 8)}...`);
          } catch (err) {
            console.error('[Bridge] Failed to save messages:', (err as Error).message);
          }
        };

        try {
          const project = (msg.project as string) || commandProject;

          // Inject context only on first message per thread (per-thread isolation)
          // If no threadId, always inject context (safety fallback)
          let needsContext = true;
          let isThreadActive = false;
          if (commandThreadId) {
            if (commandSession === 'claude') isThreadActive = state.claudeActiveThreads.has(commandThreadId);
            else if (commandSession === 'codex') isThreadActive = state.codexActiveThreads.has(commandThreadId);
            else if (commandSession === 'gemini') isThreadActive = state.geminiActiveThreads.has(commandThreadId);
            needsContext = !isThreadActive;
          }

          const globalCtx = refreshGlobalContext();
          const projectCtx = project ? loadProjectContext(project) : '';
          const contextualMessage = needsContext
            ? withContext(msg.content as string, globalCtx, projectCtx, project)
            : (msg.content as string);

          let response: { text: string[]; reasoning?: string[]; tools?: string[] };

          switch (commandSession) {
            case 'opencode':
              // Pass threadId for per-thread session isolation and project for working directory
              response = await sendToOpencodeStreaming(contextualMessage, ws, commandThreadId, project);
              {
                let output = (response.text || []).join('\n').trim();
                if (!output && response.tools && response.tools.length > 0) {
                  output = 'Completed using: ' + response.tools.join(', ');
                }
                ws.send(JSON.stringify({ type: 'ack', command: msg.content, session: commandSession, project: commandProject, threadId: commandThreadId, timestamp: Date.now() }));
                ws.send(JSON.stringify({ type: 'output', content: output || 'No response received', threadId: commandThreadId, timestamp: Date.now() }));
                saveToThread(msg.content as string, output || 'No response received', response.reasoning);
              }
              return;

            case 'claude':
              // Pass threadId for per-thread state isolation and project for working directory
              response = await sendToClaudeStreaming(contextualMessage, ws, isThreadActive, commandThreadId, project);
              if (commandThreadId) state.claudeActiveThreads.add(commandThreadId);
              {
                const output = (response.text || []).join('\n') || 'Done';
                ws.send(JSON.stringify({ type: 'ack', command: msg.content, session: commandSession, project: commandProject, threadId: commandThreadId, timestamp: Date.now() }));
                ws.send(JSON.stringify({ type: 'output', content: output, threadId: commandThreadId, timestamp: Date.now() }));
                saveToThread(msg.content as string, output, response.reasoning);
              }
              return;

            case 'codex':
              // Pass threadId for per-thread state isolation and project for working directory
              response = await sendToCodexStreaming(contextualMessage, ws, isThreadActive, commandThreadId, project);
              if (commandThreadId) state.codexActiveThreads.add(commandThreadId);
              {
                const output = (response.text || []).join('\n') || 'Done';
                ws.send(JSON.stringify({ type: 'ack', command: msg.content, session: commandSession, project: commandProject, threadId: commandThreadId, timestamp: Date.now() }));
                ws.send(JSON.stringify({ type: 'output', content: output, threadId: commandThreadId, timestamp: Date.now() }));
                saveToThread(msg.content as string, output, response.reasoning);
              }
              return;

            case 'gemini':
              // Pass threadId for per-thread state isolation and project for working directory
              response = await sendToGeminiStreaming(contextualMessage, ws, isThreadActive, commandThreadId, project);
              if (commandThreadId) state.geminiActiveThreads.add(commandThreadId);
              {
                const output = (response.text || []).join('\n') || 'Done';
                ws.send(JSON.stringify({ type: 'ack', command: msg.content, session: commandSession, project: commandProject, threadId: commandThreadId, timestamp: Date.now() }));
                ws.send(JSON.stringify({ type: 'output', content: output, threadId: commandThreadId, timestamp: Date.now() }));
                saveToThread(msg.content as string, output, response.reasoning);
              }
              return;

            case 'main':
              await sendToMain(msg.content as string);
              ws.send(JSON.stringify({ type: 'ack', command: msg.content, session: commandSession, project: commandProject, threadId: commandThreadId, timestamp: Date.now() }));
              ws.send(JSON.stringify({ type: 'output', content: 'Command sent', threadId: commandThreadId, timestamp: Date.now() }));
              saveToThread(msg.content as string, 'Command sent');
              return;

            default:
              throw new Error('Unknown session: ' + commandSession);
          }
        } catch (err) {
          const errMsg = (err as Error).message || '';

          // CLI not installed yet
          if (errMsg.includes('ENOENT') || errMsg.includes('not found')) {
            ws.send(JSON.stringify({ type: 'error', message: commandSession + ' is still installing. Try again in a moment.', threadId: commandThreadId, timestamp: Date.now() }));
          }
          // Auth failure - start interactive CLI setup
          else if (
            errMsg.match(/unauthori|authenticate|login|api.key|not.logged|credential|permission|forbidden|401|403/i) ||
            (errMsg.match(/failed|error/i) && ['claude', 'codex', 'gemini'].includes(commandSession))
          ) {
            startInteractiveCli(commandSession, ws, undefined, commandThreadId);
          } else {
            ws.send(JSON.stringify({ type: 'error', message: errMsg, threadId: commandThreadId, timestamp: Date.now() }));
          }
        } finally {
          // Always end processing state so clients stop showing thinking indicator
          if (commandThreadId) {
            endProcessing(commandThreadId);
          }
        }
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
          // Also switch connection to that session
          state.currentSession = session;
          console.log(`[Bridge] Created thread ${thread.id.substring(0, 8)}... for project ${state.currentProject}, session ${session}`);
          ws.send(JSON.stringify({ type: 'thread_created', thread, timestamp: Date.now() }));
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
            ws.send(JSON.stringify({
              type: 'thread_data',
              thread: result.thread,
              messages: result.messages,
              processingState: processingState || null,
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

          // Get OpenCode session ID before deletion for cleanup
          const threadData = getThreadForCleanup(threadId);
          const opencodeSessionId = threadData?.opencodeSessionId;

          // Delete thread (cascades to messages, cleans up state dir)
          const success = deleteThread(threadId);

          if (success) {
            // Clean up OpenCode session asynchronously
            if (opencodeSessionId) {
              deleteOpencodeSession(opencodeSessionId).catch(() => {
                // Non-fatal, log only
              });
            }

            // Clean up persistent vibe CLI sessions for this thread
            closeVibeSession(threadId);

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
    if (state.pollTimer) clearInterval(state.pollTimer);
    clearInterval(heartbeatInterval);
    killInteractiveSession(ws);
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

  // Clean up orphaned sessions from previous runs
  // (handles case where agent-bridge restarted but tmux/ttyd processes survived)
  cleanupOrphanedSessions();
  cleanupOrphanedVibeSessions();

  // Initialize OpenCode server (but don't create session yet - wait for project context)
  await ensureOpencodeServer();
  // Note: We don't call getOpencodeSession() here anymore because we don't have
  // project context. Sessions will be created on first command with proper project.

  // Initialize tmux for main shell
  ensureTmuxSession('main');

  console.log('[Bridge] Ready');
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('[Bridge] Shutting down...');
  closeAllVibeSessions(); // Close persistent vibe chat CLI sessions
  await shutdownAllSessions(); // Close terminal sessions
  wss.close();
  httpServer.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('[Bridge] Shutting down...');
  closeAllVibeSessions(); // Close persistent vibe chat CLI sessions
  await shutdownAllSessions(); // Close terminal sessions
  wss.close();
  httpServer.close();
  process.exit(0);
});

process.on('uncaughtException', (err) => {
  console.error('[Bridge] Uncaught exception:', err.message);
});

process.on('unhandledRejection', (reason) => {
  console.error('[Bridge] Unhandled rejection:', reason);
});
