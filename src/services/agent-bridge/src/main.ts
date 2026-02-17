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
  ELLULAI_MODELS,
  DEV_DOMAIN,
  type SessionType,
} from './config';
import { startZenModelRefresh, getZenModelList } from './services/zen-models.service';
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
  buildClawSystemPrompt,
  getActiveProject,
} from './services/context.service';
import { sendToOpenClaw, type OpenClawChunk } from './services/openclaw-client.service';
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
  type CliResponse,
} from './services/cli-streaming.service';
import {
  checkCliNeedsSetup,
  startInteractiveCli,
  respondToInteractiveCli,
  killInteractiveSession,
  startCliAuthInChat,
  hasCliAuthInChat,
  respondToCliAuthInChat,
  cancelCliAuthInChat,
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
  renameThread,
  updateThreadSession,
  updateThreadModel,
  clearThreadOpencodeSession,
  addMessage,
  getActiveThreadId,
  setActiveThreadId,
  type Message,
} from './services/thread.service';

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

/**
 * Get the first-thread welcome message.
 * Only shown once — when the user's very first thread is created for a project.
 */
function getFirstThreadWelcome(): string {
  const previewLine = DEV_DOMAIN
    ? `\n\nYour dev preview is live at **https://${DEV_DOMAIN}** — anything you build will be instantly accessible there.`
    : '';

  return `Welcome to **ellul.ai**! I'm your AI coding assistant — I can help you build websites, apps, APIs, and anything else you need.

Type below to get started. For example:
- "Create a hello world app"
- "Build a React landing page"
- "Set up an Express API"${previewLine}`;
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
        state.currentSession = msg.session as SessionType;

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
              ellulaiModels: ELLULAI_MODELS,
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
        respondToInteractiveCli(ws, msg.value as string, (msg.selectionType as 'number' | 'arrow') || 'number');
        return;
      }

      // In-chat CLI auth option selection (from cli_prompt sent during chat auth flow)
      if (msgType === 'cli_auth_response' && msg.value !== undefined) {
        respondToCliAuthInChat(
          ws,
          msg.value as string,
          (msg.selectionType as 'number' | 'arrow') || 'number',
        );
        return;
      }

      // ============ Command Execution ============
      if (msgType === 'command' && msg.content) {
        const userMessage = (msg.content as string).trim();

        // Dragon #2: Cancel escape hatch — user can abort in-chat auth anytime
        if (hasCliAuthInChat(ws) && /^cancel$/i.test(userMessage)) {
          cancelCliAuthInChat(ws);
          ws.send(JSON.stringify({
            type: 'output',
            content: 'Authentication cancelled. You can try again anytime.',
            threadId: state.currentThreadId,
            timestamp: Date.now(),
          }));
          return;
        }

        // Route to PTY if in-chat CLI auth is active
        if (hasCliAuthInChat(ws)) {
          respondToCliAuthInChat(ws, userMessage);
          return;
        }

        // Capture thread context at start - prevents race condition when user switches threads during processing
        const commandThreadId = state.currentThreadId;
        const commandSession = state.currentSession;
        const commandProject = state.currentProject;

        console.log(`[Bridge] Command received, threadId=${commandThreadId?.substring(0, 8) || 'null'}, session=${commandSession}`);
        ws.send(JSON.stringify({ type: 'thinking', session: commandSession, threadId: commandThreadId, timestamp: Date.now() }));

        // Track processing state so reconnecting clients can catch up on thinking steps
        if (commandThreadId) {
          startProcessing(commandThreadId, commandSession);
          // Ensure the sending ws receives thinking_step updates (belt-and-suspenders:
          // also subscribed on create_thread and set_thread, but this covers edge cases)
          subscribeProcessing(commandThreadId, ws);
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
                  ws.send(JSON.stringify({
                    type: 'output',
                    content: streamedText,
                    threadId: commandThreadId,
                    timestamp: Date.now(),
                  }));
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

            const output = openclawResponse.text.trim() || 'Done';
            ws.send(JSON.stringify({ type: 'output', content: output, threadId: commandThreadId, timestamp: Date.now() }));
            ws.send(JSON.stringify({ type: 'ack', command: msg.content, session: commandSession, project: commandProject, threadId: commandThreadId, timestamp: Date.now() }));
            saveToThread(msg.content as string, output, openclawResponse.reasoning);
          } else {
          // Auth pre-flight: check if CLI needs setup before invoking
          // opencode/main don't need external auth (uses free models)
          const sessionNeedsAuth = commandSession !== 'opencode' && commandSession !== 'main';
          if (sessionNeedsAuth && checkCliNeedsSetup(commandSession)) {
            console.log(`[Bridge] ${commandSession} needs auth setup, starting in-chat auth`);
            startCliAuthInChat(commandSession, ws, commandThreadId);
            ws.send(JSON.stringify({ type: 'ack', command: msg.content, session: commandSession, project: commandProject, threadId: commandThreadId, timestamp: Date.now() }));
            return;
          }

          // Dispatch directly to CLI — no AI middleman
          let cliResponse: CliResponse;
          switch (commandSession) {
            case 'claude':
              cliResponse = await sendToClaudeStreaming(userMessage, ws, true, commandThreadId, project);
              break;
            case 'codex':
              cliResponse = await sendToCodexStreaming(userMessage, ws, true, commandThreadId, project);
              break;
            case 'gemini':
              cliResponse = await sendToGeminiStreaming(userMessage, ws, true, commandThreadId, project);
              break;
            case 'opencode':
            case 'main':
            default:
              cliResponse = await sendToOpencodeStreaming(userMessage, ws, commandThreadId, project);
              break;
          }

          // Build final output from CLI response
          const output = cliResponse.text.filter(t => t.trim()).join('\n\n').trim()
            || (cliResponse.tools.length > 0 ? 'Done (' + cliResponse.tools.join(', ') + ')' : 'Done');

          // Send final output + ack
          ws.send(JSON.stringify({ type: 'output', content: output, threadId: commandThreadId, timestamp: Date.now() }));
          ws.send(JSON.stringify({ type: 'ack', command: msg.content, session: commandSession, project: commandProject, threadId: commandThreadId, timestamp: Date.now() }));

          // Save to thread
          saveToThread(msg.content as string, output, cliResponse.reasoning);
          }
        } catch (err) {
          const errMsg = (err as Error).message || 'Unknown error';
          console.error(`[Bridge] CLI error: ${errMsg}`);
          try {
            // Reactive auth fallback: if CLI throws auth error, start in-chat auth
            if (errMsg.match(/unauthori|authenticate|login|api.key|not.logged|credential|permission|forbidden|401|403/i)
              && ['claude', 'codex', 'gemini'].includes(commandSession)) {
              startCliAuthInChat(commandSession, ws, commandThreadId);
            } else {
              // Surface install-state errors directly, generic message for others
              const userMsg = (errMsg.includes('installing') || errMsg.includes('not installed'))
                ? errMsg
                : 'Something went wrong. Please try again.';
              ws.send(JSON.stringify({ type: 'error', message: userMsg, threadId: commandThreadId, timestamp: Date.now() }));
            }
            ws.send(JSON.stringify({ type: 'ack', command: msg.content, session: commandSession, project: commandProject, threadId: commandThreadId, timestamp: Date.now() }));
          } catch {
            // WebSocket already closed
          }
        } finally {
          // ALWAYS end processing — stops thinking spinner on frontend
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

          // Check if this is the user's first thread for this project (BEFORE creating)
          const existingThreads = listThreads(state.currentProject);
          const isFirstThread = existingThreads.length === 0;

          // Scope thread to current project (per-connection, not global)
          const thread = createThread(msg.title as string | undefined, session, state.currentProject);
          state.currentThreadId = thread.id;
          // Persist as active thread for this project (survives refresh/device switch)
          setActiveThreadId(thread.id, state.currentProject);
          // Subscribe to processing updates (thinking steps) for the new thread
          subscribeProcessing(thread.id, ws);
          // Also switch connection to that session
          state.currentSession = session;
          console.log(`[Bridge] Created thread ${thread.id.substring(0, 8)}... for project ${state.currentProject}, session ${session}, firstThread=${isFirstThread}`);

          // Inject welcome message on first-ever thread for this project
          if (isFirstThread) {
            addMessage(thread.id, {
              type: 'assistant',
              content: getFirstThreadWelcome(),
              session,
              model: null,
              thinking: null,
              metadata: { synthetic: true },
            });
            console.log(`[Bridge] Injected welcome message into first thread ${thread.id.substring(0, 8)}`);
          }

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
    clearInterval(heartbeatInterval);
    killInteractiveSession(ws);
    cancelCliAuthInChat(ws);
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
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('[Bridge] Shutting down...');
  wss.close();
  httpServer.close();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('[Bridge] Shutting down...');
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
