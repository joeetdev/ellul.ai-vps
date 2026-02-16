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
import {
  PORT,
  DEFAULT_SESSION,
  VALID_SESSIONS,
  CONTEXT_CACHE_MS,
  ELLULAI_MODELS,
  DEV_DOMAIN,
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
  buildSystemPrompt,
  getActiveProject,
} from './services/context.service';
import {
  sendToOpenClaw,
  closeOpenClawConnection,
  closeAllOpenClawConnections,
  checkOpenClawHealth,
  SESSION_MODEL_LABELS,
  type OpenClawChunk,
} from './services/openclaw-client.service';
import {
  getProviders,
  setApiKey,
  setModel,
} from './services/cli-streaming.service';
import {
  startInteractiveCli,
  respondToInteractiveCli,
  killInteractiveSession,
  startCliAuthInChat,
  hasCliAuthInChat,
  respondToCliAuthInChat,
  cancelCliAuthInChat,
} from './services/interactive.service';
import {
  ensureProjectAgent,
  reconcileAgents,
} from './services/openclaw-agent.service';

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

/**
 * Condense verbose AI responses for non-tool models.
 *
 * Good models use the coding-agent tool → produce brief responses naturally.
 * Non-tool models narrate every step as text → wall of text.
 *
 * This function is the safety net: it detects verbose narration and extracts
 * just the outcome. Applied post-stream so it doesn't affect tool-using models.
 */
function condenseVerboseResponse(text: string): string | null {
  // Short responses don't need condensing
  if (text.length < 400) return null;

  const lines = text.split('\n').filter(l => l.trim());
  if (lines.length < 6) return null;

  // Score verbose signals — each pattern adds weight
  let score = 0;
  for (const line of lines) {
    if (/^\s*\d+[\.\)]\s/.test(line)) score += 2;       // numbered steps
    if (/^\s*[-*•]\s/.test(line)) score += 1;            // bullet points
    if (/^\s*```/.test(line)) score += 2;                 // code fences
    if (/\b(First[, ]I|Then I|Next[, ]I|Now[, ]I|I'll now|Let me |I've also|I also |I then |After that|Finally[, ]I|I went ahead|I proceeded|I started by|I checked|I created|I installed|I set up|I configured|I added|I updated|I modified|Here's what|Here's a summary|Here are the|Let me walk|I ran |I opened|I wrote|I built|I generated|I launched|I initialized)/i.test(line)) score += 2; // narration
  }

  // Not verbose — good model gave a clean response
  if (score < 4) return null;

  // Extract the meaningful outcome from the verbose mess
  const paragraphs = text.split(/\n\n+/).filter(p => p.trim());
  const urlPattern = /https?:\/\/\S+/;
  const outcomePattern = /\b(running|live|access|preview|visit|available|ready|done|complete|success|deployed|started|created|listening|served|built)\b/i;

  // Scan paragraphs bottom-up for the outcome (models usually end with it)
  for (let i = paragraphs.length - 1; i >= 0; i--) {
    const p = paragraphs[i]!.trim();

    // Skip short sign-offs ("Let me know if you need anything!")
    if (p.length < 30 && !urlPattern.test(p)) continue;
    // Skip code blocks
    if (p.startsWith('```')) continue;
    // Skip bullet/step lists
    if (/^\s*[\d\-*•]/.test(p)) continue;

    if (outcomePattern.test(p) || urlPattern.test(p)) {
      // Strip filler prefixes
      const cleaned = p.replace(/^(So[, ]|In summary[,: ]+|To summarize[,: ]+|In short[,: ]+|Overall[,: ]+|That's it[.!] ?)/i, '').trim();
      // Cap at ~2 sentences max
      const sentences = cleaned.match(/[^.!?]+[.!?]+/g);
      if (sentences && sentences.length > 2) {
        return sentences.slice(0, 2).join('').trim();
      }
      return cleaned;
    }
  }

  // No outcome paragraph found — take the last non-list, non-code paragraph
  for (let i = paragraphs.length - 1; i >= 0; i--) {
    const p = paragraphs[i]!.trim();
    if (p.length > 30 && !p.startsWith('```') && !/^\s*[\d\-*•]/.test(p)) {
      const sentences = p.match(/[^.!?]+[.!?]+/g);
      if (sentences && sentences.length > 2) {
        return sentences.slice(0, 2).join('').trim();
      }
      return p;
    }
  }

  return null;
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
        const model = SESSION_MODEL_LABELS[state.currentSession] || null;
        ws.send(
          JSON.stringify({
            type: 'current_model',
            model,
            timestamp: Date.now(),
          })
        );
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

          // System prompt sent as role: "system" (first message only — saves tokens)
          // Workspace files (SOUL.md, AGENTS.md) handle persistent identity;
          // this covers per-request rules and project context.
          const systemPrompt = needsContext
            ? buildSystemPrompt(globalCtx, projectCtx, project, commandSession)
            : null;
          const contextualMessage = msg.content as string;

          // Ensure per-project agent exists (lazy creation on first message)
          if (project) {
            await ensureProjectAgent(project);
          }

          // All AI sessions route through OpenClaw agent
          // OpenClaw is the middleman — it uses the local CLIs (claude, codex, etc.)
          // as tools, orchestrates the work, and reports back what it did.
          // Auth: user's own API keys via `claude login` etc. — no extra token cost.
          const threadModel = commandThreadId ? getThread(commandThreadId)?.lastModel : null;

          // Accumulate streamed text so each 'output' message contains the full response so far
          let accumulatedText = '';

          const response = await sendToOpenClaw(
            commandThreadId || `ephemeral-${Date.now()}`,
            contextualMessage,
            commandSession,
            (chunk: OpenClawChunk) => {
              switch (chunk.type) {
                case 'text':
                  if (chunk.content) {
                    accumulatedText += chunk.content;

                    // Dragon #1: Check accumulated text for CLI setup trigger (handles split chunks)
                    const setupMatch = accumulatedText.match(/\[SETUP_CLI:(\w+)\]/);
                    if (setupMatch?.[1]) {
                      const cliSession = setupMatch[1];
                      accumulatedText = accumulatedText.replace(/\[SETUP_CLI:\w+\]/, '').trim();
                      startCliAuthInChat(cliSession, ws, commandThreadId);
                    }

                    ws.send(JSON.stringify({ type: 'output', content: accumulatedText, threadId: commandThreadId, timestamp: Date.now() }));
                  }
                  break;
                case 'tool_use':
                  if (commandThreadId) {
                    addThinkingStep(commandThreadId, `Using ${chunk.tool}...`);
                  }
                  break;
                case 'tool_result':
                  if (commandThreadId) {
                    addThinkingStep(commandThreadId, `${chunk.tool}: ${(chunk.output || '').substring(0, 200)}`);
                  }
                  break;
                case 'file_edit':
                  if (commandThreadId) {
                    addThinkingStep(commandThreadId, `Edited ${chunk.path}`);
                  }
                  break;
                case 'status':
                  if (chunk.status === 'thinking') {
                    ws.send(JSON.stringify({ type: 'thinking', session: commandSession, threadId: commandThreadId, timestamp: Date.now() }));
                  }
                  break;
                case 'error':
                  ws.send(JSON.stringify({ type: 'error', message: chunk.message, threadId: commandThreadId, timestamp: Date.now() }));
                  break;
              }
            },
            threadModel,
            project,
            systemPrompt,
          );

          // sendToOpenClaw ALWAYS returns a response (never throws).
          // On error, response.text contains a user-friendly error message.
          let output = response.text.trim() || 'Something went wrong. Please try again.';

          // Post-process: condense verbose narration into brief summary.
          // Free models can't use tools, so they narrate every step as text.
          // This replaces the wall-of-text with just the outcome summary.
          const condensed = condenseVerboseResponse(output);
          if (condensed) {
            output = condensed;
            // Send final output event with condensed text (replaces verbose version in UI)
            ws.send(JSON.stringify({ type: 'output', content: condensed, threadId: commandThreadId, timestamp: Date.now() }));
          }

          // Mark thread context as active for this session
          if (commandThreadId) {
            if (commandSession === 'claude') state.claudeActiveThreads.add(commandThreadId);
            else if (commandSession === 'codex') state.codexActiveThreads.add(commandThreadId);
            else if (commandSession === 'gemini') state.geminiActiveThreads.add(commandThreadId);
          }

          // Always send ack — this tells the frontend the request is complete
          ws.send(JSON.stringify({ type: 'ack', command: msg.content, session: commandSession, project: commandProject, threadId: commandThreadId, timestamp: Date.now() }));

          // Always save to thread — even errors, so user sees them on refresh
          saveToThread(msg.content as string, output, response.reasoning);
        } catch (err) {
          // This should rarely fire now (sendToOpenClaw handles its own errors),
          // but guard against unexpected failures (WebSocket send errors, etc.)
          const errMsg = (err as Error).message || 'Unknown error';
          console.error(`[Bridge] Unexpected error in message handler: ${errMsg}`);
          try {
            ws.send(JSON.stringify({ type: 'error', message: 'Something went wrong. Please try again.', threadId: commandThreadId, timestamp: Date.now() }));
            ws.send(JSON.stringify({ type: 'ack', command: msg.content, session: commandSession, project: commandProject, threadId: commandThreadId, timestamp: Date.now() }));
          } catch {
            // WebSocket already closed — nothing we can do
          }
        } finally {
          // ALWAYS end processing — this stops the thinking spinner on the frontend.
          // Without this, the UI hangs in "thinking" state forever.
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
            // Close OpenClaw connection for this thread
            closeOpenClawConnection(threadId);

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

  // Check OpenClaw agent health
  const openclawHealthy = await checkOpenClawHealth();
  console.log(`[Bridge] OpenClaw agent: ${openclawHealthy ? 'reachable' : 'NOT reachable (will connect on first message)'}`);

  // Reconcile per-project agents with existing projects
  if (openclawHealthy) {
    reconcileAgents().catch((err) => {
      console.error('[Bridge] Agent reconciliation failed:', (err as Error).message);
    });
  }

  console.log('[Bridge] Ready');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('[Bridge] Shutting down...');
  closeAllOpenClawConnections();
  wss.close();
  httpServer.close();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('[Bridge] Shutting down...');
  closeAllOpenClawConnections();
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
