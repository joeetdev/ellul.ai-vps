/**
 * CLI Streaming Service
 *
 * Streaming implementations for all AI CLI tools:
 * - OpenCode (HTTP API with SSE) - Per-thread sessions
 * - Claude/Codex/Gemini - Persistent tmux sessions per thread
 *
 * Each thread gets its own persistent CLI process with full conversation memory.
 * This is the enterprise approach - CLIs run continuously, maintaining state.
 */

import { spawn, execSync } from 'child_process';
import * as http from 'http';
import * as path from 'path';
import * as fs from 'fs';
import { getCliSpawnEnv } from './cli-env.service';
import { PROJECTS_DIR, OPENCODE_API_PORT, OPENCODE_BIN, CLI_TIMEOUT_MS, CLI_ONESHOT_TIMEOUT_MS } from '../config';
import { getZenModelList, refreshZenModels, type ZenModel } from './zen-models.service';
import {
  getThreadOpencodeSession,
  setThreadOpencodeSession,
  ensureThreadStateDir,
  withThreadLock,
} from './thread.service';
import { getActiveProject } from './context.service';
import { addThinkingStep } from './processing-state';

// Lazy AI flag file — touched when all background npm installs complete
const LAZY_AI_READY_FLAG = '/var/lib/ellul.ai/lazy-ai-ready';

/**
 * Check if a CLI binary is available in PATH.
 * Returns true if the binary exists, false otherwise.
 */
function isCliBinaryAvailable(name: string): boolean {
  try {
    execSync(`which ${name}`, { stdio: 'ignore', timeout: 3000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Ensure a CLI tool is installed before attempting to spawn it.
 * Throws a user-friendly error if the tool is not yet available.
 */
function requireCliBinary(name: string): void {
  if (isCliBinaryAvailable(name)) return;
  const installing = !fs.existsSync(LAZY_AI_READY_FLAG);
  if (installing) {
    throw new Error(`${name} is still installing. Please wait a moment and try again.`);
  }
  throw new Error(`${name} is not installed on this server. Try restarting the server to trigger reinstallation.`);
}

/**
 * Send a thinking step via the processing state subscriber mechanism (which forwards to
 * all subscribed WebSocket clients including the command sender). Falls back to direct
 * send only when there's no threadId (no subscriber mechanism available).
 */
function sendThinkingStep(ws: WsClient, content: string, threadId?: string | null): void {
  if (threadId) {
    // Use subscriber mechanism — the ws is already subscribed via set_thread
    addThinkingStep(threadId, content);
  } else {
    // No thread context — send directly as fallback
    try {
      ws.send(JSON.stringify({ type: 'thinking_step', content, threadId, timestamp: Date.now() }));
    } catch {
      // Connection might be closing
    }
  }
}

// WebSocket client interface
interface WsClient {
  send(data: string): void;
}

// Response structure
export interface CliResponse {
  reasoning: string[];
  text: string[];
  tools: string[];
}

// HTTP request helper
function httpRequest(
  options: http.RequestOptions,
  body: unknown = null
): Promise<{ status: number | undefined; data: unknown }> {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: data ? JSON.parse(data) : null });
        } catch {
          resolve({ status: res.statusCode, data });
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(CLI_TIMEOUT_MS, () => {
      req.destroy();
      reject(new Error('Request timeout (5 min limit reached)'));
    });
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// Run CLI command with timeout
function runCliCommand(
  command: string,
  args: string[],
  cwd = PROJECTS_DIR
): Promise<string> {
  return runCliCommandWithEnv(command, args, cwd, getCliSpawnEnv());
}

// Run CLI command with custom environment
function runCliCommandWithEnv(
  command: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv
): Promise<string> {
  return new Promise((resolve, reject) => {
    console.log('[Bridge] Running:', command, args.join(' ').substring(0, 100));

    const proc = spawn(command, args, {
      cwd,
      env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    proc.stdin?.end();

    let stdout = '';
    let stderr = '';
    let killed = false;

    proc.stdout?.on('data', (data) => (stdout += data.toString()));
    proc.stderr?.on('data', (data) => (stderr += data.toString()));

    proc.on('close', (code) => {
      if (killed) return;
      if (code === 0 || stdout) {
        resolve(stdout || stderr || 'Command completed');
      } else {
        reject(new Error(stderr || 'Command failed with code ' + code));
      }
    });

    proc.on('error', (err) => {
      if (!killed) reject(err);
    });

    setTimeout(() => {
      if (!killed) {
        killed = true;
        proc.kill('SIGTERM');
        reject(new Error('Command timeout (5 min limit reached)'));
      }
    }, CLI_TIMEOUT_MS);
  });
}

// ============ OpenCode State ============
// Global fallback session (used when no thread context)
let globalOpencodeSessionId: string | null = null;
export let opencodeReady = false;

export async function ensureOpencodeServer(): Promise<boolean> {
  try {
    const result = await httpRequest({
      hostname: '127.0.0.1',
      port: OPENCODE_API_PORT,
      path: '/session',
      method: 'GET',
      timeout: 2000,
    });
    if (result.status === 200) {
      console.log('[Bridge] OpenCode server is running');
      opencodeReady = true;
      return true;
    }
  } catch {
    console.log('[Bridge] Starting OpenCode server...');
    spawn('bash', ['-c', `cd ${PROJECTS_DIR} && ${OPENCODE_BIN} serve --port ${OPENCODE_API_PORT} &`], {
      detached: true,
      stdio: 'ignore',
    }).unref();

    for (let i = 0; i < 30; i++) {
      await new Promise((r) => setTimeout(r, 500));
      try {
        const check = await httpRequest({
          hostname: '127.0.0.1',
          port: OPENCODE_API_PORT,
          path: '/session',
          method: 'GET',
          timeout: 1000,
        });
        if (check.status === 200) {
          console.log('[Bridge] OpenCode server started');
          opencodeReady = true;
          return true;
        }
      } catch {}
    }
  }
  return false;
}

/**
 * Get or create an OpenCode session for a specific thread.
 * Each thread gets its own isolated session for independent conversations.
 *
 * Session lifecycle:
 * 1. Check if thread has stored session ID
 * 2. Validate session still exists on OpenCode server
 * 3. If invalid/missing, create new session
 * 4. Store session ID in database for persistence
 *
 * @param threadId - Optional thread ID for per-thread sessions
 * @param project - Optional project name to scope the session's working directory
 */
export async function getOpencodeSession(threadId?: string | null, project?: string | null): Promise<string | null> {
  // If threadId provided, use per-thread session
  if (threadId) {
    return getOrCreateThreadSession(threadId, project);
  }

  // Fallback to global session (no thread context)
  return getOrCreateGlobalSession(project);
}

/**
 * Get or create OpenCode session for a specific thread.
 * Handles validation, creation, and persistence.
 * Uses thread lock to prevent race conditions.
 *
 * @param threadId - Thread ID for session isolation
 * @param project - Optional project name for working directory scoping
 */
async function getOrCreateThreadSession(threadId: string, project?: string | null): Promise<string | null> {
  // Use thread lock to prevent race conditions when multiple
  // concurrent requests try to create sessions for the same thread
  return withThreadLock(threadId, async () => {
    // Check if thread already has a session
    const existingSession = getThreadOpencodeSession(threadId);

    if (existingSession) {
      // Validate session still exists on server
      const isValid = await validateOpencodeSession(existingSession);
      if (isValid) {
        console.log(`[OpenCode] Reusing session ${existingSession.substring(0, 8)}... for thread ${threadId.substring(0, 8)}...`);
        return existingSession;
      }
      console.log(`[OpenCode] Session ${existingSession.substring(0, 8)}... expired for thread ${threadId.substring(0, 8)}..., creating new`);
    }

    // Create new session for this thread with project scope
    const newSession = await createOpencodeSession(project);
    if (newSession) {
      setThreadOpencodeSession(threadId, newSession);
      console.log(`[OpenCode] Created session ${newSession.substring(0, 8)}... for thread ${threadId.substring(0, 8)}...`);
      return newSession;
    }

    console.error(`[OpenCode] Failed to create session for thread ${threadId.substring(0, 8)}...`);
    return null;
  });
}

/**
 * Get or create global OpenCode session (fallback when no thread context).
 *
 * @param project - Optional project name for working directory scoping
 */
async function getOrCreateGlobalSession(project?: string | null): Promise<string | null> {
  // For global sessions with a project, always create a fresh session
  // to ensure the correct working directory (don't reuse sessions from other projects)
  if (project) {
    const newSession = await createOpencodeSession(project);
    if (newSession) {
      console.log(`[OpenCode] Created project-scoped global session ${newSession.substring(0, 8)}...`);
      return newSession;
    }
    console.error('[OpenCode] Failed to create project-scoped global session');
    return null;
  }

  // Validate existing global session (only for non-project sessions)
  if (globalOpencodeSessionId) {
    const isValid = await validateOpencodeSession(globalOpencodeSessionId);
    if (isValid) {
      return globalOpencodeSessionId;
    }
    console.log('[OpenCode] Global session expired, creating new');
    globalOpencodeSessionId = null;
  }

  // Try to reuse an existing session on the server
  try {
    const result = await httpRequest({
      hostname: '127.0.0.1',
      port: OPENCODE_API_PORT,
      path: '/session',
      method: 'GET',
    });
    const data = result.data as Array<{ id: string }> | null;
    if (result.status === 200 && Array.isArray(data) && data.length > 0 && data[0]) {
      globalOpencodeSessionId = data[0].id;
      console.log(`[OpenCode] Reusing existing global session ${globalOpencodeSessionId.substring(0, 8)}...`);
      return globalOpencodeSessionId;
    }
  } catch {}

  // Create new global session
  const newSession = await createOpencodeSession();
  if (newSession) {
    globalOpencodeSessionId = newSession;
    console.log(`[OpenCode] Created global session ${newSession.substring(0, 8)}...`);
    return newSession;
  }

  console.error('[OpenCode] Failed to create global session');
  return null;
}

/**
 * Validate that an OpenCode session still exists and is usable.
 */
async function validateOpencodeSession(sessionId: string): Promise<boolean> {
  try {
    const result = await httpRequest({
      hostname: '127.0.0.1',
      port: OPENCODE_API_PORT,
      path: '/session/' + sessionId,
      method: 'GET',
      timeout: 5000,
    });
    return result.status === 200;
  } catch {
    return false;
  }
}

/**
 * Create a new OpenCode session.
 * @param project - Optional project name to scope the session's working directory
 */
async function createOpencodeSession(project?: string | null): Promise<string | null> {
  try {
    const dirParam = opencodeDirectoryParam(project);
    const result = await httpRequest(
      {
        hostname: '127.0.0.1',
        port: OPENCODE_API_PORT,
        path: '/session' + dirParam,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      },
      {}
    );
    const data = result.data as { id?: string } | null;
    if (result.status === 200 && data?.id) {
      const sessionId = data.id;
      console.log(`[OpenCode] Created session ${sessionId.substring(0, 8)}... for project ${project || 'default'}`);
      return sessionId;
    }
  } catch (err) {
    console.error('[OpenCode] Session creation error:', (err as Error).message);
  }
  return null;
}

/**
 * Delete an OpenCode session (cleanup when thread is deleted).
 */
export async function deleteOpencodeSession(sessionId: string): Promise<boolean> {
  try {
    const result = await httpRequest({
      hostname: '127.0.0.1',
      port: OPENCODE_API_PORT,
      path: '/session/' + sessionId,
      method: 'DELETE',
      timeout: 5000,
    });
    if (result.status === 200 || result.status === 204) {
      console.log(`[OpenCode] Deleted session ${sessionId.substring(0, 8)}...`);
      return true;
    }
  } catch (err) {
    console.warn(`[OpenCode] Failed to delete session ${sessionId.substring(0, 8)}...:`, (err as Error).message);
  }
  return false;
}

export function resetOpencodeSession(): void {
  globalOpencodeSessionId = null;
}


/**
 * Get CLI spawn environment with isolated HOME for per-thread state.
 * This ensures each thread's CLI (Claude/Codex/Gemini) has independent conversation history.
 *
 * Strategy:
 * - Set HOME to per-thread directory for complete CLI isolation
 * - Symlink API key configs from real home so auth works
 * - Each thread gets its own conversation state
 */
function getIsolatedCliEnv(threadId?: string | null): NodeJS.ProcessEnv {
  const baseEnv = getCliSpawnEnv();
  const realHome = process.env.HOME || '/home/' + (process.env.USER || 'dev');

  if (!threadId) {
    return baseEnv;
  }

  // Ensure thread state directory exists with proper structure
  const threadStateDir = ensureThreadStateDir(threadId);

  // Symlink auth/config files from real home (one-time setup per thread)
  setupThreadSymlinks(threadStateDir, realHome);

  // Set HOME to thread directory for complete isolation
  // CLIs will read/write their state to this isolated directory
  return {
    ...baseEnv,
    HOME: threadStateDir,
    // Also set XDG for CLIs that respect it
    XDG_CONFIG_HOME: threadStateDir,
    XDG_DATA_HOME: threadStateDir,
    XDG_STATE_HOME: threadStateDir,
    XDG_CACHE_HOME: path.join(threadStateDir, '.cache'),
    // Preserve real home for reference if needed
    ELLULAI_REAL_HOME: realHome,
    ELLULAI_THREAD_ID: threadId,
  };
}

/**
 * Setup symlinks from thread directory to real home for shared configs.
 * This allows threads to share authentication but have separate state.
 */
function setupThreadSymlinks(threadDir: string, realHome: string): void {
  const symlinks = [
    // Claude Code auth (API key, OAuth tokens)
    { src: '.claude.json', type: 'file' },
    { src: '.claude/settings.json', type: 'file' },
    { src: '.claude/.credentials.json', type: 'file' },
    // Codex auth
    { src: '.codex/auth.json', type: 'file' },
    { src: '.codex/config.json', type: 'file' },
    // Gemini auth
    { src: '.gemini/credentials.json', type: 'file' },
    { src: '.gemini/config.json', type: 'file' },
    // Shared CLI environment
    { src: '.ellulai-env', type: 'file' },
  ];

  for (const link of symlinks) {
    const srcPath = path.join(realHome, link.src);
    const destPath = path.join(threadDir, link.src);

    // Skip if source doesn't exist
    if (!fs.existsSync(srcPath)) continue;

    // Skip if dest already exists (symlink or real file)
    if (fs.existsSync(destPath)) continue;

    try {
      // Ensure parent directory exists
      const destDir = path.dirname(destPath);
      if (!fs.existsSync(destDir)) {
        fs.mkdirSync(destDir, { recursive: true });
      }

      // Create symlink
      fs.symlinkSync(srcPath, destPath);
      console.log(`[CLI] Symlinked ${link.src} for thread isolation`);
    } catch (err) {
      // Non-fatal - log and continue
      console.warn(`[CLI] Failed to symlink ${link.src}:`, (err as Error).message);
    }
  }
}

// Build ?directory= query string for OpenCode API (per-request context selector)
function opencodeDirectoryParam(project?: string | null): string {
  const directory = project ? path.join(PROJECTS_DIR, project) : PROJECTS_DIR;
  return '?directory=' + encodeURIComponent(directory);
}

// ============ OpenCode Streaming ============
async function sendToOpencodeWithParts(message: string, threadId?: string | null, project?: string | null): Promise<CliResponse> {
  const sessionId = await getOpencodeSession(threadId, project);
  if (!sessionId) throw new Error('No OpenCode session');
  const dirParam = opencodeDirectoryParam(project);

  const result = await httpRequest(
    {
      hostname: '127.0.0.1',
      port: OPENCODE_API_PORT,
      path: '/session/' + sessionId + '/message' + dirParam,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    },
    { parts: [{ type: 'text', text: message }] }
  );

  if (result.status === 200 && result.data) {
    const response: CliResponse = { reasoning: [], text: [], tools: [] };
    type PartType = { type?: string; text?: string; content?: string; toolInvocation?: { toolName: string }; name?: string };
    const data = result.data as { parts?: PartType[]; content?: PartType[]; text?: string };
    const parts = data.parts || data.content || [];
    if (Array.isArray(parts)) {
      for (const part of parts) {
        const partType = part.type || '';
        const partText = part.text || part.content || '';
        if ((partType === 'reasoning' || partType === 'thinking') && partText) {
          response.reasoning.push(partText);
        } else if ((partType === 'text' || partType === 'message') && partText) {
          response.text.push(partText);
        } else if (partType === 'tool-invocation' || partType === 'tool_use') {
          response.tools.push(part.toolInvocation?.toolName || part.name || 'tool');
        }
      }
    }
    if (response.text.length === 0 && data.text) {
      response.text.push(data.text);
    }
    return response;
  }
  throw new Error('OpenCode request failed (status: ' + (result?.status || 'unknown') + ')');
}

/**
 * One-shot OpenCode - spawns CLI directly in project directory.
 * This ensures the correct working directory for all operations.
 */
async function sendToOpencodeOneShot(
  message: string,
  ws: WsClient,
  threadId?: string | null,
  project?: string | null
): Promise<CliResponse> {
  return new Promise((resolve, reject) => {
    const opencodePath = path.join(process.env.HOME || '/home/' + (process.env.USER || 'dev'), '.opencode', 'bin', 'opencode');
    const args = ['run', '--format', 'json', '--thinking'];
    // Note: Don't use --continue as it requires an existing OpenCode session
    // Thread isolation is handled via separate working directories
    args.push(message);

    // Use project-specific directory
    const workingDir = project ? path.join(PROJECTS_DIR, project) : PROJECTS_DIR;
    console.log(`[OpenCode] Running one-shot in ${workingDir}`);

    // OpenCode uses API sessions for isolation, not HOME directory
    // Don't use isolated HOME as it makes projects dir appear "external"
    const proc = spawn(opencodePath, args, {
      cwd: workingDir,
      env: getCliSpawnEnv(),
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    proc.stdin?.end();

    let killed = false;
    let buffer = '';
    const response: CliResponse = { reasoning: [], text: [], tools: [] };

    proc.stdout?.on('data', (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const event = JSON.parse(line);
          // opencode run --format json spreads part data onto event: {type, timestamp, sessionID, ...partData}
          // Also check event.part for backwards compat
          const part = event.part || event;

          // Handle different event types from opencode run --format json
          if ((event.type === 'reasoning' || event.type === 'thinking')) {
            // OpenCode returns reasoning with empty text (thinking tokens used but text not exposed)
            const thinkingText = (part.text || event.content || '').trim();
            if (thinkingText) {
              response.reasoning.push(thinkingText);
              sendThinkingStep(ws, thinkingText, threadId);
            }
          } else if (event.type === 'text' && (part.text || event.text)) {
            const text = (part.text || event.text || '').trim();
            if (text && !response.text.includes(text)) {
              response.text.push(text);
              ws.send(JSON.stringify({ type: 'output', content: text, threadId, timestamp: Date.now() }));
            }
          } else if (event.type === 'tool_use' && (part.tool || event.tool)) {
            // Track tools in response but do NOT send as thinking steps
            const toolName = part.tool || event.tool;
            if (!response.tools.includes(toolName)) {
              response.tools.push(toolName);
            }
          }
        } catch {
          // Not JSON, might be plain text output
          if (line.trim()) {
            response.text.push(line.trim());
          }
        }
      }
    });

    proc.stderr?.on('data', (chunk) => {
      const text = chunk.toString().trim();
      if (text && !text.includes('Checking for updates')) {
        console.log('[OpenCode stderr]', text);
      }
    });

    proc.on('error', (err) => {
      if (!killed) {
        killed = true;
        reject(new Error('OpenCode failed: ' + err.message));
      }
    });

    proc.on('close', (code) => {
      if (!killed) {
        killed = true;
        // Process any remaining buffer
        if (buffer.trim()) {
          try {
            const event = JSON.parse(buffer);
            if (event.type === 'text' && event.content) {
              response.text.push(event.content);
            }
          } catch {
            if (buffer.trim()) {
              response.text.push(buffer.trim());
            }
          }
        }
        if (code !== 0 && response.text.length === 0) {
          reject(new Error('OpenCode exited with code ' + code));
        } else {
          resolve(response);
        }
      }
    });

    // Timeout after 5 minutes
    setTimeout(() => {
      if (!killed) {
        killed = true;
        proc.kill('SIGTERM');
        reject(new Error('OpenCode timed out'));
      }
    }, 5 * 60 * 1000);
  });
}

export async function sendToOpencodeStreaming(
  message: string,
  ws: WsClient,
  threadId?: string | null,
  project?: string | null
): Promise<CliResponse> {
  // Ensure model is a valid free zen model before sending.
  // Without this, OpenCode may use a non-free model (e.g. opencode/claude-opus-4-6)
  // which will fail without API keys. We check against actual zen models, not just prefix.
  try {
    const currentModel = await getCurrentModel();
    const zenModels = getZenModelList();
    const zenIds = new Set(zenModels.map(m => m.openCodeId));
    const isValidZenModel = currentModel ? zenIds.has(currentModel) : false;
    if (!currentModel || (!isValidZenModel && zenIds.size > 0)) {
      console.log(`[OpenCode] Model "${currentModel}" is not a free zen model, discovering available models...`);
      await refreshZenModels();
    } else if (!isValidZenModel && zenIds.size === 0) {
      // No zen models cached yet — trigger discovery
      console.log(`[OpenCode] No zen models cached, discovering...`);
      await refreshZenModels();
    }
  } catch {
    // Non-fatal — proceed with whatever model is configured
  }

  // PRIMARY: Use HTTP API with SSE via /global/event + prompt_async
  // This gives real-time streaming of reasoning, text, and tool events
  const sessionId = await getOpencodeSession(threadId, project).catch(() => null);
  if (!sessionId) {
    console.log('[OpenCode] API unavailable, falling back to one-shot CLI');
    return sendToOpencodeOneShot(message, ws, threadId, project);
  }
  console.log(`[Bridge] SSE streaming: session=${sessionId.substring(0, 12)}, thread=${threadId?.substring(0, 8) || 'none'}, project=${project || 'none'}`);
  const dirParam = opencodeDirectoryParam(project);

  return new Promise((resolve, reject) => {
    const response: CliResponse = { reasoning: [], text: [], tools: [] };
    let reasoningBuffer = '';
    let settled = false;
    let eventReq: http.ClientRequest | null = null;
    let sseConnected = false;
    let eventCount = 0;
    let reasoningCount = 0;

    function finish() {
      if (settled) return;
      settled = true;
      if (eventReq) {
        try { eventReq.destroy(); } catch {}
      }
      if (reasoningBuffer.trim()) {
        response.reasoning.push(reasoningBuffer.trim());
        sendThinkingStep(ws, reasoningBuffer.trim(), threadId);
        reasoningBuffer = '';
      }
      console.log(`[Bridge] SSE complete: ${eventCount} events, ${reasoningCount} reasoning, ${response.text.length} text parts, ${response.tools.length} tools`);
      resolve(response);
    }

    function sendMessageAsync() {
      // Use prompt_async: returns 204 immediately, events stream via SSE
      const postData = JSON.stringify({ parts: [{ type: 'text', text: message }] });
      const asyncPath = '/session/' + sessionId + '/prompt_async' + dirParam;
      console.log(`[Bridge] POST ${asyncPath}`);
      const msgReq = http.request(
        {
          hostname: '127.0.0.1',
          port: OPENCODE_API_PORT,
          path: asyncPath,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData),
          },
        },
        (msgRes) => {
          msgRes.resume(); // drain response body (204 = no content)
          console.log(`[Bridge] prompt_async status: ${msgRes.statusCode}`);
          if (msgRes.statusCode !== 204 && msgRes.statusCode !== 200) {
            console.error('[Bridge] prompt_async returned unexpected status:', msgRes.statusCode);
            // Non-success status means the session may be broken - fall back
            if (!settled) {
              settled = true;
              if (eventReq) { try { eventReq.destroy(); } catch {} }
              sendToOpencodeOneShot(message, ws, threadId, project).then(resolve).catch(reject);
            }
          }
        }
      );
      msgReq.on('error', (err) => {
        if (!settled) {
          console.error('[Bridge] prompt_async failed:', err.message);
          settled = true;
          if (eventReq) { try { eventReq.destroy(); } catch {} }
          // Fall back to one-shot CLI
          sendToOpencodeOneShot(message, ws, threadId, project).then(resolve).catch(reject);
        }
      });
      msgReq.setTimeout(CLI_TIMEOUT_MS);
      msgReq.write(postData);
      msgReq.end();
    }

    // Subscribe to /global/event SSE stream (streams all session events)
    let sseBuffer = '';
    eventReq = http.get(
      {
        hostname: '127.0.0.1',
        port: OPENCODE_API_PORT,
        path: '/global/event',
        headers: { Accept: 'text/event-stream' },
      },
      (eventRes) => {
        if (eventRes.statusCode !== 200) {
          console.error('[Bridge] SSE status:', eventRes.statusCode, '- falling back to one-shot');
          eventRes.resume();
          if (!settled) {
            settled = true;
            sendToOpencodeOneShot(message, ws, threadId, project).then(resolve).catch(reject);
          }
          return;
        }
        console.log('[Bridge] SSE /global/event connected, status 200');

        eventRes.on('data', (chunk) => {
          if (settled) return;
          sseBuffer += chunk.toString();
          const events = sseBuffer.split('\n\n');
          sseBuffer = events.pop() || '';

          for (const event of events) {
            if (settled) break;
            const lines = event.split('\n');
            let eventData = '';
            for (const line of lines) {
              if (line.startsWith('data: ')) {
                eventData += line.slice(6);
              }
            }
            if (!eventData) continue;
            try {
              const raw = JSON.parse(eventData);

              // /global/event wraps events in {payload: {...}, directory: "..."}
              // Unwrap the payload, or use raw if no payload wrapper
              const parsed = raw.payload || raw;
              eventCount++;

              if (parsed.type === 'server.connected' && !sseConnected) {
                sseConnected = true;
                console.log('[Bridge] SSE /global/event ready - sending prompt_async');
                sendMessageAsync();
                continue;
              }

              // Log first few events for debugging
              if (eventCount <= 5) {
                console.log(`[Bridge] SSE event #${eventCount}: type=${parsed.type}, partType=${parsed.properties?.part?.type || 'n/a'}, sessionID=${parsed.properties?.part?.sessionID?.substring(0, 12) || parsed.properties?.sessionID?.substring(0, 12) || 'n/a'}`);
              }

              if ((parsed.type === 'message.part.updated' || parsed.type === 'message.part.completed') && parsed.properties?.part) {
                const part = parsed.properties.part;
                if (part.sessionID && part.sessionID !== sessionId) {
                  if (eventCount <= 3) console.log(`[Bridge] SSE skipping event: part.sessionID=${part.sessionID.substring(0, 12)} !== our session=${sessionId.substring(0, 12)}`);
                  continue;
                }
                const delta = parsed.properties.delta || '';
                const partType = part.type || '';

                if (partType === 'reasoning' || partType === 'thinking') {
                  reasoningCount++;
                  if (delta && delta.trim()) {
                    reasoningBuffer += delta;
                    // Flush at 20+ chars or sentence endings for responsive display
                    if (reasoningBuffer.length > 20 || delta.match(/[.!?;:\n]\s*$/)) {
                      response.reasoning.push(reasoningBuffer.trim());
                      sendThinkingStep(ws, reasoningBuffer.trim(), threadId);
                      reasoningBuffer = '';
                    }
                  } else if (part.text && part.text.trim()) {
                    response.reasoning.push(part.text.trim());
                    sendThinkingStep(ws, part.text.trim(), threadId);
                  }
                  // Log first reasoning event
                  if (reasoningCount === 1) {
                    console.log(`[Bridge] First reasoning event: delta="${(delta || '').substring(0, 50)}", buffer="${reasoningBuffer.substring(0, 50)}"`);
                  }
                } else if (partType === 'text') {
                  if (delta) {
                    if (response.text.length === 0) response.text.push('');
                    response.text[response.text.length - 1] += delta;
                  } else if (part.text) {
                    if (response.text.length === 0) response.text.push(part.text);
                    else response.text[response.text.length - 1] = part.text;
                  }
                } else if (partType === 'tool') {
                  // Track tools in response but do NOT send as thinking steps
                  // Tool steps are actions, not reasoning — keep thinking section clean
                  const toolName = part.tool || 'tool';
                  if (!response.tools.includes(toolName)) response.tools.push(toolName);
                } else if (partType === 'step-start' || partType === 'step-finish') {
                  // Step lifecycle events — no display needed
                } else if (partType !== '') {
                  const content = (delta || part.text || part.content || '').trim();
                  if (content) {
                    response.reasoning.push(content);
                    sendThinkingStep(ws, content, threadId);
                  }
                }
              }

              if (parsed.type === 'session.idle' && parsed.properties?.sessionID === sessionId) {
                console.log('[Bridge] Session idle - response complete');
                finish();
                return;
              }
              if (parsed.type === 'session.status' && parsed.properties?.sessionID === sessionId) {
                if (parsed.properties.status?.type === 'idle') {
                  console.log('[Bridge] Session status idle - response complete');
                  finish();
                  return;
                }
              }

              // Auto-answer question tool calls — the bridge can't relay interactive
              // questions to the frontend, so pick the first option automatically.
              if (parsed.type === 'question.asked' && parsed.properties?.sessionID === sessionId) {
                const qProps = parsed.properties as { id: string; questions: Array<{ question: string; options: Array<{ label: string }> }> };
                const questionId = qProps.id;
                const answers = (qProps.questions || []).map(
                  (q: { options: Array<{ label: string }> }) => [q.options?.[0]?.label || 'yes']
                );
                console.log(`[Bridge] Auto-answering question ${questionId}: ${JSON.stringify(answers)}`);
                const replyData = JSON.stringify({ answers });
                const replyReq = http.request({
                  hostname: '127.0.0.1',
                  port: OPENCODE_API_PORT,
                  path: `/question/${questionId}/reply`,
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(replyData) },
                }, (res) => { res.resume(); console.log(`[Bridge] Question reply status: ${res.statusCode}`); });
                replyReq.on('error', (err) => console.error(`[Bridge] Question reply error: ${err.message}`));
                replyReq.write(replyData);
                replyReq.end();
              }

              // Auto-grant permission requests — OpenCode asks for permission before
              // file writes, shell commands, etc. Always allow since the agent operates
              // in a sandboxed VPS environment.
              if (parsed.type === 'permission.asked' && parsed.properties?.sessionID === sessionId) {
                const permId = (parsed.properties as { id: string }).id;
                const permName = (parsed.properties as { permission?: string }).permission || 'unknown';
                console.log(`[Bridge] Auto-granting permission ${permId}: ${permName}`);
                const replyData = JSON.stringify({ reply: 'always' });
                const replyReq = http.request({
                  hostname: '127.0.0.1',
                  port: OPENCODE_API_PORT,
                  path: `/permission/${permId}/reply`,
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(replyData) },
                }, (res) => { res.resume(); console.log(`[Bridge] Permission reply status: ${res.statusCode}`); });
                replyReq.on('error', (err) => console.error(`[Bridge] Permission reply error: ${err.message}`));
                replyReq.write(replyData);
                replyReq.end();
              }

              if (parsed.type === 'session.error' && parsed.properties?.sessionID === sessionId) {
                const errMsg = parsed.properties?.error || 'Session error';
                console.error('[Bridge] Session error:', errMsg);
                if (!settled) {
                  settled = true;
                  if (eventReq) { try { eventReq.destroy(); } catch {} }
                  reject(new Error('OpenCode: ' + errMsg));
                }
                return;
              }
            } catch {
              // Ignore parse errors
            }
          }
        });

        eventRes.on('error', (err) => {
          console.error('[Bridge] SSE stream error:', err.message);
          if (!settled) finish();
        });

        eventRes.on('end', () => {
          console.log('[Bridge] SSE stream ended unexpectedly');
          if (!settled) finish();
        });
      }
    );

    eventReq.on('error', (err) => {
      console.error('[Bridge] SSE connection error:', err.message);
      if (!settled) {
        settled = true;
        sendToOpencodeOneShot(message, ws, threadId, project).then(resolve).catch(reject);
      }
    });

    setTimeout(() => {
      if (!settled) {
        console.error('[Bridge] OpenCode streaming timeout');
        finish();
      }
    }, CLI_TIMEOUT_MS);
  });
}

// ============ Claude Code Streaming ============
export async function sendToClaudeStreaming(
  message: string,
  ws: WsClient,
  useContinue = false,
  threadId?: string | null,
  project?: string | null
): Promise<CliResponse> {
  return sendToClaudeOneShot(message, ws, useContinue, threadId, project);
}

// One-shot Claude — structured JSON output with thinking, tools, and reasoning persistence
async function sendToClaudeOneShot(
  message: string,
  ws: WsClient,
  useContinue = false,
  threadId?: string | null,
  project?: string | null
): Promise<CliResponse> {
  return new Promise((resolve, reject) => {
    // Pre-flight: ensure claude binary is installed
    try { requireCliBinary('claude'); } catch (e) { return reject(e); }

    // Use claude -p with JSON output for reliable parsing
    // --dangerously-skip-permissions allows file writes without interactive prompts
    const args = ['-p', '--output-format', 'json', '--dangerously-skip-permissions'];
    // Always use --continue for per-thread isolation since each thread has its own state dir
    if (useContinue || threadId) args.push('--continue');
    args.push(message);

    // Use project-specific directory if provided
    const workingDir = project ? path.join(PROJECTS_DIR, project) : PROJECTS_DIR;

    const proc = spawn('claude', args, {
      cwd: workingDir,
      env: getIsolatedCliEnv(threadId),
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    proc.stdin?.end();

    let killed = false;
    let buffer = '';
    let responseText = '';
    const reasoningSteps: string[] = [];
    const toolNames: string[] = [];
    const pendingHeaders = new Map<string, string>();
    let lastDisplay = '';

    proc.stdout?.on('data', (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const event = JSON.parse(line);

          if (event.type === 'thinking' && event.content) {
            reasoningSteps.push(event.content);
            sendThinkingStep(ws, event.content, threadId);
          } else if (event.type === 'tool_use') {
            const name = event.name || 'tool';
            const input = event.input || {};
            const toolId = event.id || '';
            if (!toolNames.includes(name)) toolNames.push(name);
            let display = '';

            if (name === 'Bash' && input.command) {
              const cmd = input.command.length > 60 ? input.command.substring(0, 60) + '...' : input.command;
              display = '\u25cf Bash(' + cmd + ')';
            } else if (name === 'Read' && input.file_path) {
              display = '\u25cf Reading ' + (input.file_path.split('/').pop() || input.file_path);
            } else if (name === 'Write' && input.file_path) {
              display = '\u25cf Creating ' + (input.file_path.split('/').pop() || input.file_path);
            } else if (name === 'Edit' && input.file_path) {
              display = '\u25cf Editing ' + (input.file_path.split('/').pop() || input.file_path);
            } else if ((name === 'Grep' || name === 'Glob') && input.pattern) {
              display = '\u25cf Searching ' + input.pattern.substring(0, 40);
            } else if (name === 'WebFetch' && input.url) {
              display = '\u25cf Fetching ' + input.url.substring(0, 50);
            }

            if (display && toolId) {
              pendingHeaders.set(toolId, display);
            }
          } else if (event.type === 'tool_result') {
            const toolId = event.id || '';
            const summary = event.summary || '';
            const header = pendingHeaders.get(toolId);
            if (header) {
              pendingHeaders.delete(toolId);
              if (header !== lastDisplay) {
                lastDisplay = header;
                sendThinkingStep(ws, header, threadId);
              }
              if (summary) {
                const isError = event.is_error || false;
                const prefix = isError ? '\u23bf  Error: ' : '\u23bf  ';
                sendThinkingStep(ws, prefix + summary, threadId);
              }
            }
          } else if (event.type === 'text' && event.content) {
            responseText += event.content;
          } else if (event.type === 'done') {
            if (event.response) responseText = event.response;
          } else if (event.type === 'result') {
            // claude -p --output-format json produces {type: "result", result: "..."}
            if (event.result) responseText = event.result;
          }
        } catch {
          // Non-JSON line
        }
      }
    });

    proc.stderr?.on('data', () => {});

    proc.on('close', () => {
      if (killed) return;
      if (buffer.trim()) {
        try {
          const event = JSON.parse(buffer);
          if (event.type === 'done' && event.response) {
            responseText = event.response;
          } else if (event.type === 'result' && event.result) {
            responseText = event.result;
          } else if (event.type === 'text' && event.content) {
            responseText += event.content;
          }
        } catch {}
      }
      resolve({ text: [responseText.trim() || 'Done'], reasoning: reasoningSteps, tools: toolNames });
    });

    proc.on('error', (err) => {
      if (!killed) reject(new Error('Claude: ' + err.message));
    });

    setTimeout(() => {
      if (!killed) {
        killed = true;
        proc.kill('SIGTERM');
        reject(new Error('Claude timeout (10 min limit reached)'));
      }
    }, CLI_ONESHOT_TIMEOUT_MS);
  });
}

// ============ Codex Streaming ============
export async function sendToCodexStreaming(
  message: string,
  ws: WsClient,
  useLast = false,
  threadId?: string | null,
  project?: string | null
): Promise<CliResponse> {
  return sendToCodexOneShot(message, ws, useLast, threadId, project);
}

// One-shot Codex — structured JSON output with thinking, tools, and reasoning persistence
async function sendToCodexOneShot(
  message: string,
  ws: WsClient,
  useLast = false,
  threadId?: string | null,
  project?: string | null
): Promise<CliResponse> {
  return new Promise((resolve, reject) => {
    // Pre-flight: ensure codex binary is installed
    try { requireCliBinary('codex'); } catch (e) { return reject(e); }

    const args = ['exec'];
    // Note: codex exec does NOT support --last; thread isolation is handled via getIsolatedCliEnv
    args.push('--json', '--skip-git-repo-check', '--dangerously-bypass-approvals-and-sandbox', message);

    // Use project-specific directory if provided
    const workingDir = project ? path.join(PROJECTS_DIR, project) : PROJECTS_DIR;

    const proc = spawn('codex', args, {
      cwd: workingDir,
      env: getIsolatedCliEnv(threadId),
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    proc.stdin?.end();

    let killed = false;
    let buffer = '';
    const response: CliResponse = { reasoning: [], text: [], tools: [] };

    proc.stdout?.on('data', (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const event = JSON.parse(line);
          const item = event.item;

          // Codex exec --json format: { type: "item.completed", item: { type: "agent_message", text: "..." } }
          const itemType = item?.type || item?.details?.type;
          const itemText = item?.text || item?.details?.text;

          if (!itemType) continue;

          if (itemType === 'reasoning' && itemText) {
            if (event.type === 'item.completed' || event.type === 'item_completed' || event.type === 'item.started' || event.type === 'item_started') {
              response.reasoning.push(itemText);
              sendThinkingStep(ws, itemText, threadId);
            }
          } else if (itemType === 'agent_message' && itemText) {
            if (event.type === 'item.completed' || event.type === 'item_completed') {
              // Send previous agent_messages as thinking steps, only keep latest for final output
              if (response.text.length > 0) {
                sendThinkingStep(ws, response.text[response.text.length - 1]!, threadId);
              }
              // Replace — only the last agent_message becomes the final response
              response.text = [itemText];
            }
          } else if (itemType === 'command_execution') {
            const details = item?.details || item;
            const cmd = details.command || 'command';
            if (!response.tools.includes(cmd)) response.tools.push(cmd);
            if (event.type === 'item.started' || event.type === 'item_started' || details.status === 'in_progress') {
              sendThinkingStep(ws, 'Running: ' + cmd, threadId);
            } else if (event.type === 'item.completed' || event.type === 'item_completed') {
              sendThinkingStep(ws, cmd + ' done (exit ' + (details.exit_code || 0) + ')', threadId);
            }
          } else if (itemType === 'file_change') {
            const details = item?.details || item;
            const changes = details.changes || [];
            for (const c of changes) {
              const label = (c.kind || 'edit') + ' ' + (c.path || 'file');
              if (!response.tools.includes(label)) response.tools.push(label);
              if (event.type === 'item.started' || event.type === 'item_started') {
                sendThinkingStep(ws, label + '...', threadId);
              }
            }
          } else if (itemType === 'mcp_tool_call') {
            const details = item?.details || item;
            const toolName = details.tool || 'mcp_tool';
            if (!response.tools.includes(toolName)) response.tools.push(toolName);
            if (event.type === 'item.started' || event.type === 'item_started') {
              sendThinkingStep(ws, 'Using ' + toolName + '...', threadId);
            } else if (event.type === 'item.completed' || event.type === 'item_completed') {
              sendThinkingStep(ws, toolName + ' done', threadId);
            }
          } else if (itemType === 'web_search' && (item?.query || item?.details?.query)) {
            const query = item?.query || item?.details?.query;
            response.tools.push('search: ' + query);
            sendThinkingStep(ws, 'Searching: ' + query, threadId);
          }
        } catch {
          // Non-JSON line
        }
      }
    });

    let stderr = '';
    proc.stderr?.on('data', (data) => (stderr += data.toString()));

    proc.on('close', () => {
      if (killed) return;
      if (buffer.trim()) {
        try {
          const event = JSON.parse(buffer);
          const item = event.item;
          const itemType = item?.type || item?.details?.type;
          const itemText = item?.text || item?.details?.text;
          if (itemType === 'agent_message' && itemText) {
            response.text.push(itemText);
          }
        } catch {}
      }
      if (response.text.length === 0) {
        response.text.push(stderr.trim() || 'Done');
      }
      resolve(response);
    });

    proc.on('error', (err) => {
      if (!killed) reject(new Error('Codex: ' + err.message));
    });

    setTimeout(() => {
      if (!killed) {
        killed = true;
        proc.kill('SIGTERM');
        reject(new Error('Codex timeout (10 min limit reached)'));
      }
    }, CLI_ONESHOT_TIMEOUT_MS);
  });
}

// ============ Gemini Streaming ============
export async function sendToGeminiStreaming(
  message: string,
  ws: WsClient,
  useResume = false,
  threadId?: string | null,
  project?: string | null
): Promise<CliResponse> {
  return sendToGeminiOneShot(message, ws, useResume, threadId, project);
}

// One-shot Gemini — structured JSON output with thinking, tools, and reasoning persistence
async function sendToGeminiOneShot(
  message: string,
  ws: WsClient,
  useResume = false,
  threadId?: string | null,
  project?: string | null
): Promise<CliResponse> {
  return new Promise((resolve, reject) => {
    // Pre-flight: ensure gemini binary is installed
    try { requireCliBinary('gemini'); } catch (e) { return reject(e); }

    const args = ['-p', message, '--output-format', 'stream-json'];
    // Always use --resume for per-thread isolation since each thread has its own state dir
    if (useResume || threadId) args.push('--resume');

    // Use project-specific directory if provided
    const workingDir = project ? path.join(PROJECTS_DIR, project) : PROJECTS_DIR;

    const proc = spawn('gemini', args, {
      cwd: workingDir,
      env: getIsolatedCliEnv(threadId),
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    proc.stdin?.end();

    let killed = false;
    let buffer = '';
    const reasoningSteps: string[] = [];
    const response: CliResponse = { reasoning: [], text: [], tools: [] };

    proc.stdout?.on('data', (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const event = JSON.parse(line);

          if ((event.type === 'thinking' || event.thought === true) && (event.content || event.text)) {
            const thinkingText = event.content || event.text;
            reasoningSteps.push(thinkingText);
            sendThinkingStep(ws, thinkingText, threadId);
          } else if (event.type === 'tool_use') {
            const toolName = event.name || event.tool || 'tool';
            if (!response.tools.includes(toolName)) response.tools.push(toolName);
            sendThinkingStep(ws, 'Using ' + toolName + '...', threadId);
          } else if (event.type === 'tool_result') {
            const toolName = event.name || event.tool || 'tool';
            const status = event.error ? 'failed' : 'done';
            sendThinkingStep(ws, toolName + ' ' + status, threadId);
          } else if (event.type === 'message' && event.role === 'assistant' && event.content) {
            if (event.delta) {
              if (response.text.length === 0) response.text.push('');
              response.text[response.text.length - 1] += event.content;
            } else {
              response.text.push(event.content);
            }
          }
        } catch {
          if (line.trim()) {
            if (response.text.length === 0) response.text.push('');
            response.text[response.text.length - 1] += line.trim() + '\n';
          }
        }
      }
    });

    let stderr = '';
    proc.stderr?.on('data', (data) => (stderr += data.toString()));

    proc.on('close', () => {
      if (killed) return;
      if (buffer.trim()) {
        try {
          const event = JSON.parse(buffer);
          if (event.type === 'message' && event.role === 'assistant' && event.content) {
            response.text.push(event.content);
          }
        } catch {
          if (buffer.trim()) response.text.push(buffer.trim());
        }
      }
      if (response.text.length === 0) {
        response.text.push(stderr.trim() || 'Done');
      }
      response.reasoning = reasoningSteps;
      resolve(response);
    });

    proc.on('error', (err) => {
      if (!killed) reject(new Error('Gemini: ' + err.message));
    });

    setTimeout(() => {
      if (!killed) {
        killed = true;
        proc.kill('SIGTERM');
        reject(new Error('Gemini timeout (10 min limit reached)'));
      }
    }, CLI_ONESHOT_TIMEOUT_MS);
  });
}

// ============ Provider/Model Management ============
export async function getProviders(): Promise<{
  providers: unknown[];
  connected: unknown[];
  currentModel: string | null;
  zenModels: ZenModel[];
}> {
  const result = await httpRequest({
    hostname: '127.0.0.1',
    port: OPENCODE_API_PORT,
    path: '/provider',
    method: 'GET',
  });
  const config = await httpRequest({
    hostname: '127.0.0.1',
    port: OPENCODE_API_PORT,
    path: '/config',
    method: 'GET',
  });
  const data = result.data as { all?: unknown[]; connected?: unknown[] } | null;
  const configData = config.data as { model?: string } | null;
  return {
    providers: data?.all || [],
    connected: data?.connected || [],
    currentModel: configData?.model || null,
    zenModels: getZenModelList(),
  };
}

export async function setApiKey(provider: string, key: string): Promise<boolean> {
  const result = await httpRequest(
    {
      hostname: '127.0.0.1',
      port: OPENCODE_API_PORT,
      path: '/auth/' + encodeURIComponent(provider),
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
    },
    { type: 'api', key }
  );
  return result.status === 200;
}

export async function setModel(model: string): Promise<boolean> {
  const configPath = path.join(process.env.HOME || '/root', '.config', 'opencode', 'config.json');

  // Build the config object — only opencode/ models are supported
  const config: Record<string, unknown> = {
    $schema: 'https://opencode.ai/config.json',
    model,
  };

  try {
    // Write config file and restart OpenCode so it picks up the new model.
    // Sessions persist in OpenCode's SQLite DB across restarts.
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
    console.log(`[OpenCode] Wrote config with model=${model}`);

    // Kill existing OpenCode process
    try {
      execSync('kill $(pgrep -x opencode) 2>/dev/null; true', { timeout: 3000 });
    } catch {
      // Process may not be running
    }
    opencodeReady = false;
    resetOpencodeSession();

    // Wait for it to die
    await new Promise((r) => setTimeout(r, 1000));

    // Restart — reuse the same startup logic as ensureOpencodeServer
    spawn('bash', ['-c', `cd ${PROJECTS_DIR} && ${OPENCODE_BIN} serve --port ${OPENCODE_API_PORT} &`], {
      detached: true,
      stdio: 'ignore',
    }).unref();

    // Wait for server to come back up
    for (let i = 0; i < 20; i++) {
      await new Promise((r) => setTimeout(r, 500));
      try {
        const check = await httpRequest({
          hostname: '127.0.0.1',
          port: OPENCODE_API_PORT,
          path: '/session',
          method: 'GET',
          timeout: 1000,
        });
        if (check.status === 200) {
          console.log(`[OpenCode] Restarted with model=${model}`);
          opencodeReady = true;
          return true;
        }
      } catch {}
    }
    console.error('[OpenCode] Failed to restart after model change');
    return false;
  } catch (err) {
    console.error('[OpenCode] setModel error:', (err as Error).message);
    return false;
  }
}

export async function getCurrentModel(): Promise<string | null> {
  const config = await httpRequest({
    hostname: '127.0.0.1',
    port: OPENCODE_API_PORT,
    path: '/config',
    method: 'GET',
  });
  const data = config.data as { model?: string } | null;
  return data?.model || null;
}
