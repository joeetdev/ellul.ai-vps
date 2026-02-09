/**
 * Vibe CLI Session Manager
 *
 * Enterprise-grade persistent CLI session management for vibe chat threads.
 * Each thread gets its own running CLI process with full conversation memory.
 *
 * Architecture:
 * - CLI runs in tmux session (persistent, survives disconnects)
 * - Messages sent via tmux send-keys
 * - Output captured via tmux capture-pane with ANSI stripping
 * - Intelligent response detection with multiple prompt patterns
 *
 * Robustness features:
 * - Thread-safe session creation with locking
 * - Automatic session recovery on CLI crash
 * - Health monitoring and stale session cleanup
 * - Comprehensive error handling and logging
 * - Input sanitization to prevent injection
 * - Graceful degradation when tmux unavailable
 */

import { spawn, execSync, spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { PROJECTS_DIR, CONTEXT_DIR } from '../config';
import { getCliSpawnEnv } from './cli-env.service';
import { ensureThreadStateDir, withThreadLock } from './thread.service';
import { loadGlobalContext, loadAppContext } from './context.service';

// Session types for vibe chat
export type VibeSessionType = 'claude' | 'codex' | 'gemini';

// Session states
type SessionState = 'creating' | 'ready' | 'busy' | 'error' | 'dead';

// Active CLI sessions
interface VibeCliSession {
  threadId: string;
  sessionType: VibeSessionType;
  project?: string;
  tmuxSession: string;
  createdAt: number;
  lastAccessed: number;
  lastHealthCheck: number;
  state: SessionState;
  messageCount: number;
  errorCount: number;
}

const activeSessions = new Map<string, VibeCliSession>();
const sessionLocks = new Map<string, Promise<void>>();

// CLI commands and their prompt patterns (multiple patterns for robustness)
const CLI_CONFIG: Record<VibeSessionType, {
  command: string;
  args: string[];
  promptPatterns: RegExp[];
  startupTimeoutMs: number;
  responseTimeoutMs: number;
}> = {
  claude: {
    command: 'claude',
    args: ['--dangerously-skip-permissions', '--continue'],  // Allow file writes, continue existing conversation
    // Multiple patterns: standard prompt, path prompt, waiting indicator
    promptPatterns: [
      /^>\s*$/m,
      /^[\/~].*>\s*$/m,
      /^\s*claude>\s*$/mi,
      /^Enter your message/mi,
      /❯\s*Try/m,  // New Claude CLI format: ❯ Try "how does <filepath> work?"
      /\?\s*for shortcuts/m,  // New Claude CLI format: ? for shortcuts
    ],
    startupTimeoutMs: 60000, // Claude can take a while to start
    responseTimeoutMs: 600000, // 10 minutes for long responses
  },
  codex: {
    command: 'codex',
    args: [],
    promptPatterns: [
      /^>\s*$/m,
      /^codex>\s*$/mi,
      /^\s*\$\s*$/m,
    ],
    startupTimeoutMs: 30000,
    responseTimeoutMs: 600000,
  },
  gemini: {
    command: 'gemini',
    args: [],
    promptPatterns: [
      /^>\s*$/m,
      /^gemini>\s*$/mi,
      /^\s*\$\s*$/m,
    ],
    startupTimeoutMs: 30000,
    responseTimeoutMs: 600000,
  },
};

// Health check interval (5 minutes)
const HEALTH_CHECK_INTERVAL_MS = 5 * 60 * 1000;

// Maximum consecutive errors before marking session dead
const MAX_ERROR_COUNT = 3;

// Verify tmux is available on startup
let tmuxAvailable = false;
try {
  execSync('which tmux', { stdio: 'ignore' });
  tmuxAvailable = true;
  console.log('[VibeCLI] tmux available');
} catch {
  console.error('[VibeCLI] WARNING: tmux not available - persistent sessions disabled');
}

/**
 * Get or create a persistent CLI session for a thread.
 * Uses thread locking to prevent race conditions.
 * @param threadId - The thread ID for session isolation
 * @param sessionType - The CLI type (claude, codex, gemini)
 * @param project - Optional project name to scope the working directory
 */
export async function getOrCreateVibeSession(
  threadId: string,
  sessionType: VibeSessionType,
  project?: string
): Promise<VibeCliSession | null> {
  if (!tmuxAvailable) {
    console.warn('[VibeCLI] tmux not available, cannot create session');
    return null;
  }

  // Include project in session key so each app gets its own persistent session
  const sessionKey = `${threadId}-${sessionType}-${project || 'root'}`;

  // Use locking to prevent concurrent session creation
  return withSessionLock(sessionKey, async () => {
    // Check for existing session
    const existing = activeSessions.get(sessionKey);
    if (existing) {
      // Health check the session
      if (await isSessionHealthy(existing)) {
        existing.lastAccessed = Date.now();
        return existing;
      }
      // Session unhealthy, clean up and recreate
      console.log(`[VibeCLI] Session ${sessionKey} unhealthy, recreating`);
      await cleanupSession(existing);
      activeSessions.delete(sessionKey);
    }

    // Create new session
    return createNewSession(threadId, sessionType, sessionKey, project);
  });
}

/**
 * Send a message to a vibe CLI session and get the response.
 * Handles retries and session recovery automatically.
 * @param threadId - The thread ID for session isolation
 * @param sessionType - The CLI type (claude, codex, gemini)
 * @param message - The message to send
 * @param onChunk - Optional callback for streaming chunks
 * @param project - Optional project name to scope the working directory
 */
export async function sendToVibeSession(
  threadId: string,
  sessionType: VibeSessionType,
  message: string,
  onChunk?: (chunk: string) => void,
  project?: string
): Promise<{ text: string; tools: string[] }> {
  // Validate input
  if (!message || typeof message !== 'string') {
    throw new Error('Invalid message: must be a non-empty string');
  }

  const session = await getOrCreateVibeSession(threadId, sessionType, project);
  if (!session) {
    throw new Error(`Failed to get ${sessionType} session for thread (tmux unavailable or session creation failed)`);
  }

  const config = CLI_CONFIG[sessionType];
  const sessionKey = `${threadId}-${sessionType}-${project || 'root'}`;

  // Mark session as busy
  session.state = 'busy';

  try {
    // Clear history for clean capture
    safeExecSync(`tmux clear-history -t ${escapeTmuxTarget(session.tmuxSession)}`);

    // Small delay to ensure clear completes
    await sleep(100);

    // Capture baseline content
    const baselineContent = captureTmuxPane(session.tmuxSession);

    // Send the message
    sendToTmux(session.tmuxSession, message);

    // Wait for response with streaming
    const response = await waitForResponse(
      session.tmuxSession,
      config.promptPatterns,
      baselineContent,
      onChunk,
      config.responseTimeoutMs
    );

    // Success - update stats
    session.state = 'ready';
    session.lastAccessed = Date.now();
    session.messageCount++;
    session.errorCount = 0;

    console.log(`[VibeCLI] ${sessionType} response received (${response.length} chars) for thread ${threadId.substring(0, 8)}...`);

    return {
      text: response.trim(),
      tools: parseToolUsage(response),
    };
  } catch (err) {
    session.errorCount++;
    const errorMsg = (err as Error).message;
    console.error(`[VibeCLI] Error in ${sessionType} session for thread ${threadId.substring(0, 8)}...:`, errorMsg);

    // Check if we should mark session as dead
    if (session.errorCount >= MAX_ERROR_COUNT) {
      console.error(`[VibeCLI] Session ${sessionKey} exceeded error limit, marking as dead`);
      session.state = 'dead';
      // Try to clean up
      await cleanupSession(session);
      activeSessions.delete(sessionKey);
    } else {
      session.state = 'error';
    }

    throw err;
  }
}

/**
 * Close a vibe CLI session for a thread.
 */
export async function closeVibeSession(threadId: string, sessionType?: VibeSessionType): Promise<void> {
  if (sessionType) {
    const sessionKey = `${threadId}-${sessionType}`;
    const session = activeSessions.get(sessionKey);
    if (session) {
      await cleanupSession(session);
      activeSessions.delete(sessionKey);
      console.log(`[VibeCLI] Closed ${sessionType} session for thread ${threadId.substring(0, 8)}...`);
    }
  } else {
    // Close all sessions for this thread
    const toDelete: string[] = [];
    for (const [key, session] of activeSessions) {
      if (session.threadId === threadId) {
        await cleanupSession(session);
        toDelete.push(key);
        console.log(`[VibeCLI] Closed ${session.sessionType} session for thread ${threadId.substring(0, 8)}...`);
      }
    }
    for (const key of toDelete) {
      activeSessions.delete(key);
    }
  }
}

/**
 * Close all vibe CLI sessions (for shutdown).
 */
export function closeAllVibeSessions(): void {
  console.log(`[VibeCLI] Shutting down ${activeSessions.size} sessions`);
  for (const session of activeSessions.values()) {
    try {
      killTmuxSession(session.tmuxSession);
    } catch (err) {
      console.error(`[VibeCLI] Error closing session ${session.tmuxSession}:`, (err as Error).message);
    }
  }
  activeSessions.clear();
}

/**
 * List active vibe CLI sessions.
 */
export function listVibeSessions(): Array<{
  threadId: string;
  sessionType: VibeSessionType;
  state: SessionState;
  messageCount: number;
  createdAt: number;
}> {
  return Array.from(activeSessions.values()).map((s) => ({
    threadId: s.threadId,
    sessionType: s.sessionType,
    state: s.state,
    messageCount: s.messageCount,
    createdAt: s.createdAt,
  }));
}

/**
 * Run health checks on all sessions (call periodically).
 */
export async function healthCheckAllSessions(): Promise<void> {
  const now = Date.now();
  const toRemove: string[] = [];

  for (const [key, session] of activeSessions) {
    // Skip recently checked sessions
    if (now - session.lastHealthCheck < HEALTH_CHECK_INTERVAL_MS) continue;

    session.lastHealthCheck = now;

    if (!(await isSessionHealthy(session))) {
      console.log(`[VibeCLI] Session ${key} failed health check, removing`);
      await cleanupSession(session);
      toRemove.push(key);
    }
  }

  for (const key of toRemove) {
    activeSessions.delete(key);
  }
}

// Start periodic health checks
setInterval(() => {
  healthCheckAllSessions().catch((err) => {
    console.error('[VibeCLI] Health check error:', (err as Error).message);
  });
}, HEALTH_CHECK_INTERVAL_MS);

// ============ Internal Functions ============

/**
 * Session-level locking to prevent race conditions.
 */
async function withSessionLock<T>(sessionKey: string, fn: () => Promise<T>): Promise<T> {
  // Wait for any existing lock
  const existingLock = sessionLocks.get(sessionKey);
  if (existingLock) {
    await existingLock;
  }

  // Create new lock
  let unlock: () => void;
  const lockPromise = new Promise<void>((resolve) => {
    unlock = resolve;
  });
  sessionLocks.set(sessionKey, lockPromise);

  try {
    return await fn();
  } finally {
    unlock!();
    sessionLocks.delete(sessionKey);
  }
}

/**
 * Create a new CLI session.
 */
async function createNewSession(
  threadId: string,
  sessionType: VibeSessionType,
  sessionKey: string,
  project?: string
): Promise<VibeCliSession | null> {
  // Generate safe tmux session name (alphanumeric + hyphen only)
  const safeThreadId = threadId.replace(/[^a-zA-Z0-9]/g, '').substring(0, 8);
  const tmuxSession = `vibe-${safeThreadId}-${sessionType}-${Date.now()}`;

  const session: VibeCliSession = {
    threadId,
    sessionType,
    project,
    tmuxSession,
    createdAt: Date.now(),
    lastAccessed: Date.now(),
    lastHealthCheck: Date.now(),
    state: 'creating',
    messageCount: 0,
    errorCount: 0,
  };

  try {
    // Ensure thread state directory exists
    const threadStateDir = ensureThreadStateDir(threadId);

    // Create tmux session with CLI
    const config = CLI_CONFIG[sessionType];
    await createTmuxCliSession(tmuxSession, sessionType, config, threadStateDir, project);

    // Wait for CLI to be ready
    await waitForCliReady(tmuxSession, config.promptPatterns, config.startupTimeoutMs);

    session.state = 'ready';
    activeSessions.set(sessionKey, session);

    console.log(`[VibeCLI] Created ${sessionType} session (${tmuxSession}) for thread ${threadId.substring(0, 8)}...`);
    return session;
  } catch (err) {
    console.error(`[VibeCLI] Failed to create ${sessionType} session:`, (err as Error).message);
    // Clean up failed session
    killTmuxSession(tmuxSession);
    return null;
  }
}

/**
 * Check if a session is healthy.
 */
async function isSessionHealthy(session: VibeCliSession): Promise<boolean> {
  // Check if tmux session exists
  if (!tmuxSessionExists(session.tmuxSession)) {
    console.log(`[VibeCLI] Session ${session.tmuxSession} tmux session does not exist`);
    return false;
  }

  // Check if session is in dead or error state with high error count
  if (session.state === 'dead') {
    return false;
  }

  // Check if CLI process is still running by looking for shell prompt
  const content = captureTmuxPane(session.tmuxSession);
  if (!content || content.trim().length === 0) {
    console.log(`[VibeCLI] Session ${session.tmuxSession} has no content`);
    return false;
  }

  // Look for signs the CLI crashed (bash prompt, error messages)
  if (/\$\s*$/.test(content) && !/^(claude|codex|gemini)/mi.test(content)) {
    console.log(`[VibeCLI] Session ${session.tmuxSession} appears to have crashed to shell`);
    return false;
  }

  return true;
}

/**
 * Clean up a session.
 */
async function cleanupSession(session: VibeCliSession): Promise<void> {
  try {
    // Send quit command first for graceful shutdown
    try {
      sendToTmux(session.tmuxSession, '/exit');
      await sleep(500);
    } catch {
      // Ignore errors
    }

    // Kill tmux session
    killTmuxSession(session.tmuxSession);
  } catch (err) {
    console.error(`[VibeCLI] Error cleaning up session ${session.tmuxSession}:`, (err as Error).message);
  }
}

/**
 * Check if a tmux session exists.
 */
function tmuxSessionExists(sessionName: string): boolean {
  const result = spawnSync('tmux', ['has-session', '-t', sessionName], {
    stdio: 'ignore',
    timeout: 5000,
  });
  return result.status === 0;
}

/**
 * Create a tmux session running a CLI.
 */
async function createTmuxCliSession(
  tmuxSession: string,
  sessionType: VibeSessionType,
  config: { command: string; args: string[] },
  threadStateDir: string,
  project?: string
): Promise<void> {
  // Ensure CLAUDE.md context files are available for CLI to read
  setupContextFiles(project);

  // Build environment with isolated HOME for the thread
  const env = getIsolatedEnv(threadStateDir);

  // Build the command to run inside tmux
  const cliCommand = [config.command, ...config.args].join(' ');

  // Determine working directory - scope to project if specified
  const workingDir = project ? path.join(PROJECTS_DIR, project) : PROJECTS_DIR;

  // Create a wrapper script that sets up environment and runs CLI
  const wrapperScript = `
    cd "${workingDir}" || exit 1
    export HOME="${threadStateDir}"
    export XDG_CONFIG_HOME="${threadStateDir}"
    export XDG_DATA_HOME="${threadStateDir}"
    export XDG_STATE_HOME="${threadStateDir}"
    export XDG_CACHE_HOME="${path.join(threadStateDir, '.cache')}"
    export ELLULAI_REAL_HOME="${process.env.HOME || '/home/dev'}"
    exec ${cliCommand}
  `.trim();

  // Create tmux session
  const result = spawnSync('tmux', [
    'new-session',
    '-d',
    '-s', tmuxSession,
    '-x', '200',
    '-y', '50',
    'bash', '-c', wrapperScript,
  ], {
    stdio: 'ignore',
    env: { ...process.env, ...env },
    timeout: 10000,
  });

  if (result.status !== 0) {
    throw new Error(`tmux new-session failed with status ${result.status}`);
  }

  // Verify session was created
  await sleep(500);
  if (!tmuxSessionExists(tmuxSession)) {
    throw new Error('tmux session was not created');
  }
}

/**
 * Wait for CLI to show its prompt (ready for input).
 */
async function waitForCliReady(
  tmuxSession: string,
  promptPatterns: RegExp[],
  timeoutMs: number
): Promise<void> {
  const startTime = Date.now();
  let lastContent = '';
  let trustedFolderHandled = false;

  while (Date.now() - startTime < timeoutMs) {
    const content = captureTmuxPane(tmuxSession);

    // Log progress for debugging
    if (content !== lastContent) {
      const preview = content.slice(-200).replace(/\n/g, '\\n');
      console.log(`[VibeCLI] Waiting for prompt, content: ...${preview}`);
      lastContent = content;
    }

    // Check for "Trust this folder" prompt and auto-confirm
    if (!trustedFolderHandled && /Yes, I trust this folder|trust this folder/i.test(content)) {
      console.log(`[VibeCLI] Detected trust folder prompt, auto-confirming...`);
      // Send Enter to confirm the default selection (option 1: Yes, I trust this folder)
      sendToTmux(tmuxSession, '');
      trustedFolderHandled = true;
      await sleep(1000);
      continue;
    }

    // Check for any prompt pattern
    for (const pattern of promptPatterns) {
      if (pattern.test(content)) {
        console.log(`[VibeCLI] CLI ready (matched prompt pattern)`);
        return;
      }
    }

    // Check for error indicators
    if (/error|failed|not found|command not found/i.test(content)) {
      const errorLine = content.split('\n').find(l => /error|failed/i.test(l)) || 'Unknown error';
      throw new Error(`CLI startup error: ${errorLine.substring(0, 100)}`);
    }

    await sleep(500);
  }

  throw new Error(`CLI did not become ready within ${timeoutMs}ms timeout`);
}

/**
 * Wait for CLI response and return the output.
 */
async function waitForResponse(
  tmuxSession: string,
  promptPatterns: RegExp[],
  baselineContent: string,
  onChunk?: (chunk: string) => void,
  timeoutMs = 300000
): Promise<string> {
  const startTime = Date.now();
  let lastContent = baselineContent;
  let stableCount = 0;
  let lastChunkSent = '';

  while (Date.now() - startTime < timeoutMs) {
    const rawContent = captureTmuxPane(tmuxSession);
    const content = stripAnsi(rawContent);

    // Check if there's new content
    if (content !== lastContent) {
      // Send new content as chunks
      if (onChunk) {
        const newContent = content.slice(lastContent.length);
        // Deduplicate chunks
        if (newContent && newContent !== lastChunkSent) {
          onChunk(cleanChunk(newContent));
          lastChunkSent = newContent;
        }
      }
      lastContent = content;
      stableCount = 0;
    } else {
      stableCount++;
    }

    // Check if CLI is showing prompt (response complete)
    // Need content to be stable for a bit to avoid false positives
    if (stableCount >= 3) {
      const lines = content.split('\n');
      const lastNonEmptyLine = [...lines].reverse().find(l => l.trim()) || '';

      for (const pattern of promptPatterns) {
        if (pattern.test(lastNonEmptyLine)) {
          // Response complete
          const response = extractResponse(content, baselineContent);
          return response;
        }
      }
    }

    // Check for error indicators mid-response
    if (/fatal error|panic|segmentation fault/i.test(content)) {
      throw new Error('CLI encountered a fatal error');
    }

    await sleep(150);
  }

  // Timeout - return what we have
  console.warn(`[VibeCLI] Response timeout after ${timeoutMs}ms, returning partial response`);
  return extractResponse(lastContent, baselineContent);
}

/**
 * Extract the response from CLI output.
 */
function extractResponse(fullContent: string, baselineContent: string): string {
  // Remove baseline content
  let response = fullContent;
  if (fullContent.startsWith(baselineContent)) {
    response = fullContent.slice(baselineContent.length);
  }

  // Strip ANSI codes
  response = stripAnsi(response);

  // Split into lines
  const lines = response.split('\n');

  // Remove empty lines at start/end
  while (lines.length > 0 && !lines[0]?.trim()) lines.shift();
  while (lines.length > 0 && !lines[lines.length - 1]?.trim()) lines.pop();

  // Remove prompt lines at the end
  while (lines.length > 0) {
    const lastLine = lines[lines.length - 1]?.trim() || '';
    if (/^(>|\S*>|\$)\s*$/.test(lastLine) || lastLine === '') {
      lines.pop();
    } else {
      break;
    }
  }

  // Remove echoed input (first line if it's short)
  if (lines.length > 1) {
    const firstLine = lines[0]?.trim() || '';
    // If first line is short and doesn't look like content, it's probably the echoed input
    if (firstLine.length < 200 && !firstLine.includes('\n')) {
      lines.shift();
    }
  }

  return lines.join('\n').trim();
}

/**
 * Parse tool usage from response.
 */
function parseToolUsage(response: string): string[] {
  const tools: string[] = [];

  // Look for common tool usage patterns
  const toolPatterns = [
    /Running (\w+)/gi,
    /Using (\w+)/gi,
    /Executing (\w+)/gi,
    /\[(\w+)\] (started|completed|done)/gi,
  ];

  for (const pattern of toolPatterns) {
    let match;
    while ((match = pattern.exec(response)) !== null) {
      const tool = match[1];
      if (tool && !tools.includes(tool)) {
        tools.push(tool);
      }
    }
  }

  return tools;
}

/**
 * Send text to a tmux session safely.
 */
function sendToTmux(sessionName: string, text: string): void {
  // Use tmux send-keys with literal mode to avoid interpretation
  const result = spawnSync('tmux', [
    'send-keys',
    '-t', escapeTmuxTarget(sessionName),
    '-l', text, // -l for literal mode
  ], {
    stdio: 'ignore',
    timeout: 5000,
  });

  if (result.status !== 0) {
    throw new Error(`tmux send-keys failed with status ${result.status}`);
  }

  // Send Enter separately
  spawnSync('tmux', ['send-keys', '-t', escapeTmuxTarget(sessionName), 'Enter'], {
    stdio: 'ignore',
    timeout: 5000,
  });
}

/**
 * Capture the current pane content from tmux.
 */
function captureTmuxPane(sessionName: string): string {
  const result = spawnSync('tmux', [
    'capture-pane',
    '-t', escapeTmuxTarget(sessionName),
    '-p',     // Print to stdout
    '-S', '-1000', // Start from line -1000 (history)
    '-E', '-1',    // End at last line
  ], {
    encoding: 'utf-8',
    maxBuffer: 2 * 1024 * 1024, // 2MB buffer
    timeout: 10000,
  });

  if (result.status !== 0) {
    return '';
  }

  return result.stdout || '';
}

/**
 * Kill a tmux session.
 */
function killTmuxSession(sessionName: string): void {
  spawnSync('tmux', ['kill-session', '-t', escapeTmuxTarget(sessionName)], {
    stdio: 'ignore',
    timeout: 5000,
  });
}

/**
 * Escape tmux target name for safety.
 */
function escapeTmuxTarget(name: string): string {
  // Only allow alphanumeric, hyphen, underscore
  return name.replace(/[^a-zA-Z0-9\-_]/g, '');
}

/**
 * Strip ANSI escape codes from text.
 */
function stripAnsi(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g, '');
}

/**
 * Clean chunk for streaming output.
 */
function cleanChunk(chunk: string): string {
  return stripAnsi(chunk).replace(/\r/g, '');
}

/**
 * Safe execSync wrapper.
 */
function safeExecSync(command: string): void {
  try {
    execSync(command, { stdio: 'ignore', timeout: 5000 });
  } catch {
    // Ignore errors
  }
}

/**
 * Sleep helper.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Get environment with isolated HOME for thread.
 */
function getIsolatedEnv(threadStateDir: string): NodeJS.ProcessEnv {
  const baseEnv = getCliSpawnEnv();
  const realHome = process.env.HOME || '/home/dev';

  // Setup symlinks for auth files
  setupAuthSymlinks(threadStateDir, realHome);

  return {
    ...baseEnv,
    HOME: threadStateDir,
    XDG_CONFIG_HOME: threadStateDir,
    XDG_DATA_HOME: threadStateDir,
    XDG_STATE_HOME: threadStateDir,
    XDG_CACHE_HOME: path.join(threadStateDir, '.cache'),
    ELLULAI_REAL_HOME: realHome,
    // Disable interactive prompts
    CI: 'true',
    NONINTERACTIVE: '1',
  };
}

/**
 * Setup symlinks from thread directory to real home for shared auth configs.
 */
function setupAuthSymlinks(threadDir: string, realHome: string): void {
  const symlinks = [
    // Claude Code auth
    '.claude.json',
    '.claude/settings.json',
    '.claude/.credentials.json',
    '.claude/statsig_user_id',
    // Codex auth
    '.codex/auth.json',
    '.codex/config.json',
    // Gemini auth
    '.gemini/credentials.json',
    '.gemini/config.json',
    // Shared config
    '.ellulai-env',
    '.config/gh/hosts.yml', // GitHub CLI auth
  ];

  for (const link of symlinks) {
    const srcPath = path.join(realHome, link);
    const destPath = path.join(threadDir, link);

    // Skip if source doesn't exist
    if (!fs.existsSync(srcPath)) continue;

    // Skip if destination already exists (symlink or file)
    try {
      fs.lstatSync(destPath);
      continue; // Already exists
    } catch {
      // Doesn't exist, create it
    }

    try {
      // Ensure parent directory exists
      const destDir = path.dirname(destPath);
      fs.mkdirSync(destDir, { recursive: true });

      // Create symlink
      fs.symlinkSync(srcPath, destPath);
    } catch (err) {
      // Log but don't fail - some symlinks are optional
      console.debug(`[VibeCLI] Failed to symlink ${link}:`, (err as Error).message);
    }
  }
}

// Marker constants for context file management
const MARKER_START = '<!-- ELLULAI:START';
const MARKER_END = '<!-- ELLULAI:END -->';

// Context file names that each CLI tool reads
const CONTEXT_FILES = ['CLAUDE.md', 'AGENTS.md', 'GEMINI.md'] as const;

/**
 * Write a marker-based context block to a file.
 * - If file exists WITH markers: replace content between markers
 * - If file exists WITHOUT markers: prepend generated block above existing content
 * - If file doesn't exist: create new file with generated block
 */
function writeMarkerFile(filePath: string, generatedBlock: string): void {
  if (fs.existsSync(filePath)) {
    const existing = fs.readFileSync(filePath, 'utf8');
    if (existing.includes(MARKER_START)) {
      // Replace content between markers
      const startIdx = existing.indexOf(MARKER_START);
      const endIdx = existing.indexOf(MARKER_END);
      if (startIdx !== -1 && endIdx !== -1) {
        const before = existing.substring(0, startIdx);
        const after = existing.substring(endIdx + MARKER_END.length);
        fs.writeFileSync(filePath, before + generatedBlock + after, 'utf8');
      }
    } else {
      // Prepend generated block above existing content
      fs.writeFileSync(filePath, generatedBlock + '\n\n' + existing, 'utf8');
    }
  } else {
    // Create new file
    fs.writeFileSync(filePath, generatedBlock + '\n', 'utf8');
  }
}

/**
 * Build the generated context block for a project.
 */
function buildContextBlock(projectPath: string, domain: string, appName?: string): string {
  const appNameLine = appName
    ? `2. **NAME PROTECTION**: This app is named "${appName}". The "name" field in ellulai.json is USER-DEFINED. NEVER change it. NEVER change the "name" field in package.json either.`
    : '2. **NAME PROTECTION**: The "name" field in ellulai.json and package.json is USER-DEFINED. NEVER change it.';

  // Check for deployment info
  let deploymentSection = '';
  const appsDir = path.join(process.env.HOME || '/home/dev', '.ellulai', 'apps');
  if (fs.existsSync(appsDir)) {
    try {
      const files = fs.readdirSync(appsDir);
      for (const file of files) {
        if (!file.endsWith('.json')) continue;
        const appFile = path.join(appsDir, file);
        const data = JSON.parse(fs.readFileSync(appFile, 'utf8')) as { projectPath?: string; name?: string; url?: string; port?: number };
        if (data.projectPath === projectPath) {
          deploymentSection = `\n## !! LIVE DEPLOYMENT — DO NOT CREATE A NEW ONE !!\nName: ${data.name} | URL: ${data.url} | Port: ${data.port}\nThis project is ALREADY deployed. To update: \`npm run build && pm2 restart ${data.name}\` or run \`ship\`.\nNEVER run ellulai-expose again for this project.\n`;
          break;
        }
      }
    } catch {}
  }

  return `<!-- ELLULAI:START — Auto-generated rules. Do not edit between these markers. -->
# ellul.ai (${domain})
Preview: https://dev.${domain} (port 3000) | Production: https://APPNAME-${domain}

## RULES (ALWAYS FOLLOW)
1. **WORKSPACE BOUNDARY**: All work MUST stay inside this directory (${projectPath}). NEVER create new directories under ~/projects/. NEVER modify files in other projects.
${appNameLine}
3. **SECURITY**: NEVER touch /etc/ellulai/*, ~/.ssh/authorized_keys, /var/lib/sovereign-shield/*, sovereign-shield/sshd services. Tampering = PERMANENT LOCKOUT with no recovery.
${deploymentSection}
## Setup (within THIS project)
1. Create/edit project files
2. If ellulai.json missing: create it with \`{ "type": "frontend", "previewable": true, "name": "My App", "summary": "..." }\`
   **The "name" field is USER-DEFINED. If ellulai.json already exists, NEVER change the "name" field — leave it as the user set it.**
3. Node.js: \`npm install\`
4. Static HTML (no framework): \`npx serve -l 3000\`
5. PM2: \`pm2 start npm --name preview -- run dev\` or \`pm2 start "npx serve -l 3000" --name preview\`
6. Verify: \`curl localhost:3000\` must return 200
7. Deploy: \`ship\`

## Dev Server Config (CRITICAL — preview won't work without this)
Vite: \`server: { host: true, port: 3000, allowedHosts: true }\`
Next.js: \`"dev": "next dev -H 0.0.0.0 -p 3000"\`
Other: bind to 0.0.0.0:3000

## STOP: Verification Required Before Completing
You MUST run these commands and confirm they pass:
- \`pm2 list\` → shows your app as "online"
- \`curl localhost:3000\` → returns 200 status
If verification fails:
- Missing deps? \`npm install\`
- Errors? \`pm2 logs preview --nostream\`
- Port conflict? \`pm2 delete preview\` and retry
Do NOT report task complete until verification passes!

## Rules
- Secrets: NEVER .env files (git hook blocks commits with them). Use Dashboard → process.env
- Ports: Dev=3000, Prod=3001+, Reserved=7681-7700
- Backend first: expose backend with \`ellulai-expose NAME PORT\` before frontend depends on it
- Databases: \`ellulai-install postgres|redis|mysql\` (warn user about RAM usage)
- DB GUI: user runs \`ssh -L 5432:localhost:5432 dev@${domain}\` from their machine

## Git (Code Backup)
Check \`git remote -v\` — if a remote exists, credentials are ready. If not, tell user to link a repo from Dashboard → Git tab.
\`git-flow backup\` | \`git-flow force-backup\` | \`git-flow pull\` | \`git-flow save\` | \`git-flow ship\` | \`git-flow branch\`
Standard git commands also work. NEVER configure git credentials manually (no SSH keys, no tokens).

## Commands
ship | ellulai-expose NAME PORT | ellulai-apps | ellulai-install postgres|redis|mysql | pm2 logs|restart|delete NAME
${MARKER_END}`;
}

/**
 * Setup context files (CLAUDE.md, AGENTS.md, GEMINI.md) for CLI tools to read.
 *
 * Each CLI tool reads its native context file:
 * - Claude Code: CLAUDE.md
 * - Codex / OpenCode: AGENTS.md
 * - Gemini CLI: GEMINI.md
 *
 * Uses marker-based approach so user content outside markers is preserved.
 */
export function setupContextFiles(project?: string): void {
  try {
    // Read domain
    let domain = 'YOUR-DOMAIN';
    try {
      const domainPath = '/etc/ellulai/domain';
      if (fs.existsSync(domainPath)) {
        domain = fs.readFileSync(domainPath, 'utf8').trim();
      }
    } catch {}

    // If a specific project is provided, set up context files in the project directory
    if (project) {
      const projectPath = path.join(PROJECTS_DIR, project);
      if (!fs.existsSync(projectPath)) return;

      // Read app name from ellulai.json
      let appName: string | undefined;
      try {
        const pjsonPath = path.join(projectPath, 'ellulai.json');
        if (fs.existsSync(pjsonPath)) {
          const pjson = JSON.parse(fs.readFileSync(pjsonPath, 'utf8')) as { name?: string };
          appName = pjson.name;
        }
      } catch {}

      const block = buildContextBlock(projectPath, domain, appName);

      // Write all three context files for the project
      for (const fileName of CONTEXT_FILES) {
        const filePath = path.join(projectPath, fileName);
        if (!fs.existsSync(filePath)) {
          // Only create if missing — the bash context script handles marker-based updates
          writeMarkerFile(filePath, block);
          try { fs.chownSync(filePath, 1000, 1000); } catch {} // dev:dev
          console.log(`[VibeCLI] Created ${fileName} for project ${project}`);
        }
      }
    }

    // Ensure global context files exist at projects root
    const globalBlock = buildContextBlock(PROJECTS_DIR, domain);
    for (const fileName of CONTEXT_FILES) {
      const filePath = path.join(PROJECTS_DIR, fileName);
      if (!fs.existsSync(filePath)) {
        writeMarkerFile(filePath, globalBlock);
        try { fs.chownSync(filePath, 1000, 1000); } catch {}
        console.log(`[VibeCLI] Created global ${fileName}`);
      }
    }

    // Ensure ~/.gemini/GEMINI.md exists for global Gemini context
    const realHome = process.env.HOME || '/home/dev';
    const geminiDir = path.join(realHome, '.gemini');
    const geminiGlobalPath = path.join(geminiDir, 'GEMINI.md');
    if (!fs.existsSync(geminiGlobalPath)) {
      try {
        fs.mkdirSync(geminiDir, { recursive: true });
        writeMarkerFile(geminiGlobalPath, globalBlock);
        console.log('[VibeCLI] Created global ~/.gemini/GEMINI.md');
      } catch {}
    }
  } catch (err) {
    console.error('[VibeCLI] Error setting up context files:', (err as Error).message);
  }
}

/**
 * Clean up orphaned vibe CLI sessions on startup.
 *
 * This handles the case where agent-bridge restarts but tmux sessions
 * are still running from the previous instance.
 *
 * Cleans up tmux sessions matching pattern: vibe-*
 */
export function cleanupOrphanedVibeSessions(): number {
  let killed = 0;

  try {
    const result = spawnSync('tmux', ['list-sessions', '-F', '#{session_name}'], {
      encoding: 'utf-8',
      timeout: 5000,
    });

    if (result.status === 0 && result.stdout) {
      const sessions = result.stdout.trim().split('\n').filter(s => s.startsWith('vibe-'));
      for (const session of sessions) {
        try {
          killTmuxSession(session);
          killed++;
          console.log(`[VibeCLI] Killed orphaned session: ${session}`);
        } catch {
          // Ignore errors
        }
      }
    }
  } catch {
    // tmux not running or no sessions
  }

  if (killed > 0) {
    console.log(`[VibeCLI] Startup cleanup: killed ${killed} orphaned tmux sessions`);
  }

  return killed;
}
