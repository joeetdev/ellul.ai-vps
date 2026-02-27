/**
 * Interactive CLI Service
 *
 * Handles interactive CLI setup flows for authentication:
 * - Claude: claude login
 * - Codex: codex login
 * - Gemini: gemini auth login
 *
 * Uses PTY for proper terminal emulation and parses TUI output
 * to present user-friendly prompts via WebSocket.
 */

import { spawn, ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { getCliSpawnEnv, loadCliEnv, saveCliKey } from './cli-env.service';
import { PROJECTS_DIR, INTERACTIVE_TIMEOUT_MS, MAX_BUFFER_SIZE, DEBOUNCE_MS } from '../config';
import { getThreadStateDir, addMessage } from './thread.service';
import { endProcessing } from './processing-state';

/**
 * Auth files that should be synced back to real home after successful authentication.
 * This ensures that authentication done in a thread's isolated directory
 * is available to all other threads via symlinks.
 */
const AUTH_FILES: Record<string, string[]> = {
  claude: ['.claude.json', '.claude/settings.json', '.claude/.credentials.json'],
  codex: ['.codex/auth.json', '.codex/config.json'],
  gemini: ['.gemini/credentials.json', '.gemini/config.json', '.config/gemini/credentials.json'],
};

/**
 * Sync auth files from thread directory back to real home.
 * This allows authentication done in one thread to be available to all others.
 */
function syncAuthToRealHome(session: string, threadId?: string | null): void {
  if (!threadId) return;

  const realHome = process.env.HOME || '/home/' + (process.env.USER || 'dev');
  const threadDir = getThreadStateDir(threadId);
  if (!threadDir) return;

  const files = AUTH_FILES[session] || [];

  for (const file of files) {
    const threadPath = path.join(threadDir, file);
    const realPath = path.join(realHome, file);

    // Skip if thread file doesn't exist
    if (!fs.existsSync(threadPath)) continue;

    // Skip if it's a symlink (already pointing to real home)
    try {
      const stats = fs.lstatSync(threadPath);
      if (stats.isSymbolicLink()) continue;
    } catch {
      continue;
    }

    try {
      // Ensure parent directory exists in real home
      const realDir = path.dirname(realPath);
      if (!fs.existsSync(realDir)) {
        fs.mkdirSync(realDir, { recursive: true });
      }

      // Copy auth file to real home (overwrite if exists)
      fs.copyFileSync(threadPath, realPath);
      console.log(`[Auth] Synced ${file} from thread to real home`);

      // Replace thread file with symlink to real home
      fs.unlinkSync(threadPath);
      fs.symlinkSync(realPath, threadPath);
      console.log(`[Auth] Created symlink for ${file} in thread`);
    } catch (err) {
      console.warn(`[Auth] Failed to sync ${file}:`, (err as Error).message);
    }
  }
}

// WebSocket client interface
interface WsClient {
  send(data: string): void;
}

// Interactive session state
interface InteractiveState {
  proc: ChildProcess;
  timeout: NodeJS.Timeout;
  session: string;
  awaitingResponse: boolean;
}

// Parsed CLI output
interface ParsedOutput {
  options: Array<{ number: string; label: string; description: string }>;
  selectionType: 'number' | 'arrow';
  activeArrowIdx: number;
  contextBefore: string[];
  contextAfter: string[];
  urls: string[];
  yesNoMatch: RegExpMatchArray | null;
  inputPrompt: string | undefined;
}

// Active interactive sessions per WebSocket
const interactiveSessions = new Map<WsClient, InteractiveState & { threadId?: string | null }>();

// Allowed interactive commands (whitelist only - prevents command injection)
const ALLOWED_INTERACTIVE_COMMANDS: Record<string, string[]> = {
  claude: ['claude', 'claude login'],
  codex: ['codex', 'codex login', 'codex login --device-auth'],
  gemini: ['gemini', 'gemini auth login', 'gemini'],
};

/**
 * Check if a CLI needs first-time setup (not authenticated/configured)
 */
export function checkCliNeedsSetup(session: string): boolean {
  try {
    switch (session) {
      case 'claude': {
        const home = process.env.HOME || '/home/' + (process.env.USER || 'dev');
        const claudeJson = path.join(home, '.claude.json');
        if (!fs.existsSync(claudeJson)) return true;
        const config = JSON.parse(fs.readFileSync(claudeJson, 'utf8'));
        // Check multiple auth indicators:
        // - oauthAccount: OAuth-based auth
        // - hasCompletedOnboarding: completed setup wizard
        // - claudeCodeFirstTokenDate: Claude Code token auth
        // - primaryApiKey: API key auth
        const hasAuth = !!(
          config.oauthAccount ||
          config.hasCompletedOnboarding ||
          config.claudeCodeFirstTokenDate ||
          config.primaryApiKey
        );
        // Also check for credentials file (Claude Code auth stores tokens here)
        const credentialsFile = path.join(home, '.claude', '.credentials.json');
        const hasCredentials = fs.existsSync(credentialsFile);
        return !hasAuth && !hasCredentials;
      }
      case 'codex': {
        const codexAuth = path.join(process.env.HOME || '/home/' + (process.env.USER || 'dev'), '.codex', 'auth.json');
        const openaiKey = process.env.OPENAI_API_KEY || loadCliEnv()['OPENAI_API_KEY'];
        return !fs.existsSync(codexAuth) && !openaiKey;
      }
      case 'gemini': {
        const geminiConfig = path.join(process.env.HOME || '/home/' + (process.env.USER || 'dev'), '.config', 'gemini');
        const geminiKey = process.env.GEMINI_API_KEY || loadCliEnv()['GEMINI_API_KEY'];
        return !fs.existsSync(geminiConfig) && !geminiKey;
      }
      default:
        return false;
    }
  } catch {
    return true;
  }
}

/**
 * Strip ALL ANSI/terminal escape sequences, preserving cursor-movement as whitespace
 */
function stripAnsi(text: string): string {
  let result = text
    .replace(/\x1b\[(\d+)C/g, (_, n) => ' '.repeat(parseInt(n) || 1))
    .replace(/\x1b\[(\d+)B/g, (_, n) => '\n'.repeat(parseInt(n) || 1))
    .replace(/\x1b\[[0-9;?]*[a-zA-Z]/g, '')
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, '')
    .replace(/\x1b[()][AB012]/g, '')
    .replace(/\x1b[=>NOM78HcDZ<]/g, '')
    .replace(/\x1b\[\?[0-9;]*[hl]/g, '')
    .replace(/[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]/g, '')
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n');

  const lines = result.split('\n');
  const reassembled: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    // Skip blank lines entirely during reassembly — PTY outputs \r\r\n which
    // becomes blank lines after stripping, breaking URL fragment joining
    if (line.trim() === '') {
      reassembled.push(line);
      continue;
    }
    if (reassembled.length > 0 && line.match(/^[a-zA-Z0-9%&=_.~:/?#[\]@!$'()+,;-]+$/) && !line.match(/^\s/)) {
      // Look back past blank lines to find the last non-blank entry
      let prevIdx = reassembled.length - 1;
      while (prevIdx >= 0 && reassembled[prevIdx]!.trim() === '') {
        prevIdx--;
      }
      if (prevIdx >= 0) {
        const prev = reassembled[prevIdx] ?? '';
        if (prev.match(/https?:\/\//) && !prev.match(/\s$/)) {
          reassembled[prevIdx] = prev + line;
          continue;
        }
      }
    }
    reassembled.push(line);
  }
  return reassembled.join('\n');
}

/**
 * Check if a matched label looks like code rather than a menu option
 */
function isCodeLikeLabel(label: string): boolean {
  if (label.match(/[{}();=><]/) && !label.match(/\(recommended\)/i)) return true;
  if (label.match(/^[-+]\s/)) return true;
  if (label.match(/\b(function|const|let|var|return|import|export|class|if|else|for|while)\b/)) return true;
  if (label.match(/console\.|require\(|process\.|module\./)) return true;
  if (label.match(/\/\//)) return true;
  if (label.match(/\.[a-z]+\(/)) return true;
  if (label.length > 70) return true;
  if (!label.match(/[a-zA-Z]{2,}/)) return true;
  return false;
}

/**
 * Parse CLI output to detect interactive prompts
 */
function parseCliOutput(rawText: string): ParsedOutput {
  const text = stripAnsi(rawText);
  const lines = text.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);

  const options: Array<{ number: string; label: string; description: string }> = [];
  const contextBefore: string[] = [];
  const contextAfter: string[] = [];
  let foundOptions = false;
  let selectionType: 'number' | 'arrow' = 'number';
  let activeArrowIdx = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';

    if (line.match(/^[─│┌┐└┘├┤╭╮╰╯━┃▀▄█░▒▓\s]+$/) || line.length < 2) continue;

    const hasArrowPrefix = line.match(/^[❯●◉]/);
    const isArrowMode = hasArrowPrefix || (foundOptions && selectionType === 'arrow');
    const numMatch = isArrowMode
      ? line.match(/^[❯●◉>\s]*([0-9]+)\.?\s+(.+)$/)
      : line.match(/^[>\s]*([0-9]+)\.\s+(.+)$/);

    if (numMatch) {
      let label = numMatch[2] ?? '';
      label = label.replace(/\s{2,}/g, ' ').trim();
      if (isCodeLikeLabel(label)) {
        if (!foundOptions) {
          contextBefore.push(line);
        } else {
          contextAfter.push(line);
        }
        continue;
      }
      if (hasArrowPrefix) {
        selectionType = 'arrow';
        activeArrowIdx = options.length;
      } else if (!foundOptions) {
        selectionType = 'number';
      }
      foundOptions = true;
      let description = '';
      const descSplit = label.match(/^(.+?)\s+[·]\s+(.+)$/);
      if (descSplit && descSplit[1] && descSplit[2]) {
        label = descSplit[1].trim();
        description = descSplit[2].trim();
      }
      options.push({ number: numMatch[1] ?? '', label, description });
      continue;
    }

    const arrowMarkerMatch = line.match(/^([❯●◉○◯])\s+(.+)$/);
    if (arrowMarkerMatch && arrowMarkerMatch[1] && arrowMarkerMatch[2]) {
      const arrowLabel = arrowMarkerMatch[2].replace(/\s{2,}/g, ' ').trim();
      if (arrowLabel.length >= 3 && arrowLabel.length < 80 && arrowLabel.match(/[a-zA-Z]{2,}/) && !isCodeLikeLabel(arrowLabel)) {
        const isActive = arrowMarkerMatch[1].match(/[❯●◉]/);
        if (!foundOptions) activeArrowIdx = options.length;
        foundOptions = true;
        selectionType = 'arrow';
        options.push({ number: String(options.length + 1), label: arrowLabel, description: '' });
        if (isActive) activeArrowIdx = options.length - 1;
        continue;
      }
    }

    if (!foundOptions) {
      contextBefore.push(line);
    } else {
      contextAfter.push(line);
    }
  }

  const urls: string[] = [];
  const urlRegex = /https?:\/\/[^\s"'<>]+/g;
  let match;
  while ((match = urlRegex.exec(text)) !== null) {
    urls.push(match[0].replace(/[.,;:)]+$/, ''));
  }

  const yesNoMatch = text.match(/\(([yY]\/[nN]|[nN]\/[yY])\)|\[([yY]\/[nN]|[nN]\/[yY])\]/);
  const inputPrompt = lines.find(
    (l) => l.match(/[:?>]\s*$/) && !l.match(/^[0-9]+\./) && !l.match(/^[❯●○◉]/) && l.length < 120
  );

  return { options, selectionType, activeArrowIdx, contextBefore, contextAfter, urls, yesNoMatch, inputPrompt };
}

/**
 * Start an interactive CLI process
 */
export function startInteractiveCli(
  session: string,
  ws: WsClient,
  command?: string,
  threadId?: string | null
): void {
  // Kill any existing interactive process for this ws
  const existing = interactiveSessions.get(ws);
  if (existing) {
    clearTimeout(existing.timeout);
    if (!existing.proc.killed) {
      try {
        process.kill(-existing.proc.pid!, 'SIGTERM');
      } catch {
        try {
          existing.proc.kill('SIGTERM');
        } catch {}
      }
    }
  }

  // Validate command against whitelist
  let cmd: string;
  if (command) {
    const allowed = ALLOWED_INTERACTIVE_COMMANDS[session] || [];
    if (!allowed.includes(command)) {
      ws.send(JSON.stringify({ type: 'error', message: 'Command not allowed: ' + command, timestamp: Date.now() }));
      return;
    }
    cmd = command;
  } else {
    const defaults: Record<string, string> = {
      claude: 'claude login',
      codex: 'codex login',
      gemini: 'gemini auth login',
    };
    const defaultCmd = defaults[session];
    if (!defaultCmd) {
      ws.send(JSON.stringify({ type: 'error', message: 'No interactive setup for ' + session, timestamp: Date.now() }));
      return;
    }
    cmd = defaultCmd;
  }

  // Spawn with PTY via pty-wrap
  const cmdParts = cmd.split(' ');
  const proc = spawn('pty-wrap', cmdParts, {
    cwd: PROJECTS_DIR,
    env: { ...getCliSpawnEnv(), TERM: 'xterm-256color', COLUMNS: '2000', LINES: '30' },
    stdio: ['pipe', 'pipe', 'pipe'],
    detached: true,
  });

  let buffer = '';
  let debounceTimer: NodeJS.Timeout | null = null;
  let lastPromptSent = 0;

  const timeoutHandle = setTimeout(() => {
    if (!proc.killed) {
      try {
        process.kill(-proc.pid!, 'SIGTERM');
      } catch {
        try {
          proc.kill('SIGTERM');
        } catch {}
      }
      ws.send(JSON.stringify({ type: 'error', message: session + ' setup timed out. Try again.', threadId, timestamp: Date.now() }));
    }
  }, INTERACTIVE_TIMEOUT_MS);

  const sessionState: InteractiveState & { threadId?: string | null } = { proc, timeout: timeoutHandle, session, awaitingResponse: false, threadId };
  interactiveSessions.set(ws, sessionState);

  function flushBuffer() {
    if (!buffer.trim()) {
      buffer = '';
      return;
    }
    const now = Date.now();
    if (now - lastPromptSent < 200) {
      buffer = '';
      return;
    }

    // Extract URLs from raw buffer before stripping
    const rawUrls: string[] = [];
    const urlStart = buffer.indexOf('https://');
    if (urlStart !== -1) {
      let rawUrl = buffer.slice(urlStart);
      rawUrl = rawUrl.replace(/\x1b\[[0-9;?]*[a-zA-Z]/g, '');
      rawUrl = rawUrl.replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, '');
      rawUrl = rawUrl.replace(/\x1b[()][AB012]/g, '');
      // Replace control chars with SPACE (not remove) to preserve word boundaries
      // Otherwise \r\n between URL and "Paste code here" gets removed, corrupting the URL
      rawUrl = rawUrl.replace(/[\x00-\x1f\x7f]/g, ' ');
      const urlMatch = rawUrl.match(/^(https:\/\/[^\s"'<>]+)/);
      if (urlMatch && urlMatch[1]) {
        rawUrls.push(urlMatch[1].replace(/[.,;:)]+$/, ''));
      }
    }

    const parsed = parseCliOutput(buffer);
    // Prefer parsed URL (parseCliOutput has proper multi-line URL reassembly)
    // Only fall back to raw extraction if parseCliOutput found nothing
    if (parsed.urls.length === 0 && rawUrls.length > 0) {
      parsed.urls = rawUrls;
    }
    buffer = '';

    if (parsed.options.length >= 2) {
      // Auto-select theme picker without showing to user
      const isThemePicker = parsed.options.some((o) => o.label.match(/Dark mode|Light mode/i));
      if (isThemePicker) {
        console.log('[Bridge] Auto-selecting dark mode theme');
        const darkOption = parsed.options.find((o) => o.label.match(/^Dark mode$/i)) || parsed.options.find((o) => o.label.match(/Dark mode/i));
        const targetIdx = darkOption ? parseInt(darkOption.number, 10) - 1 : 0;
        const currentIdx = parsed.activeArrowIdx || 0;
        ws.send(JSON.stringify({ type: 'cli_setup_progress', session, step: 'theme', message: 'Setting up ' + session + '...', threadId, timestamp: now }));
        const moves = targetIdx - currentIdx;
        const arrow = moves > 0 ? '\x1b[B' : '\x1b[A';
        for (let i = 0; i < Math.abs(moves); i++) {
          proc.stdin?.write(arrow);
        }
        setTimeout(() => proc.stdin?.write('\r'), 50);
        lastPromptSent = now;
        return;
      }

      const context = parsed.contextBefore
        .filter(
          (l) =>
            !l.match(/^(Tips for|Choose the|To change this|Script started|Script done|Let.s get started)/i) &&
            !l.match(/Welcome to/i) &&
            !l.match(/v\d+\.\d+\.\d+/) &&
            !l.match(/Claude Code|Codex CLI|Gemini CLI/i) &&
            !l.match(/^[^a-zA-Z]*$/)
        )
        .join('\n');

      lastPromptSent = now;
      sessionState.awaitingResponse = true;

      ws.send(
        JSON.stringify({
          type: 'cli_prompt',
          session,
          context: context || undefined,
          options: parsed.options,
          selectionType: parsed.selectionType,
          activeIndex: parsed.activeArrowIdx,
          instructions: parsed.contextAfter.join(' ') || undefined,
          threadId,
          timestamp: now,
        })
      );
    } else if (parsed.yesNoMatch) {
      lastPromptSent = now;
      sessionState.awaitingResponse = true;
      ws.send(
        JSON.stringify({
          type: 'cli_prompt',
          session,
          context: parsed.contextBefore.join('\n'),
          options: [
            { number: 'y', label: 'Yes', description: '' },
            { number: 'n', label: 'No', description: '' },
          ],
          selectionType: 'number',
          threadId,
          timestamp: now,
        })
      );
    } else if (parsed.inputPrompt) {
      // Auto-press Enter for "Press Enter to continue" prompts
      if (parsed.inputPrompt.match(/press enter|hit enter|continue/i) && !parsed.urls.length) {
        console.log('[Bridge] Auto-pressing Enter to continue');
        proc.stdin?.write('\r');
        lastPromptSent = now;
        return;
      }

      lastPromptSent = now;
      sessionState.awaitingResponse = true;

      let cleanPrompt = parsed.inputPrompt
        .replace(/if prompted\s*/i, '')
        .replace(/here\s*/i, '')
        .replace(/[>]\s*$/, '')
        .trim();
      if (!cleanPrompt || cleanPrompt.length < 3) cleanPrompt = 'Enter code';

      const authUrl = parsed.urls.length > 0 ? parsed.urls[0] : undefined;

      ws.send(
        JSON.stringify({
          type: 'cli_input',
          session,
          prompt: cleanPrompt,
          url: authUrl,
          threadId,
          timestamp: now,
        })
      );
    } else {
      const fullText = parsed.contextBefore.concat(parsed.contextAfter).join('\n');

      const authSuccessIndicators = [
        /authenticat(ed|ion)\s*(success|complete|done)/i,
        /login\s*successful/i,
        /logged\s*in\s*(as|successfully)/i,
        /signed\s*in\s*(as|successfully)/i,
        /successfully\s*(authenticat|logged|signed|connect)/i,
        /what can i help/i,
        /how can i help/i,
      ];
      const authDone = authSuccessIndicators.some((r) => r.test(fullText));
      if (authDone && !checkCliNeedsSetup(session)) {
        console.log('[Bridge] ' + session + ' auth/setup complete (verified)');
        // Sync auth files back to real home so all threads can access them
        syncAuthToRealHome(session, threadId);
        if (!proc.killed) {
          try {
            process.kill(-proc.pid!, 'SIGTERM');
          } catch {
            try {
              proc.kill('SIGTERM');
            } catch {}
          }
        }
        clearTimeout(timeoutHandle);
        interactiveSessions.delete(ws);
        ws.send(JSON.stringify({ type: 'auth_complete', session, success: true, threadId, timestamp: Date.now() }));
        return;
      }

      if (fullText.match(/Press Enter to continue|Press enter to|Hit enter/i)) {
        console.log('[Bridge] Auto-pressing Enter to continue');
        proc.stdin?.write('\r');
        lastPromptSent = now;
        return;
      }

      if (fullText.match(/Invalid code|error.*code|code.*invalid/i) && fullText.match(/retry|again|enter/i)) {
        console.log('[Bridge] Auth code error, sending Enter to retry');
        proc.stdin?.write('\r');
        lastPromptSent = now;
        ws.send(JSON.stringify({ type: 'error', message: 'Invalid code. Make sure you copy the full code from the auth page.', threadId, timestamp: now }));
        return;
      }

      const lines = fullText.split('\n').filter((l) => {
        const t = l.trim();
        if (!t) return false;
        if (t.match(/^[a-zA-Z0-9_-]{20,}$/) && !t.match(/\s/)) return false;
        if (t.startsWith('#')) return false;
        if (t.match(/Welcome to|v\d+\.\d+|Claude Code|Codex CLI|Gemini CLI/i)) return false;
        if (t.match(/Opening browser|Browser didn.t open|sign in/i)) return false;
        if (t.match(/^[\s…·*✢✶✻✽░▒▓█▀▄╌─│┌┐└┘├┤╭╮╰╯━┃]+$/)) return false;
        if (t.match(/^[^a-zA-Z]*$/) && t.length < 80) return false;
        if (t.match(/Script started|Script done|Let.s get started|Tips for/i)) return false;
        if (t.match(/Paste code|if prompted|c to copy/i)) return false;
        if (t.match(/configuration file|backup file|manually restore|cp.*\.json/i)) return false;
        if (t.match(/Login successful|Press Enter to continue|Logged in as/i)) return false;
        if (t.match(/Select login method/i)) return false;
        return true;
      });
      const cleanOutput = lines.join('\n').trim();
      if (cleanOutput) {
        ws.send(JSON.stringify({ type: 'output', content: cleanOutput, threadId, timestamp: now }));
      }
    }
  }

  function onData(data: Buffer) {
    const chunk = data.toString();
    buffer += chunk;
    if (buffer.length > MAX_BUFFER_SIZE) {
      buffer = buffer.slice(-MAX_BUFFER_SIZE);
    }
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(flushBuffer, DEBOUNCE_MS);
  }

  proc.stdout?.on('data', onData);
  proc.stderr?.on('data', onData);

  proc.on('close', (code) => {
    clearTimeout(timeoutHandle);
    if (debounceTimer) {
      clearTimeout(debounceTimer);
      flushBuffer();
    }
    interactiveSessions.delete(ws);
    const stillNeedsSetup = checkCliNeedsSetup(session);
    if (!stillNeedsSetup) {
      // Sync auth files back to real home so all threads can access them
      syncAuthToRealHome(session, threadId);
      ws.send(JSON.stringify({ type: 'auth_complete', session, success: true, threadId, timestamp: Date.now() }));
    } else {
      ws.send(JSON.stringify({ type: 'cli_interactive_done', session, code, threadId, timestamp: Date.now() }));
    }
  });

  proc.on('error', (err) => {
    clearTimeout(timeoutHandle);
    interactiveSessions.delete(ws);
    if (err.message.includes('ENOENT')) {
      ws.send(JSON.stringify({ type: 'error', message: session + ' is still installing. Try again in a moment.', threadId, timestamp: Date.now() }));
    } else {
      ws.send(JSON.stringify({ type: 'error', message: session + ' setup error: ' + err.message, threadId, timestamp: Date.now() }));
    }
  });
}

/**
 * Send a response to the active interactive CLI process
 */
export function respondToInteractiveCli(
  ws: WsClient,
  response: string,
  selectionType: 'number' | 'arrow'
): void {
  const state = interactiveSessions.get(ws);
  if (!state || !state.proc || state.proc.killed) {
    ws.send(JSON.stringify({ type: 'error', message: 'No active interactive session.', timestamp: Date.now() }));
    return;
  }

  const threadId = state.threadId;
  state.awaitingResponse = false;

  // Reset timeout on user activity
  clearTimeout(state.timeout);
  state.timeout = setTimeout(() => {
    if (!state.proc.killed) {
      try {
        process.kill(-state.proc.pid!, 'SIGTERM');
      } catch {
        try {
          state.proc.kill('SIGTERM');
        } catch {}
      }
      ws.send(JSON.stringify({ type: 'error', message: state.session + ' setup timed out.', threadId, timestamp: Date.now() }));
    }
  }, INTERACTIVE_TIMEOUT_MS);

  if (selectionType === 'arrow') {
    const targetIdx = parseInt(response, 10);
    if (isNaN(targetIdx) || targetIdx < 1) {
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid selection.', threadId, timestamp: Date.now() }));
      return;
    }
    const moves = targetIdx - 1;
    for (let i = 0; i < moves; i++) {
      state.proc.stdin?.write('\x1b[B');
    }
    setTimeout(() => state.proc.stdin?.write('\r'), 50);
  } else {
    const cleanResponse = response.trim();
    state.proc.stdin?.write(cleanResponse);
    setTimeout(() => state.proc.stdin?.write('\r'), 200);
  }
}

/**
 * Kill interactive session for a WebSocket client
 */
export function killInteractiveSession(ws: WsClient): void {
  const state = interactiveSessions.get(ws);
  if (state) {
    clearTimeout(state.timeout);
    if (!state.proc.killed) {
      try {
        process.kill(-state.proc.pid!, 'SIGTERM');
      } catch {
        try {
          state.proc.kill('SIGTERM');
        } catch {}
      }
    }
    interactiveSessions.delete(ws);
  }
}

/**
 * Check if there's an active interactive session for a WebSocket client
 */
export function hasInteractiveSession(ws: WsClient): boolean {
  return interactiveSessions.has(ws);
}

// ─── In-Chat CLI Auth ──────────────────────────────────
//
// Agent-triggered auth flow: the OpenClaw agent outputs [SETUP_CLI:claude]
// and the bridge intercepts it, spawns a PTY login process, auto-skips
// noise (theme picker, press-enter), and surfaces just the auth URL
// in the chat. User pastes the code back, bridge routes it to PTY.

const chatAuthSessions = new Map<WsClient, InteractiveState & { threadId?: string | null }>();
// Secondary index: threadId → auth state + mutable ws ref, for reconnecting after ws drop
const chatAuthByThread = new Map<string, { state: InteractiveState & { threadId?: string | null }; wsRef: { ws: WsClient } }>();

/** Remove auth session from both maps */
function removeAuthSession(ws: WsClient) {
  const state = chatAuthSessions.get(ws);
  chatAuthSessions.delete(ws);
  if (state?.threadId) chatAuthByThread.delete(state.threadId);
}

/**
 * Re-associate an auth session from a previous ws to a new ws on reconnect.
 * Returns true if an existing auth session was migrated.
 *
 * @param expectedSession - If provided, only reattach if the auth session matches.
 *   Prevents claude auth from being reattached to an opencode thread (session desync).
 */
export function reattachCliAuth(newWs: WsClient, threadId: string, expectedSession?: string): boolean {
  const entry = chatAuthByThread.get(threadId);
  if (!entry || !entry.state.proc || entry.state.proc.killed) {
    // No active auth for this thread
    chatAuthByThread.delete(threadId);
    return false;
  }
  // Don't reattach if the auth session doesn't match what the thread expects
  // (e.g., claude auth orphaned on an opencode thread due to session desync)
  if (expectedSession && entry.state.session !== expectedSession) {
    console.log(`[ChatAuth] Refusing reattach: auth session=${entry.state.session} doesn't match thread session=${expectedSession}, cancelling orphaned auth`);
    clearTimeout(entry.state.timeout);
    if (entry.state.proc && !entry.state.proc.killed) {
      try { process.kill(-entry.state.proc.pid!, 'SIGTERM'); } catch {
        try { entry.state.proc.kill('SIGTERM'); } catch {}
      }
    }
    chatAuthByThread.delete(threadId);
    chatAuthSessions.delete(entry.wsRef.ws);
    return false;
  }
  const oldWs = entry.wsRef.ws;
  // Remove from old ws
  chatAuthSessions.delete(oldWs);
  // Register under new ws
  chatAuthSessions.set(newWs, entry.state);
  // Update the mutable ws ref — this propagates to all closures in startCliAuthInChat
  entry.wsRef.ws = newWs;
  console.log(`[ChatAuth] Reattached ${entry.state.session} auth (pid=${entry.state.proc.pid}) to new ws for thread ${threadId.substring(0, 8)}`);
  return true;
}

/**
 * Detach auth session on ws close — don't kill the PTY, just remove the ws mapping.
 * The auth continues running and can be reattached on reconnect.
 */
export function detachCliAuth(ws: WsClient): void {
  const state = chatAuthSessions.get(ws);
  if (state) {
    // Only remove ws→state mapping, NOT the threadId→state mapping (needed for reconnect)
    chatAuthSessions.delete(ws);
    console.log(`[ChatAuth] Detached ${state.session} auth from closed ws (PTY pid=${state.proc?.pid} still running)`);
  }
}

/**
 * Start an interactive CLI auth flow within the chat conversation.
 * Spawns PTY, auto-skips noise, surfaces auth URL as chat output.
 *
 * Auth flows per CLI:
 * - Claude: `claude login` → theme picker (auto-skip) → OAuth URL + paste code back
 * - Codex:  `codex login --device-auth` → shows URL + device code (user enters on website, CLI auto-detects)
 * - Gemini: No headless browser auth available → prompt user for GEMINI_API_KEY directly
 */
export function startCliAuthInChat(
  session: string,
  initialWs: WsClient,
  threadId?: string | null,
): void {
  // Kill any existing in-chat auth for this ws
  cancelCliAuthInChat(initialWs);

  // Gemini has no headless auth flow — prompt for API key directly
  if (session === 'gemini') {
    startGeminiApiKeyAuth(initialWs, threadId);
    return;
  }

  const defaults: Record<string, string> = {
    claude: 'claude login',
    codex: 'codex login --device-auth',
  };
  const cmd = defaults[session];
  if (!cmd) {
    initialWs.send(JSON.stringify({ type: 'output', content: `No setup available for ${session}.`, threadId, timestamp: Date.now() }));
    return;
  }

  // Mutable ws ref — reattachCliAuth updates wsRef.ws when connection drops and reconnects.
  // All closures below use wsRef.ws (not a captured local) so they get the latest ws.
  // wsRef: mutable ws reference. reattachCliAuth updates wsRef.ws on reconnect.
  // JS closures capture `ws` by reference (since `let`), so when wsRef.ws setter updates
  // the local `ws`, all closures see the new value.
  // eslint-disable-next-line prefer-const
  let ws = initialWs;
  const wsRef = {
    get ws() { return ws; },
    set ws(v: WsClient) { ws = v; },
  };

  const cmdParts = cmd.split(' ');
  const proc = spawn('pty-wrap', cmdParts, {
    cwd: PROJECTS_DIR,
    env: { ...getCliSpawnEnv(), TERM: 'xterm-256color', COLUMNS: '2000', LINES: '30' },
    stdio: ['pipe', 'pipe', 'pipe'],
    detached: true,
  });

  let buffer = '';
  let debounceTimer: NodeJS.Timeout | null = null;
  let lastFlush = 0;
  let authUrlSent = false;

  const timeoutHandle = setTimeout(() => {
    if (!proc.killed) {
      try { process.kill(-proc.pid!, 'SIGTERM'); } catch {
        try { proc.kill('SIGTERM'); } catch {}
      }
      ws.send(JSON.stringify({ type: 'output', content: `${session} setup timed out. You can try again.`, threadId, timestamp: Date.now() }));
    }
    removeAuthSession(ws);
  }, INTERACTIVE_TIMEOUT_MS);

  const sessionState: InteractiveState & { threadId?: string | null } = {
    proc, timeout: timeoutHandle, session, awaitingResponse: false, threadId,
  };
  chatAuthSessions.set(wsRef.ws, sessionState);
  if (threadId) {
    chatAuthByThread.set(threadId, { state: sessionState, wsRef });
  }

  ws.send(JSON.stringify({
    type: 'output',
    content: `Setting up ${session}...`,
    threadId,
    timestamp: Date.now(),
  }));

  function flushBuffer() {
    if (!buffer.trim()) { buffer = ''; return; }
    const now = Date.now();
    if (now - lastFlush < 200) { buffer = ''; return; }

    // Extract URLs from raw buffer before stripping ANSI
    const rawUrls: string[] = [];
    const urlStart = buffer.indexOf('https://');
    if (urlStart !== -1) {
      let rawUrl = buffer.slice(urlStart);
      rawUrl = rawUrl.replace(/\x1b\[[0-9;?]*[a-zA-Z]/g, '');
      rawUrl = rawUrl.replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, '');
      rawUrl = rawUrl.replace(/\x1b[()][AB012]/g, '');
      // Replace control chars with SPACE (not remove) to preserve word boundaries
      rawUrl = rawUrl.replace(/[\x00-\x1f\x7f]/g, ' ');
      const urlMatch = rawUrl.match(/^(https:\/\/[^\s"'<>]+)/);
      if (urlMatch?.[1]) {
        rawUrls.push(urlMatch[1].replace(/[.,;:)]+$/, ''));
      }
    }

    const parsed = parseCliOutput(buffer);
    // Prefer parsed URL (parseCliOutput has proper multi-line URL reassembly)
    // Only fall back to raw extraction if parseCliOutput found nothing
    if (parsed.urls.length === 0 && rawUrls.length > 0) {
      parsed.urls = rawUrls;
    }
    // Build full text BEFORE clearing buffer (needed for device code extraction)
    const fullText = parsed.contextBefore.concat(parsed.contextAfter).join('\n');
    const rawBufferSnapshot = buffer;
    buffer = '';

    console.log(`[ChatAuth] flushBuffer: options=${parsed.options.length}, urls=${parsed.urls.length}, rawUrls=${rawUrls.length}, inputPrompt=${!!parsed.inputPrompt}, yesNo=${!!parsed.yesNoMatch}, authUrlSent=${authUrlSent}, fullTextLen=${fullText.length}`);
    if (parsed.urls.length > 0) console.log(`[ChatAuth] Parsed URLs: ${JSON.stringify(parsed.urls)}`);
    if (rawUrls.length > 0) console.log(`[ChatAuth] Raw URLs: ${JSON.stringify(rawUrls)}`);
    // Log first 500 chars of buffer for debugging (sanitized)
    const sanitizedPreview = stripAnsi(rawBufferSnapshot).replace(/\n/g, '\\n').substring(0, 500);
    console.log(`[ChatAuth] Buffer preview: ${sanitizedPreview}`);

    // Auto-skip: theme picker (loose regex — Dragon #3)
    if (parsed.options.length >= 2) {
      const isThemePicker = parsed.options.some(o => /theme|dark\s*mode|light\s*mode/i.test(o.label));
      if (isThemePicker) {
        console.log('[ChatAuth] Auto-selecting dark mode theme');
        const darkOption = parsed.options.find(o => /dark/i.test(o.label)) || parsed.options[0];
        const targetIdx = darkOption ? parseInt(darkOption.number, 10) - 1 : 0;
        const currentIdx = parsed.activeArrowIdx || 0;
        const moves = targetIdx - currentIdx;
        const arrow = moves > 0 ? '\x1b[B' : '\x1b[A';
        for (let i = 0; i < Math.abs(moves); i++) {
          proc.stdin?.write(arrow);
        }
        setTimeout(() => proc.stdin?.write('\r'), 50);
        lastFlush = now;
        return;
      }

      // Present meaningful options to user in chat (login method, etc.)
      // Filter noise from context lines for a clean prompt
      const context = parsed.contextBefore
        .filter(l =>
          !l.match(/^(Tips for|Choose the|To change this|Script started|Script done|Let.s get started)/i) &&
          !l.match(/Welcome to/i) &&
          !l.match(/v\d+\.\d+\.\d+/) &&
          !l.match(/Claude Code|Codex CLI|Gemini CLI/i) &&
          !l.match(/^[^a-zA-Z]*$/)
        )
        .join('\n');

      console.log(`[ChatAuth] Showing cli_prompt: ${parsed.options.length} options, selectionType=${parsed.selectionType}, activeIdx=${parsed.activeArrowIdx}`);
      sessionState.awaitingResponse = true;
      // Track activeArrowIdx so respondToCliAuthInChat can navigate correctly
      (sessionState as InteractiveState & { threadId?: string | null; lastActiveIdx?: number }).lastActiveIdx = parsed.activeArrowIdx;
      const promptOptions = parsed.options;
      const instructions = context || undefined;
      const selectionType = parsed.selectionType;
      // Clear thinking/loading spinner before showing the prompt
      if (threadId) endProcessing(threadId);
      ws.send(JSON.stringify({ type: 'ack', session, threadId, timestamp: now }));
      ws.send(JSON.stringify({
        type: 'cli_prompt',
        session,
        context: instructions,
        options: promptOptions,
        selectionType,
        activeIndex: parsed.activeArrowIdx,
        inChatAuth: true,
        threadId,
        timestamp: now,
      }));
      // Auth prompts are transient (sent via WS only, not persisted to DB)
      // to prevent duplicate auth cards when re-selecting a thread.
      lastFlush = now;
      return;
    }

    // Yes/No prompt — surface to user as selectable options
    if (parsed.yesNoMatch) {
      sessionState.awaitingResponse = true;
      ws.send(JSON.stringify({
        type: 'cli_prompt',
        session,
        context: parsed.contextBefore.join('\n') || undefined,
        options: [
          { number: 'y', label: 'Yes', description: '' },
          { number: 'n', label: 'No', description: '' },
        ],
        selectionType: 'number',
        inChatAuth: true,
        threadId,
        timestamp: now,
      }));
      lastFlush = now;
      return;
    }

    // Auto-skip: press enter to continue (loose regex — Dragon #3)
    if (parsed.inputPrompt && /press\s*enter|hit\s*enter|continue/i.test(parsed.inputPrompt) && !parsed.urls.length) {
      console.log('[ChatAuth] Auto-pressing Enter to continue');
      proc.stdin?.write('\r');
      lastFlush = now;
      return;
    }

    // Also catch press-enter in full text (loose regex)
    if (/press\s*enter|hit\s*enter|press\s*any\s*key/i.test(fullText) && !parsed.urls.length && !parsed.inputPrompt) {
      console.log('[ChatAuth] Auto-pressing Enter (fullText match)');
      proc.stdin?.write('\r');
      lastFlush = now;
      return;
    }

    // Show progress during browser-open wait (Claude shows spinner for ~10s before fallback URL)
    if (/opening\s*browser|waiting\s*for\s*browser|sign\s*in/i.test(fullText) && !parsed.urls.length && !parsed.inputPrompt && !authUrlSent) {
      console.log('[ChatAuth] Browser opening detected, showing progress');
      ws.send(JSON.stringify({
        type: 'output',
        content: `Waiting for ${session} authentication URL...`,
        threadId,
        timestamp: Date.now(),
      }));
      lastFlush = now;
      return;
    }

    // Codex device auth not enabled — user needs to enable it in ChatGPT settings
    if (session === 'codex' && /enable\s*device\s*code\s*auth|security\s*settings/i.test(fullText)) {
      console.log('[ChatAuth] Codex device auth not enabled, informing user');
      ws.send(JSON.stringify({
        type: 'output',
        content: `**Codex requires device code authorization to be enabled.**\n\nTo set this up:\n1. Go to [ChatGPT Security Settings](https://chatgpt.com/settings/security)\n2. Enable **"Device code authorization for Codex"**\n3. Then switch away from Codex and back to retry authentication.\n\n_Once enabled, the auth flow will work automatically._`,
        threadId,
        timestamp: Date.now(),
      }));
      // Kill the auth process — it can't proceed
      if (!proc.killed) {
        try { process.kill(-proc.pid!, 'SIGTERM'); } catch {
          try { proc.kill('SIGTERM'); } catch {}
        }
      }
      clearTimeout(timeoutHandle);
      removeAuthSession(ws);
      lastFlush = now;
      return;
    }

    // Auth success detection — check both text indicators AND filesystem auth state
    const authSuccessIndicators = [
      /authenticat(ed|ion)\s*(success|complete|done)/i,
      /login\s*successful/i,
      /logged\s*in\s*(as|successfully)/i,
      /signed\s*in\s*(as|successfully)/i,
      /successfully\s*(authenticat|logged|signed|connect)/i,
      /what can i help/i,
      /how can i help/i,
      /welcome\s*back/i,
      /accessing\s*workspace/i,
      /safety\s*check/i,
      /trust\s*this\s*folder/i,
    ];
    const authDone = authSuccessIndicators.some(r => r.test(fullText));
    // Also check filesystem: if auth code was already submitted (authUrlSent)
    // and the CLI no longer needs setup, auth succeeded even without text match
    const authFileReady = authUrlSent && !checkCliNeedsSetup(session);
    if ((authDone || authFileReady) && !checkCliNeedsSetup(session)) {
      console.log(`[ChatAuth] ${session} auth complete`);
      syncAuthToRealHome(session, threadId);
      if (!proc.killed) {
        try { process.kill(-proc.pid!, 'SIGTERM'); } catch {
          try { proc.kill('SIGTERM'); } catch {}
        }
      }
      clearTimeout(timeoutHandle);
      removeAuthSession(ws);
      ws.send(JSON.stringify({
        type: 'auth_complete',
        success: true,
        session,
        threadId,
        timestamp: Date.now(),
      }));
      if (threadId) {
        addMessage(threadId, {
          type: 'system',
          content: `${session} authenticated successfully! You can now send messages.`,
          session,
          model: null,
          thinking: null,
          metadata: null,
        });
      }
      return;
    }

    // Auth URL found — surface to user
    if (parsed.urls.length > 0 && !authUrlSent) {
      authUrlSent = true;
      const authUrl = parsed.urls[0];
      lastFlush = now;
      console.log(`[ChatAuth] Auth URL detected: ${authUrl}`);

      // Codex device auth: extract the one-time code from the output
      // The code appears after the URL, pattern like "XXXX-XXXXX" (uppercase alphanumeric with dash)
      if (session === 'codex') {
        // Extract device code from the FULL TEXT (not buffer, which is already cleared)
        const codeFromFullText = fullText.match(/\b([A-Z0-9]{4,6}-[A-Z0-9]{4,6})\b/);
        // Also try the raw buffer snapshot (before ANSI stripping may have lost it)
        const codeFromRaw = stripAnsi(rawBufferSnapshot).match(/\b([A-Z0-9]{4,6}-[A-Z0-9]{4,6})\b/);
        const deviceCode = codeFromFullText?.[1] || codeFromRaw?.[1] || null;
        console.log(`[ChatAuth] Codex device code: ${deviceCode || 'not found'}`);
        // Codex device auth: user enters the code ON THE WEBSITE, not in terminal
        // CLI auto-detects completion — sent as cli_input with deviceCode for proper card UI
        const codexContent = deviceCode
          ? `To authenticate **Codex**, open this link and sign in:\n\nThen enter this one-time code on the website:\n\n**${deviceCode}**\n\n_Waiting for authentication to complete..._`
          : `To authenticate **Codex**, open this link and sign in:\n\n_Waiting for authentication to complete..._`;
        ws.send(JSON.stringify({
          type: 'cli_input',
          session,
          prompt: codexContent,
          url: authUrl,
          deviceCode: deviceCode || undefined,
          inChatAuth: true,
          threadId,
          timestamp: Date.now(),
        }));
        // Auth prompts are transient — not persisted to DB
      } else {
        // Claude: user needs to paste a code back → show input field
        sessionState.awaitingResponse = true;
        ws.send(JSON.stringify({
          type: 'cli_input',
          session,
          prompt: `Authenticate ${session}`,
          url: authUrl,
          inChatAuth: true,
          threadId,
          timestamp: Date.now(),
        }));
      }
      return;
    }

    // Input prompt (auth code entry) — show dedicated input UI
    // This catches cases where the URL was shown in a previous buffer flush
    // and now we just have the "paste code" prompt
    if (parsed.inputPrompt) {
      lastFlush = now;
      sessionState.awaitingResponse = true;
      console.log(`[ChatAuth] Input prompt detected: ${parsed.inputPrompt}`);
      ws.send(JSON.stringify({
        type: 'cli_input',
        session,
        prompt: parsed.inputPrompt || 'Paste authentication code',
        url: parsed.urls[0] || undefined,
        inChatAuth: true,
        threadId,
        timestamp: Date.now(),
      }));
      // Auth prompts are transient — not persisted to DB
      return;
    }

    lastFlush = now;
  }

  function onData(data: Buffer) {
    const chunk = data.toString();
    buffer += chunk;
    console.log(`[ChatAuth] onData: +${chunk.length} bytes, bufferLen=${buffer.length}, chunk=${chunk.replace(/[\x00-\x1f\x7f]/g, '·').substring(0, 100)}`);
    if (buffer.length > MAX_BUFFER_SIZE) {
      buffer = buffer.slice(-MAX_BUFFER_SIZE);
    }
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(flushBuffer, DEBOUNCE_MS);
  }

  proc.stdout?.on('data', onData);
  proc.stderr?.on('data', onData);

  proc.on('close', (code: number | null) => {
    console.log(`[ChatAuth] PTY process closed with code ${code}, pid=${proc.pid}`);
    clearTimeout(timeoutHandle);
    if (debounceTimer) { clearTimeout(debounceTimer); flushBuffer(); }
    removeAuthSession(ws);

    if (!checkCliNeedsSetup(session)) {
      syncAuthToRealHome(session, threadId);
      ws.send(JSON.stringify({
        type: 'auth_complete',
        success: true,
        session,
        threadId,
        timestamp: Date.now(),
      }));
      if (threadId) {
        addMessage(threadId, {
          type: 'system',
          content: `${session} authenticated successfully! You can now send messages.`,
          session,
          model: null,
          thinking: null,
          metadata: null,
        });
      }
    }
  });

  proc.on('error', (err) => {
    clearTimeout(timeoutHandle);
    removeAuthSession(ws);
    if (err.message.includes('ENOENT')) {
      ws.send(JSON.stringify({ type: 'output', content: `${session} is still installing. Try again in a moment.`, threadId, timestamp: Date.now() }));
    } else {
      ws.send(JSON.stringify({ type: 'output', content: `${session} setup error: ${err.message}`, threadId, timestamp: Date.now() }));
    }
  });
}

/**
 * Gemini API key auth flow — no PTY needed.
 * Gemini CLI has no headless browser auth, so we prompt for an API key directly.
 * The key is saved to ~/.ellulai-env and loaded by the CLI spawn environment.
 */
function startGeminiApiKeyAuth(ws: WsClient, threadId?: string | null): void {
  // Mark as awaiting response (so respondToCliAuthInChat routes input here)
  const sessionState: InteractiveState & { threadId?: string | null } = {
    proc: null as unknown as ChildProcess,
    timeout: setTimeout(() => {
      removeAuthSession(ws);
      ws.send(JSON.stringify({ type: 'output', content: 'Gemini setup timed out. You can try again.', threadId, timestamp: Date.now() }));
    }, INTERACTIVE_TIMEOUT_MS),
    session: 'gemini',
    awaitingResponse: true,
    threadId,
  };
  chatAuthSessions.set(ws, sessionState);

  ws.send(JSON.stringify({
    type: 'output',
    content: 'Setting up Gemini...',
    threadId,
    timestamp: Date.now(),
  }));

  // Gemini needs an API key — send cli_input to prompt user
  ws.send(JSON.stringify({
    type: 'cli_input',
    session: 'gemini',
    prompt: 'Enter your Gemini API key',
    url: 'https://aistudio.google.com/apikey',
    inChatAuth: true,
    threadId,
    timestamp: Date.now(),
  }));
  // Auth prompts are transient — not persisted to DB
}

/**
 * Save a Gemini API key to the CLI environment file.
 * Called when the user submits their key through the cli_input UI.
 */
export function saveGeminiApiKey(apiKey: string, _threadId?: string | null): boolean {
  try {
    saveCliKey('GEMINI_API_KEY', apiKey);
    // Also set in current process so checkCliNeedsSetup sees it immediately
    process.env.GEMINI_API_KEY = apiKey;
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if there's an active in-chat auth session for a WebSocket client.
 */
export function hasCliAuthInChat(ws: WsClient): boolean {
  return chatAuthSessions.has(ws);
}

/**
 * Get the thread ID that a ws client's auth session belongs to (if any).
 */
export function getCliAuthThreadId(ws: WsClient): string | null {
  const state = chatAuthSessions.get(ws);
  return state?.threadId ?? null;
}

/**
 * Check if there's an active in-chat auth session for a specific thread.
 */
export function hasCliAuthForThread(threadId: string): boolean {
  const entry = chatAuthByThread.get(threadId);
  if (!entry || !entry.state.proc || entry.state.proc.killed) {
    chatAuthByThread.delete(threadId);
    return false;
  }
  return true;
}

/**
 * Route user's message or option selection to the active in-chat auth PTY process.
 *
 * @param selectionType - 'arrow' for arrow-key menus, 'number' for numbered lists, 'text' for raw input (auth codes)
 */
export function respondToCliAuthInChat(
  ws: WsClient,
  message: string,
  selectionType: 'number' | 'arrow' | 'text' = 'text',
): void {
  const state = chatAuthSessions.get(ws);
  if (!state) {
    ws.send(JSON.stringify({ type: 'output', content: 'No active authentication session.', timestamp: Date.now() }));
    return;
  }

  // Gemini API key flow — no PTY process, just save the key
  if (state.session === 'gemini') {
    clearTimeout(state.timeout);
    removeAuthSession(ws);
    const saved = saveGeminiApiKey(message.trim(), state.threadId);
    if (saved && !checkCliNeedsSetup('gemini')) {
      ws.send(JSON.stringify({
        type: 'auth_complete',
        success: true,
        session: 'gemini',
        threadId: state.threadId,
        timestamp: Date.now(),
      }));
      if (state.threadId) {
        addMessage(state.threadId, {
          type: 'system',
          content: 'gemini authenticated successfully! You can now send messages.',
          session: 'gemini',
          model: null,
          thinking: null,
          metadata: null,
        });
      }
    } else {
      ws.send(JSON.stringify({
        type: 'output',
        content: 'Failed to save Gemini API key. Please check the key and try again.',
        threadId: state.threadId,
        timestamp: Date.now(),
      }));
    }
    return;
  }

  if (!state.proc || state.proc.killed) {
    ws.send(JSON.stringify({ type: 'output', content: 'No active authentication session.', threadId: state?.threadId, timestamp: Date.now() }));
    return;
  }

  // Reset timeout on user activity
  clearTimeout(state.timeout);
  state.timeout = setTimeout(() => {
    if (!state.proc.killed) {
      try { process.kill(-state.proc.pid!, 'SIGTERM'); } catch {
        try { state.proc.kill('SIGTERM'); } catch {}
      }
      ws.send(JSON.stringify({ type: 'output', content: `${state.session} setup timed out.`, threadId: state.threadId, timestamp: Date.now() }));
    }
    removeAuthSession(ws);
  }, INTERACTIVE_TIMEOUT_MS);

  state.awaitingResponse = false;

  // Send progress message for option selection (not for code submission)
  if (selectionType === 'arrow' || selectionType === 'number') {
    ws.send(JSON.stringify({
      type: 'output',
      content: `Waiting for ${state.session} authentication URL...`,
      threadId: state.threadId,
      timestamp: Date.now(),
    }));
  }

  if (selectionType === 'arrow') {
    // Arrow-key selection: navigate from CURRENT cursor position to target, then Enter
    const targetIdx = parseInt(message, 10);
    if (isNaN(targetIdx) || targetIdx < 1) {
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid selection.', threadId: state.threadId, timestamp: Date.now() }));
      return;
    }
    // Account for current cursor position (tracked from the cli_prompt that was shown)
    const currentIdx = (state as InteractiveState & { lastActiveIdx?: number }).lastActiveIdx || 0;
    const targetZeroBased = targetIdx - 1;
    const moves = targetZeroBased - currentIdx;
    const arrow = moves > 0 ? '\x1b[B' : '\x1b[A';
    console.log(`[ChatAuth] Arrow selection: from ${currentIdx} to ${targetZeroBased}, moves=${moves}, procAlive=${!state.proc.killed}, pid=${state.proc.pid}, stdinWritable=${!!state.proc.stdin?.writable}`);
    for (let i = 0; i < Math.abs(moves); i++) {
      state.proc.stdin?.write(arrow);
    }
    setTimeout(() => {
      console.log(`[ChatAuth] Sending Enter to PTY (pid=${state.proc.pid}, killed=${state.proc.killed})`);
      state.proc.stdin?.write('\r');
    }, 50);
  } else if (selectionType === 'number') {
    // Numbered selection: type the number and Enter
    const cleanResponse = message.trim();
    state.proc.stdin?.write(cleanResponse);
    setTimeout(() => state.proc.stdin?.write('\r'), 200);
    console.log(`[ChatAuth] Number selection: ${cleanResponse}`);
  } else {
    // Plain text input (auth codes, etc.)
    const cleanMessage = message.trim();
    state.proc.stdin?.write(cleanMessage);
    setTimeout(() => state.proc.stdin?.write('\r'), 200);
    console.log(`[ChatAuth] Text input submitted: ${cleanMessage.substring(0, 20)}...`);
  }

  // After code submission, poll filesystem to detect auth success.
  // The PTY may keep running (showing workspace prompts, effort picker, etc.)
  // but we should kill it once auth files are written.
  const pollSession = state.session;
  const pollThreadId = state.threadId;
  let pollCount = 0;
  const pollInterval = setInterval(() => {
    pollCount++;
    if (pollCount > 30) { // 30s max
      clearInterval(pollInterval);
      return;
    }
    if (!checkCliNeedsSetup(pollSession)) {
      clearInterval(pollInterval);
      console.log(`[ChatAuth] Auth files detected after code submission (poll #${pollCount})`);
      // Auth succeeded — kill the PTY and clean up
      const currentState = chatAuthSessions.get(ws);
      if (currentState && !currentState.proc.killed) {
        syncAuthToRealHome(pollSession, pollThreadId);
        try { process.kill(-currentState.proc.pid!, 'SIGTERM'); } catch {
          try { currentState.proc.kill('SIGTERM'); } catch {}
        }
        clearTimeout(currentState.timeout);
        removeAuthSession(ws);
        ws.send(JSON.stringify({
          type: 'auth_complete',
          success: true,
          session: pollSession,
          threadId: pollThreadId,
          timestamp: Date.now(),
        }));
      }
    }
  }, 1000);
}

/**
 * Cancel an in-chat auth session. Kills PTY and cleans up.
 */
export function cancelCliAuthInChat(ws: WsClient): void {
  const state = chatAuthSessions.get(ws);
  if (state) {
    clearTimeout(state.timeout);
    if (state.proc && !state.proc.killed) {
      try { process.kill(-state.proc.pid!, 'SIGTERM'); } catch {
        try { state.proc.kill('SIGTERM'); } catch {}
      }
    }
    removeAuthSession(ws);
    console.log(`[ChatAuth] Cancelled ${state.session} auth for ws`);
  }
}
