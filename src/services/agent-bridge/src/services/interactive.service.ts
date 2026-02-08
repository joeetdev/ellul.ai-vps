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
import { getCliSpawnEnv, loadCliEnv } from './cli-env.service';
import { PROJECTS_DIR, INTERACTIVE_TIMEOUT_MS, MAX_BUFFER_SIZE, DEBOUNCE_MS } from '../config';
import { getThreadStateDir } from './thread.service';

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

  const realHome = process.env.HOME || '/home/dev';
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
  gemini: ['gemini', 'gemini auth login'],
};

/**
 * Check if a CLI needs first-time setup (not authenticated/configured)
 */
export function checkCliNeedsSetup(session: string): boolean {
  try {
    switch (session) {
      case 'claude': {
        const home = process.env.HOME || '/home/dev';
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
        const codexAuth = path.join(process.env.HOME || '/home/dev', '.codex', 'auth.json');
        const openaiKey = process.env.OPENAI_API_KEY || loadCliEnv()['OPENAI_API_KEY'];
        return !fs.existsSync(codexAuth) && !openaiKey;
      }
      case 'gemini': {
        const geminiConfig = path.join(process.env.HOME || '/home/dev', '.config', 'gemini');
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
    if (reassembled.length > 0 && line.match(/^[a-zA-Z0-9%&=_.~:/?#[\]@!$'()+,;-]+$/) && !line.match(/^\s/)) {
      const prev = reassembled[reassembled.length - 1] ?? '';
      if (prev.match(/https?:\/\//) && !prev.match(/\s$/)) {
        reassembled[reassembled.length - 1] = prev + line;
        continue;
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
      rawUrl = rawUrl.replace(/[\x00-\x1f\x7f]/g, '');
      const urlMatch = rawUrl.match(/^(https:\/\/[^\s"'<>]+)/);
      if (urlMatch && urlMatch[1]) {
        rawUrls.push(urlMatch[1].replace(/[.,;:)]+$/, ''));
      }
    }

    const parsed = parseCliOutput(buffer);
    const firstRawUrl = rawUrls[0];
    const firstParsedUrl = parsed.urls[0];
    if (firstRawUrl && firstParsedUrl) {
      const longest = firstRawUrl.length >= firstParsedUrl.length ? firstRawUrl : firstParsedUrl;
      parsed.urls = [longest];
    } else if (rawUrls.length > 0) {
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
