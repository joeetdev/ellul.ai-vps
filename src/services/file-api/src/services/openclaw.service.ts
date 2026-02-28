/**
 * OpenClaw Service
 *
 * Manages per-project OpenClaw workspace files ({project}/.openclaw/) and
 * channel configuration (~/.openclaw/openclaw.json).
 */

import * as fs from 'fs';
import * as path from 'path';
import { execFileSync, spawn, type ChildProcess } from 'child_process';
import { HOME, ROOT_DIR } from '../config';
import { getActiveProject } from './files.service';

const OPENCLAW_DIR = `${HOME}/.openclaw`;
const CONFIG_FILE = `${OPENCLAW_DIR}/openclaw.json`;

/**
 * Get the per-project .openclaw/ workspace directory.
 * Falls back to the global ~/.openclaw/workspace/ if no project is active.
 */
function getWorkspaceDir(): string {
  const activeProject = getActiveProject();
  if (activeProject && activeProject !== 'welcome') {
    return path.join(ROOT_DIR, activeProject, '.openclaw');
  }
  return `${OPENCLAW_DIR}/workspace`;
}

// Allowed workspace files (prevents path traversal)
const ALLOWED_WORKSPACE_FILES = new Set([
  'AGENTS.md',
  'SOUL.md',
  'TOOLS.md',
  'IDENTITY.md',
  'USER.md',
  'HEARTBEAT.md',
  'BOOTSTRAP.md',
  'MEMORY.md',
]);

export interface WorkspaceFileInfo {
  name: string;
  size: number;
  modified: string;
  preview: string;
}

/**
 * List all workspace files in the active project's .openclaw/ directory.
 */
export function listOpenclawWorkspaceFiles(): WorkspaceFileInfo[] {
  const wsDir = getWorkspaceDir();
  if (!fs.existsSync(wsDir)) {
    return [];
  }

  const files: WorkspaceFileInfo[] = [];
  for (const f of fs.readdirSync(wsDir)) {
    if (!f.endsWith('.md')) continue;
    const filePath = path.join(wsDir, f);
    try {
      const stat = fs.statSync(filePath);
      if (!stat.isFile()) continue;
      const content = fs.readFileSync(filePath, 'utf8');
      files.push({
        name: f,
        size: stat.size,
        modified: stat.mtime.toISOString(),
        preview: content.slice(0, 200),
      });
    } catch {
      // Skip unreadable files
    }
  }
  return files;
}

/**
 * Get a workspace file's content.
 */
export function getOpenclawWorkspaceFile(fileName: string): {
  content: string;
  size: number;
  modified: string;
} | null {
  if (!ALLOWED_WORKSPACE_FILES.has(fileName)) {
    return null;
  }

  const wsDir = getWorkspaceDir();
  const filePath = path.join(wsDir, fileName);
  if (!fs.existsSync(filePath)) {
    return null;
  }

  const realPath = fs.realpathSync(filePath);
  if (!realPath.startsWith(fs.realpathSync(wsDir))) {
    return null; // Prevent symlink traversal
  }

  const content = fs.readFileSync(realPath, 'utf8');
  const stat = fs.statSync(realPath);
  return {
    content,
    size: stat.size,
    modified: stat.mtime.toISOString(),
  };
}

/**
 * Save a workspace file.
 */
export function saveOpenclawWorkspaceFile(
  fileName: string,
  content: string
): { success: boolean; error?: string } {
  if (!ALLOWED_WORKSPACE_FILES.has(fileName)) {
    return { success: false, error: 'File not allowed' };
  }

  const wsDir = getWorkspaceDir();
  fs.mkdirSync(wsDir, { recursive: true });
  const filePath = path.join(wsDir, fileName);
  fs.writeFileSync(filePath, content);
  return { success: true };
}

/**
 * Run an openclaw CLI command with the gateway port env var.
 * Uses execFileSync with args array to prevent shell injection.
 */
function runOpenclawCli(args: string[]): string {
  return execFileSync('openclaw', args, {
    env: { ...process.env, OPENCLAW_GATEWAY_PORT: '18790' },
    encoding: 'utf8',
    timeout: 15000,
  }).trim();
}

// Validate project name (alphanumeric, hyphens, underscores only)
function isValidProjectName(name: string): boolean {
  return /^[a-zA-Z0-9_-]+$/.test(name);
}

/**
 * Read the channels section from openclaw.json.
 * If project is specified, returns only the channel accounts for that project.
 */
export function getOpenclawChannels(project?: string): Record<string, unknown> {
  if (!fs.existsSync(CONFIG_FILE)) {
    return {};
  }

  try {
    const raw = fs.readFileSync(CONFIG_FILE, 'utf8');
    const config = JSON.parse(raw);
    const channels = config.channels || {};

    if (!project) {
      return channels;
    }

    // Extract per-project channel configs from multi-account structure
    const result: Record<string, unknown> = {};
    for (const [channelName, channelData] of Object.entries(channels)) {
      if (!channelData || typeof channelData !== 'object') continue;
      const cd = channelData as Record<string, unknown>;

      // Multi-account structure: channels.telegram.accounts.{accountId}
      const accounts = cd.accounts as Record<string, unknown> | undefined;
      if (accounts && typeof accounts === 'object' && accounts[project]) {
        const acct = accounts[project] as Record<string, unknown>;
        result[channelName] = { ...acct, enabled: true };
      }
    }
    return result;
  } catch {
    return {};
  }
}

/**
 * Save a single channel's config into openclaw.json.
 * If project is specified, uses the CLI to set up multi-account + agent binding.
 */
export function saveOpenclawChannel(
  channel: string,
  channelConfig: Record<string, unknown>,
  project?: string,
): { success: boolean; error?: string } {
  const allowed = ['whatsapp', 'telegram', 'discord', 'slack'];
  if (!allowed.includes(channel)) {
    return { success: false, error: 'Unknown channel' };
  }

  if (project) {
    if (!isValidProjectName(project)) {
      return { success: false, error: 'Invalid project name' };
    }
    return saveProjectChannel(channel, channelConfig, project);
  }

  // Global (no project) — direct JSON write
  let config: Record<string, unknown> = {};
  if (fs.existsSync(CONFIG_FILE)) {
    try {
      config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    } catch {
      // Corrupt config — start fresh but preserve what we can
    }
  }

  if (!config.channels || typeof config.channels !== 'object') {
    config.channels = {};
  }

  (config.channels as Record<string, unknown>)[channel] = channelConfig;

  fs.mkdirSync(OPENCLAW_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
  return { success: true };
}

// --- WhatsApp QR login process management ---

let whatsappLoginProc: ChildProcess | null = null;
let whatsappLoginTimeout: NodeJS.Timeout | null = null;

/**
 * Strip ANSI escape sequences from a string.
 */
function stripAnsi(str: string): string {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\x1B\[[0-9;]*[a-zA-Z]/g, '').replace(/\x1B\][^\x07]*\x07/g, '');
}

/**
 * Start the WhatsApp QR login process.
 * Uses `script -qec` to allocate a pseudo-TTY so the CLI outputs its QR code.
 * Captures QR output from stdout and broadcasts it via broadcastFn.
 */
export function startWhatsAppLogin(
  project: string | undefined,
  broadcastFn: (type: string, data: unknown) => void,
): { success: boolean; error?: string } {
  // Kill any existing login process
  stopWhatsAppLogin();

  // Build the command string for `script -qec`
  // All parts are validated (channel is hardcoded, project passes isValidProjectName)
  const cmdParts = ['openclaw', 'channels', 'login', '--channel', 'whatsapp'];
  if (project && isValidProjectName(project)) {
    cmdParts.push('--account', project);
  }
  const cmdString = cmdParts.join(' ');

  try {
    // Use `script` to allocate a PTY — openclaw suppresses QR output without a TTY
    // -f flushes output after each write (prevents buffering)
    const proc = spawn('script', ['-qfec', cmdString, '/dev/null'], {
      env: { ...process.env, OPENCLAW_GATEWAY_PORT: '18790' },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    whatsappLoginProc = proc;

    // QR data pattern: Baileys emits strings like "2@ABcd..." before ASCII rendering
    const qrDataPattern = /^\d+@[\w+/=]+,[\w+/=]+,[\w+/=]+/;
    // ASCII QR art detection: lines with Unicode block characters
    const asciiQrPattern = /[▄▀█░▌▐▓▒]{3,}/;

    let asciiQrLines: string[] = [];
    let qrFlushTimer: NodeJS.Timeout | null = null;

    // Flush QR block with debounce — waits for output to stop for 500ms
    const flushQrBlock = () => {
      if (qrFlushTimer) { clearTimeout(qrFlushTimer); qrFlushTimer = null; }
      if (asciiQrLines.length >= 20) {
        broadcastFn('whatsapp_qr', { asciiQr: asciiQrLines.join('\n'), status: 'waiting' });
      }
      asciiQrLines = [];
    };

    const scheduleFlush = () => {
      if (qrFlushTimer) clearTimeout(qrFlushTimer);
      qrFlushTimer = setTimeout(flushQrBlock, 500);
    };

    const handleStdout = (chunk: Buffer) => {
      const text = stripAnsi(chunk.toString());
      const lines = text.split('\n');
      for (const line of lines) {
        // Strip carriage returns from PTY output
        const trimmed = line.replace(/\r/g, '').trimEnd();
        if (!trimmed) continue;

        // Check for raw QR data string
        if (qrDataPattern.test(trimmed)) {
          asciiQrLines = [];
          broadcastFn('whatsapp_qr', { qr: trimmed, status: 'waiting' });
        } else if (asciiQrPattern.test(trimmed)) {
          asciiQrLines.push(trimmed);
          scheduleFlush();
        }
      }
    };

    proc.stdout?.on('data', handleStdout);
    // script merges child stderr into stdout via PTY, so stderr here is script's own errors only

    proc.on('close', (code) => {
      if (whatsappLoginTimeout) {
        clearTimeout(whatsappLoginTimeout);
        whatsappLoginTimeout = null;
      }
      if (qrFlushTimer) {
        clearTimeout(qrFlushTimer);
        qrFlushTimer = null;
      }
      whatsappLoginProc = null;

      // Flush any remaining QR lines
      if (asciiQrLines.length >= 20) {
        broadcastFn('whatsapp_qr', { asciiQr: asciiQrLines.join('\n'), status: 'waiting' });
      }

      if (code === 0) {
        broadcastFn('whatsapp_qr', { status: 'connected' });
      } else {
        broadcastFn('whatsapp_qr', { status: 'error', error: `Process exited with code ${code}` });
      }
    });

    proc.on('error', (err) => {
      whatsappLoginProc = null;
      if (whatsappLoginTimeout) {
        clearTimeout(whatsappLoginTimeout);
        whatsappLoginTimeout = null;
      }
      broadcastFn('whatsapp_qr', { status: 'error', error: err.message });
    });

    // 2 minute timeout
    whatsappLoginTimeout = setTimeout(() => {
      if (whatsappLoginProc) {
        whatsappLoginProc.kill();
        whatsappLoginProc = null;
        broadcastFn('whatsapp_qr', { status: 'error', error: 'Login timed out (2 minutes)' });
      }
      whatsappLoginTimeout = null;
    }, 120_000);

    return { success: true };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: msg };
  }
}

/**
 * Stop the WhatsApp login process if running.
 */
export function stopWhatsAppLogin(): void {
  if (whatsappLoginTimeout) {
    clearTimeout(whatsappLoginTimeout);
    whatsappLoginTimeout = null;
  }
  if (whatsappLoginProc) {
    whatsappLoginProc.kill();
    whatsappLoginProc = null;
  }
}

/**
 * Serve WhatsApp QR login as an SSE stream.
 * Spawns the login process, streams QR output as SSE events to the response.
 * The response is kept open until the process exits or times out.
 */
export function handleWhatsAppQrStream(
  res: import('http').ServerResponse,
  project: string | undefined,
): void {
  // Kill any existing login process
  stopWhatsAppLogin();

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });

  const send = (event: string, data: unknown) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  send('status', { status: 'starting' });

  const cmdParts = ['openclaw', 'channels', 'login', '--channel', 'whatsapp'];
  if (project && isValidProjectName(project)) {
    cmdParts.push('--account', project);
  }
  const cmdString = cmdParts.join(' ');

  let proc: ChildProcess;
  try {
    proc = spawn('script', ['-qfec', cmdString, '/dev/null'], {
      env: { ...process.env, OPENCLAW_GATEWAY_PORT: '18790' },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (err) {
    send('status', { status: 'error', error: (err as Error).message });
    res.end();
    return;
  }

  whatsappLoginProc = proc;

  const qrDataPattern = /^\d+@[\w+/=]+,[\w+/=]+,[\w+/=]+/;
  const asciiQrPattern = /[▄▀█░▌▐▓▒]{3,}/;
  let asciiQrLines: string[] = [];
  let qrFlushTimer: NodeJS.Timeout | null = null;

  const flushQr = () => {
    if (qrFlushTimer) { clearTimeout(qrFlushTimer); qrFlushTimer = null; }
    if (asciiQrLines.length >= 20) {
      send('qr', { asciiQr: asciiQrLines.join('\n') });
    }
    asciiQrLines = [];
  };

  proc.stdout?.on('data', (chunk: Buffer) => {
    const text = stripAnsi(chunk.toString());
    for (const line of text.split('\n')) {
      const trimmed = line.replace(/\r/g, '').trimEnd();
      if (!trimmed) continue;
      if (qrDataPattern.test(trimmed)) {
        asciiQrLines = [];
        send('qr', { rawQr: trimmed });
      } else if (asciiQrPattern.test(trimmed)) {
        asciiQrLines.push(trimmed);
        if (qrFlushTimer) clearTimeout(qrFlushTimer);
        qrFlushTimer = setTimeout(flushQr, 500);
      }
    }
  });

  proc.on('close', (code) => {
    if (qrFlushTimer) { clearTimeout(qrFlushTimer); qrFlushTimer = null; }
    if (whatsappLoginTimeout) { clearTimeout(whatsappLoginTimeout); whatsappLoginTimeout = null; }
    whatsappLoginProc = null;
    if (asciiQrLines.length >= 20) {
      send('qr', { asciiQr: asciiQrLines.join('\n') });
    }
    send('status', { status: code === 0 ? 'connected' : 'error', error: code !== 0 ? `Exit code ${code}` : undefined });
    res.end();
  });

  proc.on('error', (err) => {
    whatsappLoginProc = null;
    send('status', { status: 'error', error: err.message });
    res.end();
  });

  whatsappLoginTimeout = setTimeout(() => {
    if (whatsappLoginProc) {
      whatsappLoginProc.kill();
      whatsappLoginProc = null;
      send('status', { status: 'error', error: 'Login timed out (2 minutes)' });
      res.end();
    }
    whatsappLoginTimeout = null;
  }, 120_000);

  // If client disconnects, kill the process
  res.on('close', () => {
    stopWhatsAppLogin();
  });
}

/**
 * Returns self-contained HTML for WhatsApp QR pairing page.
 * Designed to be iframed from the console.
 */
export function getWhatsAppQrPageHtml(project: string | undefined): string {
  const qs = project ? `?project=${encodeURIComponent(project)}` : '';
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,system-ui,sans-serif;background:#0a0a0a;color:#e0e0e0;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:16px}
.container{text-align:center;max-width:400px;width:100%}
.spinner{display:inline-block;width:32px;height:32px;border:3px solid #333;border-top-color:#f97316;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.status{margin-top:12px;font-size:14px;color:#888}
pre.qr{font-family:monospace;font-size:5.5px;line-height:6.5px;background:#fff;color:#000;padding:8px;border-radius:8px;display:inline-block;white-space:pre;user-select:all;margin:12px 0}
.connected{color:#22c55e;font-size:16px;font-weight:600}
.error{color:#ef4444;font-size:14px}
.retry-btn{margin-top:12px;padding:8px 20px;border-radius:6px;border:1px solid #333;background:#1a1a1a;color:#e0e0e0;cursor:pointer;font-size:13px}
.retry-btn:hover{background:#252525;border-color:#555}
</style></head><body>
<div class="container">
  <div id="content">
    <div class="spinner"></div>
    <p class="status">Connecting to WhatsApp...<br><span style="font-size:12px;color:#555">This can take up to 60 seconds</span></p>
  </div>
</div>
<script>
(function(){
  var el = document.getElementById('content');
  var es = new EventSource('/api/openclaw/channels/whatsapp/qr-stream${qs}');
  es.addEventListener('qr', function(e){
    var d = JSON.parse(e.data);
    if(d.asciiQr){
      el.innerHTML = '<p style="font-size:13px;color:#888;margin-bottom:8px">Scan with WhatsApp &rarr; Linked Devices</p><pre class="qr">' + d.asciiQr.replace(/</g,'&lt;') + '</pre><p style="font-size:11px;color:#555">QR refreshes automatically</p>';
    }
  });
  es.addEventListener('status', function(e){
    var d = JSON.parse(e.data);
    if(d.status==='connected'){
      el.innerHTML='<p class="connected">&#10003; WhatsApp Connected</p>';
      es.close();
      if(window.parent!==window){window.parent.postMessage({type:'whatsapp-connected'},'*');}
    } else if(d.status==='error'){
      el.innerHTML='<p class="error">' + (d.error||'Connection failed') + '</p><button class="retry-btn" onclick="location.reload()">Retry</button>';
      es.close();
    }
  });
  es.onerror = function(){
    el.innerHTML='<p class="error">Connection lost</p><button class="retry-btn" onclick="location.reload()">Retry</button>';
    es.close();
  };
})();
</script></body></html>`;
}

// ── BYOK LLM Key Management ──

// Default model IDs per provider (used when no custom model is specified)
const BYOK_MODEL_IDS: Record<string, string> = {
  anthropic: 'anthropic/claude-sonnet-4-20250514',
  openai: 'openai/gpt-4o',
  openrouter: 'openrouter/nvidia/nemotron-nano-9b-v2:free',
  google: 'google/gemini-2.5-flash',
};

// ENV_VAR_MAP: provider → env var name OpenClaw expects for built-in providers.
const BYOK_ENV_VARS: Record<string, string> = {
  anthropic: 'ANTHROPIC_API_KEY',
  openai: 'OPENAI_API_KEY',
  openrouter: 'OPENROUTER_API_KEY',
  google: 'GOOGLE_API_KEY',
};

/**
 * Get the current BYOK LLM key status.
 * Returns whether a key is configured, which provider, and the model ID.
 */
export function getOpenclawLlmKey(): { hasKey: boolean; provider: string | null; modelId: string | null } {
  if (!fs.existsSync(CONFIG_FILE)) {
    return { hasKey: false, provider: null, modelId: null };
  }

  try {
    const raw = fs.readFileSync(CONFIG_FILE, 'utf8');
    const config = JSON.parse(raw);
    const env = config.env as Record<string, unknown> | undefined;
    if (!env || typeof env !== 'object') {
      return { hasKey: false, provider: null, modelId: null };
    }

    // Check which BYOK env var is set
    for (const [provider, varName] of Object.entries(BYOK_ENV_VARS)) {
      if (env[varName]) {
        // Extract current model ID from config
        const modelPrimary = (config.agents as Record<string, unknown>)?.defaults as Record<string, unknown>;
        const model = modelPrimary?.model as Record<string, unknown> | undefined;
        const modelId = (model?.primary as string) || null;
        return { hasKey: true, provider, modelId };
      }
    }

    return { hasKey: false, provider: null, modelId: null };
  } catch {
    return { hasKey: false, provider: null, modelId: null };
  }
}

/**
 * Save a BYOK LLM key for the given provider.
 * Clears any existing BYOK keys, sets the new one, and updates model config.
 * For OpenRouter, accepts a custom modelId (e.g. "anthropic/claude-sonnet-4").
 */
export function saveOpenclawLlmKey(
  provider: string,
  apiKey: string,
  modelId?: string,
): { success: boolean; error?: string } {
  const validProviders = Object.keys(BYOK_MODEL_IDS);
  if (!validProviders.includes(provider)) {
    return { success: false, error: `Invalid provider. Must be one of: ${validProviders.join(', ')}` };
  }

  let config: Record<string, unknown> = {};
  if (fs.existsSync(CONFIG_FILE)) {
    try {
      config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    } catch {
      // Corrupt config — start fresh
    }
  }

  // Ensure nested structures
  if (!config.agents || typeof config.agents !== 'object') config.agents = {};
  const agents = config.agents as Record<string, unknown>;
  if (!agents.defaults || typeof agents.defaults !== 'object') agents.defaults = {};
  const defaults = agents.defaults as Record<string, unknown>;
  if (!config.env || typeof config.env !== 'object') config.env = {};
  const env = config.env as Record<string, unknown>;

  // Clear any previous BYOK env vars
  for (const varName of Object.values(BYOK_ENV_VARS)) {
    delete env[varName];
  }

  // Set the new provider's API key
  env[BYOK_ENV_VARS[provider]!] = apiKey;

  // Determine model ID: use custom modelId for OpenRouter, default for others
  let resolvedModelId = BYOK_MODEL_IDS[provider]!;
  if (provider === 'openrouter' && modelId?.trim()) {
    // Ensure the model ID has the openrouter/ prefix
    const cleaned = modelId.trim();
    resolvedModelId = cleaned.startsWith('openrouter/') ? cleaned : `openrouter/${cleaned}`;
  }

  // Set model to BYOK provider with fallback
  defaults.model = {
    primary: resolvedModelId,
    fallbacks: ['ellulai/default'],
  };

  fs.mkdirSync(OPENCLAW_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
  return { success: true };
}

/**
 * Remove the BYOK LLM key and revert to default model.
 */
export function removeOpenclawLlmKey(): { success: boolean } {
  if (!fs.existsSync(CONFIG_FILE)) {
    return { success: true };
  }

  let config: Record<string, unknown> = {};
  try {
    config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch {
    return { success: true };
  }

  // Clear all BYOK env vars
  if (config.env && typeof config.env === 'object') {
    const env = config.env as Record<string, unknown>;
    for (const varName of Object.values(BYOK_ENV_VARS)) {
      delete env[varName];
    }
    if (Object.keys(env).length === 0) delete config.env;
  }

  // Revert model to default
  if (!config.agents || typeof config.agents !== 'object') config.agents = {};
  const agents = config.agents as Record<string, unknown>;
  if (!agents.defaults || typeof agents.defaults !== 'object') agents.defaults = {};
  const defaults = agents.defaults as Record<string, unknown>;
  defaults.model = { primary: 'ellulai/default' };

  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
  return { success: true };
}

/**
 * Save a channel for a specific project.
 * Writes multi-account config directly to openclaw.json (the CLI `channels add`
 * doesn't support all channel names), then uses the CLI only for agent binding.
 */
function saveProjectChannel(
  channel: string,
  channelConfig: Record<string, unknown>,
  project: string,
): { success: boolean; error?: string } {
  // WhatsApp uses QR pairing — no token needed
  const isWhatsApp = channel === 'whatsapp';

  // Determine the token value from the config
  const tokenKey = channel === 'slack' ? 'botToken' : (channel === 'telegram' ? 'botToken' : 'token');
  const token = channelConfig[tokenKey] as string | undefined;

  if (!isWhatsApp && !token) {
    return { success: false, error: `Missing token field (${tokenKey})` };
  }

  try {
    // 1. Write channel account config directly to openclaw.json
    let config: Record<string, unknown> = {};
    if (fs.existsSync(CONFIG_FILE)) {
      try {
        config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
      } catch { /* start fresh */ }
    }

    if (!config.channels || typeof config.channels !== 'object') config.channels = {};
    const channels = config.channels as Record<string, unknown>;
    if (!channels[channel] || typeof channels[channel] !== 'object') channels[channel] = {};
    const ch = channels[channel] as Record<string, unknown>;
    if (!ch.accounts || typeof ch.accounts !== 'object') ch.accounts = {};
    const accounts = ch.accounts as Record<string, unknown>;

    // Build the account config
    const acct: Record<string, unknown> = {
      dmPolicy: 'open',
      allowFrom: ['*'],
    };

    if (token) {
      acct[tokenKey] = token;
    }

    // For Slack, also save appToken if provided
    if (channel === 'slack' && channelConfig.appToken) {
      acct.appToken = channelConfig.appToken;
    }

    accounts[project] = acct;

    // 2. Add routing binding so this channel account routes to the project agent
    const agentId = `dev-${project}`;
    if (!Array.isArray(config.bindings)) config.bindings = [];
    const bindings = config.bindings as Array<{ agentId: string; match: { channel: string; accountId: string } }>;
    const existingIdx = bindings.findIndex(
      (b) => b.match?.channel === channel && b.match?.accountId === project,
    );
    const binding = { agentId, match: { channel, accountId: project } };
    if (existingIdx >= 0) {
      bindings[existingIdx] = binding;
    } else {
      bindings.push(binding);
    }

    fs.mkdirSync(OPENCLAW_DIR, { recursive: true });
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));

    return { success: true };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: msg };
  }
}
