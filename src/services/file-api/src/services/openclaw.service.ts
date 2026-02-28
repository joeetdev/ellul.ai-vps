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
 * Start the WhatsApp QR login process.
 * Spawns `openclaw channels login --channel whatsapp`, captures QR data from stdout,
 * and broadcasts it via the provided broadcastFn.
 */
export function startWhatsAppLogin(
  project: string | undefined,
  broadcastFn: (type: string, data: unknown) => void,
): { success: boolean; error?: string } {
  // Kill any existing login process
  stopWhatsAppLogin();

  const args = ['channels', 'login', '--channel', 'whatsapp'];
  if (project && isValidProjectName(project)) {
    args.push('--account', project);
  }

  try {
    const proc = spawn('openclaw', args, {
      env: { ...process.env, OPENCLAW_GATEWAY_PORT: '18790' },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    whatsappLoginProc = proc;

    // QR data pattern: Baileys emits strings like "2@ABcd..." before ASCII rendering
    const qrDataPattern = /^\d+@[\w+/=]+,[\w+/=]+,[\w+/=]+/;

    const handleData = (chunk: Buffer) => {
      const text = chunk.toString();
      const lines = text.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        // Check for raw QR data string
        if (qrDataPattern.test(trimmed)) {
          broadcastFn('whatsapp_qr', { qr: trimmed, status: 'waiting' });
        }
      }
    };

    proc.stdout?.on('data', handleData);
    proc.stderr?.on('data', handleData);

    proc.on('close', (code) => {
      if (whatsappLoginTimeout) {
        clearTimeout(whatsappLoginTimeout);
        whatsappLoginTimeout = null;
      }
      whatsappLoginProc = null;

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

// ── BYOK LLM Key Management ──

// BYOK model IDs per provider (used in openclaw.json config)
const BYOK_MODEL_IDS: Record<string, string> = {
  anthropic: 'anthropic/claude-sonnet-4-20250514',
  openai: 'openai/gpt-4o',
  openrouter: 'openrouter/anthropic/claude-sonnet-4-20250514',
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
 * Returns whether a key is configured and which provider it's for.
 */
export function getOpenclawLlmKey(): { hasKey: boolean; provider: string | null } {
  if (!fs.existsSync(CONFIG_FILE)) {
    return { hasKey: false, provider: null };
  }

  try {
    const raw = fs.readFileSync(CONFIG_FILE, 'utf8');
    const config = JSON.parse(raw);
    const env = config.env as Record<string, unknown> | undefined;
    if (!env || typeof env !== 'object') {
      return { hasKey: false, provider: null };
    }

    // Check which BYOK env var is set
    for (const [provider, varName] of Object.entries(BYOK_ENV_VARS)) {
      if (env[varName]) {
        return { hasKey: true, provider };
      }
    }

    return { hasKey: false, provider: null };
  } catch {
    return { hasKey: false, provider: null };
  }
}

/**
 * Save a BYOK LLM key for the given provider.
 * Clears any existing BYOK keys, sets the new one, and updates model config.
 */
export function saveOpenclawLlmKey(
  provider: string,
  apiKey: string,
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

  // Set model to BYOK provider with fallback
  defaults.model = {
    primary: BYOK_MODEL_IDS[provider],
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
  // Determine the token value from the config
  const tokenKey = channel === 'slack' ? 'botToken' : (channel === 'telegram' ? 'botToken' : 'token');
  const token = channelConfig[tokenKey] as string | undefined;

  if (!token) {
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
      [tokenKey]: token,
      dmPolicy: 'open',
      allowFrom: ['*'],
    };

    // For Slack, also save appToken if provided
    if (channel === 'slack' && channelConfig.appToken) {
      acct.appToken = channelConfig.appToken;
    }

    accounts[project] = acct;

    fs.mkdirSync(OPENCLAW_DIR, { recursive: true });
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));

    // 2. Bind agent to channel account (fire-and-forget, don't fail the whole save)
    try {
      const agentId = `dev-${project}`;
      runOpenclawCli([
        'agents', 'bind',
        '--agent', agentId,
        '--bind', `${channel}:${project}`,
      ]);
    } catch (bindErr: unknown) {
      // Agent binding can fail if agent doesn't exist yet — not fatal
      const msg = bindErr instanceof Error ? bindErr.message : String(bindErr);
      console.warn(`[openclaw] Agent bind failed for ${channel}:${project}: ${msg}`);
    }

    return { success: true };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: msg };
  }
}
