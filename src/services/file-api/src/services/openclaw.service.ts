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

/**
 * Save a channel for a specific project using the openclaw CLI.
 * Sets up multi-account channel + agent binding.
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

  // Write token to temp file to avoid exposing it in process args
  const tmpFile = `/tmp/openclaw-token-${project}-${channel}-${Date.now()}`;
  try {
    fs.writeFileSync(tmpFile, token, { mode: 0o600 });

    // 1. Add channel account
    runOpenclawCli([
      'channels', 'add',
      '--channel', channel,
      '--token-file', tmpFile,
      '--account', project,
    ]);

    // 2. Configure channel policies
    runOpenclawCli([
      'config', 'set',
      `channels.${channel}.accounts.${project}.dmPolicy`,
      'open',
    ]);
    runOpenclawCli([
      'config', 'set',
      `channels.${channel}.accounts.${project}.allowFrom`,
      '["*"]',
    ]);

    // 3. For Slack, also save appToken if provided
    if (channel === 'slack' && channelConfig.appToken) {
      runOpenclawCli([
        'config', 'set',
        `channels.${channel}.accounts.${project}.appToken`,
        channelConfig.appToken as string,
      ]);
    }

    // 4. Bind agent to channel account
    const agentId = `dev-${project}`;
    runOpenclawCli([
      'agents', 'bind',
      '--agent', agentId,
      '--bind', `${channel}:${project}`,
    ]);

    return { success: true };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: `CLI error: ${msg}` };
  } finally {
    // Clean up temp file
    try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
  }
}
