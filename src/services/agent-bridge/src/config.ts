/**
 * Agent Bridge Configuration
 *
 * Constants and configuration for the Vibe Mode WebSocket server.
 */

import * as os from 'os';
import * as fs from 'fs';

const HOME = os.homedir();

// Dev preview domain (written by provisioning to /etc/ellulai/dev-domain)
let _devDomain = '';
try {
  _devDomain = fs.readFileSync('/etc/ellulai/dev-domain', 'utf8').trim();
} catch {}
export const DEV_DOMAIN = _devDomain;

export const PORT = 7700;
export const CHAT_DB_PATH = '/etc/ellulai/vibe-chat.db';
export const OPENCODE_API_PORT = 4096;
export const OPENCODE_BIN = `${HOME}/.opencode/bin/opencode`;
export const DEFAULT_SESSION = 'opencode';
export const PROJECTS_DIR = `${HOME}/projects`;
export const CONTEXT_DIR = `${HOME}/.ellulai/context`;
export const CLI_ENV_FILE = `${HOME}/.ellulai-env`;

export const VALID_SESSIONS = ['main', 'opencode', 'claude', 'codex', 'gemini', 'claw'] as const;
export type SessionType = (typeof VALID_SESSIONS)[number];

// Timeout settings
export const REQUEST_TIMEOUT_MS = 300000; // 5 minutes for AI requests
export const CLI_TIMEOUT_MS = 300000; // 5 minutes for AI CLI commands
export const CLI_ONESHOT_TIMEOUT_MS = 600000; // 10 minutes for one-shot AI CLI commands
export const INTERACTIVE_TIMEOUT_MS = 180000; // 3 min timeout for interactive sessions
export const MAX_BUFFER_SIZE = 64 * 1024; // 64KB buffer limit
export const DEBOUNCE_MS = 1200; // Wait for TUI to finish writing full frames
export const CONTEXT_CACHE_MS = 30000; // Refresh context every 30 seconds

// Relay agent UX — progress updates & stale detection
export const PROGRESS_INTERVAL_MS = 25000; // 25s between progress updates when user has no output
export const STALE_POLL_THRESHOLD = 10; // consecutive empty polls before warning user

// CLI environment variable mapping
export const CLI_KEY_MAP: Record<string, string> = {
  anthropic: 'ANTHROPIC_API_KEY',
  openai: 'OPENAI_API_KEY',
  gemini: 'GEMINI_API_KEY',
  openrouter: 'OPENROUTER_API_KEY',
};

// Allowed interactive commands (whitelist only - prevents command injection)
export const ALLOWED_INTERACTIVE_COMMANDS: Record<string, string[]> = {
  claude: ['claude', 'claude login'],
  codex: ['codex', 'codex login', 'codex login --device-auth'],
  gemini: ['gemini', 'gemini auth login'],
};

// Default interactive commands for each CLI
export const DEFAULT_INTERACTIVE_COMMANDS: Record<string, string> = {
  claude: 'claude login',
  codex: 'codex login',
  gemini: 'gemini auth login',
};

// Preview health gate (agent-bridge polls file-api for preview readiness)
export const FILE_API_PORT = 3002;
export const HEALTH_GATE_TOTAL_MS = 45_000;
export const HEALTH_GATE_INITIAL_DELAY_MS = 2_000;
export const HEALTH_GATE_MAX_INTERVAL_MS = 6_000;
export const HEALTH_GATE_BACKOFF_FACTOR = 1.5;

// Zen model discovery
export const ZEN_MODELS_URL = 'https://opencode.ai/zen/v1/models';
export const ZEN_REFRESH_MS = 30 * 60 * 1000; // 30 minutes
