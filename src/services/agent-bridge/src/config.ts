/**
 * Agent Bridge Configuration
 *
 * Constants and configuration for the Vibe Mode WebSocket server.
 */

import * as os from 'os';
import { WATERFALL_MODELS } from '../../../configs/ai';

const HOME = os.homedir();

export const PORT = 7700;
export const CHAT_DB_PATH = '/etc/phonestack/vibe-chat.db';
export const OPENCODE_API_PORT = 4096;
export const OPENCODE_BIN = `${HOME}/.opencode/bin/opencode`;
export const DEFAULT_SESSION = 'opencode';
export const PROJECTS_DIR = `${HOME}/projects`;
export const CONTEXT_DIR = `${HOME}/.phonestack/context`;
export const CLI_ENV_FILE = `${HOME}/.phonestack-env`;

export const VALID_SESSIONS = ['main', 'opencode', 'claude', 'codex', 'gemini'] as const;
export type SessionType = (typeof VALID_SESSIONS)[number];

// Timeout settings
export const REQUEST_TIMEOUT_MS = 300000; // 5 minutes for AI requests
export const CLI_TIMEOUT_MS = 300000; // 5 minutes for AI CLI commands
export const CLI_ONESHOT_TIMEOUT_MS = 600000; // 10 minutes for one-shot AI CLI commands
export const INTERACTIVE_TIMEOUT_MS = 180000; // 3 min timeout for interactive sessions
export const MAX_BUFFER_SIZE = 64 * 1024; // 64KB buffer limit
export const DEBOUNCE_MS = 1200; // Wait for TUI to finish writing full frames
export const CONTEXT_CACHE_MS = 30000; // Refresh context every 30 seconds

// CLI environment variable mapping
export const CLI_KEY_MAP: Record<string, string> = {
  anthropic: 'ANTHROPIC_API_KEY',
  openai: 'OPENAI_API_KEY',
  gemini: 'GEMINI_API_KEY',
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

// Phone Stack AI waterfall models (from ai-config.ts)
export const PHONESTACK_MODELS = WATERFALL_MODELS.map((m) => ({
  id: m.modelId,
  name: m.name,
  isPaid: m.isPaid,
}));
