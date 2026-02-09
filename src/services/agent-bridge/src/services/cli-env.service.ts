/**
 * CLI Environment Service
 *
 * Manages CLI API keys stored in ~/.ellulai-env.
 */

import * as fs from 'fs';
import * as path from 'path';
import { CLI_ENV_FILE, CLI_KEY_MAP } from '../config';

// Re-export for consumers
export { CLI_KEY_MAP };

/**
 * Load env vars from ~/.ellulai-env.
 */
export function loadCliEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  try {
    if (!fs.existsSync(CLI_ENV_FILE)) return env;
    const lines = fs.readFileSync(CLI_ENV_FILE, 'utf8').split('\n');
    for (const line of lines) {
      const match = line.match(/^export\s+(\w+)=["']?(.+?)["']?$/);
      if (match && match[1] && match[2]) {
        env[match[1]] = match[2];
      }
    }
  } catch {}
  return env;
}

/**
 * Save a key to ~/.ellulai-env (creates or updates).
 */
export function saveCliKey(varName: string, value: string): void {
  let lines: string[] = [];
  try {
    if (fs.existsSync(CLI_ENV_FILE)) {
      lines = fs.readFileSync(CLI_ENV_FILE, 'utf8').split('\n');
    }
  } catch {}

  const exportLine = 'export ' + varName + '="' + value.replace(/"/g, '\\"') + '"';
  let found = false;
  for (let i = 0; i < lines.length; i++) {
    if ((lines[i] as string).match(new RegExp('^export\\s+' + varName + '='))) {
      lines[i] = exportLine;
      found = true;
      break;
    }
  }
  if (!found) lines.push(exportLine);

  // Remove empty lines at end
  while (lines.length > 0 && (lines[lines.length - 1] as string).trim() === '') lines.pop();
  fs.writeFileSync(CLI_ENV_FILE, lines.join('\n') + '\n', { mode: 0o600 });
}

/**
 * Remove a key from ~/.ellulai-env.
 */
export function removeCliKey(varName: string): void {
  try {
    if (!fs.existsSync(CLI_ENV_FILE)) return;
    let lines = fs.readFileSync(CLI_ENV_FILE, 'utf8').split('\n');
    lines = lines.filter((l) => !l.match(new RegExp('^export\\s+' + varName + '=')));
    while (lines.length > 0 && (lines[lines.length - 1] as string).trim() === '') lines.pop();
    fs.writeFileSync(CLI_ENV_FILE, lines.join('\n') + (lines.length ? '\n' : ''), { mode: 0o600 });
  } catch {}
}

/**
 * Get spawn env with CLI keys merged.
 */
export function getCliSpawnEnv(): NodeJS.ProcessEnv {
  return { ...process.env, ...loadCliEnv(), TERM: 'xterm-256color' };
}

/**
 * Check if a CLI needs first-time setup (not authenticated/configured).
 */
export function checkCliNeedsSetup(session: string): boolean {
  try {
    switch (session) {
      case 'claude': {
        // Claude stores auth in ~/.claude.json
        const home = process.env.HOME || '/home/dev';
        const claudeJson = path.join(home, '.claude.json');
        if (!fs.existsSync(claudeJson)) return true;
        const config = JSON.parse(fs.readFileSync(claudeJson, 'utf8')) as {
          oauthAccount?: unknown;
          hasCompletedOnboarding?: boolean;
          claudeCodeFirstTokenDate?: string;
          primaryApiKey?: string;
        };
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
        // Codex stores auth via OpenAI config
        const codexAuth = path.join(process.env.HOME || '/home/dev', '.codex', 'auth.json');
        const openaiKey = process.env.OPENAI_API_KEY || loadCliEnv()['OPENAI_API_KEY'];
        return !fs.existsSync(codexAuth) && !openaiKey;
      }
      case 'gemini': {
        // Gemini stores auth in ~/.config/gemini or uses GEMINI_API_KEY
        const geminiConfig = path.join(process.env.HOME || '/home/dev', '.config', 'gemini');
        const geminiKey = process.env.GEMINI_API_KEY || loadCliEnv()['GEMINI_API_KEY'];
        return !fs.existsSync(geminiConfig) && !geminiKey;
      }
      default:
        return false;
    }
  } catch {
    return true; // If we can't check, assume needs setup
  }
}

/**
 * Get CLI keys status for frontend.
 */
export function getCliKeysStatus(): Record<string, { set: boolean; masked?: string }> {
  const env = loadCliEnv();
  const keys: Record<string, { set: boolean; masked?: string }> = {};
  for (const [provider, varName] of Object.entries(CLI_KEY_MAP)) {
    const value = env[varName];
    keys[provider] = value
      ? { set: true, masked: '***' + (value.slice(-4) || '') }
      : { set: false };
  }
  return keys;
}
