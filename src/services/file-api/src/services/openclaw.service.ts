/**
 * OpenClaw Service
 *
 * Manages per-project OpenClaw workspace files ({project}/.openclaw/) and
 * channel configuration (~/.openclaw/openclaw.json).
 */

import * as fs from 'fs';
import * as path from 'path';
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
 * Read the channels section from openclaw.json.
 */
export function getOpenclawChannels(): Record<string, unknown> {
  if (!fs.existsSync(CONFIG_FILE)) {
    return {};
  }

  try {
    const raw = fs.readFileSync(CONFIG_FILE, 'utf8');
    const config = JSON.parse(raw);
    return config.channels || {};
  } catch {
    return {};
  }
}

/**
 * Save a single channel's config into openclaw.json.
 */
export function saveOpenclawChannel(
  channel: string,
  channelConfig: Record<string, unknown>
): { success: boolean; error?: string } {
  const allowed = ['whatsapp', 'telegram', 'discord', 'slack'];
  if (!allowed.includes(channel)) {
    return { success: false, error: 'Unknown channel' };
  }

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
