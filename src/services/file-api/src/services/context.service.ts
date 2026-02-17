/**
 * Context Service
 *
 * Manages AI context files (CLAUDE.md and custom context).
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { HOME, ROOT_DIR } from '../config';

const CONTEXT_DIR = `${HOME}/.ellulai/context`;
const GLOBAL_CLAUDE = `${HOME}/CLAUDE.md`;

/**
 * Context file info.
 */
export interface ContextFileInfo {
  name: string;
  path: string;
  type: 'context' | 'project' | 'global';
  project?: string;
  size: number;
  modified: Date;
  preview: string;
}

/**
 * List all context files.
 */
export function listContextFiles(): ContextFileInfo[] {
  const files: ContextFileInfo[] = [];

  // Custom context files
  if (fs.existsSync(CONTEXT_DIR)) {
    for (const f of fs.readdirSync(CONTEXT_DIR)) {
      if (f.endsWith('.md')) {
        const filePath = path.join(CONTEXT_DIR, f);
        const stat = fs.statSync(filePath);
        const content = fs.readFileSync(filePath, 'utf8');
        files.push({
          name: f,
          path: filePath,
          type: 'context',
          size: stat.size,
          modified: stat.mtime,
          preview: content.slice(0, 200),
        });
      }
    }
  }

  // Project CLAUDE.md files
  if (fs.existsSync(ROOT_DIR)) {
    for (const proj of fs.readdirSync(ROOT_DIR)) {
      const claudeFile = path.join(ROOT_DIR, proj, 'CLAUDE.md');
      if (fs.existsSync(claudeFile)) {
        const stat = fs.statSync(claudeFile);
        const content = fs.readFileSync(claudeFile, 'utf8');
        files.push({
          name: `${proj}/CLAUDE.md`,
          path: claudeFile,
          type: 'project',
          project: proj,
          size: stat.size,
          modified: stat.mtime,
          preview: content.slice(0, 200),
        });
      }
    }
  }

  // Global CLAUDE.md
  if (fs.existsSync(GLOBAL_CLAUDE)) {
    const stat = fs.statSync(GLOBAL_CLAUDE);
    const content = fs.readFileSync(GLOBAL_CLAUDE, 'utf8');
    files.push({
      name: 'CLAUDE.md (global)',
      path: GLOBAL_CLAUDE,
      type: 'global',
      size: stat.size,
      modified: stat.mtime,
      preview: content.slice(0, 200),
    });
  }

  return files;
}

/**
 * Resolve context file name to path.
 */
function resolveContextPath(fileName: string): string {
  if (fileName.includes('/CLAUDE.md')) {
    const proj = fileName.replace('/CLAUDE.md', '');
    return path.join(ROOT_DIR, proj, 'CLAUDE.md');
  }
  if (fileName === 'CLAUDE.md (global)') {
    return GLOBAL_CLAUDE;
  }
  if (!fileName.startsWith('/')) {
    return path.join(CONTEXT_DIR, fileName);
  }
  return fileName;
}

/**
 * Validate that a resolved path is within allowed directories.
 * Prevents path traversal attacks via absolute paths or symlinks.
 */
function isAllowedPath(filePath: string): boolean {
  const resolved = path.resolve(filePath);
  return resolved.startsWith(CONTEXT_DIR) ||
    resolved.startsWith(ROOT_DIR) ||
    resolved === GLOBAL_CLAUDE;
}

/**
 * Get a context file's content.
 */
export function getContextFile(fileName: string): {
  content: string;
  path: string;
  size: number;
  modified: Date;
} | null {
  const filePath = resolveContextPath(decodeURIComponent(fileName));

  if (!isAllowedPath(filePath)) {
    return null;
  }

  if (!fs.existsSync(filePath)) {
    return null;
  }

  // Resolve symlinks to prevent symlink-based traversal
  const realPath = fs.realpathSync(filePath);
  if (!isAllowedPath(realPath)) {
    return null;
  }

  const content = fs.readFileSync(realPath, 'utf8');
  const stat = fs.statSync(realPath);

  return {
    content,
    path: filePath,
    size: stat.size,
    modified: stat.mtime,
  };
}

/**
 * Save a context file.
 */
export function saveContextFile(
  fileName: string,
  content: string
): { success: boolean; path: string; error?: string } {
  const filePath = resolveContextPath(fileName);

  if (!isAllowedPath(filePath)) {
    return { success: false, path: filePath, error: 'Path not allowed' };
  }

  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);

  // Run context aggregator
  try {
    execSync('/usr/local/bin/ellulai-ctx', {
      cwd: ROOT_DIR,
      timeout: 5000,
    });
  } catch {}

  return { success: true, path: filePath };
}

/**
 * Delete a context file.
 */
export function deleteContextFile(fileName: string): { success: boolean; error?: string } {
  const filePath = resolveContextPath(decodeURIComponent(fileName));

  // Only allow deleting custom context files
  if (!filePath.startsWith(CONTEXT_DIR)) {
    return { success: false, error: 'Can only delete context files' };
  }

  if (!fs.existsSync(filePath)) {
    return { success: false, error: 'File not found' };
  }

  fs.unlinkSync(filePath);
  return { success: true };
}
