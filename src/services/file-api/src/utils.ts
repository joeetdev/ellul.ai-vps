/**
 * File API Utilities
 *
 * Safe helper functions for file system operations.
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { BINARY_EXTENSIONS, MAX_FILE_SIZE, IGNORED_PATTERNS } from './config';

/**
 * Safely read a file, returning null on error.
 */
export function safeReadFile(filePath: string, encoding: BufferEncoding = 'utf8'): string | null {
  try {
    return fs.readFileSync(filePath, encoding);
  } catch {
    return null;
  }
}

/**
 * Safely get file stats, returning null on error.
 */
export function safeStat(filePath: string): fs.Stats | null {
  try {
    return fs.statSync(filePath);
  } catch {
    return null;
  }
}

/**
 * Safely read directory contents, returning empty array on error.
 */
export function safeReadDir(dirPath: string): string[] {
  try {
    return fs.readdirSync(dirPath);
  } catch {
    return [];
  }
}

/**
 * Safely execute a command, returning result object.
 */
export function safeExec(
  cmd: string,
  options: { cwd?: string; timeout?: number } = {}
): { success: boolean; output: string; error?: string } {
  try {
    const output = execSync(cmd, {
      encoding: 'utf8',
      timeout: options.timeout || 10000,
      cwd: options.cwd,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return { success: true, output: output.trim() };
  } catch (e) {
    const error = e as Error & { stderr?: string };
    return {
      success: false,
      output: '',
      error: error.stderr || error.message,
    };
  }
}

/**
 * Check if a file extension is binary.
 */
export function isBinaryFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return BINARY_EXTENSIONS.has(ext);
}

/**
 * Check if a path should be ignored in file tree.
 */
export function shouldIgnore(name: string): boolean {
  return IGNORED_PATTERNS.some(pattern => {
    if (pattern.startsWith('*')) {
      return name.endsWith(pattern.slice(1));
    }
    return name === pattern;
  });
}

/**
 * Get file content with size limits and binary detection.
 */
export function getFileContent(filePath: string): {
  content: string | null;
  isBinary: boolean;
  size: number;
  error?: string;
} {
  const stats = safeStat(filePath);
  if (!stats) {
    return { content: null, isBinary: false, size: 0, error: 'File not found' };
  }

  if (stats.size > MAX_FILE_SIZE) {
    return {
      content: null,
      isBinary: false,
      size: stats.size,
      error: `File too large (${Math.round(stats.size / 1024 / 1024)}MB > 5MB limit)`,
    };
  }

  if (isBinaryFile(filePath)) {
    return { content: null, isBinary: true, size: stats.size };
  }

  const content = safeReadFile(filePath);
  if (content === null) {
    return { content: null, isBinary: false, size: stats.size, error: 'Failed to read file' };
  }

  return { content, isBinary: false, size: stats.size };
}

/**
 * Build a file tree structure for a directory.
 */
export interface FileTreeNode {
  name: string;
  path: string;
  type: 'file' | 'directory';
  children?: FileTreeNode[];
  size?: number;
}

export function buildFileTree(
  dirPath: string,
  basePath: string = '',
  depth: number = 0,
  maxDepth: number = 10
): FileTreeNode[] {
  if (depth > maxDepth) return [];

  const entries = safeReadDir(dirPath);
  const result: FileTreeNode[] = [];

  for (const entry of entries) {
    if (shouldIgnore(entry)) continue;

    const fullPath = path.join(dirPath, entry);
    const relativePath = path.join(basePath, entry);
    const stats = safeStat(fullPath);

    if (!stats) continue;

    if (stats.isDirectory()) {
      result.push({
        name: entry,
        path: relativePath,
        type: 'directory',
        children: buildFileTree(fullPath, relativePath, depth + 1, maxDepth),
      });
    } else if (stats.isFile()) {
      result.push({
        name: entry,
        path: relativePath,
        type: 'file',
        size: stats.size,
      });
    }
  }

  // Sort: directories first, then files, alphabetically
  return result.sort((a, b) => {
    if (a.type !== b.type) {
      return a.type === 'directory' ? -1 : 1;
    }
    return a.name.localeCompare(b.name);
  });
}

/**
 * Get git status for a directory.
 */
export interface GitStatus {
  isRepo: boolean;
  branch?: string;
  ahead?: number;
  behind?: number;
  staged?: number;
  unstaged?: number;
  untracked?: number;
}

export function getGitStatus(dirPath: string): GitStatus {
  // Check if directory is a git repo
  const gitDir = path.join(dirPath, '.git');
  if (!fs.existsSync(gitDir)) {
    return { isRepo: false };
  }

  const result: GitStatus = { isRepo: true };

  // Get current branch
  const branchResult = safeExec('git rev-parse --abbrev-ref HEAD', { cwd: dirPath });
  if (branchResult.success) {
    result.branch = branchResult.output;
  }

  // Get status counts
  const statusResult = safeExec('git status --porcelain', { cwd: dirPath });
  if (statusResult.success) {
    const lines = statusResult.output.split('\n').filter(Boolean);
    result.staged = lines.filter(l => l[0] !== ' ' && l[0] !== '?').length;
    result.unstaged = lines.filter(l => l[1] !== ' ' && l[0] !== '?').length;
    result.untracked = lines.filter(l => l.startsWith('??')).length;
  }

  // Get ahead/behind counts
  const trackingResult = safeExec('git rev-list --left-right --count @{upstream}...HEAD', { cwd: dirPath });
  if (trackingResult.success) {
    const [behind, ahead] = trackingResult.output.split('\t').map(Number);
    result.ahead = ahead || 0;
    result.behind = behind || 0;
  }

  return result;
}

/**
 * Parse JSON safely.
 */
export function safeJsonParse<T>(json: string | null, fallback: T): T {
  if (!json) return fallback;
  try {
    return JSON.parse(json) as T;
  } catch {
    return fallback;
  }
}
