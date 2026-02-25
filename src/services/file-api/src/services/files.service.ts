/**
 * Files Service
 *
 * File tree, content, and file system operations.
 */

import * as fs from 'fs';
import * as path from 'path';
import { ROOT_DIR, HOME, MAX_FILE_SIZE } from '../config';
import { safeReadFile, safeStat, safeReadDir, shouldIgnore } from '../utils';

/**
 * File tree node.
 */
export interface FileTreeNode {
  name: string;
  type: 'file' | 'dir';
  path: string;
  mtime?: number;
  children?: FileTreeNode[];
  error?: boolean;
}

const ACTIVE_PROJECT_FILE = `${HOME}/.ellulai/active-project`;

/**
 * Set the active project (persists across refreshes).
 */
export function setActiveProject(projectName: string): boolean {
  const projectPath = path.join(ROOT_DIR, projectName);
  if (!fs.existsSync(projectPath)) return false;
  fs.mkdirSync(path.dirname(ACTIVE_PROJECT_FILE), { recursive: true });
  fs.writeFileSync(ACTIVE_PROJECT_FILE, projectName);
  return true;
}

/**
 * Get active project directory.
 * Reads from persistent file first, falls back to first non-welcome directory.
 */
export function getActiveProject(): string {
  // 1. Try persistent file
  try {
    if (fs.existsSync(ACTIVE_PROJECT_FILE)) {
      const saved = fs.readFileSync(ACTIVE_PROJECT_FILE, 'utf8').trim();
      if (saved && fs.existsSync(path.join(ROOT_DIR, saved))) return saved;
    }
  } catch {}

  // 2. Fallback: first non-welcome directory
  try {
    const projects = fs.readdirSync(ROOT_DIR).filter((f) => {
      const stat = fs.statSync(path.join(ROOT_DIR, f));
      return stat.isDirectory() && f !== 'welcome';
    });
    const fallback = projects.length > 0 ? (projects[0] as string) : 'welcome';
    // Persist the fallback so next read is consistent
    if (fallback !== 'welcome') {
      try { setActiveProject(fallback); } catch {}
    }
    return fallback;
  } catch {
    return 'welcome';
  }
}

/**
 * Build file tree recursively.
 */
export function getTree(dir: string, relativePath: string = ''): FileTreeNode {
  const stats = safeStat(dir);
  const name = path.basename(dir);

  if (!stats) {
    return { name, type: 'file', path: relativePath, error: true };
  }

  if (!stats.isDirectory()) {
    return { name, type: 'file', path: relativePath, mtime: Math.floor(stats.mtimeMs) };
  }

  const children: FileTreeNode[] = [];
  const entries = safeReadDir(dir);

  for (const entry of entries) {
    if (
      entry.startsWith('.') ||
      entry === 'node_modules' ||
      entry === 'dist' ||
      entry === 'build' ||
      entry === '.next' ||
      entry === '__pycache__' ||
      entry === 'venv'
    ) {
      continue;
    }

    const childPath = path.join(dir, entry);
    const childRelative = relativePath ? `${relativePath}/${entry}` : entry;
    const childTree = getTree(childPath, childRelative);
    if (childTree && !childTree.error) {
      children.push(childTree);
    }
  }

  // Sort: directories first, then files, alphabetically
  children.sort((a, b) => {
    if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  return { name, type: 'dir', path: relativePath, children };
}

/**
 * Get file content with security checks.
 */
export function getFileContent(
  relativePath: string,
  projectPath: string
): {
  content?: string;
  error?: string;
  statusCode: number;
} {
  // Resolve path to prevent path traversal attacks
  const resolvedProjectPath = path.resolve(projectPath);
  const fullPath = path.resolve(projectPath, relativePath);

  if (!fullPath.startsWith(resolvedProjectPath + path.sep) && fullPath !== resolvedProjectPath) {
    return { error: 'Path traversal not allowed', statusCode: 403 };
  }

  if (!fs.existsSync(fullPath)) {
    return { error: 'File not found', statusCode: 404 };
  }

  // Check for symlink escape
  try {
    const realPath = fs.realpathSync(fullPath);
    if (!realPath.startsWith(resolvedProjectPath + path.sep) && realPath !== resolvedProjectPath) {
      return { error: 'Symlink escape not allowed', statusCode: 403 };
    }
  } catch {
    return { error: 'Cannot resolve file path', statusCode: 403 };
  }

  const stat = fs.statSync(fullPath);
  if (stat.size > 500000) {
    return { error: 'File too large', statusCode: 413 };
  }

  const content = fs.readFileSync(fullPath, 'utf8');
  return { content, statusCode: 200 };
}

/**
 * List all projects.
 */
export function listProjects(): { projects: string[]; active: string } {
  const projects = fs.readdirSync(ROOT_DIR).filter((f) => {
    return fs.statSync(path.join(ROOT_DIR, f)).isDirectory();
  });
  const active = getActiveProject();
  return { projects, active };
}

/**
 * Parse multipart form data for file uploads.
 */
export interface UploadedFile {
  filename: string;
  contentType: string;
  data: Buffer;
}

export interface MultipartParts {
  [key: string]: string | UploadedFile;
}

export function parseMultipart(
  buffer: Buffer,
  contentType: string
): MultipartParts {
  const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/);
  if (!boundaryMatch) {
    throw new Error('No boundary in content-type');
  }
  const boundary = boundaryMatch[1] || boundaryMatch[2];
  const parts: MultipartParts = {};

  const boundaryBuffer = Buffer.from('--' + boundary);
  let start = 0;

  while (true) {
    const boundaryIndex = buffer.indexOf(boundaryBuffer, start);
    if (boundaryIndex === -1) break;

    const partStart = boundaryIndex + boundaryBuffer.length + 2; // Skip boundary + CRLF
    const nextBoundary = buffer.indexOf(boundaryBuffer, partStart);
    if (nextBoundary === -1) break;

    const partEnd = nextBoundary - 2; // Exclude trailing CRLF
    const partData = buffer.subarray(partStart, partEnd);

    // Find header/body separator (double CRLF)
    const headerEnd = partData.indexOf('\r\n\r\n');
    if (headerEnd === -1) {
      start = nextBoundary;
      continue;
    }

    const headerStr = partData.subarray(0, headerEnd).toString('utf8');
    const body = partData.subarray(headerEnd + 4);

    // Parse headers
    const nameMatch = headerStr.match(/name="([^"]+)"/);
    const filenameMatch = headerStr.match(/filename="([^"]+)"/);
    const contentTypeMatch = headerStr.match(/Content-Type:\s*([^\r\n]+)/i);

    if (nameMatch) {
      const fieldName = nameMatch[1] as string;
      if (filenameMatch) {
        parts[fieldName] = {
          filename: filenameMatch[1] as string,
          contentType: contentTypeMatch ? (contentTypeMatch[1] as string) : 'application/octet-stream',
          data: body,
        };
      } else {
        parts[fieldName] = body.toString('utf8');
      }
    }

    start = nextBoundary;
  }

  return parts;
}

/**
 * Upload a file to a project.
 */
export function uploadFile(
  file: UploadedFile,
  destPath: string | undefined,
  projectName: string
): {
  success: boolean;
  filename?: string;
  path?: string;
  fullPath?: string;
  size?: number;
  project?: string;
  error?: string;
} {
  const projectDir = path.join(ROOT_DIR, projectName);

  if (!fs.existsSync(projectDir)) {
    return { success: false, error: 'Project not found' };
  }

  // Determine final file path
  let finalPath: string;
  if (destPath) {
    finalPath = path.join(projectDir, destPath);
  } else {
    const uploadsDir = path.join(projectDir, '.uploads');
    fs.mkdirSync(uploadsDir, { recursive: true });
    finalPath = path.join(uploadsDir, file.filename);
  }

  // Security: ensure path stays within project (check both resolved and real path)
  const resolvedPath = path.resolve(finalPath);
  if (!resolvedPath.startsWith(projectDir)) {
    return { success: false, error: 'Path traversal not allowed' };
  }

  // Create parent directory if needed
  fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });

  // Resolve symlinks to prevent symlink-based traversal (TOCTOU mitigation)
  const parentReal = fs.realpathSync(path.dirname(resolvedPath));
  if (!parentReal.startsWith(path.resolve(projectDir))) {
    return { success: false, error: 'Path traversal not allowed' };
  }

  // Write the file
  fs.writeFileSync(resolvedPath, file.data);

  // Return relative path for AI context
  const relativePath = path.relative(ROOT_DIR, resolvedPath);

  console.log(`[Upload] Saved file to ${resolvedPath}`);

  return {
    success: true,
    filename: file.filename,
    path: relativePath,
    fullPath: resolvedPath,
    size: file.data.length,
    project: projectName,
  };
}
