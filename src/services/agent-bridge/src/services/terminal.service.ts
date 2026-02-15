/**
 * Terminal Session Manager
 *
 * Manages dynamic terminal sessions with independent tmux/ttyd instances.
 * Each session gets its own:
 * - Unique port (allocated from pool)
 * - tmux session with unique name
 * - ttyd process
 *
 * This enables multiple independent terminal sessions of the same type
 * (e.g., 3 separate Claude terminals with independent state).
 */

import { spawn, execSync, ChildProcess } from 'child_process';
import * as os from 'os';

// Session types that can be launched
export type TerminalSessionType = 'main' | 'opencode' | 'claude' | 'codex' | 'gemini';

// Port range for dynamic allocation (7700-7799, avoiding 7700-7701 used by other services)
const PORT_RANGE_START = 7710;
const PORT_RANGE_END = 7799;

// Track active sessions
interface ActiveSession {
  instanceId: string;
  type: TerminalSessionType;
  project: string | null; // App/project scope (null = global/unscoped)
  port: number;
  tmuxSession: string;
  ttydProcess: ChildProcess | null;
  createdAt: number;
  lastAccessed: number;
}

const activeSessions = new Map<string, ActiveSession>();
const usedPorts = new Set<number>();

// No idle timeout - sessions persist until explicitly closed or server restart.
// Security is enforced per-request via sovereign-shield (WebSocket auth).

/**
 * Allocate an available port from the pool.
 */
function allocatePort(): number | null {
  for (let port = PORT_RANGE_START; port <= PORT_RANGE_END; port++) {
    if (!usedPorts.has(port)) {
      usedPorts.add(port);
      return port;
    }
  }
  console.error('[Terminal] No available ports in range');
  return null;
}

/**
 * Release a port back to the pool.
 */
function releasePort(port: number): void {
  usedPorts.delete(port);
}

/**
 * Get the CLI command for a session type.
 */
function getSessionCommand(type: TerminalSessionType): string {
  const commands: Record<TerminalSessionType, string> = {
    main: 'bash',
    opencode: 'opencode',
    claude: 'claude',
    codex: 'codex',
    gemini: 'gemini',
  };
  return commands[type] || 'bash';
}

/**
 * Create a new terminal session.
 * Returns the session info including the port to connect to.
 * @param type - The terminal session type
 * @param instanceId - Optional custom instance ID
 * @param project - Optional project name to scope the working directory
 */
export async function createTerminalSession(
  type: TerminalSessionType,
  instanceId?: string,
  project?: string
): Promise<{ instanceId: string; port: number; type: TerminalSessionType } | null> {
  // Generate instance ID if not provided
  const id = instanceId || `${type}-${Date.now()}`;

  // Check if session already exists
  if (activeSessions.has(id)) {
    const existing = activeSessions.get(id)!;
    existing.lastAccessed = Date.now();
    console.log(`[Terminal] Reusing existing session ${id} on port ${existing.port}`);
    return { instanceId: id, port: existing.port, type: existing.type };
  }

  // Allocate port
  const port = allocatePort();
  if (!port) {
    return null;
  }

  // Create unique tmux session name
  const tmuxSession = `term-${id}`;

  try {
    // Start ttyd with the session
    const ttydProcess = await startTtyd(id, type, port, tmuxSession, project);

    const session: ActiveSession = {
      instanceId: id,
      type,
      project: project || null,
      port,
      tmuxSession,
      ttydProcess,
      createdAt: Date.now(),
      lastAccessed: Date.now(),
    };

    activeSessions.set(id, session);
    console.log(`[Terminal] Created session ${id} (${type}) on port ${port}`);

    return { instanceId: id, port, type };
  } catch (err) {
    releasePort(port);
    console.error(`[Terminal] Failed to create session ${id}:`, (err as Error).message);
    return null;
  }
}

/**
 * Validate and sanitize user-provided identifiers used in shell contexts.
 * Only allows alphanumeric characters, hyphens, underscores, and dots.
 * Prevents shell injection via project names or instance IDs.
 */
function sanitizeShellIdentifier(value: string, label: string): string {
  if (!/^[a-zA-Z0-9._-]+$/.test(value)) {
    throw new Error(`Invalid ${label}: contains disallowed characters`);
  }
  if (value.includes('..')) {
    throw new Error(`Invalid ${label}: path traversal not allowed`);
  }
  return value;
}

async function startTtyd(
  instanceId: string,
  type: TerminalSessionType,
  port: number,
  tmuxSession: string,
  project?: string
): Promise<ChildProcess> {
  const command = getSessionCommand(type);
  const projectsDir = `${os.homedir()}/projects`;

  // SECURITY: Validate all user-controlled values before shell interpolation
  const safeInstanceId = sanitizeShellIdentifier(instanceId, 'instanceId');
  const safeTmuxSession = sanitizeShellIdentifier(tmuxSession, 'tmuxSession');

  let workingDir = projectsDir;
  if (project) {
    const safeProject = sanitizeShellIdentifier(project, 'project');
    workingDir = `${projectsDir}/${safeProject}`;
  }

  const basePath = `/term/${safeInstanceId}/`;

  // Build the launch command using spawn array args where possible.
  // tmux session name and working dir are validated above (alphanumeric + hyphen/underscore/dot only).
  const launchCmd = type === 'main'
    ? `tmux new-session -A -s ${safeTmuxSession}`
    : `cd ${workingDir} && tmux new-session -A -s ${safeTmuxSession} "${command}; exec bash"`;

  // Start ttyd
  const ttyd = spawn('/usr/bin/ttyd', [
    '--base-path', basePath,
    '-p', String(port),
    '-i', '127.0.0.1',
    '-W',
    '-t', 'disableLeaveAlert=true',
    '-t', 'rightClickSelectsWord=true',
    '/bin/bash', '-c', launchCmd,
  ], {
    detached: true,
    stdio: 'ignore',
    env: {
      ...process.env,
      PATH: `${os.homedir()}/.node/bin:${os.homedir()}/.opencode/bin:${os.homedir()}/.local/bin:${process.env.PATH || ''}`,
    },
  });

  ttyd.unref();

  // Wait a bit for ttyd to start
  await new Promise(resolve => setTimeout(resolve, 500));

  // Verify ttyd is running
  if (ttyd.killed || ttyd.exitCode !== null) {
    throw new Error('ttyd process exited immediately');
  }

  return ttyd;
}

/**
 * Get session info by instance ID.
 */
export function getTerminalSession(instanceId: string): ActiveSession | null {
  const session = activeSessions.get(instanceId);
  if (session) {
    session.lastAccessed = Date.now();
    return session;
  }
  return null;
}

/**
 * Get port for a session (used by term-proxy).
 */
export function getTerminalSessionPort(instanceId: string): number | null {
  const session = activeSessions.get(instanceId);
  if (session) {
    session.lastAccessed = Date.now();
    return session.port;
  }
  return null;
}


/**
 * Close a terminal session and clean up resources.
 */
export async function closeTerminalSession(instanceId: string): Promise<boolean> {
  const session = activeSessions.get(instanceId);
  if (!session) {
    return false;
  }

  try {
    // Kill ttyd process
    if (session.ttydProcess && !session.ttydProcess.killed) {
      session.ttydProcess.kill('SIGTERM');
    }

    // Kill tmux session
    spawn('tmux', ['kill-session', '-t', session.tmuxSession], {
      stdio: 'ignore',
    });

    // Release port
    releasePort(session.port);

    // Remove from active sessions
    activeSessions.delete(instanceId);

    // Clear term-proxy cache
    try {
      await fetch(`http://127.0.0.1:7701/cache/clear/${instanceId}`, { method: 'DELETE' });
    } catch {
      // Non-fatal if term-proxy is not reachable
    }

    console.log(`[Terminal] Closed session ${instanceId}`);
    return true;
  } catch (err) {
    console.error(`[Terminal] Error closing session ${instanceId}:`, (err as Error).message);
    return false;
  }
}

/**
 * List active sessions, optionally filtered by project.
 * @param project - Filter by project (null = only unscoped sessions, undefined = all sessions)
 */
export function listTerminalSessions(project?: string | null): Array<{
  instanceId: string;
  type: TerminalSessionType;
  port: number;
  project: string | null;
  createdAt: number;
}> {
  let sessions = Array.from(activeSessions.values());

  // Filter by project if specified
  if (project !== undefined) {
    sessions = sessions.filter(s => s.project === project);
  }

  return sessions.map(s => ({
    instanceId: s.instanceId,
    type: s.type,
    port: s.port,
    project: s.project,
    createdAt: s.createdAt,
  }));
}

/**
 * Shutdown all sessions (for graceful shutdown).
 */
export async function shutdownAllSessions(): Promise<void> {
  console.log(`[Terminal] Shutting down ${activeSessions.size} sessions`);
  for (const id of activeSessions.keys()) {
    await closeTerminalSession(id);
  }
}

/**
 * Clean up orphaned terminal sessions on startup.
 *
 * This handles the case where agent-bridge restarts but tmux sessions
 * and ttyd processes are still running from the previous instance.
 *
 * Cleans up:
 * - tmux sessions matching pattern: term-*
 * - ttyd processes (identified by command line args)
 */
export function cleanupOrphanedSessions(): { tmuxKilled: number; ttydKilled: number } {
  let tmuxKilled = 0;
  let ttydKilled = 0;

  // 1. Kill orphaned tmux sessions (pattern: term-*)
  try {
    const tmuxList = execSync('tmux list-sessions -F "#{session_name}" 2>/dev/null || true', {
      encoding: 'utf-8',
    }).trim();

    if (tmuxList) {
      const sessions = tmuxList.split('\n').filter(s => s.startsWith('term-'));
      for (const session of sessions) {
        try {
          // Use spawn with array args to avoid shell injection from tmux session names
          const result = spawn('tmux', ['kill-session', '-t', session], { stdio: 'ignore' });
          result.on('close', () => {});
          tmuxKilled++;
          console.log(`[Terminal] Killed orphaned tmux session: ${session}`);
        } catch {
          // Ignore errors
        }
      }
    }
  } catch {
    // tmux not running or no sessions
  }

  // 2. Kill orphaned ttyd processes serving /term/ paths
  try {
    // Find ttyd processes with --base-path /term/
    const pgrep = execSync('pgrep -f "ttyd.*--base-path.*/term/" 2>/dev/null || true', {
      encoding: 'utf-8',
    }).trim();

    if (pgrep) {
      const pids = pgrep.split('\n').filter(p => p.trim());
      for (const pid of pids) {
        try {
          process.kill(parseInt(pid, 10), 'SIGTERM');
          ttydKilled++;
          console.log(`[Terminal] Killed orphaned ttyd process: ${pid}`);
        } catch {
          // Process may have already exited
        }
      }
    }
  } catch {
    // No matching processes
  }

  if (tmuxKilled > 0 || ttydKilled > 0) {
    console.log(`[Terminal] Startup cleanup: killed ${tmuxKilled} tmux sessions, ${ttydKilled} ttyd processes`);
  }

  return { tmuxKilled, ttydKilled };
}
