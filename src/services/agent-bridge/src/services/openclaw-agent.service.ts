/**
 * OpenClaw Agent Service
 *
 * Manages per-project OpenClaw agents. Each project gets an isolated agent
 * with its own workspace, memory, and identity via `openclaw agents add`.
 * Routing is done via `model: "openclaw:<agentId>"` in HTTP requests.
 */

import { execFile, execSync } from 'child_process';
import { homedir } from 'os';
import { join } from 'path';
import { readdirSync, statSync, existsSync, writeFileSync, readFileSync, mkdirSync } from 'fs';
import { PROJECTS_DIR, DEV_DOMAIN } from '../config';
import { getOpenclawIdentity, getOpenclawUser, getOpenclawSoul, getOpenclawTools, getOpenclawBootstrap } from '../../../../configs/openclaw';

const OPENCLAW_BIN_PATHS = [
  join(homedir(), '.openclaw', 'bin', 'openclaw'),
  '/usr/local/bin/openclaw',
];

// Path to the context generation script (deployed by provisioning)
const CONTEXT_SCRIPT = '/usr/local/bin/ellulai-ctx';

/**
 * Refresh CLI context files (CLAUDE.md, AGENTS.md, GEMINI.md) for a project.
 * Runs ellulai-ctx which generates platform context that CLI tools read.
 */
export function refreshProjectContext(projectDir: string): void {
  try {
    if (!existsSync(CONTEXT_SCRIPT)) {
      return; // Script not deployed yet (pre-provisioning or old VPS)
    }
    execSync(`${CONTEXT_SCRIPT} ${projectDir}`, { timeout: 10000, stdio: 'ignore' });
    console.log(`[AgentService] Refreshed CLI context for ${projectDir}`);
  } catch (err) {
    console.warn(`[AgentService] Failed to refresh CLI context:`, (err as Error).message);
  }
}

// Cache known agents to avoid repeated CLI calls
let knownAgents: Set<string> = new Set();
let agentsCacheTime = 0;
const AGENTS_CACHE_MS = 60000; // 1 minute

/**
 * Resolve the openclaw binary path.
 */
function getOpenclawBin(): string {
  for (const p of OPENCLAW_BIN_PATHS) {
    try {
      statSync(p);
      return p;
    } catch {}
  }
  return 'openclaw'; // Fall back to PATH
}

/**
 * Run an openclaw CLI command and return stdout.
 */
function runOpenclaw(args: string[]): Promise<string> {
  const bin = getOpenclawBin();
  return new Promise((resolve, reject) => {
    execFile(bin, args, { timeout: 15000 }, (err, stdout, stderr) => {
      if (err) {
        reject(new Error(`openclaw ${args.join(' ')}: ${stderr || err.message}`));
      } else {
        resolve(stdout.trim());
      }
    });
  });
}

/**
 * Get the agent ID for a project (convention-based).
 * Convention: "dev-{projectName}" for dev agents.
 * Future: "marketing-{projectName}", "ops-{projectName}", etc.
 */
export function getProjectAgentId(projectName: string): string {
  return `dev-${projectName}`;
}

// File tools the model MUST NOT have — forces it to use coding-agent (bash+process) instead.
// NOTE: Do NOT deny 'exec' — 'bash' is an alias for 'exec' in OpenClaw's tool system,
// and the coding-agent skill needs bash (pty:true) to launch CLI tools.
const DENIED_TOOLS = ['write', 'read', 'edit', 'apply_patch'];

/**
 * Deny native file/exec tools on an agent so it can only use bash+process.
 * Uses `openclaw config` to find the agent's index and set tools.sandbox.tools.deny.
 */
async function setAgentToolDeny(agentId: string): Promise<void> {
  try {
    // Find the agent's index in the config list
    const output = await runOpenclaw(['config', 'get', 'agents.list']);
    const list = JSON.parse(output) as { id: string }[];
    const idx = list.findIndex((a) => a.id === agentId);
    if (idx === -1) {
      console.warn(`[AgentService] Agent "${agentId}" not found in config, skipping tool deny`);
      return;
    }

    // Check if deny is already set
    try {
      const existing = await runOpenclaw(['config', 'get', `agents.list[${idx}].tools.sandbox.tools.deny`]);
      const parsed = JSON.parse(existing) as string[];
      if (Array.isArray(parsed) && DENIED_TOOLS.every((t) => parsed.includes(t))) {
        return; // Already configured
      }
    } catch {
      // Path doesn't exist yet — needs to be set
    }

    await runOpenclaw([
      'config', 'set',
      `agents.list[${idx}].tools.sandbox.tools.deny`,
      JSON.stringify(DENIED_TOOLS),
      '--json',
    ]);
    console.log(`[AgentService] Set tool deny for "${agentId}": ${DENIED_TOOLS.join(', ')}`);
  } catch (err) {
    console.warn(`[AgentService] Failed to set tool deny for "${agentId}":`, (err as Error).message);
  }
}

/**
 * List all OpenClaw agents.
 */
export async function listAgents(): Promise<string[]> {
  const now = Date.now();
  if (knownAgents.size > 0 && now - agentsCacheTime < AGENTS_CACHE_MS) {
    return Array.from(knownAgents);
  }

  try {
    const output = await runOpenclaw(['agents', 'list', '--json']);
    const parsed = JSON.parse(output);
    // OpenClaw agents list --json returns an array of agent objects with 'name' field
    const names: string[] = Array.isArray(parsed)
      ? parsed.map((a: { name?: string }) => a.name || '').filter(Boolean)
      : [];
    knownAgents = new Set(names);
    agentsCacheTime = now;
    return names;
  } catch (err) {
    console.error('[AgentService] Failed to list agents:', (err as Error).message);
    return Array.from(knownAgents); // Return cached if available
  }
}

/**
 * Initialize OpenClaw workspace files for a project directory.
 * Writes identity, personality, and workspace context files so the
 * agent boots with proper configuration instead of running OpenClaw's
 * default bootstrap flow ("Hey! Who am I?").
 *
 * All files are kept in sync with our config generators on each call.
 */
function initWorkspaceFiles(ocWorkspace: string, projectName: string): void {
  try {
    if (!existsSync(ocWorkspace)) {
      mkdirSync(ocWorkspace, { recursive: true });
    }

    // Write workspace files directly into the .openclaw/ directory.
    // OpenClaw reads these from its configured workspace path.
    // This keeps them separate from CLI context files (CLAUDE.md, AGENTS.md)
    // which live in the project root.
    const files: [string, string, () => string][] = [
      ['BOOTSTRAP.md', 'bootstrap status', getOpenclawBootstrap],
      ['SOUL.md', 'agent personality', getOpenclawSoul],
      ['TOOLS.md', 'available tools', getOpenclawTools],
      ['IDENTITY.md', 'agent identity', getOpenclawIdentity],
      ['USER.md', 'user context', getOpenclawUser],
    ];

    for (const [filename, label, generator] of files) {
      const filePath = join(ocWorkspace, filename);
      const desired = generator();
      const existing = existsSync(filePath) ? readFileSync(filePath, 'utf8') : '';
      if (existing !== desired) {
        writeFileSync(filePath, desired, 'utf8');
        console.log(`[AgentService] Wrote ${filename} for ${projectName}${existing ? ' (updated)' : ''}`);
      }
    }

    // HEARTBEAT.md — skip heartbeat for dev agents (write-once)
    const heartbeatPath = join(ocWorkspace, 'HEARTBEAT.md');
    if (!existsSync(heartbeatPath)) {
      writeFileSync(heartbeatPath, `# Keep empty to skip heartbeat checks for dev agents.\n`, 'utf8');
    }
  } catch (err) {
    console.warn(`[AgentService] Failed to init workspace files for ${projectName}:`, (err as Error).message);
  }
}

/**
 * Ensure a project agent exists. Idempotent — no-op if already created.
 */
export async function ensureProjectAgent(projectName: string): Promise<boolean> {
  const agentId = getProjectAgentId(projectName);

  const projectDir = join(PROJECTS_DIR, projectName);
  const ocWorkspace = join(projectDir, '.openclaw');

  // Ensure CLI context files exist (only runs ellulai-ctx if CLAUDE.md is missing)
  const claudeMdPath = join(projectDir, 'CLAUDE.md');
  if (!existsSync(claudeMdPath)) {
    refreshProjectContext(projectDir);
  }

  // Check cache first
  if (knownAgents.has(agentId)) {
    // Agent exists — still ensure workspace files are correct.
    // reconcileAgents does this at startup, but is skipped if OpenClaw
    // isn't reachable yet. This is our safety net.
    initWorkspaceFiles(ocWorkspace, projectName);
    return true;
  }

  // Refresh agent list
  const agents = await listAgents();
  if (agents.includes(agentId)) {
    // Agent exists but wasn't cached — sync workspace files + tool deny
    initWorkspaceFiles(ocWorkspace, projectName);
    await setAgentToolDeny(agentId);
    return true;
  }

  // Create agent with .openclaw/ as its workspace (keeps OpenClaw files
  // separate from CLI context files like CLAUDE.md in the project root)
  try {
    console.log(`[AgentService] Creating agent "${agentId}" with workspace ${ocWorkspace}`);
    await runOpenclaw([
      'agents', 'add', agentId,
      '--workspace', ocWorkspace,
      '--non-interactive',
    ]);
    knownAgents.add(agentId);
    console.log(`[AgentService] Agent "${agentId}" created`);

    // `openclaw agents add` writes default workspace files (SOUL.md = "Dev Assistant",
    // BOOTSTRAP.md, etc.) synchronously. The gateway also detects the config change
    // and may write additional files during its reload (~500ms later).
    // We MUST wait for both to finish before overwriting with our relay versions,
    // otherwise the gateway's async file writes clobber ours.
    await new Promise((r) => setTimeout(r, 3000));

    // Now overwrite with our relay config — gateway reload is done by now.
    // This includes writing our own BOOTSTRAP.md (says "already bootstrapped")
    // over OpenClaw's default one (says "Who am I?").
    initWorkspaceFiles(ocWorkspace, projectName);
    console.log(`[AgentService] Wrote relay workspace files for "${agentId}"`);

    // Generate CLI context files (CLAUDE.md, AGENTS.md, GEMINI.md)
    refreshProjectContext(projectDir);

    // Deny native file/exec tools so the model MUST use coding-agent (bash+process).
    // Without this, the model uses write/exec directly and bypasses the CLI tool.
    await setAgentToolDeny(agentId);

    return true;
  } catch (err) {
    console.error(`[AgentService] Failed to create agent "${agentId}":`, (err as Error).message);
    return false;
  }
}

/**
 * Delete a project's agent. Silent if agent doesn't exist.
 */
export async function deleteProjectAgent(projectName: string): Promise<void> {
  const agentId = getProjectAgentId(projectName);
  try {
    console.log(`[AgentService] Deleting agent "${agentId}"`);
    await runOpenclaw(['agents', 'delete', agentId]);
    knownAgents.delete(agentId);
    console.log(`[AgentService] Agent "${agentId}" deleted`);
  } catch (err) {
    // Silent — agent may not exist
    knownAgents.delete(agentId);
    console.log(`[AgentService] Agent "${agentId}" delete skipped:`, (err as Error).message);
  }
}

/**
 * Reconcile agents with existing projects on startup.
 * Creates missing agents for existing project directories.
 */
export async function reconcileAgents(): Promise<void> {
  console.log('[AgentService] Reconciling agents with projects...');

  // List project directories
  let projectNames: string[] = [];
  try {
    const entries = readdirSync(PROJECTS_DIR, { withFileTypes: true });
    projectNames = entries
      .filter((e) => e.isDirectory() && !e.name.startsWith('.'))
      .map((e) => e.name);
  } catch {
    console.log('[AgentService] Projects directory not found, skipping reconciliation');
    return;
  }

  if (projectNames.length === 0) {
    console.log('[AgentService] No projects found');
    return;
  }

  // Get existing agents
  const agents = await listAgents();
  const agentSet = new Set(agents);

  // Create missing agents + ensure workspace files exist for all
  let created = 0;
  for (const project of projectNames) {
    const agentId = getProjectAgentId(project);
    const projectDir = join(PROJECTS_DIR, project);
    const ocWorkspace = join(projectDir, '.openclaw');

    // Ensure OpenClaw workspace files are up-to-date (even for existing agents)
    initWorkspaceFiles(ocWorkspace, project);

    // Generate CLI context files (CLAUDE.md, AGENTS.md, GEMINI.md) for the project.
    // Agent-bridge sessions don't go through the terminal launcher, so ellulai-ctx
    // must be triggered here to ensure CLI tools have proper platform context.
    refreshProjectContext(projectDir);

    if (!agentSet.has(agentId)) {
      const ok = await ensureProjectAgent(project);
      if (ok) created++;
    } else {
      // Ensure tool deny is set for existing agents
      await setAgentToolDeny(agentId);
    }
  }

  console.log(`[AgentService] Reconciliation complete: ${projectNames.length} projects, ${created} agents created`);
}
