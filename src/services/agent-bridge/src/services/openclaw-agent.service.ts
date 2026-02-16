/**
 * OpenClaw Agent Service
 *
 * Manages per-project OpenClaw agents. Each project gets an isolated agent
 * with its own workspace, memory, and identity via `openclaw agents add`.
 * Routing is done via `model: "openclaw:<agentId>"` in HTTP requests.
 */

import { execFile } from 'child_process';
import { homedir } from 'os';
import { join } from 'path';
import { readdirSync, statSync, existsSync, writeFileSync, readFileSync, mkdirSync } from 'fs';
import { PROJECTS_DIR, DEV_DOMAIN } from '../config';
import { getOpenclawIdentity, getOpenclawUser } from '../../../../configs/openclaw';

const OPENCLAW_BIN_PATHS = [
  join(homedir(), '.openclaw', 'bin', 'openclaw'),
  '/usr/local/bin/openclaw',
];

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
 * Writes relay agent config (SOUL.md, AGENTS.md) and identity files
 * (IDENTITY.md, USER.md) so the agent boots as a relay instead of
 * running OpenClaw's default bootstrap flow ("Hey! Who am I?").
 *
 * SOUL.md + AGENTS.md are always kept in sync (platform-managed).
 * IDENTITY.md + USER.md are write-once (signal "already bootstrapped").
 */
function initWorkspaceFiles(workspace: string, projectName: string): void {
  try {
    const ocDir = join(workspace, '.openclaw');
    if (!existsSync(ocDir)) {
      mkdirSync(ocDir, { recursive: true });
    }

    // SOUL.md — relay agent identity (always overwrite to ensure relay behavior)
    // Platform-managed: enforces relay pattern so the model delegates to CLI tools.
    const soulPath = join(workspace, 'SOUL.md');
    const previewSection = DEV_DOMAIN
      ? `\n## Dev Preview
Apps listening on port 3000 are served at: https://${DEV_DOMAIN}
Configure dev servers to bind \`0.0.0.0:3000\` internally, but always tell the user their preview is at the URL above.
After starting a dev server, verify with \`curl localhost:3000\` then share the preview URL.\n`
      : '';

    const relaySoul = `# SOUL.md — Relay Agent for ${projectName}

You are a RELAY agent on ellul.ai. You delegate ALL coding work to a CLI tool and return results. You NEVER write code yourself.

## Rules
- ONLY use \`bash\` (with pty:true) and \`process\` tools. Nothing else.
- NEVER use write, exec, or read tools. NEVER create files yourself.
- NEVER fall back to doing the work yourself if the CLI seems slow — just wait for it.
- NEVER output code blocks, file listings, or plans.
- Follow the EXACT steps in the system prompt for launching and monitoring the CLI.
- If the CLI errors, tell the user briefly and suggest trying again.
${previewSection}
`;
    // Always write — stale SOUL.md (e.g. "Dev Assistant") causes the model to go rogue
    const existingSoul = existsSync(soulPath) ? readFileSync(soulPath, 'utf8') : '';
    if (existingSoul !== relaySoul) {
      writeFileSync(soulPath, relaySoul, 'utf8');
      console.log(`[AgentService] Wrote SOUL.md for ${projectName}${existingSoul ? ' (updated stale file)' : ''}`);
    }

    // AGENTS.md — operational instructions (always overwrite like SOUL.md)
    const agentsPath = join(workspace, 'AGENTS.md');
    const relayAgents = `# AGENTS.md — Workspace Instructions

You are a relay agent. Follow the system prompt steps exactly. Only use bash and process tools.
Never use write, exec, or read tools. Never attempt coding work yourself.
`;
    const existingAgents = existsSync(agentsPath) ? readFileSync(agentsPath, 'utf8') : '';
    if (existingAgents !== relayAgents) {
      writeFileSync(agentsPath, relayAgents, 'utf8');
      console.log(`[AgentService] Wrote AGENTS.md for ${projectName}${existingAgents ? ' (updated stale file)' : ''}`);
    }

    // IDENTITY.md + USER.md — signals to OpenClaw that the workspace is already
    // bootstrapped. Without these, OpenClaw creates BOOTSTRAP.md on every wake
    // which triggers the "Who am I?" identity discovery flow.
    const identityPath = join(workspace, 'IDENTITY.md');
    if (!existsSync(identityPath)) {
      writeFileSync(identityPath, getOpenclawIdentity(), 'utf8');
      console.log(`[AgentService] Wrote IDENTITY.md for ${projectName}`);
    }

    const userPath = join(workspace, 'USER.md');
    if (!existsSync(userPath)) {
      writeFileSync(userPath, getOpenclawUser(), 'utf8');
      console.log(`[AgentService] Wrote USER.md for ${projectName}`);
    }

    // HEARTBEAT.md — skip heartbeat for dev agents
    const heartbeatPath = join(workspace, 'HEARTBEAT.md');
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

  // Check cache first
  if (knownAgents.has(agentId)) return true;

  // Refresh agent list
  const agents = await listAgents();
  if (agents.includes(agentId)) return true;

  // Create agent
  const workspace = join(PROJECTS_DIR, projectName);
  try {
    // Initialize workspace files BEFORE agent creation so OpenClaw picks them up.
    // IDENTITY.md + USER.md prevent OpenClaw from creating BOOTSTRAP.md.
    initWorkspaceFiles(workspace, projectName);

    console.log(`[AgentService] Creating agent "${agentId}" with workspace ${workspace}`);
    await runOpenclaw([
      'agents', 'add', agentId,
      '--workspace', workspace,
      '--non-interactive',
    ]);
    knownAgents.add(agentId);
    console.log(`[AgentService] Agent "${agentId}" created`);

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
    const workspace = join(PROJECTS_DIR, project);

    // Ensure workspace files are up-to-date (even for existing agents)
    initWorkspaceFiles(workspace, project);

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
