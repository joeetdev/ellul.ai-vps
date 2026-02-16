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
import { readdirSync, statSync, existsSync, writeFileSync, mkdirSync } from 'fs';
import { PROJECTS_DIR, DEV_DOMAIN } from '../config';

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
 * Writes dev-focused SOUL.md and AGENTS.md so the agent boots as a
 * development assistant instead of running the default bootstrap flow
 * ("Hey! Who am I?"). Files are only written if they don't already exist.
 */
function initWorkspaceFiles(workspace: string, projectName: string): void {
  try {
    const ocDir = join(workspace, '.openclaw');
    if (!existsSync(ocDir)) {
      mkdirSync(ocDir, { recursive: true });
    }

    // SOUL.md — dev assistant identity (replaces default "who am I?" bootstrap)
    const soulPath = join(workspace, 'SOUL.md');
    if (!existsSync(soulPath)) {
      const previewSection = DEV_DOMAIN
        ? `\n## Dev Preview
Apps listening on port 3000 are served at: https://${DEV_DOMAIN}
Configure dev servers to bind \`0.0.0.0:3000\` internally, but always tell the user their preview is at the URL above.
After starting a dev server, verify with \`curl localhost:3000\` then share the preview URL.\n`
        : '';

      writeFileSync(soulPath, `# SOUL.md — Relay Agent for ${projectName}

You are a RELAY agent for the **${projectName}** project on **ellul.ai**. You relay the user's messages to CLI coding tools and return the results.

## How You Work (CRITICAL)
1. User sends a coding request → you use \`coding-agent\` skill to send it to the CLI
2. CLI does the work (creates files, runs commands) → you return the result briefly

## Rules
- ALWAYS use \`coding-agent\` for ANY coding work — you cannot create files or write code yourself
- NEVER write code, show file listings, or describe files you "created"
- NEVER ask "Would you like me to proceed?" — just relay to the CLI
- Keep responses to 1-2 natural sentences: "Done — your app is running. Preview at [URL]."
- Stay in scope: all work inside this project directory only
${previewSection}
## CLI Setup
If the CLI is not authenticated, output [SETUP_CLI:toolname] BEFORE attempting work.
`, 'utf8');
      console.log(`[AgentService] Wrote SOUL.md for ${projectName}`);
    }

    // AGENTS.md — operational instructions
    const agentsPath = join(workspace, 'AGENTS.md');
    if (!existsSync(agentsPath)) {
      writeFileSync(agentsPath, `# AGENTS.md — Workspace Instructions

## Every Request
1. Receive the user's message
2. Use \`coding-agent\` skill to relay it to the CLI tool
3. Return the result in 1-2 brief sentences

## Rules
- ALWAYS use \`coding-agent\` — never write code yourself
- ALL file operations stay within this workspace
- Never change the "name" field in ellulai.json or package.json
- If the CLI isn't set up, output [SETUP_CLI:toolname] first
`, 'utf8');
      console.log(`[AgentService] Wrote AGENTS.md for ${projectName}`);
    }

    // HEARTBEAT.md — skip heartbeat for dev agents
    const heartbeatPath = join(workspace, 'HEARTBEAT.md');
    if (!existsSync(heartbeatPath)) {
      writeFileSync(heartbeatPath, `# Keep empty to skip heartbeat checks for dev agents.\n`, 'utf8');
    }

    // Remove BOOTSTRAP.md if it exists — prevents "Who am I?" flow
    const bootstrapPath = join(workspace, 'BOOTSTRAP.md');
    if (existsSync(bootstrapPath)) {
      const { unlinkSync } = require('fs');
      unlinkSync(bootstrapPath);
      console.log(`[AgentService] Removed BOOTSTRAP.md for ${projectName} (prevents identity bootstrap)`);
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
    // Initialize workspace files BEFORE agent creation so OpenClaw picks them up
    initWorkspaceFiles(workspace, projectName);

    console.log(`[AgentService] Creating agent "${agentId}" with workspace ${workspace}`);
    await runOpenclaw([
      'agents', 'add', agentId,
      '--workspace', workspace,
      '--non-interactive',
    ]);
    knownAgents.add(agentId);
    console.log(`[AgentService] Agent "${agentId}" created`);
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

    // Ensure workspace files exist (even for existing agents)
    initWorkspaceFiles(workspace, project);

    if (!agentSet.has(agentId)) {
      const ok = await ensureProjectAgent(project);
      if (ok) created++;
    }
  }

  console.log(`[AgentService] Reconciliation complete: ${projectNames.length} projects, ${created} agents created`);
}
