/**
 * Context Service
 *
 * Manages AI context loading for global and project-specific contexts.
 */

import * as fs from 'fs';
import * as path from 'path';
import { PROJECTS_DIR, CONTEXT_DIR, CONTEXT_CACHE_MS, DEV_DOMAIN } from '../config';
import { checkCliNeedsSetup } from './interactive.service';

// Context cache
let cachedGlobalContext = '';
let globalContextLastRead = 0;

// Active project for app-level context
let activeProject: string | null = null;

/**
 * Load global context (CLAUDE.md, custom context files).
 */
export function loadGlobalContext(): string {
  const now = Date.now();
  if (cachedGlobalContext && now - globalContextLastRead < CONTEXT_CACHE_MS) {
    return cachedGlobalContext;
  }

  let context = '';
  try {
    // Load global context
    const globalPath = path.join(CONTEXT_DIR, 'global.md');
    if (fs.existsSync(globalPath)) {
      context += fs.readFileSync(globalPath, 'utf8') + '\n\n';
    }

    // Load projects CLAUDE.md for structure rules
    const projectsClaudePath = path.join(PROJECTS_DIR, 'CLAUDE.md');
    if (fs.existsSync(projectsClaudePath)) {
      context += fs.readFileSync(projectsClaudePath, 'utf8') + '\n\n';
    }

    // Load any custom context files (*.md in context dir, except global.md and current.md)
    if (fs.existsSync(CONTEXT_DIR)) {
      const files = fs.readdirSync(CONTEXT_DIR);
      for (const file of files) {
        if (file.endsWith('.md') && file !== 'global.md' && file !== 'current.md') {
          const filePath = path.join(CONTEXT_DIR, file);
          context += '# Custom Context: ' + file + '\n';
          context += fs.readFileSync(filePath, 'utf8') + '\n\n';
        }
      }
    }
  } catch (err) {
    const error = err as Error;
    console.error('[Bridge] Error loading global context:', error.message);
  }

  cachedGlobalContext = context.trim();
  globalContextLastRead = now;
  return cachedGlobalContext;
}

/**
 * Load app-specific context (CLAUDE.md, README.md in project folder).
 */
export function loadAppContext(projectName: string | null): string {
  if (!projectName) return '';

  let context = '';
  try {
    const projectPath = path.join(PROJECTS_DIR, projectName);
    if (!fs.existsSync(projectPath)) return '';

    // Load project's CLAUDE.md
    const claudePath = path.join(projectPath, 'CLAUDE.md');
    if (fs.existsSync(claudePath)) {
      context += '# Project Context: ' + projectName + '\n';
      context += fs.readFileSync(claudePath, 'utf8') + '\n\n';
    }

    // Load project's README.md for additional context
    const readmePath = path.join(projectPath, 'README.md');
    if (fs.existsSync(readmePath)) {
      const readme = fs.readFileSync(readmePath, 'utf8');
      // Only include first 2000 chars of README to avoid bloating context
      context += '# Project README: ' + projectName + '\n';
      context +=
        readme.substring(0, 2000) + (readme.length > 2000 ? '\n...(truncated)' : '') + '\n\n';
    }

    // Read ellulai.json for app identity
    const ellulaiPath = path.join(projectPath, 'ellulai.json');
    if (fs.existsSync(ellulaiPath)) {
      try {
        const pjson = JSON.parse(fs.readFileSync(ellulaiPath, 'utf8')) as { name?: string; type?: string; summary?: string };
        if (pjson.name) {
          context += 'App name: ' + pjson.name + ' (USER-DEFINED — do not change)\n';
        }
        if (pjson.type) context += 'App type: ' + pjson.type + '\n';
        if (pjson.summary) context += 'Summary: ' + pjson.summary + '\n';
        context += '\n';
      } catch {}
    }

    // Check for package.json to understand project type
    const pkgPath = path.join(projectPath, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as {
          name?: string;
          description?: string;
          scripts?: Record<string, string>;
        };
        context += '# Project: ' + (pkg.name || projectName) + '\n';
        if (pkg.description) context += 'Description: ' + pkg.description + '\n';
        if (pkg.scripts) context += 'Available scripts: ' + Object.keys(pkg.scripts).join(', ') + '\n';
        context += '\n';
      } catch {}
    }
  } catch (err) {
    const error = err as Error;
    console.error('[Bridge] Error loading app context:', error.message);
  }

  return context;
}

/**
 * Load project-specific context (alias for loadAppContext).
 */
export function loadProjectContext(projectName: string | null): string {
  return loadAppContext(projectName);
}

// Session → CLI tool info (for system prompt injection)
const SESSION_CLI_INFO: Record<string, { cli: string; desc: string; cmd: string }> = {
  claude: { cli: 'claude', desc: 'Claude Code (Anthropic)', cmd: "claude 'REQUEST'" },
  codex: { cli: 'codex', desc: 'Codex CLI (OpenAI)', cmd: "codex exec --full-auto 'REQUEST'" },
  gemini: { cli: 'gemini', desc: 'Gemini CLI (Google)', cmd: "gemini 'REQUEST'" },
  opencode: { cli: 'opencode', desc: 'OpenCode', cmd: "opencode run 'REQUEST'" },
};

/**
 * Build a proper system prompt for OpenClaw.
 * Sent as `role: "system"` in the messages array — much stronger signal
 * than embedding context in the user message.
 */
export function buildSystemPrompt(
  globalContext: string,
  projectContext: string,
  projectName?: string | null,
  session?: string | null,
): string {
  const parts: string[] = [];

  // Core identity + exact command template. The model gets a concrete, mechanical
  // pattern to follow — no skill file reading or command construction needed.
  if (session) {
    const info = SESSION_CLI_INFO[session];
    if (info) {
      const needsSetup = session !== 'opencode' && checkCliNeedsSetup(session);
      if (needsSetup) {
        parts.push(`You are a relay agent on ellul.ai. This thread uses **${info.desc}** but it is NOT SET UP yet. Output [SETUP_CLI:${info.cli}] before doing any work. Do NOT attempt to write code or use any tools until authentication is complete.`);
      } else {
        const projectPath = projectName ? path.join(PROJECTS_DIR, projectName) : '~/projects';
        parts.push(`You are a relay agent on ellul.ai. You delegate ALL coding work to a CLI tool and report back what it did.

## Current CLI Tool
**${info.desc}**: \`${info.cmd}\`

## How to handle a coding request (follow EXACTLY)

STEP 1: Output "On it!" as your very first line.

STEP 2: Launch the CLI:
bash pty:true workdir:${projectPath} background:true command:"${info.cmd}"
Replace REQUEST with the user's actual request.

STEP 3: Monitor until done:
process action:poll sessionId:SESSION_ID
process action:log sessionId:SESSION_ID
Repeat poll/log until the CLI finishes. If you see meaningful progress in the logs, briefly summarize in 1 sentence.

STEP 4: Tell the user the result in 1-2 sentences.

## Model Selection (opencode only)
The CLI uses free models from OpenCode Zen. You can pick the model with the \`-m\` flag:
\`opencode run -m PROVIDER/MODEL 'REQUEST'\`

Run \`opencode models\` to see what's available. Pick the best quality model — prefer these in order:
1. opencode/kimi-k2.5-free (best)
2. opencode/minimax-m2.5-free
3. Any other free model available

If the user asks to change models, use \`opencode models\` to show them what's available and switch with \`-m\`.

## Rules
- ONLY use bash (with pty:true) and process tools. NEVER use write, exec, or read.
- NEVER create files yourself. NEVER fall back to doing the work if the CLI is slow — wait for it.
- NEVER output code blocks, plans, or file listings.
- For non-coding questions (general knowledge, platform questions), just answer directly.`);
      }
    }
  } else {
    parts.push(`You are a relay agent on ellul.ai. Use the coding-agent skill for all coding work. Never use write, exec, or read tools directly.`);
  }

  // Project workspace rules
  if (projectName) {
    const projectPath = path.join(PROJECTS_DIR, projectName);
    let appNameLine = '';
    try {
      const ellulaiJsonPath = path.join(projectPath, 'ellulai.json');
      if (fs.existsSync(ellulaiJsonPath)) {
        const pjson = JSON.parse(fs.readFileSync(ellulaiJsonPath, 'utf8')) as { name?: string };
        if (pjson.name) {
          appNameLine = `The app name is "${pjson.name}" (user-defined — never change it).`;
        }
      }
    } catch {}

    parts.push(`## Workspace Rules
- You are working ONLY inside: ${projectPath}
- ALL file operations MUST stay within this directory
- NEVER create new projects, re-scaffold, or re-initialize existing ones
- ${appNameLine || 'Never change the "name" field in ellulai.json or package.json.'}`);
  }

  // Dev preview — tell agent the actual preview URL so it can share with users
  if (DEV_DOMAIN) {
    parts.push(`## Dev Preview
Your dev preview URL: **https://${DEV_DOMAIN}**
Apps listening on port 3000 are served at this URL via reverse proxy.
When configuring a dev server, bind to \`0.0.0.0:3000\` internally — but always tell the user their app is live at **https://${DEV_DOMAIN}**.
After starting a dev server, verify with \`curl localhost:3000\` then share the preview URL.`);
  }

  // CLI auth status — accurate for ALL tools including active session
  const cliStatus = ['claude', 'codex', 'gemini']
    .map(cli => {
      const needsSetup = checkCliNeedsSetup(cli);
      const label = session === cli ? ' (current thread)' : '';
      return `${cli}: ${needsSetup ? 'NOT SET UP' : 'ready'}${label}`;
    })
    .join(', ');
  parts.push(`## CLI Auth Status\n${cliStatus}\n\nIf any CLI is NOT SET UP and the user wants to use it, output [SETUP_CLI:toolname] and the system will handle authentication. Do NOT attempt coding work with an unauthenticated CLI.`);

  // Global + project context
  if (globalContext) parts.push(globalContext);
  if (projectContext) parts.push(projectContext);

  return parts.join('\n\n');
}

/**
 * Build system prompt for Claw (direct agent) mode.
 * Unlike buildSystemPrompt(), this has NO relay/CLI delegation instructions.
 * The OpenClaw agent works directly with its native tools.
 */
export function buildClawSystemPrompt(
  globalContext: string,
  projectContext: string,
  projectName?: string | null,
): string {
  const parts: string[] = [];

  parts.push(`You are ellul, a full-stack coding assistant on ellul.ai. You help users build websites, apps, APIs, and other software projects.

## Guidelines
- Be concise and direct. Avoid unnecessary preamble.
- Write clean, working code. Prefer simplicity over cleverness.
- When making changes, explain what you did and why in 1-2 sentences.
- If something is ambiguous, ask for clarification rather than guessing.`);

  if (projectName) {
    const projectPath = path.join(PROJECTS_DIR, projectName);
    let appNameLine = '';
    try {
      const ellulaiJsonPath = path.join(projectPath, 'ellulai.json');
      if (fs.existsSync(ellulaiJsonPath)) {
        const pjson = JSON.parse(fs.readFileSync(ellulaiJsonPath, 'utf8')) as { name?: string };
        if (pjson.name) {
          appNameLine = `The app name is "${pjson.name}" (user-defined — never change it).`;
        }
      }
    } catch {}

    parts.push(`## Workspace Rules
- You are working ONLY inside: ${projectPath}
- ALL file operations MUST stay within this directory
- NEVER create new projects, re-scaffold, or re-initialize existing ones
- ${appNameLine || 'Never change the "name" field in ellulai.json or package.json.'}`);
  }

  if (DEV_DOMAIN) {
    parts.push(`## Dev Preview
Your dev preview URL: **https://${DEV_DOMAIN}**
Apps listening on port 3000 are served at this URL via reverse proxy.
When configuring a dev server, bind to \`0.0.0.0:3000\` internally — but always tell the user their app is live at **https://${DEV_DOMAIN}**.`);
  }

  if (globalContext) parts.push(globalContext);
  if (projectContext) parts.push(projectContext);

  return parts.join('\n\n');
}

/**
 * Legacy context wrapper — now a pass-through since context is sent
 * via the system message in buildSystemPrompt().
 */
export function withContext(
  message: string,
  _globalContext: string,
  _projectContext: string,
  _projectName?: string | null,
  _session?: string | null
): string {
  return message;
}

/**
 * Set the active project for context.
 */
export function setActiveProject(projectName: string): boolean {
  if (projectName && fs.existsSync(path.join(PROJECTS_DIR, projectName))) {
    activeProject = projectName;
    console.log('[Bridge] Active project set to:', projectName);
    return true;
  }
  return false;
}

/**
 * Get the active project.
 */
export function getActiveProject(): string | null {
  return activeProject;
}
