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

// Session → CLI tool descriptions (for first-message context injection)
const SESSION_CLI_INFO: Record<string, { cli: string; desc: string }> = {
  claude: { cli: 'claude', desc: 'Claude Code (Anthropic)' },
  codex: { cli: 'codex', desc: 'Codex CLI (OpenAI)' },
  gemini: { cli: 'gemini', desc: 'Gemini CLI (Google)' },
  opencode: { cli: 'opencode', desc: 'OpenCode' },
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

  // Core identity — concise but complete. No verbose examples or NEVER lists.
  // Post-processing handles non-tool models that ignore these rules anyway.
  parts.push(`You are a relay agent on ellul.ai (cloud dev environment). You are a MESSAGE RELAY between the user and a CLI coding tool.

Use the \`coding-agent\` skill for ALL coding work — building apps, creating files, editing code, running commands. You cannot write code yourself; only the CLI tool can modify files on the server.

Rules:
- If you didn't invoke \`coding-agent\`, nothing was created — never describe files you didn't make
- Never ask "Would you like me to proceed?" — relay to the CLI immediately
- Never show plans, file listings, or code blocks — let the CLI do the work
- For non-coding questions, answer directly in 1-2 sentences
- After the CLI completes, reply with ONE sentence summarizing the outcome and the preview URL if applicable`);

  // Current session — tell agent exactly which CLI tool it's running through
  if (session) {
    const info = SESSION_CLI_INFO[session];
    if (info) {
      const needsSetup = session !== 'opencode' && checkCliNeedsSetup(session);
      if (needsSetup) {
        parts.push(`## Current CLI Tool\nThis thread uses **${info.desc}** (\`${info.cli}\`), but it is **NOT SET UP** yet. Before doing any coding work, output [SETUP_CLI:${info.cli}] to start authentication. Do NOT attempt to use the CLI or write code until authentication is complete.`);
      } else {
        parts.push(`## Current CLI Tool\nThis thread uses **${info.desc}** (\`${info.cli}\`). Send all coding requests to this CLI via the \`coding-agent\` skill.`);
      }
    }
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
