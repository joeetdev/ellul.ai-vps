/**
 * Context Service
 *
 * Manages AI context loading for global and project-specific contexts.
 */

import * as fs from 'fs';
import * as path from 'path';
import { PROJECTS_DIR, CONTEXT_DIR, CONTEXT_CACHE_MS } from '../config';

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

    // Read phonestack.json for app identity
    const phonestackPath = path.join(projectPath, 'phonestack.json');
    if (fs.existsSync(phonestackPath)) {
      try {
        const pjson = JSON.parse(fs.readFileSync(phonestackPath, 'utf8')) as { name?: string; type?: string; summary?: string };
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

/**
 * Prepend context to message for AI CLIs.
 * Includes explicit working directory information so the AI knows where it's operating.
 */
export function withContext(
  message: string,
  globalContext: string,
  projectContext: string,
  projectName?: string | null
): string {
  let fullContext = '';

  // Add mandatory rules for the project scope
  if (projectName) {
    const projectPath = path.join(PROJECTS_DIR, projectName);

    // Read app name from phonestack.json if available
    let appNameLine = '';
    try {
      const phonestackJsonPath = path.join(projectPath, 'phonestack.json');
      if (fs.existsSync(phonestackJsonPath)) {
        const pjson = JSON.parse(fs.readFileSync(phonestackJsonPath, 'utf8')) as { name?: string };
        if (pjson.name) {
          appNameLine = `The "name" field in phonestack.json is "${pjson.name}" — this is USER-DEFINED. NEVER change the "name" field in phonestack.json or package.json.`;
        }
      }
    } catch {}

    fullContext += `## MANDATORY RULES
1. WORKSPACE: You are working ONLY inside: ${projectPath}. ALL file operations MUST stay within this directory. NEVER create new projects. NEVER modify files outside this directory.
2. APP NAME: ${appNameLine || 'The "name" field in phonestack.json and package.json is USER-DEFINED. NEVER change it.'}
3. This is an EXISTING project. Do NOT create a new project, re-scaffold, or re-initialize.

`;
  }

  if (globalContext) fullContext += globalContext + '\n\n';
  if (projectContext) fullContext += projectContext;

  if (!fullContext.trim()) return message;

  return `<system_context>
${fullContext.trim()}
</system_context>

User request: ${message}`;
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
