/**
 * Preview Service
 *
 * App preview management using PM2.
 * Includes request ordering to handle rapid app switching.
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { HOME, ROOT_DIR } from '../config';
import { PORTS } from '../../../shared/constants';

const PREVIEW_FILE = `${HOME}/.ellulai/preview-app`;

// Request ordering - ensures only the latest request is processed
let latestRequestId = 0;

// ---------------------------------------------------------------------------
// Vite Plugin Registry — declarative mapping from UI library → Vite plugin
// ---------------------------------------------------------------------------

interface VitePluginSpec {
  /** Dependency in package.json that triggers this requirement */
  trigger: string;
  /** npm package to install */
  pluginPackage: string;
  /** Import line to add to vite config */
  importLine: string;
  /** Plugin call to add to plugins array */
  pluginCall: string;
  /** Strings that indicate plugin is already configured */
  detectPatterns: string[];
}

const VITE_PLUGIN_REGISTRY: VitePluginSpec[] = [
  {
    trigger: 'react',
    pluginPackage: '@vitejs/plugin-react',
    importLine: 'import react from "@vitejs/plugin-react";',
    pluginCall: 'react()',
    detectPatterns: ['plugin-react', 'pluginReact'],
  },
  {
    trigger: 'vue',
    pluginPackage: '@vitejs/plugin-vue',
    importLine: 'import vue from "@vitejs/plugin-vue";',
    pluginCall: 'vue()',
    detectPatterns: ['plugin-vue', 'pluginVue'],
  },
  {
    trigger: 'svelte',
    pluginPackage: '@sveltejs/vite-plugin-svelte',
    importLine: 'import { svelte } from "@sveltejs/vite-plugin-svelte";',
    pluginCall: 'svelte()',
    detectPatterns: ['vite-plugin-svelte', 'pluginSvelte'],
  },
  {
    trigger: 'solid-js',
    pluginPackage: 'vite-plugin-solid',
    importLine: 'import solid from "vite-plugin-solid";',
    pluginCall: 'solid()',
    detectPatterns: ['vite-plugin-solid', 'pluginSolid'],
  },
  {
    trigger: 'preact',
    pluginPackage: '@preact/preset-vite',
    importLine: 'import preact from "@preact/preset-vite";',
    pluginCall: 'preact()',
    detectPatterns: ['preset-vite', '@preact/preset'],
  },
];

/**
 * Generate a new request ID and return it.
 * Also updates the latest request ID.
 */
function getNextRequestId(): number {
  latestRequestId++;
  return latestRequestId;
}

/**
 * Check if this request is still the latest.
 * Returns false if a newer request has come in.
 */
function isLatestRequest(requestId: number): boolean {
  return requestId === latestRequestId;
}

// Ensure nvm binaries (node, npm, pm2, npx) are in PATH for execSync calls
const NVM_BIN = `${HOME}/.node/bin`;
const EXEC_ENV = (() => {
  const { PORT: _leaked, ...rest } = process.env;
  return { ...rest, PATH: `${NVM_BIN}:${rest.PATH || ''}` };
})();

/**
 * Check if npm install is complete — node_modules exists AND expected framework binaries are present.
 * A partial install (directory exists but key packages missing) returns false.
 */
function isInstallComplete(appPath: string): boolean {
  const nm = path.join(appPath, 'node_modules');
  if (!fs.existsSync(nm)) return false;
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(appPath, 'package.json'), 'utf8'));
    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
    const binaryChecks: [string, string][] = [
      ['vite', '.bin/vite'],
      ['next', '.bin/next'],
      ['react-scripts', '.bin/react-scripts'],
      ['astro', '.bin/astro'],
      ['@remix-run/dev', '.bin/remix'],
    ];
    for (const [dep, bin] of binaryChecks) {
      if (allDeps[dep] && !fs.existsSync(path.join(nm, bin))) return false;
    }
  } catch {
    return false;
  }
  return true;
}

/**
 * Run PM2 command safely.
 */
function runPm2(cmd: string): string {
  try {
    return execSync(cmd, { encoding: 'utf8', timeout: 30000, env: EXEC_ENV });
  } catch {
    return '';
  }
}

/**
 * Get app path from directory identifier.
 * Primary: directory name (the unique identifier used throughout the system)
 * Fallback: display name lookup (for backward compatibility)
 * Also handles monorepo nested apps.
 */
function getAppPath(appIdentifier: string): string {
  if (appIdentifier.includes('/')) {
    const parts = appIdentifier.split('/');
    const monorepoName = parts[0];
    const packageName = parts.slice(1).join('/');

    const possiblePaths = [
      path.join(ROOT_DIR, monorepoName as string, 'packages', packageName),
      path.join(ROOT_DIR, monorepoName as string, 'apps', packageName),
      path.join(ROOT_DIR, monorepoName as string, packageName),
    ];

    for (const p of possiblePaths) {
      if (fs.existsSync(p)) return p;
    }
  }
  // Direct directory match (primary - this is what the frontend sends)
  const directPath = path.join(ROOT_DIR, appIdentifier);
  if (fs.existsSync(directPath)) return directPath;
  // Fallback: resolve display name → directory name for backward compatibility
  const { detectApps } = require('./apps.service');
  const apps = detectApps();
  const match = apps.find((a: { name: string; directory: string }) => a.name === appIdentifier);
  if (match) return path.join(ROOT_DIR, match.directory);
  return directPath;
}

/**
 * Get the PID of the process listening on a given port, or null if port is free.
 */
function getPidOnPort(port: number): number | null {
  try {
    const out = execSync(`ss -tlnp 'sport = :${port}'`, { encoding: 'utf8', timeout: 3000 });
    const m = out.match(/pid=(\d+)/);
    return m?.[1] ? parseInt(m[1], 10) : null;
  } catch { return null; }
}

/**
 * Retry-based port cleanup — verifies the port is actually free.
 */
function ensurePortFree(port: number): boolean {
  for (let attempt = 0; attempt < 5; attempt++) {
    const pid = getPidOnPort(port);
    if (pid === null) return true;
    try {
      execSync(`kill ${pid} 2>/dev/null || true`, { env: EXEC_ENV, timeout: 3000 });
      execSync('sleep 0.8', { env: EXEC_ENV });
    } catch {}
  }
  // Hard kill any remaining process
  const residual = getPidOnPort(port);
  if (residual !== null) {
    try { execSync(`kill -9 ${residual} 2>/dev/null || true`, { env: EXEC_ENV, timeout: 3000 }); } catch {}
    execSync('sleep 0.3', { env: EXEC_ENV });
  }
  return getPidOnPort(port) === null;
}

/**
 * Get the PM2-managed preview process PID.
 */
function getPreviewPid(): number | null {
  const list = runPm2('pm2 jlist');
  try {
    const procs = JSON.parse(list || '[]');
    const preview = procs.find((p: any) => p.name === 'preview' && p.pm2_env?.status === 'online');
    return preview?.pid ?? null;
  } catch { return null; }
}

/**
 * Check if childPid is a descendant of ancestorPid via /proc/PID/status.
 */
function isDescendantOf(childPid: number, ancestorPid: number): boolean {
  let pid = childPid;
  for (let i = 0; i < 8; i++) {
    if (pid === ancestorPid) return true;
    try {
      const status = fs.readFileSync(`/proc/${pid}/status`, 'utf8');
      const m = status.match(/^PPid:\s+(\d+)/m);
      if (!m?.[1]) return false;
      pid = parseInt(m[1], 10);
      if (pid <= 1) return false;
    } catch { return false; }
  }
  return false;
}

interface ReadyResult {
  status: 'ready' | 'wrong_process' | 'timeout' | 'module_error';
  /** Entry points that failed MIME validation */
  badModules?: Array<{ path: string; contentType: string }>;
}

/**
 * Wait for preview to be ready with process ownership + content-type verification.
 * Also validates that module entry points are served with correct MIME types.
 */
function waitForReady(maxWaitMs: number = 10000): ReadyResult {
  const startTime = Date.now();
  while (Date.now() - startTime < maxWaitMs) {
    const portPid = getPidOnPort(PORTS.PREVIEW);
    if (portPid !== null) {
      const previewPid = getPreviewPid();
      if (previewPid !== null && isDescendantOf(portPid, previewPid)) {
        // Ownership confirmed — check content-type
        try {
          const headers = execSync(
            `curl -sI http://localhost:${PORTS.PREVIEW}/ 2>/dev/null`,
            { encoding: 'utf8', timeout: 3000, env: EXEC_ENV }
          );
          if (/content-type:.*text\/html/i.test(headers)) {
            // HTML OK — now validate module entry points
            const badModules = validateModuleEntryPoints();
            if (badModules.length > 0) {
              return { status: 'module_error', badModules };
            }
            return { status: 'ready' };
          }
        } catch {}
      } else if (portPid !== null && previewPid !== null) {
        // Wrong process on port — kill it immediately
        try { execSync(`kill -9 ${portPid} 2>/dev/null || true`, { env: EXEC_ENV, timeout: 3000 }); } catch {}
      }
    }
    try { execSync('sleep 0.5', { env: EXEC_ENV }); } catch {}
  }
  return { status: 'timeout' };
}

/**
 * Parse the index HTML for <script type="module" src="..."> tags and verify
 * each module src is served with a JavaScript content-type (not text/jsx etc).
 */
function validateModuleEntryPoints(): Array<{ path: string; contentType: string }> {
  const bad: Array<{ path: string; contentType: string }> = [];
  try {
    const html = execSync(
      `curl -s http://localhost:${PORTS.PREVIEW}/ 2>/dev/null`,
      { encoding: 'utf8', timeout: 3000, env: EXEC_ENV }
    );
    // Match <script type="module" src="/src/main.tsx"> and similar
    const scriptRe = /<script[^>]+type\s*=\s*["']module["'][^>]+src\s*=\s*["']([^"']+)["']/gi;
    let m: RegExpExecArray | null;
    while ((m = scriptRe.exec(html)) !== null) {
      const src = m[1]!;
      try {
        const headers = execSync(
          `curl -sI http://localhost:${PORTS.PREVIEW}${src.startsWith('/') ? '' : '/'}${src} 2>/dev/null`,
          { encoding: 'utf8', timeout: 3000, env: EXEC_ENV }
        );
        const ctMatch = headers.match(/content-type:\s*([^\r\n;]+)/i);
        const ct = ctMatch?.[1]?.trim() || '';
        // text/jsx, text/tsx, text/x-vue etc are wrong — must be application/javascript or similar
        if (ct && /^text\/(jsx|tsx|x-vue|x-svelte)/.test(ct)) {
          bad.push({ path: src, contentType: ct });
        }
      } catch {}
    }
  } catch {}
  return bad;
}

/**
 * Ensure Vite projects have the correct config: allowedHosts, framework plugins, etc.
 * Idempotent — safe to call multiple times. Uses VITE_PLUGIN_REGISTRY to handle
 * all Vite-based frameworks (React, Vue, Svelte, Solid, Preact).
 */
function ensureViteConfig(appPath: string): void {
  const pkgPath = path.join(appPath, 'package.json');
  if (!fs.existsSync(pkgPath)) return;

  let allDeps: Record<string, string> = {};
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
    if (!allDeps['vite']) return;
  } catch {
    return;
  }

  // Determine which plugins are required based on package.json dependencies
  const requiredPlugins = VITE_PLUGIN_REGISTRY.filter((spec) => !!allDeps[spec.trigger]);

  const VITE_CONFIG_FILES = ['vite.config.js', 'vite.config.ts', 'vite.config.mjs', 'vite.config.mts'];
  const existingConfig = VITE_CONFIG_FILES.find((f) => fs.existsSync(path.join(appPath, f)));

  // ── No config exists → generate a complete one ──────────────────────────
  if (!existingConfig) {
    const imports = ['import { defineConfig } from "vite";'];
    const pluginCalls: string[] = [];
    for (const spec of requiredPlugins) {
      imports.push(spec.importLine);
      pluginCalls.push(spec.pluginCall);
      // Install plugin package if missing from node_modules
      installPluginIfMissing(appPath, spec);
    }
    const pluginsLine = pluginCalls.length > 0 ? `\n  plugins: [${pluginCalls.join(', ')}],` : '';
    fs.writeFileSync(
      path.join(appPath, 'vite.config.js'),
      `${imports.join('\n')}\nexport default defineConfig({${pluginsLine}\n  server: {\n    host: true,\n    port: ${PORTS.PREVIEW},\n    allowedHosts: true,\n  },\n});\n`
    );
    return;
  }

  // ── Config exists → patch as needed ─────────────────────────────────────
  const configPath = path.join(appPath, existingConfig);
  let content = fs.readFileSync(configPath, 'utf8');

  // 1. Patch allowedHosts if missing
  if (!content.includes('allowedHosts')) {
    if (content.includes('server:') || content.includes('server :')) {
      content = content.replace(/(server\s*:\s*\{)/, '$1\n    allowedHosts: true,');
    } else if (content.includes('defineConfig(')) {
      content = content.replace(
        /(defineConfig\s*\(\s*\{)/,
        `$1\n  server: { host: true, port: ${PORTS.PREVIEW}, allowedHosts: true },`
      );
    }
  }

  // 2. For each required plugin, install + patch if not already present
  for (const spec of requiredPlugins) {
    const alreadyConfigured = spec.detectPatterns.some((p) => content.includes(p));
    if (alreadyConfigured) continue;

    // Install npm package if missing
    installPluginIfMissing(appPath, spec);

    // Add import line after existing vite import, or at the top
    if (/import\s+.*from\s+['"]vite['"]/.test(content)) {
      content = content.replace(
        /(import\s+.*from\s+['"]vite['"].*\n)/,
        `$1${spec.importLine}\n`
      );
    } else {
      content = spec.importLine + '\n' + content;
    }

    // Add plugin call to plugins array, or create plugins array
    if (content.includes('plugins')) {
      content = content.replace(/(plugins\s*:\s*\[)/, `$1${spec.pluginCall}, `);
    } else if (content.includes('defineConfig(')) {
      content = content.replace(
        /(defineConfig\s*\(\s*\{)/,
        `$1\n  plugins: [${spec.pluginCall}],`
      );
    }
  }

  fs.writeFileSync(configPath, content);
}

/**
 * Install a Vite plugin npm package if it's not already in node_modules.
 */
function installPluginIfMissing(appPath: string, spec: VitePluginSpec): void {
  // Derive the node_modules subpath from the package name
  const pluginDir = path.join(appPath, 'node_modules', ...spec.pluginPackage.split('/'));
  if (fs.existsSync(pluginDir)) return;
  try {
    execSync(`npm install -D ${spec.pluginPackage} 2>/dev/null`, {
      cwd: appPath, encoding: 'utf8', timeout: 60000, env: EXEC_ENV,
    });
  } catch {}
}

// ---------------------------------------------------------------------------
// CSS Reset Injection — guarantees no white border regardless of LLM output
// ---------------------------------------------------------------------------

/** Marker attribute to detect if reset was already injected (idempotent) */
const CSS_RESET_MARKER = 'data-ellulai-reset';

/** Minified CSS reset: removes all default margins/padding, ensures full-viewport coverage */
const CSS_RESET_STYLE = `<style ${CSS_RESET_MARKER}>*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}html,body,#root,#__next,#app{width:100%;height:100%;min-height:100vh}</style>`;

/**
 * Inject a CSS reset <style> tag into the <head> of index.html.
 * Idempotent — skips if already injected. Works for all frameworks:
 * Vite preserves <style> tags in <head> (only strips body inline styles).
 * Also injects into dist/index.html if it exists (for deployments).
 */
function ensureCssReset(appPath: string): void {
  const htmlFiles = [
    path.join(appPath, 'index.html'),
    path.join(appPath, 'dist', 'index.html'),
    path.join(appPath, 'build', 'index.html'),
    path.join(appPath, 'out', 'index.html'),
  ];

  for (const htmlPath of htmlFiles) {
    if (!fs.existsSync(htmlPath)) continue;
    try {
      let html = fs.readFileSync(htmlPath, 'utf8');
      if (html.includes(CSS_RESET_MARKER)) continue; // Already injected
      // Inject after <head> opening tag (or after <!DOCTYPE...><html...><head> patterns)
      if (html.includes('<head>')) {
        html = html.replace('<head>', `<head>\n${CSS_RESET_STYLE}`);
      } else if (html.includes('<head ')) {
        html = html.replace(/<head\s[^>]*>/, `$&\n${CSS_RESET_STYLE}`);
      } else if (html.includes('<html')) {
        // No <head> tag — inject after <html...>
        html = html.replace(/<html[^>]*>/, `$&\n<head>${CSS_RESET_STYLE}</head>`);
      } else {
        // Bare HTML — prepend
        html = `${CSS_RESET_STYLE}\n${html}`;
      }
      fs.writeFileSync(htmlPath, html);
    } catch {}
  }
}

/**
 * Preview start result.
 */
export interface PreviewStartResult {
  success: boolean;
  error?: string;
  ready?: boolean;
  alreadyRunning?: boolean;
  failReason?: 'port_stuck' | 'wrong_process' | 'timeout' | 'module_error' | 'no_config' | null;
  /** Module scripts that failed MIME validation */
  diagnostics?: Array<{ path: string; contentType: string }>;
}

/**
 * Start preview for an app.
 * @param appDirectory - The app's directory name (unique identifier)
 * @param requestId - Optional request ID for ordering (skip work if superseded)
 */
export function startPreview(appDirectory: string, requestId?: number): PreviewStartResult {
  const appPath = getAppPath(appDirectory);

  if (!fs.existsSync(appPath)) {
    return { success: false, error: 'App path not found: ' + appPath };
  }

  // Check if superseded before cleanup
  if (requestId !== undefined && !isLatestRequest(requestId)) {
    return { success: false, error: 'Superseded by newer request' };
  }

  const ecosystemPath = path.join(appPath, 'ecosystem.config.js');
  const packageJsonPath = path.join(appPath, 'package.json');

  // Robust cleanup: stop PM2 process + ensure port 3000 is actually free
  runPm2('pm2 delete preview 2>/dev/null || true');
  if (!ensurePortFree(PORTS.PREVIEW)) {
    return { success: false, error: `Port ${PORTS.PREVIEW} could not be freed`, failReason: 'port_stuck' };
  }

  // Clean up stale preview metadata (port 3000 apps) so the dashboard
  // doesn't show the previous preview as still "deployed" after switching.
  try {
    const appsDir = `${HOME}/.ellulai/apps`;
    if (fs.existsSync(appsDir)) {
      for (const f of fs.readdirSync(appsDir).filter(f => f.endsWith('.json'))) {
        try {
          const meta = JSON.parse(fs.readFileSync(`${appsDir}/${f}`, 'utf8'));
          if (meta.port === PORTS.PREVIEW && meta.isPreview !== false) fs.unlinkSync(`${appsDir}/${f}`);
        } catch {}
      }
    }
  } catch {}

  // Check if superseded after cleanup
  if (requestId !== undefined && !isLatestRequest(requestId)) {
    return { success: false, error: 'Superseded by newer request' };
  }

  // Auto-install dependencies if node_modules is missing or incomplete
  // Non-blocking: fire-and-forget so the HTTP response returns immediately.
  // The bash ellulai-preview script's wait_for_install() handles startup after install.
  if (fs.existsSync(packageJsonPath) && !isInstallComplete(appPath)) {
    const lockFile = fs.existsSync(path.join(appPath, 'pnpm-lock.yaml'))
      ? 'pnpm' : fs.existsSync(path.join(appPath, 'yarn.lock'))
      ? 'yarn' : 'npm';
    try {
      execSync(`nohup bash -c 'cd "${appPath}" && ${lockFile} install' >/dev/null 2>&1 &`,
        { timeout: 3000, env: EXEC_ENV });
    } catch {}
    // Don't start PM2 yet — deps not ready. Frontend polls until ready.
    return { success: true, ready: false, failReason: null };
  }

  let started = false;

  // Ensure child processes spawned by pm2 also have the correct PATH
  const pathEnv = `${NVM_BIN}:${process.env.PATH || '/usr/local/bin:/usr/bin:/bin'}`;

  // Environment variables to ensure frameworks allow external host access.
  // Without these, reverse-proxied previews get blocked by host checks.
  const frameworkEnv = [
    `export PATH=${pathEnv}`,
    `export PORT=${PORTS.PREVIEW}`,                  // Explicit preview port for child processes
    'export DANGEROUSLY_DISABLE_HOST_CHECK=true', // CRA
    'export HOST=127.0.0.1',                      // Bind to localhost only (Caddy reverse proxies)
  ].join(' && ');

  // Ensure Vite projects have correct config: allowedHosts + framework plugins.
  // Without the right plugin, Vite serves .jsx/.tsx/.vue files with wrong MIME types.
  ensureViteConfig(appPath);

  // Inject CSS reset into index.html to eliminate white border from missing resets.
  // Infrastructure-level fix — doesn't depend on LLM including CSS resets.
  ensureCssReset(appPath);

  // Try ecosystem.config.js first
  if (fs.existsSync(ecosystemPath)) {
    const result = runPm2(`cd "${appPath}" && ${frameworkEnv} && pm2 start ecosystem.config.js --only preview`);
    if (result.includes('launched') || result.includes('online')) {
      started = true;
    }
  }

  // Framework-aware direct startup — bypasses package.json scripts to avoid
  // broken CLI flags written by the AI agent (e.g. `vite -H` instead of `vite --host`).
  if (!started && fs.existsSync(packageJsonPath)) {
    const FRAMEWORK_COMMANDS: Record<string, { bin: string; cmd: string }> = {
      vite:   { bin: '.bin/vite',           cmd: `npx vite --host 0.0.0.0 --port ${PORTS.PREVIEW}` },
      nextjs: { bin: '.bin/next',           cmd: `npx next dev -H 0.0.0.0 -p ${PORTS.PREVIEW}` },
      cra:    { bin: '.bin/react-scripts',  cmd: 'npx react-scripts start' },
      astro:  { bin: '.bin/astro',          cmd: `npx astro dev --host 0.0.0.0 --port ${PORTS.PREVIEW}` },
      remix:  { bin: '.bin/remix',          cmd: `npx remix vite:dev --host 0.0.0.0 --port ${PORTS.PREVIEW}` },
    };

    try {
      const { detectApps } = require('./apps.service');
      const apps = detectApps();
      const app = apps.find((a: { directory: string }) => a.directory === appDirectory);
      const fw = app?.framework as string | undefined;
      const fwCmd = fw ? FRAMEWORK_COMMANDS[fw] : undefined;

      if (fwCmd && fs.existsSync(path.join(appPath, 'node_modules', fwCmd.bin))) {
        const result = runPm2(
          `cd "${appPath}" && pm2 start bash --name preview --cwd "${appPath}" -- -c "${frameworkEnv} && ${fwCmd.cmd}"`
        );
        if (result.includes('launched') || result.includes('online')) {
          started = true;
        }
      }
    } catch {}
  }

  // Fallback: try package.json scripts for unknown frameworks
  if (!started && fs.existsSync(packageJsonPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8')) as {
        scripts?: Record<string, string>;
      };
      const scripts = pkg.scripts || {};

      const devScript = scripts.dev || scripts.start || scripts.serve;
      if (devScript) {
        const scriptName = scripts.dev ? 'dev' : scripts.start ? 'start' : 'serve';
        const result = runPm2(`cd "${appPath}" && pm2 start bash --name preview --cwd "${appPath}" -- -c "${frameworkEnv} && npm run ${scriptName}"`);
        if (result.includes('launched') || result.includes('online')) {
          started = true;
        }
      }
    } catch {}
  }

  if (!started) {
    return { success: false, error: 'No runnable configuration found' };
  }

  runPm2('pm2 save');

  // Schedule background health check + auto-repair after response is sent.
  // Frontend detects readiness via status polling with getPreviewHealth().
  setTimeout(() => {
    if (requestId !== undefined && !isLatestRequest(requestId)) return;
    const result = waitForReady(8000);
    if (result.status === 'module_error') {
      console.log('[preview] Module MIME error detected, attempting auto-repair:', result.badModules);
      ensureViteConfig(appPath);
      try { fs.rmSync(path.join(appPath, 'node_modules', '.vite'), { recursive: true, force: true }); } catch {}
      runPm2('pm2 restart preview');
    }
  }, 100);

  return { success: true, ready: false, failReason: null };
}

/**
 * Stop preview.
 */
export function stopPreview(): void {
  // Clean up preview deployment metadata (port 3000 apps)
  try {
    const appsDir = `${HOME}/.ellulai/apps`;
    if (fs.existsSync(appsDir)) {
      for (const f of fs.readdirSync(appsDir).filter(f => f.endsWith('.json'))) {
        try {
          const meta = JSON.parse(fs.readFileSync(`${appsDir}/${f}`, 'utf8'));
          if (meta.port === PORTS.PREVIEW && meta.isPreview !== false) fs.unlinkSync(`${appsDir}/${f}`);
        } catch {}
      }
    }
  } catch {}

  runPm2('pm2 delete preview 2>/dev/null || true');
  runPm2(`fuser -k ${PORTS.PREVIEW}/tcp 2>/dev/null || true`);
}

/**
 * Get current preview status.
 */
export function getPreviewStatus(): {
  app: string | null;
  running: boolean;
} {
  let current: string | null = null;
  if (fs.existsSync(PREVIEW_FILE)) {
    current = fs.readFileSync(PREVIEW_FILE, 'utf8').trim() || null;
  }

  const pm2List = runPm2('pm2 jlist');
  let isRunning = false;
  try {
    const processes = JSON.parse(pm2List || '[]') as Array<{
      name: string;
      pm2_env?: { status: string };
    }>;
    isRunning = processes.some((p) => p.name === 'preview' && p.pm2_env?.status === 'online');
  } catch {}

  return { app: current, running: isRunning };
}

/**
 * Get preview health with actual port-level verification.
 * Returns granular phase info instead of just PM2 process status.
 * Uses curl -m 1 (1s max) so the status endpoint stays fast.
 */
export function getPreviewHealth(): {
  app: string | null;
  phase: 'idle' | 'installing' | 'starting' | 'ready' | 'error';
  active: boolean;
} {
  // 1. Read current app
  let current: string | null = null;
  if (fs.existsSync(PREVIEW_FILE)) {
    current = fs.readFileSync(PREVIEW_FILE, 'utf8').trim() || null;
  }

  if (!current) {
    return { app: null, phase: 'idle', active: false };
  }

  // 2. Check if deps are installed
  const appPath = getAppPath(current);
  const packageJsonPath = path.join(appPath, 'package.json');
  if (fs.existsSync(packageJsonPath) && !isInstallComplete(appPath)) {
    return { app: current, phase: 'installing', active: false };
  }

  // 3. Check if something is listening on the preview port
  const pid = getPidOnPort(PORTS.PREVIEW);
  if (pid === null) {
    return { app: current, phase: 'starting', active: false };
  }

  // 4. Check if it's actually serving responses (1s timeout)
  // Accept any HTTP response (not just text/html) — backend APIs return JSON
  try {
    const headers = execSync(
      `curl -sI -m 1 http://localhost:${PORTS.PREVIEW}/ 2>/dev/null`,
      { encoding: 'utf8', timeout: 3000, env: EXEC_ENV }
    );
    if (/^HTTP\/[\d.]+ \d{3}/i.test(headers)) {
      return { app: current, phase: 'ready', active: true };
    }
  } catch {}

  return { app: current, phase: 'starting', active: false };
}

/**
 * Set current preview app and optionally start it.
 * Uses request ordering to handle rapid app switching - only the latest request wins.
 */
export function setPreviewApp(
  appDirectory: string | null,
  script?: string
): {
  success: boolean;
  app: string | null;
  preview?: PreviewStartResult;
  superseded?: boolean;
} {
  // Get a request ID for ordering
  const requestId = getNextRequestId();
  console.log(`[preview] setPreviewApp called for "${appDirectory}" (request #${requestId})`);

  fs.mkdirSync(`${HOME}/.ellulai`, { recursive: true });

  // Check if we've been superseded before doing any work
  if (!isLatestRequest(requestId)) {
    console.log(`[preview] Request #${requestId} superseded before start, skipping`);
    return { success: true, app: appDirectory, superseded: true };
  }

  // Write the directory name - this is quick so we do it even if superseded later
  fs.writeFileSync(PREVIEW_FILE, appDirectory || '');
  if (script) {
    fs.writeFileSync(`${HOME}/.ellulai/preview-script`, script);
  }

  if (!appDirectory) {
    return { success: true, app: null };
  }

  // Check again before starting the expensive preview operation
  if (!isLatestRequest(requestId)) {
    console.log(`[preview] Request #${requestId} superseded before preview start, skipping`);
    return { success: true, app: appDirectory, superseded: true };
  }

  // Start the preview - this is the slow part
  const result = startPreview(appDirectory, requestId);

  // Final check - if superseded during startup, the result might be stale
  if (!isLatestRequest(requestId)) {
    console.log(`[preview] Request #${requestId} superseded after preview start, result may be stale`);
    return { success: true, app: appDirectory, preview: result, superseded: true };
  }

  console.log(`[preview] Request #${requestId} completed successfully for "${appDirectory}"`);
  return { success: true, app: appDirectory, preview: result };
}
