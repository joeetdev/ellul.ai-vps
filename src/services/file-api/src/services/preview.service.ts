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

const PREVIEW_FILE = `${HOME}/.ellulai/preview-app`;

// Request ordering - ensures only the latest request is processed
let latestRequestId = 0;
let currentRequestId = 0;

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
const EXEC_ENV = { ...process.env, PATH: `${NVM_BIN}:${process.env.PATH || ''}` };

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

/**
 * Wait for preview to be ready with process ownership + content-type verification.
 */
function waitForReady(maxWaitMs: number = 10000): 'ready' | 'wrong_process' | 'timeout' {
  const startTime = Date.now();
  while (Date.now() - startTime < maxWaitMs) {
    const portPid = getPidOnPort(3000);
    if (portPid !== null) {
      const previewPid = getPreviewPid();
      if (previewPid !== null && isDescendantOf(portPid, previewPid)) {
        // Ownership confirmed — check content-type
        try {
          const headers = execSync(
            'curl -sI http://localhost:3000/ 2>/dev/null',
            { encoding: 'utf8', timeout: 3000, env: EXEC_ENV }
          );
          if (/content-type:.*text\/html/i.test(headers)) {
            return 'ready';
          }
        } catch {}
      } else if (portPid !== null && previewPid !== null) {
        // Wrong process on port — kill it immediately
        try { execSync(`kill -9 ${portPid} 2>/dev/null || true`, { env: EXEC_ENV, timeout: 3000 }); } catch {}
      }
    }
    try { execSync('sleep 0.5', { env: EXEC_ENV }); } catch {}
  }
  return 'timeout';
}

/**
 * Ensure Vite projects have allowedHosts configured so preview works behind reverse proxy.
 * Creates a vite.config.js if none exists, or patches an existing one if allowedHosts is missing.
 */
function ensureViteAllowedHosts(appPath: string): void {
  // Only act on Vite projects - check for vite in devDependencies or dependencies
  const pkgPath = path.join(appPath, 'package.json');
  if (!fs.existsSync(pkgPath)) return;

  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
    if (!allDeps['vite']) return;
  } catch {
    return;
  }

  const configFiles = ['vite.config.js', 'vite.config.ts', 'vite.config.mjs', 'vite.config.mts'];
  const existingConfig = configFiles.find((f) => fs.existsSync(path.join(appPath, f)));

  if (!existingConfig) {
    // No vite config - create one with allowedHosts
    fs.writeFileSync(
      path.join(appPath, 'vite.config.js'),
      `import { defineConfig } from "vite";\nexport default defineConfig({\n  server: {\n    host: true,\n    port: 3000,\n    allowedHosts: true,\n  },\n});\n`
    );
    return;
  }

  // Config exists - check if allowedHosts is already set
  const configPath = path.join(appPath, existingConfig);
  const content = fs.readFileSync(configPath, 'utf8');
  if (content.includes('allowedHosts')) return;

  // Patch: inject allowedHosts into existing server config, or add server block
  if (content.includes('server:') || content.includes('server :')) {
    // Has server block - add allowedHosts to it
    const patched = content.replace(
      /(server\s*:\s*\{)/,
      '$1\n    allowedHosts: true,'
    );
    if (patched !== content) {
      fs.writeFileSync(configPath, patched);
      return;
    }
  }

  // Has defineConfig but no server block - add one
  if (content.includes('defineConfig(')) {
    const patched = content.replace(
      /(defineConfig\s*\(\s*\{)/,
      '$1\n  server: { host: true, port: 3000, allowedHosts: true },'
    );
    if (patched !== content) {
      fs.writeFileSync(configPath, patched);
      return;
    }
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
  failReason?: 'port_stuck' | 'wrong_process' | 'timeout' | 'no_config' | null;
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
  if (!ensurePortFree(3000)) {
    return { success: false, error: 'Port 3000 could not be freed', failReason: 'port_stuck' };
  }

  // Clean up stale preview metadata (port 3000 apps) so the dashboard
  // doesn't show the previous preview as still "deployed" after switching.
  try {
    const appsDir = `${HOME}/.ellulai/apps`;
    if (fs.existsSync(appsDir)) {
      for (const f of fs.readdirSync(appsDir).filter(f => f.endsWith('.json'))) {
        try {
          const meta = JSON.parse(fs.readFileSync(`${appsDir}/${f}`, 'utf8'));
          if (meta.port === 3000 && meta.isPreview !== false) fs.unlinkSync(`${appsDir}/${f}`);
        } catch {}
      }
    }
  } catch {}

  // Check if superseded after cleanup
  if (requestId !== undefined && !isLatestRequest(requestId)) {
    return { success: false, error: 'Superseded by newer request' };
  }

  // Auto-install dependencies if node_modules is missing or incomplete
  if (fs.existsSync(packageJsonPath) && !isInstallComplete(appPath)) {
    const lockFile = fs.existsSync(path.join(appPath, 'pnpm-lock.yaml'))
      ? 'pnpm' : fs.existsSync(path.join(appPath, 'yarn.lock'))
      ? 'yarn' : 'npm';
    runPm2(`cd "${appPath}" && ${lockFile} install`);
  }

  // Check if superseded after install
  if (requestId !== undefined && !isLatestRequest(requestId)) {
    return { success: false, error: 'Superseded by newer request' };
  }

  let started = false;

  // Ensure child processes spawned by pm2 also have the correct PATH
  const pathEnv = `${NVM_BIN}:${process.env.PATH || '/usr/local/bin:/usr/bin:/bin'}`;

  // Environment variables to ensure frameworks allow external host access.
  // Without these, reverse-proxied previews get blocked by host checks.
  const frameworkEnv = [
    `export PATH=${pathEnv}`,
    'export DANGEROUSLY_DISABLE_HOST_CHECK=true', // CRA
    'export HOST=127.0.0.1',                      // Bind to localhost only (Caddy reverse proxies)
  ].join(' && ');

  // Ensure Vite projects have allowedHosts configured.
  // Vite blocks requests from unknown hostnames by default - this is the only
  // reliable way to fix it since env vars don't control this setting.
  ensureViteAllowedHosts(appPath);

  // Try ecosystem.config.js first
  if (fs.existsSync(ecosystemPath)) {
    const result = runPm2(`cd "${appPath}" && pm2 start ecosystem.config.js --only preview`);
    if (result.includes('launched') || result.includes('online')) {
      started = true;
    }
  }

  // Framework-aware direct startup — bypasses package.json scripts to avoid
  // broken CLI flags written by the AI agent (e.g. `vite -H` instead of `vite --host`).
  if (!started && fs.existsSync(packageJsonPath)) {
    const FRAMEWORK_COMMANDS: Record<string, { bin: string; cmd: string }> = {
      vite:   { bin: '.bin/vite',           cmd: 'npx vite --host 0.0.0.0 --port 3000' },
      nextjs: { bin: '.bin/next',           cmd: 'npx next dev -H 0.0.0.0 -p 3000' },
      cra:    { bin: '.bin/react-scripts',  cmd: 'npx react-scripts start' },
      astro:  { bin: '.bin/astro',          cmd: 'npx astro dev --host 0.0.0.0 --port 3000' },
      remix:  { bin: '.bin/remix',          cmd: 'npx remix vite:dev --host 0.0.0.0 --port 3000' },
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

  // Try static HTML with live-server
  if (!started) {
    const indexHtml = path.join(appPath, 'index.html');
    if (fs.existsSync(indexHtml)) {
      const result = runPm2(
        `cd "${appPath}" && pm2 start bash --name preview --cwd "${appPath}" -- -c "${frameworkEnv} && npx -y live-server --port=3000 --no-browser --quiet"`
      );
      if (result.includes('launched') || result.includes('online')) {
        started = true;
      }
    }
  }

  if (!started) {
    return { success: false, error: 'No runnable configuration found' };
  }

  runPm2('pm2 save');

  // Check if superseded before waiting - don't waste time waiting if superseded
  if (requestId !== undefined && !isLatestRequest(requestId)) {
    return { success: true, ready: false, error: 'Superseded - skipped wait' };
  }

  const readyStatus = waitForReady(10000);

  return {
    success: true,
    ready: readyStatus === 'ready',
    failReason: readyStatus === 'ready' ? null : readyStatus,
  };
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
          if (meta.port === 3000 && meta.isPreview !== false) fs.unlinkSync(`${appsDir}/${f}`);
        } catch {}
      }
    }
  } catch {}

  runPm2('pm2 delete preview 2>/dev/null || true');
  runPm2('fuser -k 3000/tcp 2>/dev/null || true');
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
