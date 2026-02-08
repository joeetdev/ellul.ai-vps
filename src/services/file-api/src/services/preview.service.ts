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

const PREVIEW_FILE = `${HOME}/.phonestack/preview-app`;

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
const NVM_BIN = `${HOME}/.nvm/versions/node/v20.20.0/bin`;
const EXEC_ENV = { ...process.env, PATH: `${NVM_BIN}:${process.env.PATH || ''}` };

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
 * Wait for preview to be ready.
 */
function waitForReady(maxWaitMs: number = 10000): boolean {
  const startTime = Date.now();
  while (Date.now() - startTime < maxWaitMs) {
    try {
      execSync(
        'curl -s -o /dev/null -w "%{http_code}" http://localhost:3000 | grep -q "200\\|304\\|301\\|302"',
        {
          timeout: 2000,
          stdio: 'pipe',
          env: EXEC_ENV,
        }
      );
      return true;
    } catch {
      execSync('sleep 0.5', { env: EXEC_ENV });
    }
  }
  return false;
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

  // Robust cleanup: stop PM2 process + kill any orphaned processes on port 3000
  runPm2('pm2 delete preview 2>/dev/null || true');
  runPm2('fuser -k 3000/tcp 2>/dev/null || true');
  runPm2('sleep 0.5'); // Allow port to fully release

  // Check if superseded after cleanup
  if (requestId !== undefined && !isLatestRequest(requestId)) {
    return { success: false, error: 'Superseded by newer request' };
  }

  // Auto-install dependencies if node_modules is missing
  if (fs.existsSync(packageJsonPath) && !fs.existsSync(path.join(appPath, 'node_modules'))) {
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
    'export HOST=0.0.0.0',                        // General
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

  // Try package.json scripts
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

  const ready = waitForReady(8000);

  return { success: true, ready };
}

/**
 * Stop preview.
 */
export function stopPreview(): void {
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

  fs.mkdirSync(`${HOME}/.phonestack`, { recursive: true });

  // Check if we've been superseded before doing any work
  if (!isLatestRequest(requestId)) {
    console.log(`[preview] Request #${requestId} superseded before start, skipping`);
    return { success: true, app: appDirectory, superseded: true };
  }

  // Write the directory name - this is quick so we do it even if superseded later
  fs.writeFileSync(PREVIEW_FILE, appDirectory || '');
  if (script) {
    fs.writeFileSync(`${HOME}/.phonestack/preview-script`, script);
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
