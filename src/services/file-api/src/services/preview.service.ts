/**
 * Preview Service
 *
 * App preview management using PM2.
 * Includes request ordering to handle rapid app switching.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import { execSync } from 'child_process';
import { HOME, ROOT_DIR } from '../config';
import { PORTS, PREVIEW_PORT_MIN, PREVIEW_PORT_MAX, PREVIEW_LIMITS } from '../../../shared/constants';

const PREVIEW_FILE = `${HOME}/.ellulai/preview-app`;
const PORT_REGISTRY_FILE = `${HOME}/.ellulai/preview-ports.json`;

// Request ordering - ensures only the latest request is processed
let latestRequestId = 0;

// ---------------------------------------------------------------------------
// Self-Healing State — tracks automated error-fix attempts per project
// ---------------------------------------------------------------------------

interface HealState {
  errorHash: string;      // SHA-256 of error summary — dedup identical errors
  attempts: number;       // How many times we've asked the agent to fix this
  lastAttemptAt: number;  // Timestamp of last heal request
  resolved: boolean;      // Set true when process restarts successfully
}

const healStates = new Map<string, HealState>();
const MAX_HEAL_ATTEMPTS = 3;
const HEAL_DEBOUNCE_MS = 30_000;

// LRU access tracker for preview eviction
const previewLastAccess = new Map<string, number>();

// ---------------------------------------------------------------------------
// Operational Metrics — lightweight counters for observability
// ---------------------------------------------------------------------------

const metrics = {
  evictions: 0,
  healAttempted: 0,
  healSucceeded: 0,
  healExhausted: 0,
  gcPortsReclaimed: 0,
  gcOrphansKilled: 0,
  portNearExhaustion: 0,  // port allocation when >80% of range is used
  backpressureRejections: 0,
  registryRebuilds: 0,
  startedAt: Date.now(),
};

/**
 * Get preview system metrics for observability.
 * Exposed via GET /api/preview/metrics.
 */
export function getPreviewMetrics(): Record<string, unknown> {
  const registry = getPortRegistry();
  const usedPorts = Object.keys(registry).length;
  const totalPorts = PREVIEW_PORT_MAX - PREVIEW_PORT_MIN + 1;
  return {
    ...metrics,
    uptimeMs: Date.now() - metrics.startedAt,
    portsUsed: usedPorts,
    portsTotal: totalPorts,
    portsUtilization: Math.round((usedPorts / totalPorts) * 100),
    activeHeals: healStates.size,
    trackedPreviews: previewLastAccess.size,
  };
}

// ---------------------------------------------------------------------------
// Generic Preview Config — framework-agnostic convention-based detection
// ---------------------------------------------------------------------------

interface PreviewConfig {
  runtime: 'node' | 'python' | 'rust' | 'go' | 'static' | 'custom';
  install: string | null;
  command: string;
  env: Record<string, string>;
  source: 'explicit' | 'convention';
  description: string;
}

type ResolveResult =
  | { ok: true; config: PreviewConfig }
  | { ok: false; reason: string };

/**
 * Resolve preview config for a project directory.
 * Priority: ellulai.json explicit config > convention detection from file markers.
 */
function resolvePreviewConfig(appPath: string, port: number): ResolveResult {
  // 1. Explicit config from ellulai.json
  const ellulaiJsonPath = path.join(appPath, 'ellulai.json');
  if (fs.existsSync(ellulaiJsonPath)) {
    try {
      const config = JSON.parse(fs.readFileSync(ellulaiJsonPath, 'utf8'));
      if (config.preview?.command) {
        return {
          ok: true,
          config: {
            runtime: 'custom',
            install: config.preview.install || null,
            command: config.preview.command.replace(/\$PORT/g, String(port)),
            env: { PORT: String(port), HOST: '0.0.0.0', ...(config.preview.env || {}) },
            source: 'explicit',
            description: `Custom command from ellulai.json`,
          },
        };
      }
    } catch {}
  }

  // 2. Convention detection — Node.js (package.json)
  const pkgPath = path.join(appPath, 'package.json');
  if (fs.existsSync(pkgPath)) {
    const pkg = safeReadJsonSync<{
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      scripts?: Record<string, string>;
    }>(pkgPath);
    if (pkg) {
      const allDeps: Record<string, string> = { ...pkg.dependencies, ...pkg.devDependencies };
      const nodeEnv: Record<string, string> = {
        PORT: String(port),
        HOST: '127.0.0.1',
        NODE_ENV: 'development',
        DANGEROUSLY_DISABLE_HOST_CHECK: 'true',
      };

      // Framework-specific commands (ordered by priority)
      const nodeFrameworks: Array<{ dep: string; cmd: string; desc: string }> = [
        { dep: 'next',              cmd: `npx next dev -H 0.0.0.0 -p ${port}`,                    desc: 'Next.js' },
        { dep: 'vite',              cmd: `npx vite --host 0.0.0.0 --port ${port}`,                desc: 'Vite' },
        { dep: 'astro',             cmd: `npx astro dev --host 0.0.0.0 --port ${port}`,           desc: 'Astro' },
        { dep: 'react-scripts',     cmd: `npx react-scripts start`,                               desc: 'Create React App' },
        { dep: 'nuxt',              cmd: `npx nuxi dev --port ${port}`,                           desc: 'Nuxt' },
        { dep: '@remix-run/dev',    cmd: `npx remix vite:dev --host 0.0.0.0 --port ${port}`,     desc: 'Remix' },
        { dep: 'gatsby',            cmd: `npx gatsby develop -p ${port}`,                          desc: 'Gatsby' },
        { dep: '@sveltejs/kit',     cmd: `npx vite dev --host 0.0.0.0 --port ${port}`,           desc: 'SvelteKit' },
      ];

      for (const fw of nodeFrameworks) {
        if (allDeps[fw.dep]) {
          const lockFile = fs.existsSync(path.join(appPath, 'pnpm-lock.yaml'))
            ? 'pnpm install' : fs.existsSync(path.join(appPath, 'yarn.lock'))
            ? 'yarn install' : 'npm install';
          return {
            ok: true,
            config: {
              runtime: 'node',
              install: lockFile,
              command: fw.cmd,
              env: nodeEnv,
              source: 'convention',
              description: fw.desc,
            },
          };
        }
      }

      // Node.js fallback: npm scripts
      const scripts = pkg.scripts || {};
      const scriptName = scripts.dev ? 'dev' : scripts.start ? 'start' : scripts.serve ? 'serve' : null;
      if (scriptName) {
        const lockFile = fs.existsSync(path.join(appPath, 'pnpm-lock.yaml'))
          ? 'pnpm install' : fs.existsSync(path.join(appPath, 'yarn.lock'))
          ? 'yarn install' : 'npm install';
        return {
          ok: true,
          config: {
            runtime: 'node',
            install: lockFile,
            command: `npm run ${scriptName}`,
            env: nodeEnv,
            source: 'convention',
            description: `npm run ${scriptName}`,
          },
        };
      }

      return { ok: false, reason: 'package.json found but no framework detected and no dev/start/serve script' };
    }
  }

  // 3. Python (requirements.txt or pyproject.toml)
  const hasPyReqs = fs.existsSync(path.join(appPath, 'requirements.txt'));
  const hasPyProject = fs.existsSync(path.join(appPath, 'pyproject.toml'));
  if (hasPyReqs || hasPyProject) {
    let pyContent = '';
    try {
      if (hasPyReqs) pyContent = fs.readFileSync(path.join(appPath, 'requirements.txt'), 'utf8');
      else pyContent = fs.readFileSync(path.join(appPath, 'pyproject.toml'), 'utf8');
    } catch {}

    const pyEnv: Record<string, string> = { PORT: String(port), HOST: '0.0.0.0' };
    const pyInstall = hasPyReqs ? 'pip install -r requirements.txt' : 'pip install -e .';

    if (/\b(fastapi|uvicorn)\b/i.test(pyContent)) {
      // Try to find the main app module
      const mainCandidates = ['main.py', 'app.py', 'server.py', 'api.py'];
      const mainFile = mainCandidates.find(f => fs.existsSync(path.join(appPath, f))) || 'main.py';
      const module = mainFile.replace('.py', '');
      return { ok: true, config: { runtime: 'python', install: pyInstall, command: `uvicorn ${module}:app --host 0.0.0.0 --port ${port} --reload`, env: pyEnv, source: 'convention', description: 'FastAPI/Uvicorn' } };
    }
    if (/\bflask\b/i.test(pyContent)) {
      return { ok: true, config: { runtime: 'python', install: pyInstall, command: `flask run --host 0.0.0.0 --port ${port}`, env: pyEnv, source: 'convention', description: 'Flask' } };
    }
    if (/\bdjango\b/i.test(pyContent)) {
      return { ok: true, config: { runtime: 'python', install: pyInstall, command: `python manage.py runserver 0.0.0.0:${port}`, env: pyEnv, source: 'convention', description: 'Django' } };
    }
    if (/\bstreamlit\b/i.test(pyContent)) {
      const appFile = fs.existsSync(path.join(appPath, 'app.py')) ? 'app.py' : 'main.py';
      return { ok: true, config: { runtime: 'python', install: pyInstall, command: `streamlit run ${appFile} --server.port ${port} --server.address 0.0.0.0`, env: pyEnv, source: 'convention', description: 'Streamlit' } };
    }
    // Python fallback
    const appFile = fs.existsSync(path.join(appPath, 'app.py')) ? 'app.py' : 'main.py';
    return { ok: true, config: { runtime: 'python', install: pyInstall, command: `python ${appFile}`, env: pyEnv, source: 'convention', description: 'Python' } };
  }

  // 4. Rust (Cargo.toml)
  if (fs.existsSync(path.join(appPath, 'Cargo.toml'))) {
    return { ok: true, config: { runtime: 'rust', install: null, command: 'cargo run', env: { PORT: String(port), HOST: '0.0.0.0' }, source: 'convention', description: 'Rust (cargo run)' } };
  }

  // 5. Go (go.mod)
  if (fs.existsSync(path.join(appPath, 'go.mod'))) {
    return { ok: true, config: { runtime: 'go', install: null, command: 'go run .', env: { PORT: String(port), HOST: '0.0.0.0' }, source: 'convention', description: 'Go (go run)' } };
  }

  // 6. Static (index.html without package.json)
  if (fs.existsSync(path.join(appPath, 'index.html'))) {
    return { ok: true, config: { runtime: 'static', install: null, command: `npx serve -l ${port}`, env: { PORT: String(port) }, source: 'convention', description: 'Static (npx serve)' } };
  }

  return { ok: false, reason: 'No recognized project structure found (no package.json, requirements.txt, Cargo.toml, go.mod, or index.html)' };
}

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

// ---------------------------------------------------------------------------
// Structured Logger
// ---------------------------------------------------------------------------

type LogLevel = 'debug' | 'info' | 'warn' | 'error';
function log(level: LogLevel, msg: string, ctx?: Record<string, unknown>): void {
  const entry = { ts: new Date().toISOString(), level, svc: 'preview', msg, ...ctx };
  console.log(JSON.stringify(entry));
}

// ---------------------------------------------------------------------------
// Structured PM2 Wrapper
// ---------------------------------------------------------------------------

interface Pm2Result { success: boolean; output: string; error?: string; }

function execPm2(cmd: string): Pm2Result {
  try {
    return { success: true, output: execSync(cmd, { encoding: 'utf8', timeout: 30000, env: EXEC_ENV }) };
  } catch (e) {
    const err = e as Error & { stderr?: string };
    const error = err.stderr?.trim() || err.message;
    if (error.includes('command not found') || error.includes('ENOENT')) {
      log('error', 'pm2 binary not found', { cmd });
    } else {
      log('warn', 'pm2 command failed', { cmd, error: error.slice(0, 300) });
    }
    return { success: false, output: '', error };
  }
}

// ---------------------------------------------------------------------------
// Port Registry — per-project preview port allocation (4000-4099)
// ---------------------------------------------------------------------------

function getPortRegistry(): Record<string, number> {
  try {
    const parsed = JSON.parse(fs.readFileSync(PORT_REGISTRY_FILE, 'utf8'));
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
      const valid = Object.entries(parsed).every(
        ([, v]) => typeof v === 'number' && v >= PREVIEW_PORT_MIN && v <= PREVIEW_PORT_MAX
      );
      if (valid) return parsed;
    }
    log('warn', 'port registry corrupt, rebuilding from PM2');
  } catch { /* file missing — normal on first run */ }
  return rebuildPortRegistry();
}

/**
 * Rebuild port registry by scanning PM2 preview-* processes for PORT env.
 */
function rebuildPortRegistry(): Record<string, number> {
  metrics.registryRebuilds++;
  const registry: Record<string, number> = {};
  try {
    const list = execPm2('pm2 jlist');
    if (!list.success) return registry;
    const procs = JSON.parse(list.output || '[]');
    for (const p of procs) {
      if (typeof p.name === 'string' && p.name.startsWith('preview-')) {
        const project = p.name.slice('preview-'.length);
        const port = extractPortFromPm2Proc(p);
        if (port !== null) {
          registry[project] = port;
        }
      }
    }
    if (Object.keys(registry).length > 0) {
      savePortRegistry(registry);
      log('info', 'port registry rebuilt from PM2', { count: Object.keys(registry).length });
    }
  } catch {}
  return registry;
}

/**
 * Extract the preview port from a PM2 process entry.
 * Tries multiple sources since PORT is set via `bash -c "export PORT=NNNN"`,
 * not as a PM2 env var.
 *
 * Priority:
 * 1. pm2_env.PORT / pm2_env.env.PORT (if PM2 captured it)
 * 2. Parse `export PORT=NNNN` from the bash -c args string
 * 3. Parse `--port NNNN` from the command args
 * 4. Check which port the process is actually listening on via ss
 */
function extractPortFromPm2Proc(p: any): number | null {
  // 1. PM2 env vars
  for (const envPort of [p.pm2_env?.PORT, p.pm2_env?.env?.PORT]) {
    const n = typeof envPort === 'string' ? parseInt(envPort, 10) : envPort;
    if (typeof n === 'number' && n >= PREVIEW_PORT_MIN && n <= PREVIEW_PORT_MAX) return n;
  }

  // 2+3. Parse args string for `export PORT=NNNN` or `--port NNNN`
  const args: unknown[] = p.pm2_env?.args || [];
  const argsStr = args.map(String).join(' ');
  const exportMatch = argsStr.match(/\bPORT=(\d+)\b/);
  if (exportMatch) {
    const n = parseInt(exportMatch[1]!, 10);
    if (n >= PREVIEW_PORT_MIN && n <= PREVIEW_PORT_MAX) return n;
  }
  const flagMatch = argsStr.match(/--port\s+(\d+)/);
  if (flagMatch) {
    const n = parseInt(flagMatch[1]!, 10);
    if (n >= PREVIEW_PORT_MIN && n <= PREVIEW_PORT_MAX) return n;
  }

  // 4. Check what port the process is actually listening on
  if (typeof p.pid === 'number' && p.pid > 0) {
    try {
      const ss = execSync(`ss -tlnp 2>/dev/null | grep "pid=${p.pid},"`, {
        encoding: 'utf8', timeout: 3000,
      });
      const portMatch = ss.match(/:(\d+)\s/);
      if (portMatch) {
        const n = parseInt(portMatch[1]!, 10);
        if (n >= PREVIEW_PORT_MIN && n <= PREVIEW_PORT_MAX) return n;
      }
    } catch {}
  }

  return null;
}

function savePortRegistry(registry: Record<string, number>): void {
  fs.mkdirSync(path.dirname(PORT_REGISTRY_FILE), { recursive: true });
  const tmp = PORT_REGISTRY_FILE + '.tmp';
  const fd = fs.openSync(tmp, 'w', 0o600);
  try { fs.writeSync(fd, JSON.stringify(registry, null, 2)); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  fs.renameSync(tmp, PORT_REGISTRY_FILE);
}

/**
 * Get or allocate a dedicated preview port for a project.
 */
export function getProjectPort(projectName: string): number {
  previewLastAccess.set(projectName, Date.now());
  const registry = getPortRegistry();
  if (registry[projectName] !== undefined) return registry[projectName]!;
  const usedPorts = new Set(Object.values(registry));
  const totalPorts = PREVIEW_PORT_MAX - PREVIEW_PORT_MIN + 1;
  if (usedPorts.size > totalPorts * 0.8) {
    metrics.portNearExhaustion++;
    log('warn', 'port range near exhaustion', { used: usedPorts.size, total: totalPorts });
  }
  for (let port = PREVIEW_PORT_MIN; port <= PREVIEW_PORT_MAX; port++) {
    if (!usedPorts.has(port)) {
      registry[projectName] = port;
      savePortRegistry(registry);
      return port;
    }
  }
  throw new Error(`Preview port exhaustion: all ports ${PREVIEW_PORT_MIN}-${PREVIEW_PORT_MAX} allocated`);
}

/**
 * Release a project's preview port from the registry.
 */
export function releaseProjectPort(projectName: string): void {
  const registry = getPortRegistry();
  if (registry[projectName] !== undefined) {
    delete registry[projectName];
    savePortRegistry(registry);
  }
}

// ---------------------------------------------------------------------------
// Caddy Dev Route — dynamically written when active project changes
// Serialized via caddyWriteMutex to prevent concurrent write/validate/reload races.
// ---------------------------------------------------------------------------

// Promise-based mutex — ensures only one Caddy write+validate+reload runs at a time.
// Without this, two concurrent preview starts can both write .tmp, both validate,
// and one rename clobbers the other's config before its reload finishes.
let caddyWriteMutex: Promise<void> = Promise.resolve();

function writeCaddyDevRoute(port: number): void {
  // Queue this write behind any in-flight Caddy operation
  caddyWriteMutex = caddyWriteMutex.then(() => writeCaddyDevRouteImpl(port)).catch(() => {});
}

/**
 * Ensure the Caddy dev route points to the given port.
 * No-op if it already does — avoids unnecessary reloads on every poll.
 * Called from GET /api/preview to fix routes when the bash preview daemon
 * starts the server but nobody called writeCaddyDevRoute.
 */
export function ensureCaddyRoute(port: number): void {
  try {
    const existing = fs.readFileSync('/etc/caddy/app-routes.d/dev.caddy', 'utf8');
    if (existing.includes(`reverse_proxy localhost:${port}`)) return;
  } catch { /* file missing — need to write */ }
  writeCaddyDevRoute(port);
}

function writeCaddyDevRouteImpl(port: number): void {
  let devDomain = '';
  try {
    devDomain = fs.readFileSync('/etc/ellulai/dev-domain', 'utf8').trim();
  } catch {}
  if (!devDomain) return;

  const config = `@dev host ${devDomain}
handle @dev {
    @notAuth not path /_auth/*
    header @notAuth Content-Security-Policy "frame-ancestors 'self' https://console.ellul.ai"

    route {
        forward_auth localhost:${PORTS.SOVEREIGN_SHIELD} {
            uri /api/auth/session
            header_up Cookie {http.request.header.Cookie}
            header_up Accept {http.request.header.Accept}
            header_up X-PoP-Signature {http.request.header.X-PoP-Signature}
            header_up X-PoP-Timestamp {http.request.header.X-PoP-Timestamp}
            header_up X-PoP-Nonce {http.request.header.X-PoP-Nonce}
            header_up User-Agent {http.request.header.User-Agent}
            header_up Sec-Ch-Ua {http.request.header.Sec-Ch-Ua}
            header_up Sec-Ch-Ua-Mobile {http.request.header.Sec-Ch-Ua-Mobile}
            header_up Sec-Ch-Ua-Platform {http.request.header.Sec-Ch-Ua-Platform}
            header_up Sec-Fetch-Dest {http.request.header.Sec-Fetch-Dest}
            header_up Sec-Fetch-Mode {http.request.header.Sec-Fetch-Mode}
            header_up X-Forwarded-Uri {uri}
            header_up X-Forwarded-Host {host}
            copy_headers X-Auth-User X-Auth-Tier X-Auth-Session
        }
        uri query -_shield_session
        uri query -_preview_token
        reverse_proxy localhost:${port} {
            header_up Host localhost
            header_up X-Real-IP {remote_host}
        }
    }
}
`;
  const caddyDir = '/etc/caddy/app-routes.d';
  const caddyPath = `${caddyDir}/dev.caddy`;
  const caddyTmp = `${caddyPath}.tmp.${process.pid}`;
  // Snapshot old config for rollback on validation/reload failure
  let oldConfig = '';
  try { oldConfig = fs.readFileSync(caddyPath, 'utf8'); } catch {}
  try {
    fs.mkdirSync(caddyDir, { recursive: true });
    // Atomic write: tmp → fsync → rename
    const fd = fs.openSync(caddyTmp, 'w', 0o644);
    try { fs.writeSync(fd, config); fs.fsyncSync(fd); }
    finally { fs.closeSync(fd); }
    fs.renameSync(caddyTmp, caddyPath);

    // Advisory validation — log but don't block on failure.
    // caddy validate can fail in systemd ProtectSystem=strict sandboxes
    // even when the config is valid, due to restricted filesystem access.
    try {
      execSync('caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile',
        { stdio: 'pipe', timeout: 10000 });
    } catch (valErr) {
      log('warn', 'caddy validate failed (advisory, proceeding with reload)', {
        error: (valErr as Error).message.slice(0, 500),
      });
    }

    // Reload is the actual gate — it validates internally and atomically
    // applies the new config or rejects it without disrupting the running config.
    try {
      execSync('caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile',
        { stdio: 'pipe', timeout: 10000 });
    } catch (reloadErr) {
      // Reload failed — config is genuinely invalid or caddy is unresponsive.
      // Rollback to previous config and attempt to restore.
      log('error', 'caddy reload failed, rolling back', {
        error: (reloadErr as Error).message.slice(0, 500),
      });
      if (oldConfig) { fs.writeFileSync(caddyPath, oldConfig); }
      else { try { fs.unlinkSync(caddyPath); } catch {} }
      try {
        execSync('caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile',
          { stdio: 'pipe', timeout: 10000 });
      } catch {}
      return;
    }
  } catch (e) {
    log('error', 'caddy dev route write/reload failed', { error: (e as Error).message.slice(0, 300) });
    try { fs.unlinkSync(caddyTmp); } catch {}
    // Restore old config if write succeeded but reload failed
    if (oldConfig && fs.existsSync(caddyPath)) {
      try { fs.writeFileSync(caddyPath, oldConfig); } catch {}
    }
  }
}

/**
 * Check if npm install is complete — node_modules exists AND expected framework binaries are present.
 * A partial install (directory exists but key packages missing) returns false.
 */
function isInstallComplete(appPath: string): boolean {
  const nm = path.join(appPath, 'node_modules');
  if (!fs.existsSync(nm)) return false;
  const pkg = safeReadJsonSync<{ dependencies?: Record<string, string>; devDependencies?: Record<string, string> }>(path.join(appPath, 'package.json'));
  if (!pkg) return false;
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
  return true;
}


/**
 * Get app path from directory identifier.
 * Primary: directory name (the unique identifier used throughout the system).
 * Fallback: display name lookup (resolves human-readable name → directory).
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
  // Fallback: resolve display name → directory name
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
 * Safely read and parse a JSON file with retry on parse failure.
 * Handles mid-write race: editors truncate then write, so a read during
 * save sees empty or partial content. Retry after a short delay catches this.
 */
function safeReadJsonSync<T = unknown>(filePath: string, retries = 2, delayMs = 80): T | null {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const raw = fs.readFileSync(filePath, 'utf8');
      if (!raw.trim()) throw new Error('empty file');
      return JSON.parse(raw) as T;
    } catch {
      if (attempt < retries) {
        // Busy-wait is acceptable here — 80ms max, non-hot path, prevents cascade failure
        const end = Date.now() + delayMs;
        while (Date.now() < end) { /* spin */ }
      }
    }
  }
  return null;
}

// Non-blocking sleep for async paths
const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms));

/**
 * Kill a process and all its descendants (children, grandchildren, etc.).
 * Sends the given signal to the entire process tree bottom-up.
 */
function killProcessTree(pid: number, signal: 'TERM' | 'KILL' = 'TERM'): void {
  try {
    // Find all child PIDs recursively and kill bottom-up
    const children = execSync(`pgrep -P ${pid} 2>/dev/null || true`, {
      encoding: 'utf8', timeout: 3000,
    }).trim().split('\n').filter(Boolean);
    for (const childPid of children) {
      killProcessTree(parseInt(childPid, 10), signal);
    }
    execSync(`kill -${signal} ${pid} 2>/dev/null || true`, { timeout: 3000 });
  } catch {}
}

/**
 * Aggressively kill ALL processes occupying a port.
 * Uses multiple strategies to ensure nothing survives:
 * 1. Process tree kill (catches children spawned by bash/npm wrappers)
 * 2. fuser -k (catches any process with the port open)
 * 3. Direct PID kill as final fallback
 */
function killPortOccupants(port: number, signal: 'TERM' | 'KILL' = 'TERM'): void {
  const pid = getPidOnPort(port);
  if (pid === null) return;
  // Strategy 1: Kill the process tree (parent → children → grandchildren)
  killProcessTree(pid, signal);
  // Strategy 2: fuser kills ALL processes with this port open
  const fuserSignal = signal === 'KILL' ? '-KILL' : '-TERM';
  try { execSync(`fuser ${fuserSignal} ${port}/tcp 2>/dev/null || true`, { timeout: 5000 }); } catch {}
  // Strategy 3: Direct kill as final fallback (in case fuser missed it)
  const remaining = getPidOnPort(port);
  if (remaining !== null) {
    try { execSync(`kill -${signal} ${remaining} 2>/dev/null || true`, { timeout: 3000 }); } catch {}
  }
}

/**
 * Retry-based port cleanup — verifies the port is actually free.
 * Async to avoid blocking the event loop during waits.
 */
async function ensurePortFreeAsync(port: number): Promise<boolean> {
  for (let attempt = 0; attempt < 5; attempt++) {
    if (getPidOnPort(port) === null) return true;
    killPortOccupants(port, 'TERM');
    await sleep(800);
  }
  // Hard kill any remaining process tree
  if (getPidOnPort(port) !== null) {
    killPortOccupants(port, 'KILL');
    await sleep(500);
  }
  return getPidOnPort(port) === null;
}




/**
 * Preview start result.
 */
export interface PreviewStartResult {
  success: boolean;
  error?: string;
  ready?: boolean;
  alreadyRunning?: boolean;
  failReason?: 'port_stuck' | 'no_config' | null;
}

/**
 * Start preview for an app using generic resolvePreviewConfig().
 * @param appDirectory - The app's directory name (unique identifier)
 * @param requestId - Optional request ID for ordering (skip work if superseded)
 */
export async function startPreview(appDirectory: string, requestId?: number): Promise<PreviewStartResult> {
  // System backpressure — refuse new previews under heavy load
  const memRatio = 1 - (os.freemem() / os.totalmem());
  if (memRatio > PREVIEW_LIMITS.RAM_THRESHOLD) {
    metrics.backpressureRejections++;
    return { success: false, error: `System RAM at ${Math.round(memRatio * 100)}% — stop other previews first`, failReason: null };
  }
  const load = os.loadavg()[0] ?? 0;
  if (load > os.cpus().length * PREVIEW_LIMITS.LOAD_MULTIPLIER) {
    metrics.backpressureRejections++;
    return { success: false, error: `System load too high (${load.toFixed(1)}) — try again shortly`, failReason: null };
  }

  const appPath = getAppPath(appDirectory);

  if (!fs.existsSync(appPath)) {
    return { success: false, error: 'App path not found: ' + appPath };
  }

  // Check if superseded before cleanup
  if (requestId !== undefined && !isLatestRequest(requestId)) {
    return { success: false, error: 'Superseded by newer request' };
  }

  const projectPort = getProjectPort(appDirectory);
  const pm2Name = `preview-${appDirectory}`;

  // Resolve preview config (generic, framework-agnostic)
  const resolved = resolvePreviewConfig(appPath, projectPort);
  if (resolved.ok === false) {
    return { success: false, error: resolved.reason, failReason: 'no_config' };
  }

  const config = resolved.config;
  log('info', 'preview config resolved', { appDirectory, runtime: config.runtime, source: config.source, description: config.description });

  // LRU eviction: if at max concurrent previews, evict the least recently used
  previewLastAccess.set(appDirectory, Date.now());
  try {
    const list = execPm2('pm2 jlist');
    const procs = JSON.parse(list.output || '[]');
    const otherPreviews = procs.filter(
      (p: any) => typeof p.name === 'string' && p.name.startsWith('preview-') && p.name !== pm2Name
    );
    if (otherPreviews.length >= PREVIEW_LIMITS.MAX_CONCURRENT) {
      let lruName: string | null = null;
      let lruTime = Infinity;
      for (const p of otherPreviews) {
        const project = (p.name as string).slice('preview-'.length);
        const lastAccess = previewLastAccess.get(project) ?? 0;
        if (lastAccess < lruTime) {
          lruTime = lastAccess;
          lruName = p.name;
        }
      }
      if (lruName) {
        metrics.evictions++;
        const lruProject = lruName.slice('preview-'.length);
        const lruPort = getProjectPort(lruProject);
        log('info', 'LRU evicting preview', { evicted: lruName, port: lruPort, reason: 'max_concurrent', totalEvictions: metrics.evictions });
        execPm2(`pm2 delete ${JSON.stringify(lruName)} 2>/dev/null || true`);
        killPortOccupants(lruPort, 'TERM');
      }
    }
  } catch {}

  // Stop any existing PM2 process with this name before starting fresh.
  execPm2(`pm2 delete ${JSON.stringify(pm2Name)} 2>/dev/null || true`);
  execPm2('pm2 delete preview 2>/dev/null || true');
  await sleep(500);

  // Ensure this project's dedicated port is free
  if (!(await ensurePortFreeAsync(projectPort))) {
    return { success: false, error: `Port ${projectPort} could not be freed`, failReason: 'port_stuck' };
  }

  // Clean up stale preview metadata
  try {
    const appsDir = `${HOME}/.ellulai/apps`;
    if (fs.existsSync(appsDir)) {
      for (const f of fs.readdirSync(appsDir).filter(f => f.endsWith('.json'))) {
        try {
          const meta = JSON.parse(fs.readFileSync(`${appsDir}/${f}`, 'utf8'));
          if (meta.port >= PREVIEW_PORT_MIN && meta.port <= PREVIEW_PORT_MAX && meta.isPreview !== false) fs.unlinkSync(`${appsDir}/${f}`);
        } catch {}
      }
    }
  } catch {}

  // Check if superseded after cleanup
  if (requestId !== undefined && !isLatestRequest(requestId)) {
    return { success: false, error: 'Superseded by newer request' };
  }

  // Auto-install dependencies if needed (Node: node_modules missing/incomplete)
  if (config.runtime === 'node' && config.install && !isInstallComplete(appPath)) {
    try {
      execSync(`nohup bash -c 'cd "${appPath}" && ${config.install}' >/dev/null 2>&1 &`,
        { timeout: 3000, env: EXEC_ENV });
    } catch {}
    return { success: true, ready: false, failReason: null };
  }

  // Build env exports for the PM2 bash wrapper
  const pathEnv = `${NVM_BIN}:${process.env.PATH || '/usr/local/bin:/usr/bin:/bin'}`;
  const envExports = [
    `export PATH=${pathEnv}`,
    ...Object.entries({ ...config.env }).map(([k, v]) => `export ${k}=${v}`),
  ].join(' && ');

  // PM2 resilience flags
  const PM2_FLAGS = `--max-memory-restart ${PREVIEW_LIMITS.MAX_MEMORY_MB}M --max-restarts ${PREVIEW_LIMITS.MAX_RESTARTS} --restart-delay ${PREVIEW_LIMITS.RESTART_DELAY_MS} --exp-backoff-restart-delay 100`;

  // Try ecosystem.config.js first (user-provided PM2 config)
  let started = false;
  const ecosystemPath = path.join(appPath, 'ecosystem.config.js');
  if (fs.existsSync(ecosystemPath)) {
    const result = execPm2(
      `cd "${appPath}" && ${envExports} && pm2 start ecosystem.config.js --only preview --name ${JSON.stringify(pm2Name)} ${PM2_FLAGS}`
    );
    if (result.output.includes('launched') || result.output.includes('online')) {
      started = true;
    }
  }

  // Start via resolved command
  if (!started) {
    const result = execPm2(
      `cd "${appPath}" && pm2 start bash --name ${JSON.stringify(pm2Name)} ${PM2_FLAGS} --cwd "${appPath}" -- -c "${envExports} && ${config.command}"`
    );
    if (result.output.includes('launched') || result.output.includes('online')) {
      started = true;
    }
  }

  if (!started) {
    return { success: false, error: `Failed to start: ${config.command}`, failReason: null };
  }

  execPm2('pm2 save');
  ensureCaddyRoute(projectPort);

  return { success: true, ready: false, failReason: null };
}

/**
 * Stop preview.
 * @param appDirectory - If provided, stop only that project's preview. Otherwise stop ALL preview-* processes.
 */
export function stopPreview(appDirectory?: string): void {
  // Clean up preview deployment metadata
  try {
    const appsDir = `${HOME}/.ellulai/apps`;
    if (fs.existsSync(appsDir)) {
      for (const f of fs.readdirSync(appsDir).filter(f => f.endsWith('.json'))) {
        try {
          const meta = JSON.parse(fs.readFileSync(`${appsDir}/${f}`, 'utf8'));
          if (meta.port >= PREVIEW_PORT_MIN && meta.port <= PREVIEW_PORT_MAX && meta.isPreview !== false) fs.unlinkSync(`${appsDir}/${f}`);
        } catch {}
      }
    }
  } catch {}

  if (appDirectory) {
    // Stop specific project's preview
    const pm2Name = `preview-${appDirectory}`;
    execPm2(`pm2 delete ${JSON.stringify(pm2Name)} 2>/dev/null || true`);
    // Also kill legacy "preview" name from old ecosystem.config.js
    execPm2('pm2 delete preview 2>/dev/null || true');
    // Kill entire process tree on the port — prevents orphaned children
    const port = getProjectPort(appDirectory);
    killPortOccupants(port, 'TERM');
    // Verify cleanup — hard kill if anything survived
    if (getPidOnPort(port) !== null) {
      killPortOccupants(port, 'KILL');
    }
  } else {
    // Stop ALL preview-* processes (including legacy "preview" name)
    execPm2('pm2 delete preview 2>/dev/null || true');
    try {
      const list = execPm2('pm2 jlist');
      const procs = JSON.parse(list.output || '[]');
      for (const p of procs) {
        if (typeof p.name === 'string' && p.name.startsWith('preview-')) {
          execPm2(`pm2 delete ${JSON.stringify(p.name)} 2>/dev/null || true`);
        }
      }
    } catch {}
    // Clear active preview state so health endpoint returns idle
    try { fs.writeFileSync(PREVIEW_FILE, ''); } catch {}
  }
}

/**
 * Get current preview status.
 */
export function getPreviewStatus(): {
  app: string | null;
  running: boolean;
  port: number;
} {
  let current: string | null = null;
  if (fs.existsSync(PREVIEW_FILE)) {
    current = fs.readFileSync(PREVIEW_FILE, 'utf8').trim() || null;
  }

  const pm2Name = current ? `preview-${current}` : null;
  const pm2List = execPm2('pm2 jlist');
  let isRunning = false;
  try {
    const processes = JSON.parse(pm2List.output || '[]') as Array<{
      name: string;
      pm2_env?: { status: string };
    }>;
    isRunning = processes.some((p) =>
      (pm2Name ? p.name === pm2Name : p.name.startsWith('preview-')) && p.pm2_env?.status === 'online'
    );
  } catch {}

  const port = current ? getProjectPort(current) : PREVIEW_PORT_MIN;
  return { app: current, running: isRunning, port };
}

// ---------------------------------------------------------------------------
// Error Capture — PM2 log reading and error extraction
// ---------------------------------------------------------------------------

/** Strip ANSI escape codes from log output */
function stripAnsi(str: string): string {
  return str.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '');
}

/**
 * Read PM2 logs for a preview process.
 * Returns combined stderr+stdout, ANSI-stripped, last `lines` lines.
 */
function getPreviewLogs(pm2Name: string, lines = 30): string {
  const logDir = `${HOME}/.pm2/logs`;
  const logParts: string[] = [];

  for (const suffix of ['-error.log', '-out.log']) {
    const logPath = `${logDir}/${pm2Name}${suffix}`;
    try {
      if (fs.existsSync(logPath)) {
        const content = fs.readFileSync(logPath, 'utf8');
        logParts.push(content);
      }
    } catch {}
  }

  if (logParts.length === 0) return '';

  const combined = logParts.join('\n');
  const allLines = combined.split('\n');
  const tail = allLines.slice(-lines).join('\n');
  // Limit to ~2KB
  const trimmed = tail.length > 2048 ? tail.slice(-2048) : tail;
  return stripAnsi(trimmed);
}

/**
 * Extract a human-readable error summary from log output.
 * Matches common error patterns across runtimes.
 */
function extractErrorSummary(logs: string): string | null {
  if (!logs) return null;

  const patterns = [
    // Node.js
    /SyntaxError:\s*(.+)/,
    /Module not found:\s*(.+)/,
    /Cannot find module\s*['"]([^'"]+)['"]/,
    /Error:\s*listen EADDRINUSE/,
    /TypeError:\s*(.+)/,
    /ReferenceError:\s*(.+)/,
    // Python
    /ModuleNotFoundError:\s*(.+)/,
    /ImportError:\s*(.+)/,
    /SyntaxError:\s*(.+)/,
    // Rust
    /error\[E\d+\]:\s*(.+)/,
    // Go
    /cannot find package\s*(.+)/,
    // Generic
    /(?:FATAL|FAIL):\s*(.+)/,
    /Error:\s*(.+)/,
  ];

  for (const line of logs.split('\n').reverse()) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    for (const pattern of patterns) {
      const match = trimmed.match(pattern);
      if (match) return match[0].slice(0, 200);
    }
  }

  return null;
}

/**
 * Check if PM2 process has crashed (errored/stopped status).
 */
function isPm2ProcessCrashed(pm2Name: string): boolean {
  try {
    const list = execPm2('pm2 jlist');
    const procs = JSON.parse(list.output || '[]');
    const proc = procs.find((p: any) => p.name === pm2Name);
    if (!proc) return false;
    const status = proc.pm2_env?.status;
    return status === 'errored' || status === 'stopped';
  } catch { return false; }
}

/**
 * Trigger self-healing: POST build error to agent-bridge for automated repair.
 */
function checkAndHeal(projectName: string, errorSummary: string, logTail: string): void {
  const errorHash = crypto.createHash('sha256').update(errorSummary).digest('hex').slice(0, 16);
  const existing = healStates.get(projectName);

  // Guards
  if (existing) {
    if (existing.attempts >= MAX_HEAL_ATTEMPTS) return;
    if (Date.now() - existing.lastAttemptAt < HEAL_DEBOUNCE_MS) return;
    if (existing.errorHash === errorHash && existing.attempts > 0) return;
  }

  // Fire-and-forget POST to agent-bridge
  const body = JSON.stringify({ projectName, error: errorSummary, logTail });
  const req = require('http').request({
    hostname: '127.0.0.1',
    port: 7700,
    path: '/api/internal/preview-error',
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    timeout: 5000,
  }, () => {});
  req.on('error', () => {});
  req.write(body);
  req.end();

  const attempts = (existing?.attempts ?? 0) + 1;
  metrics.healAttempted++;
  if (attempts >= MAX_HEAL_ATTEMPTS) metrics.healExhausted++;

  healStates.set(projectName, {
    errorHash,
    attempts,
    lastAttemptAt: Date.now(),
    resolved: false,
  });

  log('info', 'self-heal triggered', { projectName, errorHash, attempt: attempts });
}

export interface PreviewHealthResult {
  app: string | null;
  phase: 'idle' | 'installing' | 'starting' | 'ready' | 'error' | 'crashed';
  active: boolean;
  port: number;
  error?: string;
  logTail?: string;
  healAttempts?: number;
  healStatus?: 'healing' | 'exhausted' | null;
}

/**
 * Get preview health with actual port-level verification.
 * Returns granular phase info, error details, and self-healing status.
 * Uses curl -m 1 (1s max) so the status endpoint stays fast.
 */
export function getPreviewHealth(): PreviewHealthResult {
  // 1. Read current app
  let current: string | null = null;
  if (fs.existsSync(PREVIEW_FILE)) {
    current = fs.readFileSync(PREVIEW_FILE, 'utf8').trim() || null;
  }

  if (!current) {
    return { app: null, phase: 'idle', active: false, port: PREVIEW_PORT_MIN };
  }

  const projectPort = getProjectPort(current);
  const pm2Name = `preview-${current}`;

  // 2. Check if deps are installed
  const appPath = getAppPath(current);
  const packageJsonPath = path.join(appPath, 'package.json');
  if (fs.existsSync(packageJsonPath) && !isInstallComplete(appPath)) {
    return { app: current, phase: 'installing', active: false, port: projectPort };
  }

  // 3. Check if PM2 process has crashed
  if (isPm2ProcessCrashed(pm2Name)) {
    const logTail = getPreviewLogs(pm2Name);
    const error = extractErrorSummary(logTail) || 'Process crashed';

    // Trigger self-healing
    checkAndHeal(current, error, logTail);

    const heal = healStates.get(current);
    return {
      app: current,
      phase: 'crashed',
      active: false,
      port: projectPort,
      error,
      logTail,
      healAttempts: heal?.attempts ?? 0,
      healStatus: heal ? (heal.attempts >= MAX_HEAL_ATTEMPTS ? 'exhausted' : 'healing') : null,
    };
  }

  // 4. Check if something is listening on the project's preview port
  const pid = getPidOnPort(projectPort);
  if (pid === null) {
    return { app: current, phase: 'starting', active: false, port: projectPort };
  }

  // 5. Check if it's actually serving responses (1s timeout)
  try {
    const headers = execSync(
      `curl -sI -m 1 http://localhost:${projectPort}/ 2>/dev/null`,
      { encoding: 'utf8', timeout: 3000, env: EXEC_ENV }
    );
    const statusMatch = headers.match(/^HTTP\/[\d.]+ (\d{3})/i);
    if (statusMatch) {
      const httpStatus = parseInt(statusMatch[1]!, 10);
      if (httpStatus >= 200 && httpStatus < 400) {
        ensureCaddyRoute(projectPort);
        // Reset heal state on successful recovery
        const heal = healStates.get(current);
        if (heal && !heal.resolved) {
          heal.resolved = true;
          metrics.healSucceeded++;
          log('info', 'self-heal succeeded', { projectName: current, attempts: heal.attempts });
        }
        return { app: current, phase: 'ready', active: true, port: projectPort };
      }
      // 4xx/5xx — app is broken or routes are missing
      const logTail = getPreviewLogs(pm2Name);
      const error = extractErrorSummary(logTail) || `HTTP ${httpStatus}`;

      // Trigger self-healing
      checkAndHeal(current, error, logTail);

      const heal = healStates.get(current);
      return {
        app: current,
        phase: 'error',
        active: false,
        port: projectPort,
        error,
        logTail,
        healAttempts: heal?.attempts ?? 0,
        healStatus: heal ? (heal.attempts >= MAX_HEAL_ATTEMPTS ? 'exhausted' : 'healing') : null,
      };
    }
  } catch {}

  return { app: current, phase: 'starting', active: false, port: projectPort };
}

/**
 * Set current preview app and optionally start it.
 * Uses request ordering to handle rapid app switching - only the latest request wins.
 */
export async function setPreviewApp(
  appDirectory: string | null,
  script?: string
): Promise<{
  success: boolean;
  app: string | null;
  preview?: PreviewStartResult;
  superseded?: boolean;
}> {
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
    // Null means "stop all previews" — clean up running processes
    stopPreview();
    return { success: true, app: null };
  }

  // Write Caddy route IMMEDIATELY when the active project changes.
  // This is decoupled from startPreview() because there are multiple code paths
  // that start the server (PM2 via startPreview, bash ellulai-preview daemon,
  // manual start) — all of them need Caddy to proxy to the correct port.
  // Caddy returns 502 while the server is starting, which is correct behavior.
  const projectPort = getProjectPort(appDirectory);
  writeCaddyDevRoute(projectPort);

  // Check again before starting the expensive preview operation
  if (!isLatestRequest(requestId)) {
    console.log(`[preview] Request #${requestId} superseded before preview start, skipping`);
    return { success: true, app: appDirectory, superseded: true };
  }

  // Start the preview - Caddy route is already written above
  const result = await startPreview(appDirectory, requestId);

  // Final check - if superseded during startup, the result might be stale
  if (!isLatestRequest(requestId)) {
    console.log(`[preview] Request #${requestId} superseded after preview start, result may be stale`);
    return { success: true, app: appDirectory, preview: result, superseded: true };
  }

  console.log(`[preview] Request #${requestId} completed successfully for "${appDirectory}"`);
  return { success: true, app: appDirectory, preview: result };
}

// ---------------------------------------------------------------------------
// Garbage Collection
// ---------------------------------------------------------------------------

/**
 * Reconcile port registry: remove entries where the project directory
 * doesn't exist AND no PM2 process is running AND port is free.
 */
export function reconcilePortRegistry(): void {
  try {
    const registry = getPortRegistry();
    let changed = false;
    const runningNames = new Set<string>();
    try {
      const list = execPm2('pm2 jlist');
      const procs = JSON.parse(list.output || '[]');
      for (const p of procs) {
        if (typeof p.name === 'string') runningNames.add(p.name);
      }
    } catch {}

    for (const [project, port] of Object.entries(registry)) {
      const projectDir = path.join(ROOT_DIR, project);
      const pm2Name = `preview-${project}`;
      if (!fs.existsSync(projectDir) && !runningNames.has(pm2Name) && getPidOnPort(port) === null) {
        delete registry[project];
        changed = true;
        metrics.gcPortsReclaimed++;
        log('info', 'GC: removed orphaned port registry entry', { project, port });
      }
    }
    if (changed) savePortRegistry(registry);
  } catch (e) {
    log('error', 'reconcilePortRegistry failed', { error: (e as Error).message });
  }
}

/**
 * Stop PM2 preview-* processes whose project directory no longer exists.
 */
export function cleanupOrphanedPreviews(): void {
  try {
    const list = execPm2('pm2 jlist');
    const procs = JSON.parse(list.output || '[]');
    for (const p of procs) {
      if (typeof p.name === 'string' && p.name.startsWith('preview-')) {
        const project = p.name.slice('preview-'.length);
        const projectDir = path.join(ROOT_DIR, project);
        if (!fs.existsSync(projectDir)) {
          metrics.gcOrphansKilled++;
          log('info', 'GC: stopping orphaned preview process', { name: p.name, project });
          execPm2(`pm2 delete ${JSON.stringify(p.name)} 2>/dev/null || true`);
        }
      }
    }
  } catch (e) {
    log('error', 'cleanupOrphanedPreviews failed', { error: (e as Error).message });
  }
}
