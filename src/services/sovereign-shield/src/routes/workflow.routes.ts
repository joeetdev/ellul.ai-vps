/**
 * Workflow Routes
 *
 * Server-side handlers for workflow commands (writing Caddy configs,
 * managing PM2 processes, reloading services). Runs as $SVC_USER.
 *
 * The client (e.g. ellulai-expose) is a dumb thin client that
 * POSTs to these endpoints. All security logic runs server-side.
 *
 * Endpoints:
 * - POST /api/workflow/expose   - Expose an app with tier-aware Caddy config
 * - POST /api/workflow/hydrate  - Restore workspace from snapshot (upgrade/wake)
 */

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import type { Hono } from 'hono';
import { RESERVED_PORTS } from '../../../shared/constants';
import { findAppRoot, detectFramework, getStartCommand, getInstallCommand, resolveModule } from '../../../shared/framework';

const BILLING_TIER_FILE = '/etc/ellulai/billing-tier';
const DOMAIN_FILE = '/etc/ellulai/domain';
const CADDYFILE = '/etc/caddy/Caddyfile';
const SITES_DIR = '/etc/caddy/sites-enabled';
const APP_ROUTES_DIR = '/etc/caddy/app-routes.d';
const CF_CA_FILE = '/etc/caddy/cf-origin-pull-ca.pem';

function getBillingTier(): string {
  try {
    return fs.readFileSync(BILLING_TIER_FILE, 'utf8').trim();
  } catch {
    return 'free'; // Default to free (fail restrictive)
  }
}

function getUserInfo(): { user: string; home: string; appsDir: string } {
  const tier = getBillingTier();
  const user = tier === 'free' ? 'coder' : 'dev';
  const home = `/home/${user}`;
  return { user, home, appsDir: `${home}/.ellulai/apps` };
}

function getServerDomain(): string {
  try {
    return fs.readFileSync(DOMAIN_FILE, 'utf8').trim();
  } catch {
    return '';
  }
}

function isProxiedMode(): boolean {
  try {
    const caddyfile = fs.readFileSync(CADDYFILE, 'utf8');
    return caddyfile.includes('auto_https off');
  } catch {
    return false;
  }
}

function getCfCaBase64(): string {
  try {
    const pem = fs.readFileSync(CF_CA_FILE, 'utf8');
    return pem
      .split('\n')
      .filter(line => !line.startsWith('-----'))
      .join('');
  } catch {
    return '';
  }
}

/**
 * Check if a port has a healthy HTTP listener.
 * Returns true for any real HTTP response (100-599), false for connection refused/timeout.
 */
function isHttpAlive(port: number): boolean {
  try {
    const code = execSync(
      `curl -s -o /dev/null -w '%{http_code}' -m 3 http://localhost:${port}`,
      { stdio: 'pipe', timeout: 5000, encoding: 'utf8' },
    ).trim();
    return /^[1-5]\d{2}$/.test(code);
  } catch {
    return false;
  }
}

/**
 * Check if a port has a HEALTHY HTTP listener (2xx/3xx only).
 * Rejects 4xx/5xx — a process returning error pages is not considered healthy.
 * Returns { alive, healthy, httpStatus } for richer diagnostics.
 */
function isHttpHealthy(port: number): { alive: boolean; healthy: boolean; httpStatus: number } {
  try {
    const code = execSync(
      `curl -s -o /dev/null -w '%{http_code}' -m 3 http://localhost:${port}`,
      { stdio: 'pipe', timeout: 5000, encoding: 'utf8' },
    ).trim();
    const httpStatus = parseInt(code, 10);
    if (isNaN(httpStatus)) return { alive: false, healthy: false, httpStatus: 0 };
    return {
      alive: httpStatus >= 100 && httpStatus < 600,
      healthy: httpStatus >= 200 && httpStatus < 400,
      httpStatus,
    };
  } catch {
    return { alive: false, healthy: false, httpStatus: 0 };
  }
}

/**
 * Check if a port is occupied by a listening TCP socket.
 */
function isPortOccupied(p: number): boolean {
  try {
    const out = execSync(`ss -tlnH sport = :${p}`, {
      stdio: 'pipe',
      timeout: 3000,
      encoding: 'utf8',
    });
    return out.trim().length > 0;
  } catch {
    return false;
  }
}

/**
 * Start a pm2 process with framework-agnostic detection.
 * Uses the shared framework registry to detect the stack and build the start command.
 * Handles Node.js, Ruby, Python, Go, Rust, Elixir, PHP, Dart, static sites, and more.
 */
function startPm2Process(procName: string, port: number, projectPath: string): { started: boolean } {
  const appRoot = findAppRoot(projectPath);
  const fw = detectFramework(appRoot);

  if (!fw) {
    // No framework detected AND no build output with index.html — fail with diagnostic
    console.error(`[shield] No recognized framework in ${appRoot} — cannot start process`);
    return { started: false };
  }

  // Resolve FastAPI $MODULE with actual files
  let { command, env } = getStartCommand(fw, port, 'production');
  if (fw.id === 'fastapi') {
    const mod = resolveModule(appRoot);
    command = command.replace(/\bmain:app\b/, `${mod}:app`);
  }

  // Build env export string for bash
  const envExports = Object.entries(env)
    .map(([k, v]) => `export ${k}=${JSON.stringify(v)}`)
    .join(' && ');

  const startCmd = `pm2 start bash --name ${JSON.stringify(procName)} --cwd ${JSON.stringify(appRoot)} -- -c "${envExports} && ${command}"`;

  try {
    console.log(`[shield] Starting "${procName}" on port ${port} (${fw.id}: ${command})`);
    execSync(`bash -lc '${startCmd}'`, { stdio: 'pipe', timeout: 30000 });
    try { execSync(`bash -lc 'pm2 save --force 2>/dev/null'`, { stdio: 'pipe', timeout: 5000 }); } catch {}
    return { started: true };
  } catch {
    return { started: false };
  }
}

const sleep = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));

/**
 * Poll a port for a healthy HTTP response (2xx/3xx) with timeout.
 * Async to avoid blocking the event loop — Shield can still serve other requests.
 * Returns { healthy, httpStatus } for rich diagnostics on failure.
 */
async function waitForHealthy(
  port: number,
  timeoutMs: number,
  intervalMs: number,
): Promise<{ healthy: boolean; httpStatus: number }> {
  const deadline = Date.now() + timeoutMs;
  let lastStatus = 0;

  while (Date.now() < deadline) {
    const check = isHttpHealthy(port);
    lastStatus = check.httpStatus;

    if (check.healthy) return { healthy: true, httpStatus: lastStatus };

    // Process alive but returning server errors — won't self-fix, bail early
    if (check.alive && check.httpStatus >= 500) {
      return { healthy: false, httpStatus: lastStatus };
    }

    // Check if PM2 process crashed — no point polling a dead process
    try {
      const raw = execSync(`bash -lc 'pm2 jlist 2>/dev/null'`, {
        stdio: 'pipe', timeout: 5000, encoding: 'utf8',
      });
      const list = JSON.parse(raw);
      // Check for any process on this port that has crashed
      const crashed = list.find((p: any) =>
        (p.pm2_env?.status === 'errored' || p.pm2_env?.status === 'stopped') &&
        String(p.pm2_env?.PORT || p.pm2_env?.env?.PORT) === String(port)
      );
      if (crashed) {
        return { healthy: false, httpStatus: 0 };
      }
    } catch {}

    await sleep(intervalMs);
  }

  return { healthy: false, httpStatus: lastStatus };
}

/**
 * Ensure the app process is running on the correct port via pm2.
 * Handles port conflict resolution, process lifecycle, and health checks.
 * Used for first-deploy path; blue-green redeploys use startPm2Process directly.
 */
async function ensureAppProcess(
  name: string,
  requestedPort: number,
  projectPath: string,
  appsDir: string,
): Promise<{ port: number }> {
  // Fast path: if the requested port already has a healthy listener owned by THIS project,
  // skip PM2 entirely. Prevents the destructive delete-and-restart cycle when
  // preview hands off a running process.
  try {
    if (!isHttpAlive(requestedPort)) throw new Error('not alive');
    const pid = execSync(
      `ss -tlnpH sport = :${requestedPort} 2>/dev/null | grep -oP 'pid=\\K\\d+' | head -1`,
      { stdio: 'pipe', timeout: 3000, encoding: 'utf8' },
    ).trim();
    if (pid && fs.existsSync(`/proc/${pid}/cwd`)) {
      const cwd = fs.readlinkSync(`/proc/${pid}/cwd`);
      if (cwd === projectPath || cwd.startsWith(projectPath + '/')) {
        console.log(`[shield] Fast-path: reusing healthy process on port ${requestedPort} (pid ${pid})`);
        return { port: requestedPort };
      }
    }
  } catch {}

  // Clean up any existing PM2 process for this app
  try {
    execSync(`bash -lc 'pm2 delete ${JSON.stringify(name)} 2>/dev/null'`, {
      stdio: 'pipe', timeout: 5000,
    });
  } catch {}

  // Resolve port — guarantee no conflict
  let port = requestedPort;
  if (isPortOccupied(port)) {
    let occupiedBySame = false;
    try {
      const files = fs.readdirSync(appsDir).filter((f) => f.endsWith('.json'));
      for (const file of files) {
        try {
          const meta = JSON.parse(fs.readFileSync(`${appsDir}/${file}`, 'utf8'));
          if (meta.port === port && meta.projectPath === projectPath) {
            occupiedBySame = true;
            break;
          }
        } catch {}
      }
    } catch {}

    if (!occupiedBySame) {
      port = findFreePort(port + 1);
    }
  }

  // Start via shared helper
  const result = startPm2Process(name, port, projectPath);
  if (!result.started) {
    throw new Error(`Failed to start PM2 process "${name}" on port ${port}`);
  }

  // Health check — wait up to 8s with rich diagnostics
  const healthResult = await waitForHealthy(port, 8000, 500);
  if (!healthResult.healthy) {
    let diagnosis = '';
    if (healthResult.httpStatus > 0) {
      diagnosis = ` — HTTP ${healthResult.httpStatus}`;
    }

    // Check PM2 process status for crash diagnostics
    try {
      const raw = execSync(`bash -lc 'pm2 jlist 2>/dev/null'`, {
        stdio: 'pipe', timeout: 5000, encoding: 'utf8',
      });
      const list = JSON.parse(raw);
      const proc = list.find((p: any) => p.name === name);
      if (proc?.pm2_env?.status === 'errored') {
        diagnosis += ' — process crashed';
        try {
          const logs = execSync(
            `bash -lc 'pm2 logs ${JSON.stringify(name)} --lines 5 --nostream --err 2>/dev/null'`,
            { stdio: 'pipe', timeout: 5000, encoding: 'utf8' }
          ).trim();
          const lastLine = logs.split('\n').filter(l => l.trim()).pop() || '';
          if (lastLine) diagnosis += `: ${lastLine.replace(/^\d+\|[^|]+\|\s*/, '')}`;
        } catch {}
      } else if (proc?.pm2_env?.status) {
        diagnosis += ` — PM2 status: ${proc.pm2_env.status}`;
      }
    } catch {}

    try {
      execSync(`bash -lc 'pm2 delete ${JSON.stringify(name)} 2>/dev/null'`, {
        stdio: 'pipe', timeout: 5000,
      });
    } catch {}

    throw new Error(
      `App failed to start on port ${port} (health check timed out after 8s${diagnosis})`
    );
  }

  return { port };
}

/**
 * Find the next free port starting from a candidate.
 */
function findFreePort(startPort: number): number {
  let candidate = startPort;
  while (candidate <= 65535) {
    if (!RESERVED_PORTS.has(candidate) && !isPortOccupied(candidate)) {
      return candidate;
    }
    candidate++;
  }
  throw new Error('No free ports available');
}

// ---------------------------------------------------------------------------
// Deployment Metrics — lightweight counters for observability
// ---------------------------------------------------------------------------

const deployMetrics = {
  deploys: 0,
  deploysSucceeded: 0,
  deploysFailed: 0,
  rollbacks: 0,
  rollbacksSucceeded: 0,
  rollbacksFailed: 0,
  canaryPromotions: 0,
  canaryPromotionsFailed: 0,
  caddyReloadFailures: 0,
  npmInstallFailures: 0,
  snapshotFailures: 0,
  lockContentions: 0,
  startedAt: Date.now(),
};

/**
 * Register workflow routes on Hono app
 */
export function registerWorkflowRoutes(app: Hono): void {

  // GET /api/workflow/metrics — deployment observability
  app.get('/api/workflow/metrics', (c) => {
    return c.json({
      ...deployMetrics,
      uptimeMs: Date.now() - deployMetrics.startedAt,
    });
  });
  /**
   * POST /api/workflow/expose
   *
   * Privileged expose handler. Accepts app config from the thin client,
   * enforces billing tier limits, generates Caddy config, and reloads.
   */
  app.post('/api/workflow/expose', async (c) => {
    deployMetrics.deploys++;
    let body: {
      name?: string;
      port?: number;
      customDomain?: string;
      projectPath?: string;
      stack?: string;
    };

    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: 'Invalid JSON body' }, 400);
    }

    const { customDomain, projectPath, stack } = body;
    let name = body.name;
    let port = body.port || 3001;

    // ── Validate inputs ──────────────────────────────────────────────
    if (!name) {
      return c.json({ error: 'name is required' }, 400);
    }

    // Sanitize name
    name = name.toLowerCase().replace(/[^a-z0-9-]/g, '');
    if (!name) {
      return c.json({ error: 'Invalid app name (alphanumeric and hyphens only)' }, 400);
    }

    if (!Number.isInteger(port) || port < 1024 || port > 65535) {
      return c.json({ error: `Invalid port: ${port} (must be 1024-65535)` }, 400);
    }

    if (RESERVED_PORTS.has(port)) {
      return c.json({ error: `Port ${port} is reserved for ellul.ai internal services` }, 400);
    }

    // ── Read billing tier + resolve user paths ──────────────────────
    const billingTier = getBillingTier();
    const isFree = billingTier === 'free';
    const { appsDir } = getUserInfo();

    // SECURITY: Validate customDomain to prevent command injection and Caddy config injection
    if (customDomain && !/^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(customDomain)) {
      return c.json({ error: 'Invalid custom domain format' }, 400);
    }

    // ── Free tier enforcements ───────────────────────────────────────
    if (isFree && customDomain) {
      return c.json({
        error: 'Custom domains require Sovereign tier',
        upgrade: true,
      }, 403);
    }

    // ── Ensure directories exist ─────────────────────────────────────
    try {
      fs.mkdirSync(SITES_DIR, { recursive: true });
      fs.mkdirSync(APP_ROUTES_DIR, { recursive: true });
      fs.mkdirSync(appsDir, { recursive: true });
    } catch {}

    // ── Load existing apps (for duplicate detection) ─────────────────
    let currentApps: string[] = [];
    try {
      currentApps = fs.readdirSync(appsDir).filter(f => f.endsWith('.json'));
    } catch {}

    // ── Duplicate detection (same projectPath, different name) ───────
    if (projectPath) {
      for (const file of currentApps) {
        try {
          const meta = JSON.parse(fs.readFileSync(`${appsDir}/${file}`, 'utf8'));
          if (meta.projectPath === projectPath && meta.name !== name) {
            // Clean up old deployment
            const oldName = meta.name;
            try { fs.unlinkSync(`${SITES_DIR}/${oldName}.caddy`); } catch {}
            try { fs.unlinkSync(`${APP_ROUTES_DIR}/${oldName}.caddy`); } catch {}
            try { fs.unlinkSync(`${appsDir}/${oldName}.json`); } catch {}
            name = oldName; // Reuse old name
            break;
          }
        } catch {}
      }
    }

    // ── Create versioned deployment snapshot ─────────────────────
    // Every deploy takes a fresh snapshot into a timestamped version dir.
    // A 'current' symlink points to the live version, enabling instant rollback.
    let servingPath = projectPath;
    const { home } = getUserInfo();
    // isFirstDeploy is computed INSIDE the lock to prevent race conditions.
    // Two concurrent deploys could both see isFirstDeploy=false, but only one
    // gets the lock — the loser must re-evaluate after acquiring it.
    let isFirstDeploy = true;

    if (projectPath) {
      const appDeployDir = `${home}/.ellulai/deployments/${name}`;
      const currentLink = `${appDeployDir}/current`;
      const versionDir = `${appDeployDir}/${Date.now()}`;

      try {
        fs.mkdirSync(versionDir, { recursive: true });

        // Build snapshot WITHOUT killing old process (zero-downtime for redeploys)
        execSync(
          `rsync -a --exclude='node_modules' --exclude='.git' ${JSON.stringify(projectPath + '/')} ${JSON.stringify(versionDir + '/')}`,
          { stdio: 'pipe', timeout: 30000 }
        );
        // Install production deps in snapshot using framework-aware install command.
        // 120s timeout covers slow VPSes. --prefer-offline for npm avoids hung registry requests.
        {
          const snapAppRoot = findAppRoot(versionDir);
          const snapFw = detectFramework(snapAppRoot);
          const installCmd = snapFw ? getInstallCommand(snapFw, 'production') : null;
          if (installCmd) {
            try {
              // For npm: add --prefer-offline to avoid hung registry requests
              const fullCmd = snapFw?.runtime === 'node'
                ? `${installCmd} --prefer-offline`
                : installCmd;
              execSync(`bash -lc 'cd ${JSON.stringify(snapAppRoot)} && ${fullCmd} 2>&1'`, {
                stdio: 'pipe', timeout: 120000,
              });
            } catch (installErr) {
              const err = installErr as Error & { killed?: boolean; signal?: string };
              const reason = err.killed ? `killed by timeout (${err.signal || 'SIGTERM'}) after 120s` : err.message;
              console.error(`[shield] ${installCmd} failed in snapshot: ${reason}`);
              deployMetrics.npmInstallFailures++;
            }
          }

          // Strip hardcoded PORT=XXXX from start script (Node.js only)
          if (snapFw?.runtime === 'node') {
            try {
              const pkgPath = `${snapAppRoot}/package.json`;
              const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
              if (pkg.scripts?.start && /\bPORT=\d+/.test(pkg.scripts.start)) {
                pkg.scripts.start = pkg.scripts.start.replace(/\bPORT=\d+\s*/g, '').trim();
                fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));
              }
            } catch {}
          }
        }

        // Atomic symlink swap: create tmp link then rename over current
        // rename() is atomic on POSIX — guarantees no window where 'current' is missing
        const tmpLink = `${appDeployDir}/.current-tmp-${Date.now()}`;
        fs.symlinkSync(versionDir, tmpLink);
        try {
          fs.renameSync(tmpLink, currentLink);
        } catch (renameErr) {
          try { fs.unlinkSync(tmpLink); } catch {}
          // Symlink swap failed — rollback state will be inconsistent.
          // Serve from the new version dir directly (it's already built).
          console.error(`[shield] Symlink swap failed: ${(renameErr as Error).message} — rollback unavailable for this deploy`);
        }

        // Purge old versions — keep last 3
        try {
          const entries = fs.readdirSync(appDeployDir)
            .filter(e => /^\d+$/.test(e))
            .sort((a, b) => parseInt(a) - parseInt(b));
          const toRemove = entries.slice(0, Math.max(0, entries.length - 3));
          for (const old of toRemove) {
            fs.rmSync(`${appDeployDir}/${old}`, { recursive: true, force: true });
          }
        } catch {}

        servingPath = versionDir;
        console.log(`[shield] Created deployment snapshot v${path.basename(versionDir)}`);
      } catch (e) {
        // Cleanup failed version dir
        try { fs.rmSync(versionDir, { recursive: true, force: true }); } catch {}
        console.error(`[shield] Snapshot failed, serving from source: ${(e as Error).message}`);
        deployMetrics.snapshotFailures++;
      }
    }

    // ── Blue-green deploy (zero-downtime for redeploys) ──────────
    const lockFile = `/tmp/ellulai-deploy-${name}.lock`;
    // Atomic concurrency guard: O_EXCL fails if file exists (no TOCTOU race)
    try {
      const fd = fs.openSync(lockFile, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o644);
      fs.writeSync(fd, String(process.pid));
      fs.closeSync(fd);
    } catch {
      // Lock exists — check if stale (>2 min = dead deployer)
      try {
        const lockAge = Date.now() - (fs.statSync(lockFile).mtimeMs || 0);
        if (lockAge < 120000) {
          deployMetrics.lockContentions++;
          deployMetrics.deploysFailed++;
          return c.json({ error: 'Deploy already in progress' }, 409);
        }
        // Stale lock — atomic reclaim: unlink + re-create with O_EXCL.
        // If another process also sees the stale lock, only one reclaim succeeds.
        fs.unlinkSync(lockFile);
        const fd = fs.openSync(lockFile, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o644);
        fs.writeSync(fd, String(process.pid));
        fs.closeSync(fd);
      } catch {
        deployMetrics.lockContentions++;
        deployMetrics.deploysFailed++;
        return c.json({ error: 'Deploy lock contention' }, 409);
      }
    }

    // Track canary state for cleanup on any error path
    let canaryActive = false;
    const canaryProcName = `${name}__canary`;
    const cleanupCanary = () => {
      if (!canaryActive) return;
      try {
        execSync(`bash -lc 'pm2 delete ${JSON.stringify(canaryProcName)} 2>/dev/null'`, {
          stdio: 'pipe', timeout: 5000,
        });
      } catch {}
      canaryActive = false;
    };
    const releaseLock = () => {
      try { fs.unlinkSync(lockFile); } catch {}
    };

    try {
      // Evaluate isFirstDeploy INSIDE the lock to prevent race conditions
      isFirstDeploy = !isHttpAlive(port);

      // Clean up stale canary from a crashed prior deploy (not the live process).
      // A canary left from a failed deploy won't be serving on the live port.
      try {
        execSync(`bash -lc 'pm2 delete ${JSON.stringify(canaryProcName)} 2>/dev/null'`, {
          stdio: 'pipe', timeout: 5000,
        });
      } catch {}

      if (!isFirstDeploy && servingPath && servingPath !== projectPath) {
        // ── Blue-green: old process stays alive, start canary alongside ──
        const canaryPort = findFreePort(port + 1);

        // Start canary process
        const canaryResult = startPm2Process(canaryProcName, canaryPort, servingPath);
        if (!canaryResult.started) throw new Error('Canary process failed to start');
        canaryActive = true;

        // Health check canary (500ms polls, 15s timeout)
        const canaryCheck = await waitForHealthy(canaryPort, 15000, 500);

        if (canaryCheck.healthy) {
          // Canary is healthy — swap traffic
          port = canaryPort;
          // Old process will be cleaned up after Caddy config is written and reloaded (below)
          // We defer the pm2 delete of the old process until after Caddy reload
        } else {
          // Canary failed — kill it, keep old process running
          cleanupCanary();
          releaseLock();
          deployMetrics.deploysFailed++;
          const reason = canaryCheck.httpStatus > 0
            ? `HTTP ${canaryCheck.httpStatus}`
            : 'no response';
          return c.json({
            error: `New version failed health check (${reason}) — old version still running`,
          }, 500);
        }
      } else {
        // First deploy or no snapshot — simple path
        if (isFirstDeploy) {
          // Kill existing process if any (first deploy, no live traffic to protect)
          try {
            execSync(`bash -lc 'pm2 delete ${JSON.stringify(name!)} 2>/dev/null'`, {
              stdio: 'pipe', timeout: 15000,
            });
          } catch {}
          // Kill orphan on previous port
          try {
            const prevMeta = JSON.parse(fs.readFileSync(`${appsDir}/${name}.json`, 'utf8'));
            if (prevMeta.port) {
              execSync(`fuser -k ${prevMeta.port}/tcp 2>/dev/null || true`, {
                stdio: 'pipe', timeout: 3000,
              });
            }
          } catch {}
        }

        if (servingPath) {
          try {
            const result = await ensureAppProcess(name!, port, servingPath, appsDir);
            port = result.port;
          } catch (e) {
            releaseLock();
            return c.json({ error: (e as Error).message }, 500);
          }
        }
      }
    } catch (e) {
      cleanupCanary();
      releaseLock();
      deployMetrics.deploysFailed++;
      return c.json({ error: (e as Error).message }, 500);
    }

    // ── Build domain ─────────────────────────────────────────────────
    const serverDomain = getServerDomain();
    const shortId = (serverDomain.match(/^([a-f0-9]{8})-/) || [])[1] || serverDomain.split('.')[0];
    const appDomain = customDomain || `${shortId}-${name}.ellul.app`;
    const isCustom = !!customDomain;

    // ── Generate Caddy config ────────────────────────────────────────
    // Proxied mode (gateway/cloudflare): write handler-only route inside the
    // main .app site block via app-routes.d/ — TLS is shared with the main block.
    // Direct mode / custom domain: write standalone site block in sites-enabled/.
    const proxied = !isCustom && isProxiedMode();
    let caddyConfig: string;
    let configDir: string;

    if (isCustom) {
      // Custom domain — standalone site block, user handles TLS
      configDir = SITES_DIR;
      caddyConfig = `${appDomain} {
    header ?Access-Control-Allow-Origin "https://console.ellul.ai"
    header ?Access-Control-Allow-Credentials "true"
    reverse_proxy localhost:${port}
    log {
        output file /var/log/caddy/${name}.log
        format json
    }
}
`;
    } else if (proxied) {
      // Gateway/Cloudflare mode — handler-only block imported inside main .app site block.
      // CORS headers are inherited from the .app site block level — no need to add here.
      configDir = APP_ROUTES_DIR;
      const authBlock = isFree
        ? `
    forward_auth localhost:3005 {
        uri /api/auth/check
        header_up Cookie {http.request.header.Cookie}
    }`
        : '';
      caddyConfig = `@app-${name} host ${appDomain}
handle @app-${name} {${authBlock}
    reverse_proxy localhost:${port}
}
`;
    } else {
      // Direct connect — standalone site block with Let's Encrypt
      configDir = SITES_DIR;
      caddyConfig = `${appDomain} {
    header ?Access-Control-Allow-Origin "https://console.ellul.ai"
    header ?Access-Control-Allow-Credentials "true"
    reverse_proxy localhost:${port}
    log {
        output file /var/log/caddy/${name}.log
        format json
    }
}
`;
    }

    // ── Write Caddy config ───────────────────────────────────────────
    // Save old config for rollback on Caddy reload failure (blue-green safety)
    const configFile = `${configDir}/${name}.caddy`;
    let oldCaddyConfig = '';
    try { oldCaddyConfig = fs.readFileSync(configFile, 'utf8'); } catch {}
    let oldMetaContent = '';
    const metaFile = `${appsDir}/${name}.json`;
    try { oldMetaContent = fs.readFileSync(metaFile, 'utf8'); } catch {}

    try {
      fs.writeFileSync(configFile, caddyConfig);
    } catch (e) {
      cleanupCanary();
      releaseLock();
      deployMetrics.deploysFailed++;
      return c.json({ error: `Failed to write Caddy config: ${(e as Error).message}` }, 500);
    }

    // ── Write app metadata ───────────────────────────────────────────
    const isPreview = isFree;
    const directory = projectPath ? path.basename(projectPath) : name;
    const appMeta = {
      name,
      directory,
      port,
      domain: appDomain,
      url: `https://${appDomain}`,
      customDomain: isCustom ? customDomain : null,
      isCustomDomain: isCustom,
      isPreview,
      stack: stack || 'Unknown',
      summary: '',
      createdAt: new Date().toISOString(),
      projectPath: projectPath || null,
      deploymentPath: servingPath !== projectPath ? servingPath : null,
    };

    try {
      fs.writeFileSync(metaFile, JSON.stringify(appMeta, null, 2));
    } catch (e) {
      // Restore old Caddy config, clean up canary
      if (oldCaddyConfig) { try { fs.writeFileSync(configFile, oldCaddyConfig); } catch {} }
      else { try { fs.unlinkSync(configFile); } catch {} }
      cleanupCanary();
      releaseLock();
      deployMetrics.deploysFailed++;
      return c.json({ error: `Failed to write app metadata: ${(e as Error).message}` }, 500);
    }

    // ── Validate + reload Caddy ──────────────────────────────────────
    try {
      execSync('caddy validate --adapter caddyfile --config /etc/caddy/Caddyfile 2>&1', {
        stdio: 'pipe',
        timeout: 10000,
      });
    } catch (e) {
      // Validation failed — restore old config state
      if (oldCaddyConfig) { try { fs.writeFileSync(configFile, oldCaddyConfig); } catch {} }
      else { try { fs.unlinkSync(configFile); } catch {} }
      if (oldMetaContent) { try { fs.writeFileSync(metaFile, oldMetaContent); } catch {} }
      else { try { fs.unlinkSync(metaFile); } catch {} }
      cleanupCanary();
      releaseLock();
      deployMetrics.deploysFailed++;
      return c.json({ error: 'Caddy configuration invalid — rolled back' }, 500);
    }

    let caddyReloadOk = false;
    try {
      // Use caddy reload (admin API) — works without root since shield runs as $SVC_USER.
      // systemctl reload requires root and fails silently when run as non-root.
      execSync('caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1', {
        stdio: 'pipe',
        timeout: 10000,
      });
      caddyReloadOk = true;
    } catch {
      console.error('[shield] Caddy reload failed after valid config write');
      deployMetrics.caddyReloadFailures++;
    }

    // ── Blue-green cleanup: retire old process after Caddy points to canary ──
    // SAFETY: Only proceed if Caddy reload succeeded. If it failed, the old
    // config is still active in memory — killing the old process would cause downtime.
    if (canaryActive && !isFirstDeploy && servingPath && servingPath !== projectPath) {
      if (!caddyReloadOk) {
        // Caddy reload failed — abort blue-green. Restore old config so future
        // reloads don't point to the (about to be killed) canary port.
        console.error('[shield] Caddy reload failed during blue-green — aborting, keeping old process');
        if (oldCaddyConfig) { try { fs.writeFileSync(configFile, oldCaddyConfig); } catch {} }
        else { try { fs.unlinkSync(configFile); } catch {} }
        if (oldMetaContent) { try { fs.writeFileSync(metaFile, oldMetaContent); } catch {} }
        else { try { fs.unlinkSync(metaFile); } catch {} }
        cleanupCanary();
        releaseLock();
        deployMetrics.deploysFailed++;
        deployMetrics.caddyReloadFailures++;
        return c.json({ error: 'Caddy reload failed — old version still running' }, 500);
      }

      // Grace period: let Caddy drain connections to old upstream (2s)
      await sleep(2000);

      // 1. Delete old canonical process — Caddy already routes to canary port
      try {
        execSync(`bash -lc 'pm2 delete ${JSON.stringify(name!)} 2>/dev/null'`, {
          stdio: 'pipe', timeout: 5000,
        });
      } catch {}

      // 2. Promote canary to canonical name: delete canary, immediately restart
      //    under the canonical name on the SAME port. The ~100ms gap is absorbed
      //    by Caddy's automatic retries (reverse_proxy retries on connect failure).
      //    This ensures `pm2 list` shows the canonical name and the next deploy's
      //    stale canary cleanup doesn't kill the live process.
      canaryActive = false; // We're about to delete it intentionally
      try {
        execSync(`bash -lc 'pm2 delete ${JSON.stringify(canaryProcName)} 2>/dev/null'`, {
          stdio: 'pipe', timeout: 5000,
        });
      } catch {}
      const promoted = startPm2Process(name!, port, servingPath);
      if (!promoted.started) {
        console.error(`[shield] CRITICAL: Canary promotion failed for "${name}" on port ${port}`);
        deployMetrics.canaryPromotionsFailed++;
        // Caddy is pointing to this port — try one more time
        await sleep(1000);
        const retry = startPm2Process(name!, port, servingPath);
        if (!retry.started) {
          console.error(`[shield] CRITICAL: Canary promotion retry failed — port ${port} may be unserved`);
        } else {
          deployMetrics.canaryPromotions++;
        }
      } else {
        deployMetrics.canaryPromotions++;
      }

      try { execSync(`bash -lc 'pm2 save --force 2>/dev/null'`, { stdio: 'pipe', timeout: 5000 }); } catch {}
    } else if (!caddyReloadOk) {
      // First deploy with failed Caddy reload — retry once via systemctl as fallback.
      // If caddy reload (admin API) failed, it may be a Caddy process issue, not a config issue
      // (validation already passed above).
      console.error('[shield] Caddy reload failed on first deploy — retrying via systemctl');
      try {
        await sleep(1000);
        execSync('systemctl reload caddy 2>/dev/null || systemctl restart caddy 2>/dev/null', {
          stdio: 'pipe', timeout: 15000,
        });
        caddyReloadOk = true;
        console.log('[shield] Caddy reload succeeded on retry via systemctl');
      } catch {
        // Still failed — app is running but unreachable. Surface this clearly.
        console.error('[shield] CRITICAL: Caddy reload retry failed — app running but not routable');
        deployMetrics.caddyReloadFailures++;
      }
    }

    // Release deploy lock
    releaseLock();
    deployMetrics.deploysSucceeded++;

    // ── Update ellulai.json in project root ───────────────────────
    if (projectPath) {
      const psjsonPath = `${projectPath}/ellulai.json`;
      try {
        // SECURITY: Use Node.js JSON operations instead of shell jq to prevent injection
        let existing: Record<string, unknown> = {};
        if (fs.existsSync(psjsonPath)) {
          existing = JSON.parse(fs.readFileSync(psjsonPath, 'utf8'));
        }
        existing.name = name; // Sync app name with deployment name
        existing.deployedUrl = `https://${appDomain}`;
        existing.deployedDomain = appDomain;
        existing.deployedPort = port;
        fs.writeFileSync(psjsonPath, JSON.stringify(existing, null, 2));
      } catch {}
    }

    // ── Trigger immediate heartbeat so deployments show in dashboard instantly ──
    try {
      const pid = fs.readFileSync('/run/ellulai-enforcer.pid', 'utf8').trim();
      if (pid) {
        execSync(`kill -USR1 ${pid}`, { stdio: 'pipe', timeout: 2000 });
      }
    } catch {}

    // ── Kick off background AI inspection ────────────────────────────
    try {
      execSync(`/usr/local/bin/ellulai-inspect "${name}" 2>/dev/null &`, {
        stdio: 'pipe',
        timeout: 2000,
      });
    } catch {}

    // ── Build response ───────────────────────────────────────────────
    const previewNote = isPreview
      ? ' (Dev Preview — only you can access this URL)'
      : '';

    const caddyWarning = !caddyReloadOk
      ? `  ⚠ Warning: Caddy reload failed — URL may not be reachable yet. Try: caddy reload`
      : '';

    const message = [
      '',
      `App deployed!`,
      '',
      `  Live at: https://${appDomain}${previewNote}`,
      `  Stack:   ${appMeta.stack}`,
      ...(isCustom ? [`  Note:    Custom domain — ensure DNS points to this server`] : []),
      ...(isPreview ? [`  Tip:     Upgrade to Sovereign tier for public live URLs`] : []),
      ...(caddyWarning ? [caddyWarning] : []),
      '',
    ].join('\n');

    return c.json({
      url: `https://${appDomain}`,
      domain: appDomain,
      isPreview,
      name,
      port,
      stack: appMeta.stack,
      message,
    });
  });

  /**
   * POST /api/workflow/rollback
   *
   * Rolls back a deployed app to the previous version snapshot.
   * Swaps the 'current' symlink to the previous version and restarts PM2.
   */
  app.post('/api/workflow/rollback', async (c) => {
    deployMetrics.rollbacks++;
    const body = await c.req.json().catch(() => ({}));
    const { name } = body as { name?: string };

    if (!name) return c.json({ error: 'name is required' }, 400);

    // Sanitize name same as expose
    const safeName = name.toLowerCase().replace(/[^a-z0-9-]/g, '');
    if (!safeName) return c.json({ error: 'Invalid app name' }, 400);

    // Acquire deploy lock — prevents race with concurrent deploy/rollback
    const lockFile = `/tmp/ellulai-deploy-${safeName}.lock`;
    try {
      const fd = fs.openSync(lockFile, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o644);
      fs.writeSync(fd, String(process.pid));
      fs.closeSync(fd);
    } catch {
      try {
        const lockAge = Date.now() - (fs.statSync(lockFile).mtimeMs || 0);
        if (lockAge < 120000) {
          return c.json({ error: 'Deploy in progress — cannot rollback now' }, 409);
        }
        fs.unlinkSync(lockFile);
        const fd = fs.openSync(lockFile, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o644);
        fs.writeSync(fd, String(process.pid));
        fs.closeSync(fd);
      } catch {
        return c.json({ error: 'Deploy lock contention' }, 409);
      }
    }
    const releaseLock = () => { try { fs.unlinkSync(lockFile); } catch {} };

    const { home, appsDir } = getUserInfo();
    const appDeployDir = `${home}/.ellulai/deployments/${safeName}`;
    const currentLink = `${appDeployDir}/current`;
    const metaFile = `${appsDir}/${safeName}.json`;

    if (!fs.existsSync(appDeployDir)) {
      releaseLock();
      return c.json({ error: 'No deployment versions found' }, 404);
    }

    // List version directories (numeric timestamps)
    const versions = fs.readdirSync(appDeployDir)
      .filter(e => /^\d+$/.test(e))
      .sort((a, b) => parseInt(a) - parseInt(b));

    if (versions.length < 2) {
      releaseLock();
      return c.json({ error: 'No previous version to roll back to' }, 400);
    }

    // Determine current and previous versions
    const currentVersion = fs.existsSync(currentLink)
      ? path.basename(fs.readlinkSync(currentLink))
      : versions[versions.length - 1]!;
    const currentIdx = versions.indexOf(currentVersion);
    const previousIdx = currentIdx > 0 ? currentIdx - 1 : versions.length - 2;
    const previousVersion = versions[previousIdx];
    const previousDir = `${appDeployDir}/${previousVersion}`;

    if (!fs.existsSync(previousDir)) {
      releaseLock();
      return c.json({ error: 'Previous version directory missing' }, 500);
    }

    // Read current app metadata for port and domain
    let appMeta: Record<string, unknown> = {};
    let port = 3000;
    try {
      appMeta = JSON.parse(fs.readFileSync(metaFile, 'utf8'));
      port = (appMeta.port as number) || port;
    } catch {}

    // Atomic symlink swap
    const tmpLink = `${appDeployDir}/.current-tmp-${Date.now()}`;
    try {
      fs.symlinkSync(previousDir, tmpLink);
      fs.renameSync(tmpLink, currentLink);
    } catch (e) {
      try { fs.unlinkSync(tmpLink); } catch {}
      releaseLock();
      deployMetrics.rollbacksFailed++;
      return c.json({ error: `Symlink swap failed: ${(e as Error).message}` }, 500);
    }

    // Kill existing processes (canonical + any leftover canary)
    for (const proc of [safeName, `${safeName}__canary`]) {
      try {
        execSync(`bash -lc 'pm2 delete ${JSON.stringify(proc)} 2>/dev/null'`, {
          stdio: 'pipe', timeout: 5000,
        });
      } catch {}
    }

    // Start from rolled-back version
    const started = startPm2Process(safeName, port, previousDir);
    if (!started.started) {
      releaseLock();
      deployMetrics.rollbacksFailed++;
      return c.json({ error: 'Failed to start rolled-back version' }, 500);
    }

    // Health check the rolled-back version
    const healthCheck = await waitForHealthy(port, 10000, 500);
    if (!healthCheck.healthy) {
      console.error(`[shield] Rollback health check failed (HTTP ${healthCheck.httpStatus})`);
      // Don't abort — the process may still come up, and we've already swapped the symlink
    }

    // Update app metadata with new deployment path
    try {
      appMeta.deploymentPath = previousDir;
      fs.writeFileSync(metaFile, JSON.stringify(appMeta, null, 2));
    } catch {}

    // Caddy reload (config points to same port, but ensures clean state)
    let caddyOk = false;
    try {
      execSync('caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1', {
        stdio: 'pipe', timeout: 10000,
      });
      caddyOk = true;
    } catch {
      // Retry via systemctl
      try {
        execSync('systemctl reload caddy 2>/dev/null || systemctl restart caddy 2>/dev/null', {
          stdio: 'pipe', timeout: 15000,
        });
        caddyOk = true;
      } catch {
        console.error('[shield] Caddy reload failed during rollback — app may be unreachable');
      }
    }

    try { execSync(`bash -lc 'pm2 save --force 2>/dev/null'`, { stdio: 'pipe', timeout: 5000 }); } catch {}

    releaseLock();
    deployMetrics.rollbacksSucceeded++;

    // Trigger heartbeat
    try {
      const pid = fs.readFileSync('/run/ellulai-enforcer.pid', 'utf8').trim();
      if (pid) execSync(`kill -USR1 ${pid}`, { stdio: 'pipe', timeout: 2000 });
    } catch {}

    return c.json({
      message: `Rolled back ${safeName} to version ${previousVersion}`,
      version: previousVersion,
      previousVersion: currentVersion,
      healthy: healthCheck.healthy,
      caddyReloaded: caddyOk,
    });
  });

  /**
   * POST /api/workflow/remove
   *
   * Removes a deployed app: stops PM2 processes, removes Caddy config,
   * cleans up app metadata and deployment snapshots.
   */
  app.post('/api/workflow/remove', async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const { name } = body as { name?: string };

    if (!name) return c.json({ error: 'name is required' }, 400);

    const safeName = name.toLowerCase().replace(/[^a-z0-9-]/g, '');
    if (!safeName) return c.json({ error: 'Invalid app name' }, 400);

    // Acquire deploy lock
    const lockFile = `/tmp/ellulai-deploy-${safeName}.lock`;
    try {
      const fd = fs.openSync(lockFile, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o644);
      fs.writeSync(fd, String(process.pid));
      fs.closeSync(fd);
    } catch {
      try {
        const lockAge = Date.now() - (fs.statSync(lockFile).mtimeMs || 0);
        if (lockAge < 120000) {
          return c.json({ error: 'Deploy in progress — cannot remove now' }, 409);
        }
        fs.unlinkSync(lockFile);
        const fd = fs.openSync(lockFile, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o644);
        fs.writeSync(fd, String(process.pid));
        fs.closeSync(fd);
      } catch {
        return c.json({ error: 'Deploy lock contention' }, 409);
      }
    }
    const releaseLock = () => { try { fs.unlinkSync(lockFile); } catch {} };

    const { home, appsDir } = getUserInfo();

    try {
      // 1. Stop PM2 processes (canonical + canary)
      for (const proc of [safeName, `${safeName}__canary`]) {
        try {
          execSync(`bash -lc 'pm2 delete ${JSON.stringify(proc)} 2>/dev/null'`, {
            stdio: 'pipe', timeout: 10000,
          });
        } catch {}
      }

      // 2. Remove Caddy configs
      try { fs.unlinkSync(`${SITES_DIR}/${safeName}.caddy`); } catch {}
      try { fs.unlinkSync(`${APP_ROUTES_DIR}/${safeName}.caddy`); } catch {}

      // 3. Remove app metadata
      try { fs.unlinkSync(`${appsDir}/${safeName}.json`); } catch {}

      // 4. Validate + reload Caddy
      try {
        execSync('caddy validate --adapter caddyfile --config /etc/caddy/Caddyfile 2>&1', {
          stdio: 'pipe', timeout: 10000,
        });
        execSync('caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1', {
          stdio: 'pipe', timeout: 10000,
        });
      } catch (e) {
        console.error(`[shield] Caddy reload after remove failed: ${(e as Error).message}`);
      }

      // 5. Remove deployment snapshots
      const deployDir = `${home}/.ellulai/deployments/${safeName}`;
      try { fs.rmSync(deployDir, { recursive: true, force: true }); } catch {}

      // 6. Save PM2 state
      try { execSync(`bash -lc 'pm2 save --force 2>/dev/null'`, { stdio: 'pipe', timeout: 5000 }); } catch {}

      releaseLock();

      // 7. Trigger heartbeat
      try {
        const pid = fs.readFileSync('/run/ellulai-enforcer.pid', 'utf8').trim();
        if (pid) execSync(`kill -USR1 ${pid}`, { stdio: 'pipe', timeout: 2000 });
      } catch {}

      return c.json({ message: `Deployment "${safeName}" removed` });
    } catch (e) {
      releaseLock();
      return c.json({ error: (e as Error).message }, 500);
    }
  });

  /**
   * POST /api/workflow/hydrate
   *
   * Restores workspace from a snapshot stored in Neon.
   * Called by the API during free→paid upgrade or wake from hibernation.
   *
   * Reads server config from /etc/ellulai/* to determine:
   * - API URL + auth token for fetching snapshot chunks
   * - Billing tier → target directory (/home/dev for paid, /home/coder for free)
   */
  app.post('/api/workflow/hydrate', async (c) => {
    const LOG = '[hydrate]';

    try {
      // ── Read server config ──────────────────────────────────────────
      const serverId = fs.readFileSync('/etc/ellulai/server-id', 'utf8').trim();
      const apiUrl = fs.readFileSync('/etc/ellulai/api-url', 'utf8').trim();
      const aiProxyToken = fs.readFileSync('/etc/ellulai/ai-proxy-token', 'utf8').trim();
      const billingTier = getBillingTier();

      const targetDir = billingTier === 'free' ? '/home/coder' : '/home/dev';

      console.log(`${LOG} Starting hydration for server ${serverId.slice(0, 8)}... → ${targetDir}`);

      // ── Fetch snapshot chunks from API ───────────────────────────────
      const response = await fetch(
        `${apiUrl}/api/servers/${serverId}/snapshot-chunks`,
        {
          headers: {
            'Authorization': `Bearer ${aiProxyToken}`,
            'Content-Type': 'application/json',
          },
        }
      );

      if (!response.ok) {
        throw new Error(`API returned ${response.status}: ${await response.text()}`);
      }

      const data = await response.json() as {
        hasSnapshot: boolean;
        totalChunks?: number;
        compressedSizeBytes?: number;
        chunks?: Array<{ chunkIndex: number; data: string; sizeBytes: number; checksum: string }>;
      };

      if (!data.hasSnapshot || !data.chunks || data.chunks.length === 0) {
        console.log(`${LOG} No snapshot found — empty workspace`);
        return c.json({ success: true, message: 'No snapshot to hydrate' });
      }

      console.log(`${LOG} Received ${data.chunks.length} chunks (${data.compressedSizeBytes} bytes compressed)`);

      // ── Reassemble chunks into tarball ───────────────────────────────
      const sortedChunks = data.chunks.sort((a, b) => a.chunkIndex - b.chunkIndex);
      const buffers = sortedChunks.map(chunk => Buffer.from(chunk.data, 'base64'));
      const tarball = Buffer.concat(buffers);

      const tempFile = '/tmp/hydrate-workspace.tar.gz';
      fs.writeFileSync(tempFile, tarball);
      console.log(`${LOG} Tarball reassembled: ${tarball.length} bytes`);

      // ── Extract to target directory ──────────────────────────────────
      fs.mkdirSync(targetDir, { recursive: true });

      execSync(`tar xzf ${tempFile} -C ${targetDir} --strip-components=0`, {
        stdio: 'pipe',
        timeout: 120000,
      });

      console.log(`${LOG} Workspace extracted to ${targetDir}`);

      // ── Post-hydration setup ─────────────────────────────────────────
      const packageJson = `${targetDir}/package.json`;
      if (fs.existsSync(packageJson)) {
        console.log(`${LOG} Found package.json — running npm install...`);
        try {
          execSync(
            `bash -lc "cd ${targetDir} && npm install --prefer-offline 2>&1"`,
            { stdio: 'pipe', timeout: 120000 }
          );
          console.log(`${LOG} npm install complete`);
        } catch (npmErr) {
          const err = npmErr as Error & { killed?: boolean; signal?: string };
          const reason = err.killed ? `killed by timeout (${err.signal || 'SIGTERM'}) after 120s` : (err as Error).message;
          console.warn(`${LOG} npm install failed (non-fatal): ${reason}`);
        }
      }

      // ── Cleanup ──────────────────────────────────────────────────────
      try { fs.unlinkSync(tempFile); } catch {}

      console.log(`${LOG} Hydration complete`);
      return c.json({ success: true });
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      console.error(`${LOG} Hydration failed: ${msg}`);
      return c.json({ success: false, error: msg }, 500);
    }
  });
}
