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
import { execSync } from 'child_process';
import type { Hono } from 'hono';
import { RESERVED_PORTS } from '../../../shared/constants';

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
 * Ensure the app process is running on the correct port via pm2.
 * Handles port conflict resolution, process lifecycle, and health checks.
 */
function ensureAppProcess(
  name: string,
  requestedPort: number,
  projectPath: string,
  appsDir: string,
): { port: number } {
  // Fast path: if the requested port already has a healthy listener owned by THIS project,
  // skip PM2 entirely. This prevents the destructive delete-and-restart cycle when
  // preview hands off a running process, while ensuring we don't accept a stale app.
  try {
    execSync(`curl -sf -o /dev/null http://localhost:${requestedPort}`, {
      stdio: 'pipe',
      timeout: 2000,
    });
    // Verify the listener actually belongs to this project via /proc/{pid}/cwd
    const pid = execSync(
      `ss -tlnpH sport = :${requestedPort} 2>/dev/null | grep -oP 'pid=\\K\\d+' | head -1`,
      { stdio: 'pipe', timeout: 3000, encoding: 'utf8' },
    ).trim();
    if (pid && fs.existsSync(`/proc/${pid}/cwd`)) {
      const cwd = fs.readlinkSync(`/proc/${pid}/cwd`);
      if (cwd === projectPath) {
        return { port: requestedPort };
      }
    }
  } catch {
    // Port not healthy or identity check failed — fall through to PM2 management
  }

  // A. Get pm2 process list
  let pm2List: Array<{
    name: string;
    pm2_env?: { cwd?: string; PORT?: string; status?: string };
  }> = [];
  try {
    const raw = execSync(`bash -lc 'pm2 jlist 2>/dev/null'`, {
      stdio: 'pipe',
      timeout: 10000,
    }).toString();
    pm2List = JSON.parse(raw);
  } catch {}

  // B. Check if this app already has a running pm2 process
  const existing = pm2List.find(
    (p) => p.pm2_env?.cwd === projectPath || p.name === name,
  );

  if (existing) {
    if (
      existing.pm2_env?.cwd === projectPath &&
      existing.pm2_env?.status === 'online'
    ) {
      const existingPort = parseInt(
        existing.pm2_env?.PORT || (existing.pm2_env as any)?.env?.PORT || '0', 10
      );
      if (existingPort > 0 && !RESERVED_PORTS.has(existingPort)) {
        // Verify port is actually listening by this pm2 process (not another service)
        try {
          const pid = (existing as { pid?: number }).pid;
          const check = pid
            ? `ss -tlnpH sport = :${existingPort} 2>/dev/null | grep -q 'pid=${pid},'`
            : `ss -tlnH sport = :${existingPort} 2>/dev/null`;
          execSync(check, {
            stdio: 'pipe',
            timeout: 3000,
          });
          return { port: existingPort };
        } catch {
          // Port not listening or owned by different process — fall through to restart
        }
      }
    }
    // Stale or wrong cwd — remove it
    try {
      execSync(`bash -lc 'pm2 delete ${JSON.stringify(existing.name)} 2>/dev/null'`, {
        stdio: 'pipe',
        timeout: 5000,
      });
    } catch {}
  }

  // C. Resolve port — guarantee no conflict
  let port = requestedPort;

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

  if (isPortOccupied(port)) {
    // Check if occupied by the same project
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
      // Find next free port
      let candidate = port + 1;
      while (candidate <= 65535) {
        if (!RESERVED_PORTS.has(candidate) && !isPortOccupied(candidate)) {
          port = candidate;
          break;
        }
        candidate++;
      }
      if (candidate > 65535) {
        throw new Error('No free ports available');
      }
    }
  }

  // D. Start the process
  try {
    execSync(`bash -lc 'pm2 delete ${JSON.stringify(name)} 2>/dev/null'`, {
      stdio: 'pipe',
      timeout: 5000,
    });
  } catch {}

  // Detect start method
  let hasStartScript = false;
  let hasPackageJson = false;
  let startScriptValue = '';
  try {
    const pkg = JSON.parse(fs.readFileSync(`${projectPath}/package.json`, 'utf8'));
    hasPackageJson = true;
    if (pkg.scripts && pkg.scripts.start) {
      hasStartScript = true;
      startScriptValue = pkg.scripts.start;
    }
  } catch {}

  // Determine if this is a static HTML site that needs a file server.
  // If the start script just runs a plain node file (no framework server)
  // and index.html exists, use npx serve instead — the node script likely
  // won't bind to the right port or serve static files correctly.
  const hasIndexHtml = fs.existsSync(`${projectPath}/index.html`);
  const isStaticSite = hasIndexHtml && (
    !hasStartScript ||
    /^node\s+\S+\.js$/.test(startScriptValue.trim())
  );

  let startCmd: string;
  if (isStaticSite) {
    startCmd = `PORT=${port} pm2 start "npx -y serve -s . -l ${port}" --name ${JSON.stringify(name)} --cwd ${JSON.stringify(projectPath)}`;
  } else if (hasStartScript) {
    startCmd = `PORT=${port} pm2 start npm --name ${JSON.stringify(name)} --cwd ${JSON.stringify(projectPath)} -- start`;
  } else {
    // Set PORT env var so ensureAppProcess can detect the port on subsequent calls
    startCmd = `PORT=${port} pm2 start "npx -y serve -s . -l ${port}" --name ${JSON.stringify(name)} --cwd ${JSON.stringify(projectPath)}`;
  }

  execSync(`bash -lc '${startCmd}'`, {
    stdio: 'pipe',
    timeout: 30000,
  });

  try {
    execSync(`bash -lc 'pm2 save --force 2>/dev/null'`, {
      stdio: 'pipe',
      timeout: 5000,
    });
  } catch {}

  // E. Health check — wait up to 8 seconds
  const maxWait = 8000;
  const interval = 500;
  let waited = 0;
  let healthy = false;

  while (waited < maxWait) {
    try {
      execSync(`curl -sf -o /dev/null http://localhost:${port}`, {
        stdio: 'pipe',
        timeout: 2000,
      });
      healthy = true;
      break;
    } catch {}
    execSync(`sleep 0.5`, { stdio: 'pipe' });
    waited += interval;
  }

  if (!healthy) {
    // Clean up
    try {
      execSync(`bash -lc 'pm2 delete ${JSON.stringify(name)} 2>/dev/null'`, {
        stdio: 'pipe',
        timeout: 5000,
      });
    } catch {}
    throw new Error(`App failed to start on port ${port} (health check timed out after ${maxWait / 1000}s)`);
  }

  return { port };
}

/**
 * Register workflow routes on Hono app
 */
export function registerWorkflowRoutes(app: Hono): void {
  /**
   * POST /api/workflow/expose
   *
   * Privileged expose handler. Accepts app config from the thin client,
   * enforces billing tier limits, generates Caddy config, and reloads.
   */
  app.post('/api/workflow/expose', async (c) => {
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

    // ── Create deployment snapshot (isolate deployed code from dev) ──
    // Every deploy takes a fresh snapshot of the current source code.
    // The snapshot freezes the deployed state so dev edits don't affect live.
    let servingPath = projectPath;
    const { home } = getUserInfo();

    if (projectPath) {
      const deploymentsDir = `${home}/.ellulai/deployments`;
      const deploymentPath = `${deploymentsDir}/${name}`;

      try {
        fs.mkdirSync(deploymentsDir, { recursive: true });

        // Kill existing deployed process — will restart from fresh snapshot
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

        // Create fresh snapshot of current project state
        // Exclude node_modules and .git to keep snapshot fast and small
        if (fs.existsSync(deploymentPath)) {
          fs.rmSync(deploymentPath, { recursive: true, force: true });
        }
        fs.mkdirSync(deploymentPath, { recursive: true });
        execSync(
          `rsync -a --exclude='node_modules' --exclude='.git' ${JSON.stringify(projectPath + '/')} ${JSON.stringify(deploymentPath + '/')}`,
          { stdio: 'pipe', timeout: 30000 }
        );
        // Install production deps in snapshot if package.json exists
        if (fs.existsSync(`${deploymentPath}/package.json`)) {
          try {
            execSync(`bash -lc 'cd ${JSON.stringify(deploymentPath)} && npm install --omit=dev 2>&1'`, {
              stdio: 'pipe', timeout: 60000,
            });
          } catch {}
        }

        servingPath = deploymentPath;
        console.log(`[shield] Created deployment snapshot: ${deploymentPath}`);
      } catch (e) {
        console.error(`[shield] Snapshot failed, serving from source: ${(e as Error).message}`);
      }
    }

    // ── Ensure app process is running (port ownership + lifecycle) ──
    if (servingPath) {
      try {
        const result = ensureAppProcess(name!, port, servingPath, appsDir);
        port = result.port;
      } catch (e) {
        return c.json({ error: (e as Error).message }, 500);
      }
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
    const configFile = `${configDir}/${name}.caddy`;
    try {
      fs.writeFileSync(configFile, caddyConfig);
    } catch (e) {
      return c.json({ error: `Failed to write Caddy config: ${(e as Error).message}` }, 500);
    }

    // ── Write app metadata ───────────────────────────────────────────
    const isPreview = isFree;
    const appMeta = {
      name,
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

    const metaFile = `${appsDir}/${name}.json`;
    try {
      fs.writeFileSync(metaFile, JSON.stringify(appMeta, null, 2));
    } catch (e) {
      // Clean up Caddy config on metadata write failure
      try { fs.unlinkSync(configFile); } catch {}
      return c.json({ error: `Failed to write app metadata: ${(e as Error).message}` }, 500);
    }

    // ── Validate + reload Caddy ──────────────────────────────────────
    try {
      execSync('caddy validate --adapter caddyfile --config /etc/caddy/Caddyfile 2>&1', {
        stdio: 'pipe',
        timeout: 10000,
      });
    } catch (e) {
      // Validation failed — clean up
      try { fs.unlinkSync(configFile); } catch {}
      try { fs.unlinkSync(metaFile); } catch {}
      return c.json({ error: 'Caddy configuration invalid — rolled back' }, 500);
    }

    try {
      // Use caddy reload (admin API) — works without root since shield runs as $SVC_USER.
      // systemctl reload requires root and fails silently when run as non-root.
      execSync('caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1', {
        stdio: 'pipe',
        timeout: 10000,
      });
    } catch {
      // Config is valid but reload failed — leave config in place
      console.error('[shield] Caddy reload failed after valid config write');
    }

    // ── Update ellulai.json in project root ───────────────────────
    if (projectPath) {
      const psjsonPath = `${projectPath}/ellulai.json`;
      try {
        if (fs.existsSync(psjsonPath)) {
          // SECURITY: Use Node.js JSON operations instead of shell jq to prevent injection
          const existing = JSON.parse(fs.readFileSync(psjsonPath, 'utf8'));
          existing.deployedUrl = `https://${appDomain}`;
          existing.deployedDomain = appDomain;
          existing.deployedPort = port;
          fs.writeFileSync(psjsonPath, JSON.stringify(existing, null, 2));
        }
      } catch {}
    }

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

    const message = [
      '',
      `App deployed!`,
      '',
      `  Live at: https://${appDomain}${previewNote}`,
      `  Stack:   ${appMeta.stack}`,
      ...(isCustom ? [`  Note:    Custom domain — ensure DNS points to this server`] : []),
      ...(isPreview ? [`  Tip:     Upgrade to Sovereign tier for public live URLs`] : []),
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
          console.warn(`${LOG} npm install failed (non-fatal): ${npmErr}`);
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
