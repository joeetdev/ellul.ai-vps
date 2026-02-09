/**
 * Workflow Routes
 *
 * Privileged server-side handlers for workflow commands that require
 * root access (writing Caddy configs, reloading services, etc.).
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

const BILLING_TIER_FILE = '/etc/ellulai/billing-tier';
const DOMAIN_FILE = '/etc/ellulai/domain';
const SITES_DIR = '/etc/caddy/sites-enabled';
const CF_CA_FILE = '/etc/caddy/cf-origin-pull-ca.pem';

// Ports reserved for ellul.ai internal services
const RESERVED_PORTS = new Set([
  22, 2019, 3002, 3005,
  7681, 7682, 7683, 7684, 7685, 7686, 7687, 7688, 7689,
  7690, 7691, 7692, 7693, 7694, 7695, 7696, 7697, 7698, 7699, 7700, 7701,
]);

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
    const port = body.port;

    // ── Validate inputs ──────────────────────────────────────────────
    if (!name || !port) {
      return c.json({ error: 'name and port are required' }, 400);
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
    const { user: systemUser, appsDir } = getUserInfo();

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
            try { fs.unlinkSync(`${appsDir}/${oldName}.json`); } catch {}
            name = oldName; // Reuse old name
            break;
          }
        } catch {}
      }
    }

    // ── Build domain ─────────────────────────────────────────────────
    const serverDomain = getServerDomain();
    const shortId = (serverDomain.match(/^([a-f0-9]{8})-/) || [])[1] || serverDomain.split('.')[0];
    const appDomain = customDomain || `${name}-${shortId}.ellul.app`;
    const isCustom = !!customDomain;

    // ── Generate Caddy config ────────────────────────────────────────
    let caddyConfig: string;

    if (isCustom) {
      // Custom domain — user handles TLS
      caddyConfig = `${appDomain} {
    reverse_proxy localhost:${port}
    log {
        output file /var/log/caddy/${name}.log
        format json
    }
}
`;
    } else {
      // ellul.ai domain — origin cert + Cloudflare Edge
      const cfCaBase64 = getCfCaBase64();
      if (!cfCaBase64) {
        return c.json({
          error: 'Cloudflare Origin Pull CA not found. Run ellulai-update to fix.',
        }, 500);
      }

      if (isFree) {
        // Free tier: add forward_auth for owner-only preview
        caddyConfig = `${appDomain}:443 {
    tls /etc/caddy/origin-app.crt /etc/caddy/origin-app.key {
        client_auth {
            mode require_and_verify
            trusted_ca_cert ${cfCaBase64}
        }
    }
    forward_auth localhost:3005 {
        uri /api/auth/check
        header_up Cookie {http.request.header.Cookie}
    }
    reverse_proxy localhost:${port}
    log {
        output file /var/log/caddy/${name}.log
        format json
    }
}
`;
      } else {
        // Paid tier: public access, no forward_auth
        caddyConfig = `${appDomain}:443 {
    tls /etc/caddy/origin-app.crt /etc/caddy/origin-app.key {
        client_auth {
            mode require_and_verify
            trusted_ca_cert ${cfCaBase64}
        }
    }
    reverse_proxy localhost:${port}
    log {
        output file /var/log/caddy/${name}.log
        format json
    }
}
`;
      }
    }

    // ── Write Caddy config ───────────────────────────────────────────
    const configFile = `${SITES_DIR}/${name}.caddy`;
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
    };

    const metaFile = `${appsDir}/${name}.json`;
    try {
      fs.writeFileSync(metaFile, JSON.stringify(appMeta, null, 2));
      // chown to coder so the user can read it
      execSync(`chown ${systemUser}:${systemUser} ${metaFile}`, { stdio: 'pipe' });
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
      execSync('systemctl reload caddy 2>/dev/null || systemctl restart caddy', {
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
          execSync(
            `jq --arg url "https://${appDomain}" --arg domain "${appDomain}" --argjson port ${port} ` +
            `'. + {deployedUrl: $url, deployedDomain: $domain, deployedPort: $port}' ` +
            `"${psjsonPath}" > "${psjsonPath}.tmp" && mv "${psjsonPath}.tmp" "${psjsonPath}"`,
            { stdio: 'pipe', timeout: 5000 }
          );
          execSync(`chown ${systemUser}:${systemUser} "${psjsonPath}" 2>/dev/null || true`, { stdio: 'pipe' });
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
      const targetUser = billingTier === 'free' ? 'coder' : 'dev';

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

      execSync(`chown -R ${targetUser}:${targetUser} ${targetDir}`, {
        stdio: 'pipe',
        timeout: 30000,
      });

      console.log(`${LOG} Workspace extracted to ${targetDir}`);

      // ── Post-hydration setup ─────────────────────────────────────────
      const packageJson = `${targetDir}/package.json`;
      if (fs.existsSync(packageJson)) {
        console.log(`${LOG} Found package.json — running npm install...`);
        try {
          execSync(
            `su - ${targetUser} -c "cd ${targetDir} && npm install --prefer-offline 2>&1"`,
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
