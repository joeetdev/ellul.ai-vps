/**
 * Deployment Service
 *
 * Switch deployment model (cloudflare/direct/gateway) by regenerating
 * the Caddyfile and updating TLS certificates.
 * Ported from enforcer switch_deployment_model() in deployment.sh.
 *
 * Called via bridge endpoint (passkey-authenticated).
 */

import { execSync } from 'child_process';
import fs from 'fs';

export interface DeploymentSwitchOpts {
  model: 'cloudflare' | 'direct' | 'gateway';
  domain: string;
  serverId?: string;
  cfOriginCert?: string;
  cfOriginKey?: string;
  cfAppOriginCert?: string;
  cfAppOriginKey?: string;
}

const CADDYFILE = '/etc/caddy/Caddyfile';
const DOMAIN_FILE = '/etc/ellulai/domain';
const SERVER_ID_FILE = '/etc/ellulai/server-id';

/**
 * Write a certificate file with proper ownership.
 */
function writeCert(path: string, content: string, mode: number): void {
  fs.writeFileSync(path, content);
  fs.chmodSync(path, mode);
  try { execSync(`chown caddy:caddy '${path}' 2>/dev/null`, { timeout: 3_000 }); } catch {}
}

/**
 * Detect current deployment model from Caddyfile.
 */
function detectCurrentModel(): 'cloudflare' | 'direct' | 'gateway' {
  try {
    const caddyfile = fs.readFileSync(CADDYFILE, 'utf8');
    if (caddyfile.includes('auto_https off')) {
      return caddyfile.includes('tls internal') ? 'gateway' : 'cloudflare';
    }
  } catch {}
  return 'direct';
}

/**
 * Read current short server ID (first 8 chars).
 */
function getShortId(): string {
  try {
    return fs.readFileSync(SERVER_ID_FILE, 'utf8').trim().slice(0, 8);
  } catch {
    return '';
  }
}

/**
 * Compute code and dev subdomains for a given model and short ID.
 */
function computeSubdomains(model: string, shortId: string): { code: string; dev: string } {
  const prefix = model === 'direct' ? 'd' : '';
  return {
    code: `${shortId}-${prefix}code.ellul.ai`,
    dev: `${shortId}-${prefix}dev.ellul.app`,
  };
}

/**
 * Ensure the daemon port Caddyfile exists and is properly configured.
 * Delegates to the enforce loop's ensure_daemon_port (keep this in bash).
 */
function ensureDaemonPort(): void {
  try {
    execSync('ufw allow 3006/tcp comment "Daemon API" 2>/dev/null || true', { timeout: 5_000 });
  } catch {}
}

/**
 * Switch the deployment model. Handles:
 * - Same-model domain update (sed replace, preserve Caddyfile)
 * - Model switch (regenerate Caddyfile via ellulai-caddy-gen)
 * - Origin cert rotation
 * - State file updates
 * - Sovereign-shield restart + Caddy reload
 */
export function switchDeployment(opts: DeploymentSwitchOpts): { success: boolean; error?: string } {
  const currentModel = detectCurrentModel();
  const oldDomain = (() => { try { return fs.readFileSync(DOMAIN_FILE, 'utf8').trim(); } catch { return ''; } })();
  const oldShortId = getShortId();

  const newShortId = opts.serverId ? opts.serverId.slice(0, 8) : oldShortId;
  if (!newShortId) {
    return { success: false, error: 'Cannot determine server ID' };
  }

  const newSubs = computeSubdomains(opts.model, newShortId);

  // Write origin certs if provided (*.ellul.ai)
  if (opts.cfOriginCert) writeCert('/etc/caddy/origin.crt', opts.cfOriginCert, 0o644);
  if (opts.cfOriginKey) writeCert('/etc/caddy/origin.key', opts.cfOriginKey, 0o600);
  // App origin certs (*.ellul.app)
  if (opts.cfAppOriginCert) writeCert('/etc/caddy/origin-app.crt', opts.cfAppOriginCert, 0o644);
  if (opts.cfAppOriginKey) writeCert('/etc/caddy/origin-app.key', opts.cfAppOriginKey, 0o600);

  if (opts.model === currentModel && oldDomain) {
    // Same model: sed-replace domains only (preserves full Caddyfile structure)
    if (oldDomain !== opts.domain) {
      const oldSubs = computeSubdomains(currentModel, oldShortId);
      try {
        execSync(`sed -i "s|${oldDomain}|${opts.domain}|g" ${CADDYFILE}`, { timeout: 5_000 });
        execSync(`sed -i "s|${oldSubs.code}|${newSubs.code}|g" ${CADDYFILE}`, { timeout: 5_000 });
        execSync(`sed -i "s|${oldSubs.dev}|${newSubs.dev}|g" ${CADDYFILE}`, { timeout: 5_000 });
      } catch (e) {
        return { success: false, error: `sed replace failed: ${(e as Error).message}` };
      }
    }
  } else {
    // Model switch: regenerate Caddyfile from scratch
    // Download AOP CA cert for cloudflare model
    if (opts.model === 'cloudflare') {
      if (!fs.existsSync('/etc/caddy/cf-origin-pull-ca.pem')) {
        try {
          execSync(
            'curl -sS https://developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem -o /etc/caddy/cf-origin-pull-ca.pem',
            { timeout: 10_000 }
          );
          execSync('chown caddy:caddy /etc/caddy/cf-origin-pull-ca.pem', { timeout: 3_000 });
        } catch {}
      }
    }

    try {
      execSync(
        `node /usr/local/bin/ellulai-caddy-gen --model ${opts.model} --main-domain ${opts.domain} --code-domain ${newSubs.code} --dev-domain ${newSubs.dev} > ${CADDYFILE}`,
        { timeout: 10_000 }
      );
    } catch (e) {
      return { success: false, error: `Caddyfile generation failed: ${(e as Error).message}` };
    }
  }

  // Ensure daemon port
  ensureDaemonPort();

  // Update state files AFTER Caddyfile (so retries can find old domains)
  if (opts.serverId) {
    const currentId = (() => { try { return fs.readFileSync(SERVER_ID_FILE, 'utf8').trim(); } catch { return ''; } })();
    if (opts.serverId !== currentId) {
      fs.writeFileSync(SERVER_ID_FILE, opts.serverId);
    }
  }
  fs.writeFileSync(DOMAIN_FILE, opts.domain);

  // Restart sovereign-shield to pick up new domain (WebAuthn + CORS)
  try {
    execSync('systemctl restart ellulai-sovereign-shield 2>/dev/null || true', { timeout: 15_000 });
  } catch {}

  // Wait for shield to boot, then validate and reload Caddy
  try {
    execSync('sleep 2', { timeout: 5_000 });
    const valid = (() => {
      try {
        execSync('caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>/dev/null', { timeout: 10_000 });
        return true;
      } catch { return false; }
    })();

    if (valid) {
      execSync('caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile 2>/dev/null || systemctl restart caddy', { timeout: 15_000 });
    } else {
      return { success: false, error: 'Invalid Caddyfile — previous config preserved' };
    }
  } catch (e) {
    return { success: false, error: `Caddy reload failed: ${(e as Error).message}` };
  }

  return { success: true };
}
