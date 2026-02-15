/**
 * rebuild-all.ts — Regenerate ALL deployed files from source.
 *
 * Standalone entry point: bundled with esbuild during updates, then run as:
 *   node /tmp/ellulai-rebuild-all.js
 *
 * Reads config from /etc/ellulai/ and writes every script, config,
 * service file, and Node.js bundle to their deploy locations.
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

// ─── Config generators ─────────────────────────────────────────────
import {
  getGlobalGitignore,
  getPreCommitHook,
  getSshHardeningConfig,
  getFail2banConfig,
  getUnattendedUpgradesConfig,
  getAutoUpgradesConfig,
  getTmuxConfig,
  getStarshipConfig,
  getBashrcConfig,
  getMotdScript,
  getWelcomeReadme,
  getWelcomeEcosystem,
  getWelcomeClaudeMd,
  getGlobalClaudeMd,
  getProjectsClaudeMd,
} from '../../configs';

import { getOpencodeConfigJson } from '../../configs/ai';

// ─── Session scripts ────────────────────────────────────────────────
import {
  getSessionLauncherScript,
  getTtydWrapperScript,
  getTtydSystemdTemplate,
  getPtyWrapScript,
} from '../sessions';

// ─── Security scripts ───────────────────────────────────────────────
import {
  getSetupSshKeyScript,
  getAddSshKeyScript,
  getLockWebOnlyScript,
  getVerifyScript,
  getDecryptScript,
  getLazyAiInstallerScript,
  getLazyAiShimsScript,
  getDeleteScript,
  getRebuildScript,
  getRollbackScript,
  getChangeTierScript,
  getSettingsScript,
  getDeploymentScript,
  getEllulaiUpdateScript,
} from '../security';

// ─── Workflow scripts ───────────────────────────────────────────────
import {
  getGitFlowScript,
  getExposeScript,
  getAppsScript,
  getInspectScript,
  getUndoScript,
  getCleanScript,
  getDoctorScript,
  getPerfMonitorScript,
  getPerfMonitorService,
  getServiceInstallerScript,
  getPreviewScript,
  getPreviewService,
  getContextScript,
  getContextReadme,
  getAiFlowScript,
} from '../workflow';

// ─── Core scripts ───────────────────────────────────────────────────
import { getReportProgressScript, getTermProxyScript, getTermProxyService } from '..';

// ─── Service bundles ────────────────────────────────────────────────
import { getEnforcerService } from '../../services/enforcer/bundle';
import { getFileApiService } from '../../services/file-api/bundle';
import { getAgentBridgeService } from '../../services/agent-bridge/bundle';
import {
  getVpsAuthService,
  getDowngradeScript,
  getWebLockedSwitchScript,
  getResetAuthScript,
  getTierSwitchHelperScript,
} from '../../services/sovereign-shield/bundle';

import { VERSION } from '../../version';

// ─── Constants ──────────────────────────────────────────────────────
const REPO_DIR = '/opt/ellulai';
const ENFORCER_LIB_DIR = path.join(REPO_DIR, 'src', 'services', 'enforcer', 'lib');

// ─── Config reading ─────────────────────────────────────────────────

interface VpsConfig {
  serverId: string;
  domain: string;
  apiUrl: string;
  aiProxyToken: string;
  billingTier: string;
}

function readConfig(): VpsConfig {
  const read = (file: string): string => {
    try {
      return fs.readFileSync(file, 'utf8').trim();
    } catch {
      return '';
    }
  };
  return {
    serverId: read('/etc/ellulai/server-id'),
    domain: read('/etc/ellulai/domain'),
    apiUrl: read('/etc/ellulai/api-url'),
    aiProxyToken: read('/etc/ellulai/ai-proxy-token'),
    billingTier: read('/etc/ellulai/billing-tier') || 'paid',
  };
}

// ─── Enforcer assembly (inlined — can't use import.meta.url in CJS) ─

function assembleEnforcerScript(apiUrl: string, svcHome: string = "/home/dev"): string {
  const readLib = (name: string): string => {
    const libPath = path.join(ENFORCER_LIB_DIR, `${name}.sh`);
    return fs.readFileSync(libPath, 'utf8').replace(/^#!\/bin\/bash\n/, '').trim();
  };

  const modules = [
    'constants', 'logging', 'terminals', 'security', 'status',
    'enforcement', 'deployment', 'heartbeat', 'services',
  ];

  const sections = modules.map((mod) => {
    const header = mod.charAt(0).toUpperCase() + mod.slice(1);
    return `# ============================================\n# ${header}\n# ============================================\n${readLib(mod)}`;
  });

  return `#!/bin/bash
# ellul.ai State Enforcer Daemon (ellulai-env)
# Version: ${VERSION.components.daemon}
# Rebuilt by rebuild-all

API_URL="${apiUrl}"
TOKEN="$ELLULAI_AI_TOKEN"
DAEMON_VERSION="${VERSION.components.daemon}"

${sections.join('\n\n')}

# ============================================
# Main Daemon Loop
# ============================================

run_daemon() {
  log "============================================"
  log "ellul.ai Enforcer UPDATED - v\${DAEMON_VERSION}"
  log "If you see this, the update was successful!"
  log "============================================"
  log "Starting state enforcer daemon v\${DAEMON_VERSION} (heartbeat every \${HEARTBEAT_INTERVAL}s)..."

  # Write PID file
  echo \$\$ > "\$ENFORCER_PID_FILE"
  trap 'rm -f "\$ENFORCER_PID_FILE"' EXIT

  WAKEUP=0
  trap 'WAKEUP=1' USR1

  # Clean up any stale lockdown markers from pre-Phase 4
  rm -f /etc/ellulai/.emergency-lockdown /etc/ellulai/.in_lockdown 2>/dev/null || true

  local HEARTBEAT_COUNT=0
  local SERVICE_CHECK_COUNT=0
  local CONSECUTIVE_FAILURES=0

  while true; do
    if heartbeat_raw 2>/dev/null; then
      # Heartbeat succeeded - reset failure counter
      if [ "\$CONSECUTIVE_FAILURES" -gt 0 ]; then
        CONSECUTIVE_FAILURES=0
        reset_failure_count
      fi
    else
      # Heartbeat failed — log only, no lockdown
      CONSECUTIVE_FAILURES=\$((CONSECUTIVE_FAILURES + 1))
      save_failure_count "\$CONSECUTIVE_FAILURES"
      log "WARN: Heartbeat failed (\$CONSECUTIVE_FAILURES consecutive failures)"
    fi

    SERVICE_CHECK_COUNT=$((SERVICE_CHECK_COUNT + 1))
    if [ $SERVICE_CHECK_COUNT -ge 2 ]; then
      check_critical_services
      SERVICE_CHECK_COUNT=0
    fi

    # Phase 4: Version updates deferred to future self-update mechanism
    # (heartbeat response no longer carries version/update signals)

    # Interruptible sleep: SIGUSR1 interrupts wait immediately (zero latency)
    WAKEUP=0
    sleep \$HEARTBEAT_INTERVAL &
    SLEEP_PID=\$!
    wait \$SLEEP_PID 2>/dev/null
    if [ \$WAKEUP -eq 1 ]; then
      kill \$SLEEP_PID 2>/dev/null
      wait \$SLEEP_PID 2>/dev/null
      log "Push trigger received — running immediate heartbeat"
    fi
  done
}

# ============================================
# CLI Handler
# ============================================

case "\$1" in
  sync) sync_all ;;
  heartbeat) heartbeat ;;
  daemon) run_daemon ;;
  sessions) get_active_sessions ;;
  apps) get_deployed_apps ;;
  status)
    echo ""
    echo -e "\\033[32mellul.ai Status\\033[0m"
    echo ""
    echo "  Terminal Sessions:"
    for name in main opencode claude codex gemini aider git branch save ship undo logs clean; do
      STATUS=$(systemctl is-active "ttyd@\$name" 2>/dev/null || echo "inactive")
      if [ "\$STATUS" = "active" ]; then
        echo -e "    \\033[32m*\\033[0m \$name"
      else
        echo -e "    \\033[90mo\\033[0m \$name"
      fi
    done
    echo ""
    echo "  Deployed Apps:"
    APPS_DIR="${svcHome}/.ellulai/apps"
    if ls "\$APPS_DIR"/*.json &>/dev/null; then
      for f in "\$APPS_DIR"/*.json; do
        [ -f "\$f" ] || continue
        APP_NAME=$(jq -r '.name' "\$f")
        APP_URL=$(jq -r '.url' "\$f")
        APP_PORT=$(jq -r '.port' "\$f")
        echo -e "    \\033[32m*\\033[0m \$APP_NAME (:\$APP_PORT) -> \$APP_URL"
      done
    else
      echo -e "    \\033[90mo\\033[0m (none deployed)"
    fi
    echo ""
    echo "  CPU Usage: $(get_cpu_usage)%"
    echo "  RAM Usage: $(get_ram_usage)%"
    echo -n "  SSH: "; ufw status | grep -q "22/tcp.*ALLOW" && echo "OPEN" || echo "CLOSED"
    echo ""
    ;;
  kill)
    SESSION="\$2"
    if [ -z "\$SESSION" ]; then
      echo "Usage: ellulai-env kill <session>"
      exit 1
    fi
    log "Manually stopping session: \$SESSION"
    systemctl stop "ttyd@\$SESSION" 2>/dev/null
    echo "Stopped: \$SESSION"
    ;;
  *) echo "Usage: ellulai-env {sync|heartbeat|daemon|sessions|apps|status|kill <session>}" ;;
esac
`;
}

// ─── File manifest ──────────────────────────────────────────────────

interface FileEntry {
  path: string;
  content: string;
  mode?: number;
  owner?: string; // 'dev' for user-owned files, default is root
}

function buildManifest(config: VpsConfig): FileEntry[] {
  const { serverId, domain, apiUrl, aiProxyToken, billingTier } = config;
  const svcUser = billingTier === "free" ? "coder" : "dev";
  const svcHome = `/home/${svcUser}`;

  return [
    // ── Config files ──────────────────────────────────────────────
    { path: `${svcHome}/.global_gitignore`, content: getGlobalGitignore(), mode: 0o644, owner: svcUser },
    { path: `${svcHome}/.ellulai/hooks/pre-commit`, content: getPreCommitHook(), owner: svcUser },
    { path: '/etc/ssh/sshd_config.d/ellulai.conf', content: getSshHardeningConfig(), mode: 0o644 },
    { path: '/etc/fail2ban/jail.d/ellulai.conf', content: getFail2banConfig(), mode: 0o644 },
    { path: '/etc/apt/apt.conf.d/50unattended-upgrades', content: getUnattendedUpgradesConfig(), mode: 0o644 },
    { path: '/etc/apt/apt.conf.d/20auto-upgrades', content: getAutoUpgradesConfig(), mode: 0o644 },
    { path: `${svcHome}/.tmux.conf`, content: getTmuxConfig(), mode: 0o644, owner: svcUser },
    { path: `${svcHome}/.config/starship.toml`, content: getStarshipConfig(), mode: 0o644, owner: svcUser },
    { path: '/etc/profile.d/99-ellulai-motd.sh', content: getMotdScript() },
    { path: '/etc/profile.d/99-lazy-ai-shims.sh', content: getLazyAiShimsScript(), mode: 0o644 },

    // ── Session scripts ───────────────────────────────────────────
    { path: '/usr/local/bin/ellulai-launch', content: getSessionLauncherScript(svcUser) },
    { path: '/usr/local/bin/ellulai-ttyd-wrapper', content: getTtydWrapperScript() },
    { path: '/usr/local/bin/pty-wrap', content: getPtyWrapScript() },

    // ── Security scripts ──────────────────────────────────────────
    { path: '/usr/local/bin/setup-ssh-key', content: getSetupSshKeyScript() },
    { path: '/usr/local/bin/ellulai-add-key', content: getAddSshKeyScript() },
    { path: '/usr/local/bin/lock-web-only', content: getLockWebOnlyScript() },
    { path: '/usr/local/bin/ellulai-verify', content: getVerifyScript() },
    { path: '/usr/local/bin/ellulai-decrypt', content: getDecryptScript() },
    { path: '/usr/local/bin/install-lazy-ai.sh', content: getLazyAiInstallerScript() },
    { path: '/usr/local/bin/ellulai-update', content: getEllulaiUpdateScript() },

    // ── Scripts needing apiUrl ─────────────────────────────────────
    { path: '/usr/local/bin/ellulai-delete', content: getDeleteScript(apiUrl) },
    { path: '/usr/local/bin/ellulai-rebuild', content: getRebuildScript(apiUrl) },
    { path: '/usr/local/bin/ellulai-rollback', content: getRollbackScript(apiUrl) },
    { path: '/usr/local/bin/ellulai-change-tier', content: getChangeTierScript(apiUrl) },
    { path: '/usr/local/bin/ellulai-settings', content: getSettingsScript() },
    { path: '/usr/local/bin/ellulai-deployment', content: getDeploymentScript(apiUrl) },
    { path: '/usr/local/bin/ellulai-ai-flow', content: getAiFlowScript(apiUrl) },

    // ── Scripts needing apiUrl + aiProxyToken ──────────────────────
    { path: '/usr/local/bin/report-progress', content: getReportProgressScript(apiUrl, aiProxyToken) },

    // ── Workflow scripts ──────────────────────────────────────────
    { path: '/usr/local/bin/ellulai-git-flow', content: getGitFlowScript() },
    { path: '/usr/local/bin/ellulai-expose', content: getExposeScript() },
    { path: '/usr/local/bin/ellulai-apps', content: getAppsScript() },
    { path: '/usr/local/bin/ellulai-inspect', content: getInspectScript() },
    { path: '/usr/local/bin/ellulai-undo', content: getUndoScript() },
    { path: '/usr/local/bin/ellulai-clean', content: getCleanScript() },
    { path: '/usr/local/bin/ellulai-ctx', content: getContextScript() },
    { path: '/usr/local/bin/ellulai-preview', content: getPreviewScript() },
    { path: '/usr/local/bin/ellulai-install', content: getServiceInstallerScript() },
    { path: '/usr/local/bin/ellulai-doctor', content: getDoctorScript() },
    { path: '/usr/local/bin/ellulai-perf-monitor', content: getPerfMonitorScript() },
    { path: '/usr/local/bin/ellulai-term-proxy', content: getTermProxyScript() },

    // ── Sovereign Shield helper scripts ───────────────────────────
    { path: '/usr/local/bin/ellulai-downgrade', content: getDowngradeScript() },
    { path: '/usr/local/bin/ellulai-web-locked', content: getWebLockedSwitchScript() },
    { path: '/usr/local/bin/ellulai-reset-auth', content: getResetAuthScript() },
    { path: '/usr/local/bin/ellulai-tier-switch', content: getTierSwitchHelperScript() },

    // ── Enforcer (assembled from .sh modules) ─────────────────────
    { path: '/usr/local/bin/ellulai-env', content: assembleEnforcerScript(apiUrl, svcHome) },

    // ── Systemd service files ─────────────────────────────────────
    { path: '/etc/systemd/system/ttyd@.service', content: getTtydSystemdTemplate(svcUser), mode: 0o644 },
    { path: '/etc/systemd/system/ellulai-enforcer.service', content: getEnforcerService(aiProxyToken), mode: 0o644 },
    { path: '/etc/systemd/system/ellulai-file-api.service', content: getFileApiService(svcUser), mode: 0o644 },
    { path: '/etc/systemd/system/ellulai-agent-bridge.service', content: getAgentBridgeService(svcUser), mode: 0o644 },
    { path: '/etc/systemd/system/ellulai-term-proxy.service', content: getTermProxyService(svcUser), mode: 0o644 },
    { path: '/etc/systemd/system/ellulai-preview.service', content: getPreviewService(svcUser), mode: 0o644 },
    { path: '/etc/systemd/system/ellulai-sovereign-shield.service', content: getVpsAuthService(), mode: 0o644 },
    { path: '/etc/systemd/system/ellulai-perf-monitor.service', content: getPerfMonitorService(apiUrl, aiProxyToken), mode: 0o644 },

    // ── User config files ─────────────────────────────────────────
    { path: `${svcHome}/.bashrc`, content: getBashrcConfig(aiProxyToken), mode: 0o644, owner: svcUser },
    { path: `${svcHome}/.config/opencode/config.json`, content: getOpencodeConfigJson(apiUrl, aiProxyToken), mode: 0o644, owner: svcUser },
    { path: `${svcHome}/.ellulai/context/README.md`, content: getContextReadme(), mode: 0o644, owner: svcUser },

    // ── Welcome/docs files ────────────────────────────────────────
    { path: `${svcHome}/projects/welcome/README.md`, content: getWelcomeReadme(), mode: 0o644, owner: svcUser },
    { path: `${svcHome}/projects/welcome/ecosystem.config.js`, content: getWelcomeEcosystem(svcHome), mode: 0o644, owner: svcUser },
    { path: `${svcHome}/projects/welcome/CLAUDE.md`, content: getWelcomeClaudeMd(domain, billingTier), mode: 0o644, owner: svcUser },
    { path: `${svcHome}/CLAUDE.md`, content: getGlobalClaudeMd(domain, billingTier, svcHome), mode: 0o644, owner: svcUser },
    { path: `${svcHome}/projects/CLAUDE.md`, content: getProjectsClaudeMd(billingTier), mode: 0o644, owner: svcUser },
  ];
}

// ─── Atomic file write ──────────────────────────────────────────────

function writeFileAtomic(entry: FileEntry): void {
  const dir = path.dirname(entry.path);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const tmp = entry.path + '.rebuild-tmp';
  fs.writeFileSync(tmp, entry.content, { mode: entry.mode ?? 0o755 });
  fs.renameSync(tmp, entry.path);

  if (entry.owner) {
    try { execSync(`chown ${entry.owner}:${entry.owner} ${JSON.stringify(entry.path)}`, { stdio: 'pipe' }); } catch {}
  }
}

// ─── Node.js service rebuilds ───────────────────────────────────────

async function rebuildNodeServices(config: VpsConfig): Promise<number> {
  let esbuild;
  try {
    esbuild = require('esbuild');
  } catch {
    console.log('[rebuild-all] esbuild not available, skipping Node.js service rebuilds');
    return 0;
  }

  const NODE_EXTERNALS = [
    'fs', 'path', 'crypto', 'http', 'https', 'url',
    'events', 'stream', 'util', 'os', 'child_process',
  ];

  const services = [
    {
      name: 'sovereign-shield',
      entry: path.join(REPO_DIR, 'src/services/sovereign-shield/src/main.ts'),
      out: path.join(REPO_DIR, 'auth/server.js'),
      banner: `process.env.ELLULAI_HOSTNAME = ${JSON.stringify(config.domain)};`,
      external: [...NODE_EXTERNALS, 'hono', '@hono/node-server', 'better-sqlite3', '@simplewebauthn/server'],
    },
    {
      name: 'file-api',
      entry: path.join(REPO_DIR, 'src/services/file-api/src/main.ts'),
      out: '/usr/local/bin/ellulai-file-api',
      banner: `process.env.ELLULAI_SERVER_ID = ${JSON.stringify(config.serverId)};`,
      external: [...NODE_EXTERNALS, 'ws', 'chokidar'],
    },
    {
      name: 'agent-bridge',
      entry: path.join(REPO_DIR, 'src/services/agent-bridge/src/main.ts'),
      out: '/usr/local/bin/ellulai-agent-bridge',
      banner: '',
      external: [...NODE_EXTERNALS, 'ws', 'node-pty'],
    },
  ];

  let rebuilt = 0;
  for (const svc of services) {
    if (!fs.existsSync(svc.entry)) {
      console.log(`[rebuild-all] SKIP ${svc.name}: entry not found at ${svc.entry}`);
      continue;
    }
    try {
      const result = await esbuild.build({
        entryPoints: [svc.entry],
        bundle: true,
        platform: 'node',
        target: 'node18',
        format: 'cjs',
        write: false,
        external: svc.external,
      });

      const code = (svc.banner ? svc.banner + '\n' : '') + result.outputFiles[0].text;
      const tmp = svc.out + '.rebuild-tmp';
      fs.writeFileSync(tmp, code);
      fs.renameSync(tmp, svc.out);
      if (svc.out.startsWith('/usr/local/bin/')) {
        fs.chmodSync(svc.out, 0o755);
      }
      console.log(`[rebuild-all] Rebuilt ${svc.name}`);
      rebuilt++;
    } catch (err) {
      console.error(`[rebuild-all] FAILED to rebuild ${svc.name}: ${err}`);
    }
  }

  return rebuilt;
}

// ─── Symlinks ───────────────────────────────────────────────────────

function recreateSymlinks(svcUser: string): void {
  const links: [string, string][] = [
    ['/usr/local/bin/ellulai-ai-flow', '/usr/local/bin/ship'],
    ['/usr/local/bin/ellulai-git-flow', '/usr/local/bin/save'],
    ['/usr/local/bin/ellulai-git-flow', '/usr/local/bin/branch'],
  ];
  for (const [target, link] of links) {
    try { fs.unlinkSync(link); } catch {}
    try { fs.symlinkSync(target, link); } catch {}
  }

  // Create/refresh ~/.node symlink → actual NVM node version (CPU-agnostic)
  const svcHome = `/home/${svcUser}`;
  const nvmVersionsDir = path.join(svcHome, '.nvm', 'versions', 'node');
  try {
    let nodeVersion = '';
    try {
      nodeVersion = execSync(
        `su - ${svcUser} -c 'node --version' 2>/dev/null`,
        { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
      ).trim();
    } catch {
      // Fallback: scan NVM versions directory for installed versions
      if (fs.existsSync(nvmVersionsDir)) {
        const versions = fs.readdirSync(nvmVersionsDir).filter(v => v.startsWith('v')).sort();
        if (versions.length > 0) {
          nodeVersion = versions[versions.length - 1]!;
          console.log(`[rebuild-all] node --version failed, detected from filesystem: ${nodeVersion}`);
        }
      }
    }
    if (nodeVersion && nodeVersion.startsWith('v')) {
      const target = path.join(nvmVersionsDir, nodeVersion);
      const link = path.join(svcHome, '.node');
      if (fs.existsSync(target)) {
        try { fs.unlinkSync(link); } catch {}
        fs.symlinkSync(target, link);
        execSync(`chown -h ${svcUser}:${svcUser} ${JSON.stringify(link)}`, { stdio: 'pipe' });
        console.log(`[rebuild-all] .node symlink: ${link} → ${target}`);
      }
    }
  } catch (err) {
    console.warn(`[rebuild-all] Failed to create .node symlink: ${err}`);
  }
}

// ─── Main ───────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log(`[rebuild-all] ellul.ai v${VERSION.release} — rebuilding all deployed files`);

  // 1. Read config
  const config = readConfig();
  if (!config.apiUrl) {
    console.error('[rebuild-all] FATAL: /etc/ellulai/api-url not found');
    process.exit(1);
  }
  console.log(`[rebuild-all] Server: ${config.serverId} Domain: ${config.domain}`);

  // 2. Generate file manifest
  const manifest = buildManifest(config);
  console.log(`[rebuild-all] Writing ${manifest.length} files...`);

  // 3. Write all files
  let written = 0;
  let failed = 0;
  for (const entry of manifest) {
    try {
      writeFileAtomic(entry);
      written++;
    } catch (err) {
      console.error(`[rebuild-all] FAILED: ${entry.path}: ${err}`);
      failed++;
    }
  }
  console.log(`[rebuild-all] Files: ${written} written, ${failed} failed`);

  // 4. Rebuild Node.js service bundles
  const rebuilt = await rebuildNodeServices(config);
  console.log(`[rebuild-all] Node.js services: ${rebuilt} rebuilt`);

  // 5. Symlinks (including .node → NVM version detection)
  const svcUser = config.billingTier === "free" ? "coder" : "dev";
  recreateSymlinks(svcUser);

  // 6. Reload systemd to pick up service file changes
  try {
    execSync('systemctl daemon-reload', { stdio: 'pipe' });
    console.log('[rebuild-all] systemd daemon-reload done');
  } catch {}

  // 7. Reload SSH and fail2ban if configs changed
  try { execSync('systemctl reload sshd 2>/dev/null || true', { stdio: 'pipe' }); } catch {}
  try { execSync('systemctl restart fail2ban 2>/dev/null || true', { stdio: 'pipe' }); } catch {}

  console.log(`[rebuild-all] Complete. ${written + rebuilt} total files updated.`);
}

main().catch((err) => {
  console.error(`[rebuild-all] FATAL: ${err}`);
  process.exit(1);
});
