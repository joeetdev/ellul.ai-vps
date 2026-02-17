/**
 * Enforcer Bundle Generator
 *
 * This file generates the complete bash daemon script by assembling
 * modular shell script components.
 *
 * Usage:
 *   import { getEnforcerScript } from './bundle';
 *   const script = getEnforcerScript(apiUrl);
 */

import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { VERSION } from '../../version';

// Cache for assembled script
let cachedScript: string | null = null;
let cachedApiUrl: string | null = null;

/**
 * Get the source directory path.
 * Works whether running from src/ (dev) or dist/ (production).
 */
function getSourceDir(): string {
  const currentFile = fileURLToPath(import.meta.url);
  const currentDir = path.dirname(currentFile);

  // If we're in dist (compiled), go up to package root and into src/
  if (currentDir.includes('/dist/') || currentDir.endsWith('/dist')) {
    const packageRoot = currentDir.replace(/\/dist(\/.*)?$/, '');
    return path.join(packageRoot, 'src', 'services', 'enforcer');
  }

  // Already in src/
  return currentDir;
}

/**
 * Read a shell library file.
 */
function readLib(name: string): string {
  const sourceDir = getSourceDir();
  const libPath = path.join(sourceDir, 'lib', `${name}.sh`);
  if (fs.existsSync(libPath)) {
    // Remove shebang line if present
    return fs.readFileSync(libPath, 'utf8').replace(/^#!\/bin\/bash\n/, '').trim();
  }
  throw new Error(`Library not found: ${libPath}`);
}

/**
 * Assemble the enforcer script from modules.
 */
function assembleScript(apiUrl: string): string {
  // Read library modules
  const constants = readLib('constants');
  const logging = readLib('logging');
  const terminals = readLib('terminals');
  const security = readLib('security');
  const status = readLib('status');
  const enforcement = readLib('enforcement');
  const deployment = readLib('deployment');
  const agents = readLib('agents');
  const heartbeat = readLib('heartbeat');
  const services = readLib('services');

  // Assemble complete script
  return `#!/bin/bash
# ellul.ai State Enforcer Daemon (ellulai-env)
# Version: ${VERSION.components.daemon}
# Generated from modular components

API_URL="${apiUrl}"
TOKEN="$ELLULAI_AI_TOKEN"
DAEMON_VERSION="${VERSION.components.daemon}"

# ============================================
# Constants
# ============================================
${constants}

# ============================================
# Logging
# ============================================
${logging}

# ============================================
# Terminal Management
# ============================================
${terminals}

# ============================================
# Security (Tier Detection, Identity Pinning)
# ============================================
${security}

# ============================================
# Status Reporting
# ============================================
${status}

# ============================================
# Enforcement (Settings, Kill Orders, Actions)
# ============================================
${enforcement}

# ============================================
# Deployment Model Switching
# ============================================
${deployment}

# ============================================
# Agent Telemetry
# ============================================
${agents}

# ============================================
# Heartbeat & Sync
# ============================================
${heartbeat}

# ============================================
# Service Health Monitoring
# ============================================
${services}

# ============================================
# Main Daemon Loop
# ============================================

run_daemon() {
  log "============================================"
  log "ellul.ai Enforcer UPDATED - v\${DAEMON_VERSION}"
  log "If you see this, the update was successful!"
  log "============================================"
  log "Starting state enforcer daemon v\${DAEMON_VERSION} (heartbeat every \${HEARTBEAT_INTERVAL}s, push via SIGUSR1)..."

  # Write PID file for SIGUSR1-based push triggers (nginx/PostgreSQL pattern)
  echo \$\$ > "\$ENFORCER_PID_FILE"
  trap 'rm -f "\$ENFORCER_PID_FILE"' EXIT

  # SIGUSR1 handler: API pushes commands via file-api -> SIGUSR1 -> immediate heartbeat
  WAKEUP=0
  trap 'WAKEUP=1' USR1

  # Clean up any stale lockdown markers from pre-Phase 4
  rm -f /etc/ellulai/.emergency-lockdown /etc/ellulai/.in_lockdown 2>/dev/null || true

  # STARTUP ENFORCEMENT: Run enforcement immediately on daemon start.
  # This ensures SSH is enabled (if keys exist) before the first heartbeat,
  # preventing lockout during the initial 30-second window.
  local SETTINGS_FILE="/etc/ellulai/shield-data/settings.json"
  local BOOT_TERMINAL=\$(jq -r '.terminalEnabled // "true"' "\$SETTINGS_FILE" 2>/dev/null || echo "true")
  local BOOT_SSH=\$(jq -r '.sshEnabled // "false"' "\$SETTINGS_FILE" 2>/dev/null || echo "false")
  log "Running startup enforcement (terminal=\$BOOT_TERMINAL, ssh=\$BOOT_SSH)..."
  enforce_settings "\$BOOT_TERMINAL" "\$BOOT_SSH"
  log "Startup enforcement complete"

  # BOOT VALIDATION: Verify all critical services are operational.
  # Catches provisioning failures (missing binaries, broken firewall, etc.)
  # and attempts remediation before the first user interaction.
  log "Running boot validation..."
  validate_full_stack
  log "Boot validation complete"

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
      if svc_is_active "ttyd@\$name"; then
        echo -e "    \\033[32m*\\033[0m \$name"
      else
        echo -e "    \\033[90mo\\033[0m \$name"
      fi
    done
    echo ""
    echo "  Deployed Apps:"
    APPS_DIR="\${SVC_HOME}/.ellulai/apps"
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
    echo -n "  SSH: "; fw_is_allowed 22 && echo "OPEN" || echo "CLOSED"
    echo ""
    ;;
  kill)
    SESSION="\$2"
    if [ -z "\$SESSION" ]; then
      echo "Usage: ellulai-env kill <session>"
      exit 1
    fi
    log "Manually stopping session: \$SESSION"
    svc_stop "ttyd@\$SESSION"
    echo "Stopped: \$SESSION"
    ;;
  *) echo "Usage: ellulai-env {sync|heartbeat|daemon|sessions|apps|status|kill <session>}" ;;
esac
`;
}

/**
 * Generate the complete VPS enforcer script.
 *
 * @param apiUrl - The ellul.ai API URL for heartbeat/sync calls
 */
export function getEnforcerScript(apiUrl: string): string {
  // Check cache
  if (cachedScript && cachedApiUrl === apiUrl) {
    return cachedScript;
  }

  // Assemble script from modular components
  cachedScript = assembleScript(apiUrl);
  cachedApiUrl = apiUrl;
  return cachedScript;
}

/**
 * Get the systemd service file content.
 *
 * @param aiProxyToken - The server's AI proxy token for authentication
 */
export function getEnforcerService(_aiProxyToken?: string): string {
  return `[Unit]
Description=ellul.ai State Enforcer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ellulai-env daemon
ExecReload=/bin/kill -USR1 $MAINPID
PIDFile=/run/ellulai-enforcer.pid
Restart=always
RestartSec=5
User=root
EnvironmentFile=-/etc/default/ellulai
StandardOutput=append:/var/log/ellulai-enforcer.log
StandardError=append:/var/log/ellulai-enforcer.log

# Security hardening (root required for systemd/service management)
NoNewPrivileges=true
ProtectHome=read-only
PrivateTmp=true

[Install]
WantedBy=multi-user.target`;
}

/**
 * Get the launchd plist for macOS BYOS deployments.
 *
 * @param aiProxyToken - The server's AI proxy token for authentication
 */
export function getEnforcerLaunchdPlist(aiProxyToken: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ai.ellulai.enforcer</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/ellulai-env</string>
        <string>daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>EnvironmentVariables</key>
    <dict>
        <key>ELLULAI_AI_TOKEN</key>
        <string>${aiProxyToken}</string>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
    <key>StandardOutPath</key>
    <string>/var/log/ellulai-enforcer.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/ellulai-enforcer.log</string>
</dict>
</plist>`;
}

/**
 * Get the version of the enforcer module.
 */
export function getEnforcerVersion(): string {
  return VERSION.components.daemon;
}

/**
 * Invalidate the script cache (useful for development).
 */
export function invalidateScriptCache(): void {
  cachedScript = null;
  cachedApiUrl = null;
}
