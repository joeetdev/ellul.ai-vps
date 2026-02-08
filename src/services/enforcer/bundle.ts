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
  const heartbeat = readLib('heartbeat');
  const update = readLib('update');
  const lockdown = readLib('lockdown');
  const services = readLib('services');

  // Assemble complete script
  return `#!/bin/bash
# Phone Stack State Enforcer Daemon (phonestack-env)
# Version: ${VERSION.components.daemon}
# Generated from modular components

API_URL="${apiUrl}"
TOKEN="$PHONESTACK_AI_TOKEN"
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
# Heartbeat & Sync
# ============================================
${heartbeat}

# ============================================
# Self-Update
# ============================================
${update}

# ============================================
# Emergency Lockdown
# ============================================
${lockdown}

# ============================================
# Service Health Monitoring
# ============================================
${services}

# ============================================
# Main Daemon Loop
# ============================================

run_daemon() {
  log "============================================"
  log "Phone Stack Enforcer UPDATED - v\${DAEMON_VERSION}"
  log "If you see this, the update was successful!"
  log "============================================"
  log "Starting state enforcer daemon v\${DAEMON_VERSION} (heartbeat every \${HEARTBEAT_INTERVAL}s, push via SIGUSR1)..."

  # Write PID file for SIGUSR1-based push triggers (nginx/PostgreSQL pattern)
  echo \$\$ > "\$ENFORCER_PID_FILE"
  trap 'rm -f "\$ENFORCER_PID_FILE"' EXIT

  # SIGUSR1 handler: API pushes commands via file-api -> SIGUSR1 -> immediate heartbeat
  WAKEUP=0
  trap 'WAKEUP=1' USR1

  # H8 FIX: Check for lockdown markers from previous session (survives reboot)
  if [ -f /etc/phonestack/.emergency-lockdown ] || [ -f "$LOCKDOWN_MARKER" ]; then
    log "STARTUP: Lockdown markers detected from previous session — re-entering lockdown"
    emergency_lockdown
    emergency_lockdown_loop
    # emergency_lockdown_loop only returns via exec (restart), so this is unreachable
  fi

  sync_all 2>/dev/null || true
  local HEARTBEAT_COUNT=0
  local SERVICE_CHECK_COUNT=0
  # L1 FIX: Load persisted failure count on startup
  local CONSECUTIVE_FAILURES=$(load_failure_count)
  if [ "$CONSECUTIVE_FAILURES" -gt 0 ]; then
    log "Resumed with $CONSECUTIVE_FAILURES previous heartbeat failures"
  fi

  while true; do
    if RESPONSE=$(heartbeat_raw 2>/dev/null); then
      # Heartbeat succeeded - reset failure counter
      if [ "$CONSECUTIVE_FAILURES" -gt 0 ]; then
        CONSECUTIVE_FAILURES=0
        reset_failure_count
      fi
    else
      # Heartbeat failed
      CONSECUTIVE_FAILURES=$((CONSECUTIVE_FAILURES + 1))
      save_failure_count "$CONSECUTIVE_FAILURES"
      log "WARN: Heartbeat failed ($CONSECUTIVE_FAILURES/$MAX_HEARTBEAT_FAILURES consecutive failures)"

      # Try sync as fallback
      sync_all 2>/dev/null || true

      # Check if we've hit the failure threshold
      if [ $CONSECUTIVE_FAILURES -ge $MAX_HEARTBEAT_FAILURES ]; then
        emergency_lockdown
        emergency_lockdown_loop
      fi
    fi

    SERVICE_CHECK_COUNT=$((SERVICE_CHECK_COUNT + 1))
    if [ $SERVICE_CHECK_COUNT -ge 2 ]; then
      check_critical_services
      SERVICE_CHECK_COUNT=0
    fi

    HEARTBEAT_COUNT=$((HEARTBEAT_COUNT + 1))
    if [ $HEARTBEAT_COUNT -ge 10 ] && [ -n "$RESPONSE" ]; then
      check_for_update "$RESPONSE"
      HEARTBEAT_COUNT=0
    fi

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
    echo -e "\\033[32mPhone Stack Status\\033[0m"
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
    APPS_DIR="/home/dev/.phonestack/apps"
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
      echo "Usage: phonestack-env kill <session>"
      exit 1
    fi
    log "Manually stopping session: \$SESSION"
    systemctl stop "ttyd@\$SESSION" 2>/dev/null
    echo "Stopped: \$SESSION"
    ;;
  *) echo "Usage: phonestack-env {sync|heartbeat|daemon|sessions|apps|status|kill <session>}" ;;
esac
`;
}

/**
 * Generate the complete VPS enforcer script.
 *
 * @param apiUrl - The Phone Stack API URL for heartbeat/sync calls
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
export function getEnforcerService(aiProxyToken: string): string {
  return `[Unit]
Description=Phone Stack State Enforcer
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/phonestack-env daemon
ExecReload=/bin/kill -USR1 $MAINPID
PIDFile=/run/phonestack-enforcer.pid
Restart=always
RestartSec=5
User=root
Environment=PHONESTACK_AI_TOKEN=${aiProxyToken}
StandardOutput=append:/var/log/phonestack-enforcer.log
StandardError=append:/var/log/phonestack-enforcer.log

[Install]
WantedBy=multi-user.target`;
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
