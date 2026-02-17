#!/bin/bash
# Enforcer Constants
# Configuration variables and paths for the state enforcer daemon.

# ─── Platform Detection ──────────────────────────────────────
# Detect once at startup; every helper branches on IS_MACOS.
IS_MACOS=false
if [ "$(uname -s)" = "Darwin" ]; then
  IS_MACOS=true
fi

# API_URL resolution: config file > environment > baked-in value from bundle.ts
# This ensures the enforcer works even if the script was installed with stale/placeholder values
if [ -f /etc/ellulai/api-url ]; then
  API_URL="$(cat /etc/ellulai/api-url 2>/dev/null | tr -d '\n')"
fi
API_URL="${API_URL:-}"
TOKEN="${ELLULAI_AI_TOKEN:-}"
# Derive service user from PS_USER (loaded by systemd EnvironmentFile from /etc/default/ellulai)
SVC_USER="${PS_USER:-dev}"
if [ "$IS_MACOS" = true ]; then
  SVC_HOME="/Users/${SVC_USER}"
else
  SVC_HOME="/home/${SVC_USER}"
fi
ENV_FILE="${SVC_HOME}/.ellulai-env"
STATE_FILE="/etc/ellulai/access-state.json"
STATUS_FILE="${SVC_HOME}/.ellulai/server-status.json"
LOG_FILE="/var/log/ellulai-enforcer.log"
SOVEREIGN_MARKER="/etc/ellulai/.sovereign-mode"
SOVEREIGN_KEYS_LOCK="/etc/ellulai/shield-data/.sovereign-keys"
OWNER_LOCK_FILE="/etc/ellulai/owner.lock"
HEARTBEAT_FAILURE_FILE="/etc/ellulai/.heartbeat-failures"
HEARTBEAT_INTERVAL=30
ENFORCER_PID_FILE="/run/ellulai-enforcer.pid"
# DAEMON_VERSION is injected by bundle.ts from version.ts

# Verified Git Pull update constants
AGENT_REPO_DIR="/opt/ellulai"
AGENT_VERSION_FILE="/etc/ellulai/current-version"

# All terminal services - used for lockdown and health checks
if [ "$IS_MACOS" = true ]; then
  # macOS: terminals are dynamic (agent-bridge managed), no systemd template units
  ALL_TERMINALS=""
else
  ALL_TERMINALS="ttyd@main ttyd@opencode ttyd@claude ttyd@codex ttyd@gemini ttyd@aider ttyd@git ttyd@branch ttyd@save ttyd@ship ttyd@undo ttyd@logs ttyd@clean"
fi

# ─── Platform-Aware Service Helpers ──────────────────────────
# Abstract systemctl (Linux) vs launchctl (macOS).
# macOS launchd labels: ai.ellulai.<name> (from provisioning plists)
# Linux systemd units:  ellulai-<name> (from provisioning .service files)

# Map a systemd unit name to a launchd label.
# e.g. "ellulai-file-api" → "ai.ellulai.file-api"
#      "ttyd@main"         → "" (no macOS equivalent)
_launchd_label() {
  local svc="$1"
  case "$svc" in
    ellulai-*) echo "ai.ellulai.${svc#ellulai-}" ;;
    ttyd@*)    echo "" ;; # No macOS equivalent — terminals are dynamic
    *)         echo "$svc" ;;
  esac
}

# Check if a service is running
svc_is_active() {
  local svc="$1"
  if [ "$IS_MACOS" = true ]; then
    local label=$(_launchd_label "$svc")
    [ -z "$label" ] && return 1
    launchctl print "system/$label" &>/dev/null 2>&1
  else
    systemctl is-active --quiet "$svc" 2>/dev/null
  fi
}

# Check if a service is enabled (auto-start)
svc_is_enabled() {
  local svc="$1"
  if [ "$IS_MACOS" = true ]; then
    local label=$(_launchd_label "$svc")
    [ -z "$label" ] && return 1
    # launchd: if plist exists in LaunchDaemons and is loaded, it's "enabled"
    launchctl print "system/$label" &>/dev/null 2>&1
  else
    systemctl is-enabled --quiet "$svc" 2>/dev/null
  fi
}

# Start a service
svc_start() {
  local svc="$1"
  if [ "$IS_MACOS" = true ]; then
    local label=$(_launchd_label "$svc")
    [ -z "$label" ] && return 0
    launchctl kickstart "system/$label" 2>/dev/null || true
  else
    systemctl start "$svc" 2>/dev/null
  fi
}

# Stop a service
svc_stop() {
  local svc="$1"
  if [ "$IS_MACOS" = true ]; then
    local label=$(_launchd_label "$svc")
    [ -z "$label" ] && return 0
    launchctl kill SIGTERM "system/$label" 2>/dev/null || true
  else
    systemctl stop "$svc" 2>/dev/null
  fi
}

# Restart a service (stop + start)
svc_restart() {
  local svc="$1"
  if [ "$IS_MACOS" = true ]; then
    local label=$(_launchd_label "$svc")
    [ -z "$label" ] && return 0
    launchctl kickstart -k "system/$label" 2>/dev/null || true
  else
    systemctl restart "$svc" 2>/dev/null
  fi
}

# Enable a service (auto-start on boot)
svc_enable() {
  local svc="$1"
  if [ "$IS_MACOS" = true ]; then
    # launchd: RunAtLoad in plist handles this; load if not already loaded
    local label=$(_launchd_label "$svc")
    [ -z "$label" ] && return 0
    launchctl load "/Library/LaunchDaemons/${label}.plist" 2>/dev/null || true
  else
    systemctl enable "$svc" 2>/dev/null
  fi
}

# Disable a service
svc_disable() {
  local svc="$1"
  if [ "$IS_MACOS" = true ]; then
    local label=$(_launchd_label "$svc")
    [ -z "$label" ] && return 0
    launchctl bootout "system/$label" 2>/dev/null || true
  else
    systemctl disable "$svc" 2>/dev/null
  fi
}

# Reset failed state (Linux-only; no-op on macOS)
svc_reset_failed() {
  if [ "$IS_MACOS" = true ]; then
    return 0
  fi
  systemctl reset-failed $@ 2>/dev/null || true
}

# ─── Platform-Aware System Helpers ───────────────────────────

# Run a command as the service user
run_as_user() {
  if [ "$IS_MACOS" = true ]; then
    sudo -u "$SVC_USER" bash -c "$@"
  else
    runuser -l "$SVC_USER" -c "$@"
  fi
}

# Get all listening TCP ports
get_listening_ports() {
  if [ "$IS_MACOS" = true ]; then
    lsof -iTCP -sTCP:LISTEN -nP 2>/dev/null | awk 'NR>1{print $9}' | awk -F: '{print $NF}' | sort -n | uniq | tr '\n' ',' | sed 's/,$//'
  else
    ss -tlnH 2>/dev/null | awk '{print $4}' | awk -F: '{print $NF}' | sort -n | uniq | tr '\n' ',' | sed 's/,$//'
  fi
}

# Get public IP address
get_public_ip() {
  local ip
  ip=$(curl -sf --connect-timeout 2 http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address 2>/dev/null \
    || curl -sf --connect-timeout 2 "http://169.254.169.254/hetzner/v1/metadata/public-ipv4" 2>/dev/null)
  if [ -z "$ip" ]; then
    if [ "$IS_MACOS" = true ]; then
      ip=$(ipconfig getifaddr en0 2>/dev/null || route get default 2>/dev/null | awk '/interface:/{print $2}' | xargs ipconfig getifaddr 2>/dev/null)
    else
      ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')
    fi
  fi
  echo "$ip"
}

# Firewall: allow a TCP port
fw_allow() {
  local port="$1"
  local comment="${2:-}"
  if [ "$IS_MACOS" = true ]; then
    # macOS BYOS uses relaxed mode — Application Firewall doesn't block by port
    return 0
  else
    ufw allow "$port/tcp" comment "$comment" 2>/dev/null || true
  fi
}

# Firewall: deny/remove a TCP port rule
fw_deny() {
  local port="$1"
  if [ "$IS_MACOS" = true ]; then
    return 0
  else
    ufw delete allow "$port/tcp" 2>/dev/null || true
  fi
}

# Firewall: check if a TCP port is allowed
fw_is_allowed() {
  local port="$1"
  if [ "$IS_MACOS" = true ]; then
    # macOS BYOS: always allowed (relaxed mode)
    return 0
  else
    ufw status | grep -q "${port}/tcp.*ALLOW"
  fi
}

# Get file modification time as epoch seconds
file_mtime() {
  local file="$1"
  if [ "$IS_MACOS" = true ]; then
    stat -f %m "$file" 2>/dev/null || echo 0
  else
    stat -c %Y "$file" 2>/dev/null || echo 0
  fi
}

# In-place sed (macOS requires '' backup arg)
sed_inplace() {
  if [ "$IS_MACOS" = true ]; then
    sed -i '' "$@"
  else
    sed -i "$@"
  fi
}

# base64 encode without line wrapping
b64_encode() {
  if [ "$IS_MACOS" = true ]; then
    base64
  else
    base64 -w0
  fi
}

# base64 encode a file without line wrapping
b64_encode_file() {
  if [ "$IS_MACOS" = true ]; then
    base64 -i "$1"
  else
    base64 -w0 "$1"
  fi
}
