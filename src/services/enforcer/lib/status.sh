#!/bin/bash
# Enforcer Status Functions
# Status reporting and system metrics.

# Write status to local file for file-api WebSocket to broadcast
write_local_status() {
  local CPU="$1"
  local RAM="$2"
  local SESSIONS="$3"
  local TERMINAL_ENABLED="$4"
  local SSH_ENABLED="$5"
  mkdir -p /home/dev/.ellulai
  jq -n \
    --arg cpu "$CPU" \
    --arg ram "$RAM" \
    --argjson sessions "$SESSIONS" \
    --arg terminalEnabled "$TERMINAL_ENABLED" \
    --arg sshEnabled "$SSH_ENABLED" \
    --arg timestamp "$(date -Iseconds)" \
    '{
      cpuUsage: ($cpu | tonumber),
      ramUsage: ($ram | tonumber),
      activeSessions: $sessions,
      terminalEnabled: ($terminalEnabled == "true"),
      sshEnabled: ($sshEnabled == "true"),
      lastSync: $timestamp
    }' > "$STATUS_FILE.tmp" && mv "$STATUS_FILE.tmp" "$STATUS_FILE"
  chown dev:dev "$STATUS_FILE" 2>/dev/null || true
}

# Get deployed apps list
get_deployed_apps() {
  local APPS_DIR="/home/dev/.ellulai/apps"
  if [ -d "$APPS_DIR" ] && ls "$APPS_DIR"/*.json &>/dev/null; then
    echo "["
    local FIRST=true
    for f in "$APPS_DIR"/*.json; do
      [ -f "$f" ] || continue
      [ "$FIRST" = true ] || echo ","
      FIRST=false
      cat "$f"
    done
    echo "]"
  else
    echo "[]"
  fi
}

# Get RAM usage percentage
get_ram_usage() {
  free | awk '/^Mem:/ {printf "%.0f", $3/$2 * 100}'
}

# Get CPU usage percentage
get_cpu_usage() {
  top -bn2 -d 0.5 | grep "Cpu(s)" | tail -1 | awk '{print 100 - $8}' | cut -d. -f1
}
