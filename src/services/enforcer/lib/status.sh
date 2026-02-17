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
  mkdir -p "${SVC_HOME}/.ellulai"
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
  chown ${SVC_USER}:${SVC_USER} "$STATUS_FILE" 2>/dev/null || true
}

# Get deployed apps list
get_deployed_apps() {
  local APPS_DIR="${SVC_HOME}/.ellulai/apps"
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
  if [ "$IS_MACOS" = true ]; then
    local page_size=$(sysctl -n hw.pagesize 2>/dev/null || echo 4096)
    local total_mem=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
    local vm_info=$(vm_stat 2>/dev/null)
    local pages_active=$(echo "$vm_info" | awk '/Pages active:/ {gsub(/\./, "", $3); print $3}')
    local pages_wired=$(echo "$vm_info" | awk '/Pages wired down:/ {gsub(/\./, "", $4); print $4}')
    local pages_compressed=$(echo "$vm_info" | awk '/Pages occupied by compressor:/ {gsub(/\./, "", $5); print $5}')
    local used_mem=$(( (${pages_active:-0} + ${pages_wired:-0} + ${pages_compressed:-0}) * page_size ))
    if [ "$total_mem" -gt 0 ]; then
      echo "$used_mem $total_mem" | awk '{printf "%.0f", $1/$2 * 100}'
    else
      echo "0"
    fi
  else
    free | awk '/^Mem:/ {printf "%.0f", $3/$2 * 100}'
  fi
}

# Get CPU usage percentage
get_cpu_usage() {
  if [ "$IS_MACOS" = true ]; then
    # Sum per-process CPU usage and normalize by core count
    local ncpu=$(sysctl -n hw.ncpu 2>/dev/null || echo 1)
    ps -A -o %cpu 2>/dev/null | awk -v n="$ncpu" 'NR>1{s+=$1} END {v=s/n; if(v>100) v=100; printf "%.0f", v}'
  else
    top -bn2 -d 0.5 | grep "Cpu(s)" | tail -1 | awk '{print 100 - $8}' | cut -d. -f1
  fi
}
