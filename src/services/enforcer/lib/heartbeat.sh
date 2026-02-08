#!/bin/bash
# Enforcer Heartbeat Functions
# Heartbeat, sync, and communication with Phone Stack API.

# Get all listening TCP ports (for ghost port detection)
get_active_ports() {
  ss -tlnH 2>/dev/null | awk '{print $4}' | awk -F: '{print $NF}' | sort -n | uniq | tr '\n' ',' | sed 's/,$//'
}

# Get auth token
get_token() {
  if [ -z "$TOKEN" ]; then
    TOKEN=$(grep PHONESTACK_AI_TOKEN /home/dev/.bashrc 2>/dev/null | cut -d'"' -f2 || true)
  fi
  echo "$TOKEN"
}

# Main heartbeat function
heartbeat() {
  local TOKEN=$(get_token)
  [ -z "$TOKEN" ] && { log "Error: PHONESTACK_AI_TOKEN not set"; return 1; }
  local ACTIVE_SESSIONS=$(get_active_sessions)
  local RAM_USAGE=$(get_ram_usage)
  local CPU_USAGE=$(get_cpu_usage)
  local DEPLOYED_APPS=$(get_deployed_apps)
  local SSH_KEY_COUNT=$(get_ssh_key_count)
  local OPEN_PORTS=$(get_active_ports)
  local CURRENT_TAG=$(cat "$AGENT_VERSION_FILE" 2>/dev/null | tr -d '\n')
  local PAYLOAD=$(jq -n \
    --argjson activeSessions "$ACTIVE_SESSIONS" \
    --argjson deployments "$DEPLOYED_APPS" \
    --arg ramUsage "$RAM_USAGE" \
    --arg cpuUsage "$CPU_USAGE" \
    --arg securityTier "$(detect_security_tier)" \
    --arg sshKeyCount "$SSH_KEY_COUNT" \
    --arg openPorts "$OPEN_PORTS" \
    --arg currentTag "${CURRENT_TAG:-}" \
    '{activeSessions: $activeSessions, deployments: $deployments, ramUsage: ($ramUsage | tonumber), cpuUsage: ($cpuUsage | tonumber), securityTier: $securityTier, sshKeyCount: ($sshKeyCount | tonumber), open_ports: ($openPorts | split(",") | map(select(. != "") | tonumber)), currentTag: $currentTag}')
  RESPONSE=$(curl -sS --connect-timeout 5 --max-time 10 \
    "$API_URL/api/servers/heartbeat" \
    -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" 2>/dev/null)
  [ -z "$RESPONSE" ] && return 1
  echo "$RESPONSE" | jq -e '.error' >/dev/null 2>&1 && { log "Error: $(echo "$RESPONSE" | jq -r '.error')"; return 1; }

  # IDENTITY PINNING: Verify owner before accepting ANY commands
  local API_USER_ID=$(echo "$RESPONSE" | jq -r '.userId // ""')
  local JWT_SECRET=$(echo "$RESPONSE" | jq -r '.jwtSecret // ""')
  if ! verify_owner "$API_USER_ID" "$JWT_SECRET"; then
    # Ownership mismatch - in lockdown, skip all commands
    return 0
  fi

  local TERMINAL_ENABLED=$(echo "$RESPONSE" | jq -r 'if .terminalEnabled == null then "true" else .terminalEnabled end')
  local CURRENT_SSH=$(ufw status | grep -q "22/tcp.*ALLOW" && echo "true" || echo "false")
  local SSH_ENABLED=$(echo "$RESPONSE" | jq -r --arg current "$CURRENT_SSH" 'if .sshEnabled == null then $current else .sshEnabled end')
  local KILL_SESSIONS=$(echo "$RESPONSE" | jq -c '.killSessions // []')
  local SECRETS=$(echo "$RESPONSE" | jq -c '.secrets // []')
  local KILL_PORTS=$(echo "$RESPONSE" | jq -c '.killPorts // null')
  local SECURITY_ACTION=$(echo "$RESPONSE" | jq -r '.securityAction // ""')
  local SHIELD_SETUP_TOKEN=$(echo "$RESPONSE" | jq -r '.shieldSetupToken // ""')
  local GIT_ACTION=$(echo "$RESPONSE" | jq -r '.gitAction // ""')
  local ACTIVE_GIT_APP=$(echo "$RESPONSE" | jq -r '.activeGitApp // ""')

  # VPS-DRIVEN: SSH keys are managed on VPS only, not accepted from platform
  enforce_settings "$TERMINAL_ENABLED" "$SSH_ENABLED"
  kill_dev_ports "$KILL_PORTS"
  execute_kill_orders "$KILL_SESSIONS"
  sync_secrets "$SECRETS"
  handle_security_action "$SECURITY_ACTION" "$SHIELD_SETUP_TOKEN"
  handle_git_action "$GIT_ACTION" "$ACTIVE_GIT_APP"
  switch_deployment_model "$RESPONSE"
}

# Raw heartbeat with full processing - returns response
heartbeat_raw() {
  local TOKEN=$(get_token)
  [ -z "$TOKEN" ] && { log "Error: PHONESTACK_AI_TOKEN not set"; return 1; }
  local ACTIVE_SESSIONS=$(get_active_sessions)
  local RAM_USAGE=$(get_ram_usage)
  local CPU_USAGE=$(get_cpu_usage)
  local DEPLOYED_APPS=$(get_deployed_apps)
  local SSH_KEY_COUNT=$(get_ssh_key_count)
  local OPEN_PORTS=$(get_active_ports)
  local CURRENT_TAG=$(cat "$AGENT_VERSION_FILE" 2>/dev/null | tr -d '\n')
  local PAYLOAD=$(jq -n \
    --argjson activeSessions "$ACTIVE_SESSIONS" \
    --argjson deployments "$DEPLOYED_APPS" \
    --arg ramUsage "$RAM_USAGE" \
    --arg cpuUsage "$CPU_USAGE" \
    --arg securityTier "$(detect_security_tier)" \
    --arg sshKeyCount "$SSH_KEY_COUNT" \
    --arg openPorts "$OPEN_PORTS" \
    --arg currentTag "${CURRENT_TAG:-}" \
    '{activeSessions: $activeSessions, deployments: $deployments, ramUsage: ($ramUsage | tonumber), cpuUsage: ($cpuUsage | tonumber), securityTier: $securityTier, sshKeyCount: ($sshKeyCount | tonumber), open_ports: ($openPorts | split(",") | map(select(. != "") | tonumber)), currentTag: $currentTag}')
  local RESPONSE=$(curl -sS --connect-timeout 5 --max-time 10 \
    "$API_URL/api/servers/heartbeat" \
    -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" 2>/dev/null)
  [ -z "$RESPONSE" ] && return 1
  echo "$RESPONSE" | jq -e '.error' >/dev/null 2>&1 && { log "Error: $(echo "$RESPONSE" | jq -r '.error')"; return 1; }

  # IDENTITY PINNING: Verify owner before accepting ANY commands
  local API_USER_ID=$(echo "$RESPONSE" | jq -r '.userId // ""')
  local JWT_SECRET=$(echo "$RESPONSE" | jq -r '.jwtSecret // ""')
  if ! verify_owner "$API_USER_ID" "$JWT_SECRET"; then
    # Ownership mismatch - in lockdown, skip all commands
    echo "$RESPONSE"
    return 0
  fi

  local TERMINAL_ENABLED=$(echo "$RESPONSE" | jq -r 'if .terminalEnabled == null then "true" else .terminalEnabled end')
  local CURRENT_SSH=$(ufw status | grep -q "22/tcp.*ALLOW" && echo "true" || echo "false")
  local SSH_ENABLED=$(echo "$RESPONSE" | jq -r --arg current "$CURRENT_SSH" 'if .sshEnabled == null then $current else .sshEnabled end')
  local KILL_SESSIONS=$(echo "$RESPONSE" | jq -c '.killSessions // []')
  local SECRETS=$(echo "$RESPONSE" | jq -c '.secrets // []')
  local KILL_PORTS=$(echo "$RESPONSE" | jq -c '.killPorts // null')
  local SECURITY_ACTION=$(echo "$RESPONSE" | jq -r '.securityAction // ""')
  local SHIELD_SETUP_TOKEN=$(echo "$RESPONSE" | jq -r '.shieldSetupToken // ""')
  local GIT_ACTION=$(echo "$RESPONSE" | jq -r '.gitAction // ""')
  local ACTIVE_GIT_APP=$(echo "$RESPONSE" | jq -r '.activeGitApp // ""')

  # VPS-DRIVEN: SSH keys are managed on VPS only, not accepted from platform
  enforce_settings "$TERMINAL_ENABLED" "$SSH_ENABLED"
  kill_dev_ports "$KILL_PORTS"
  execute_kill_orders "$KILL_SESSIONS"
  sync_secrets "$SECRETS"
  handle_security_action "$SECURITY_ACTION" "$SHIELD_SETUP_TOKEN"
  handle_git_action "$GIT_ACTION" "$ACTIVE_GIT_APP"
  switch_deployment_model "$RESPONSE"

  # Write local status for WebSocket broadcast
  write_local_status "$CPU_USAGE" "$RAM_USAGE" "$ACTIVE_SESSIONS" "$TERMINAL_ENABLED" "$SSH_ENABLED"

  echo "$RESPONSE"
}

# Sync all secrets from platform
sync_all() {
  local TOKEN=$(get_token)
  [ -z "$TOKEN" ] && { log "Error: PHONESTACK_AI_TOKEN not set"; return 1; }
  RESPONSE=$(curl -sS --connect-timeout 10 --max-time 30 \
    "$API_URL/api/servers/secrets/sync" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" 2>/dev/null)
  [ -z "$RESPONSE" ] && { log "Error: Empty response"; return 1; }
  echo "$RESPONSE" | jq -e '.error' >/dev/null 2>&1 && { log "Error: $(echo "$RESPONSE" | jq -r '.error')"; return 1; }
  local TERMINAL_ENABLED=$(echo "$RESPONSE" | jq -r 'if .terminalEnabled == null then "true" else .terminalEnabled end')
  local CURRENT_SSH=$(ufw status | grep -q "22/tcp.*ALLOW" && echo "true" || echo "false")
  local SSH_ENABLED=$(echo "$RESPONSE" | jq -r --arg current "$CURRENT_SSH" 'if .sshEnabled == null then $current else .sshEnabled end')
  enforce_settings "$TERMINAL_ENABLED" "$SSH_ENABLED"
  local SECRETS=$(echo "$RESPONSE" | jq -c '.secrets // []')
  sync_secrets "$SECRETS"
  log "Sync complete"
}
