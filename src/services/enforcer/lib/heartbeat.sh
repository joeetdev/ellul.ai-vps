#!/bin/bash
# Enforcer Heartbeat Functions
# Heartbeat, sync, and communication with ellul.ai API.

# Get all listening TCP ports (for ghost port detection)
get_active_ports() {
  get_listening_ports
}

# Get auth token
get_token() {
  if [ -z "$TOKEN" ]; then
    TOKEN=$(grep ELLULAI_AI_TOKEN "${SVC_HOME}/.bashrc" 2>/dev/null | cut -d'"' -f2 || true)
  fi
  echo "$TOKEN"
}

# Ed25519 heartbeat signing (Phase 4: asymmetric auth)
# Signs timestamp:serverId with private key. API verifies with stored public key.
# Compromised API cannot forge heartbeats — only the VPS holds the private key.
HEARTBEAT_KEY_FILE="/etc/ellulai/heartbeat.key"
HEARTBEAT_PUB_FILE="/etc/ellulai/heartbeat.pub"
SERVER_ID_FILE="/etc/ellulai/server-id"

# Compute Ed25519 signature for heartbeat
# Sets: HB_SIGNATURE, HB_TIMESTAMP, HB_SERVER_ID, HB_PUBKEY
compute_heartbeat_signature() {
  HB_SIGNATURE=""
  HB_TIMESTAMP=""
  HB_SERVER_ID=""
  HB_PUBKEY=""

  [ ! -f "$HEARTBEAT_KEY_FILE" ] && return

  HB_TIMESTAMP=$(date +%s)
  HB_SERVER_ID=$(cat "$SERVER_ID_FILE" 2>/dev/null | tr -d '\n')
  [ -z "$HB_SERVER_ID" ] && return

  local SIGN_DATA="${HB_TIMESTAMP}:${HB_SERVER_ID}"
  HB_SIGNATURE=$(printf '%s' "$SIGN_DATA" | openssl pkeyutl -sign -inkey "$HEARTBEAT_KEY_FILE" 2>/dev/null | b64_encode 2>/dev/null || echo "")

  # Read public key for first-write-wins registration (base64-encoded for HTTP header safety)
  if [ -f "$HEARTBEAT_PUB_FILE" ]; then
    HB_PUBKEY=$(b64_encode_file "$HEARTBEAT_PUB_FILE" 2>/dev/null || echo "")
  fi
}

# Execute curl with optional Ed25519 signature headers
# Usage: heartbeat_curl <url> <payload>
heartbeat_curl() {
  local HB_URL="$1"
  local HB_PAYLOAD="$2"
  local HB_CURL_ARGS=()

  HB_CURL_ARGS+=(-s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10)
  HB_CURL_ARGS+=("$HB_URL" -X POST)
  HB_CURL_ARGS+=(-H "Authorization: Bearer $TOKEN")
  HB_CURL_ARGS+=(-H "Content-Type: application/json")

  # Ed25519 signature headers (present when keypair exists)
  if [ -n "$HB_SIGNATURE" ]; then
    HB_CURL_ARGS+=(-H "X-Heartbeat-Signature: $HB_SIGNATURE")
    HB_CURL_ARGS+=(-H "X-Heartbeat-Timestamp: $HB_TIMESTAMP")
    HB_CURL_ARGS+=(-H "X-Server-Id: $HB_SERVER_ID")
    if [ -n "$HB_PUBKEY" ]; then
      HB_CURL_ARGS+=(-H "X-Heartbeat-Public-Key: $HB_PUBKEY")
    fi
  fi

  HB_CURL_ARGS+=(-d "$HB_PAYLOAD")
  curl "${HB_CURL_ARGS[@]}" 2>/dev/null
}

# Main heartbeat function
# Phase 4: One-way heartbeat. VPS sends telemetry, response body is DISCARDED.
# All operational commands now route through the passkey-authenticated bridge.
# A compromised API cannot inject any data, commands, or credentials into the VPS.
heartbeat() {
  local TOKEN=$(get_token)
  [ -z "$TOKEN" ] && { log "Error: ELLULAI_AI_TOKEN not set"; return 1; }
  local ACTIVE_SESSIONS=$(get_active_sessions)
  local RAM_USAGE=$(get_ram_usage)
  local CPU_USAGE=$(get_cpu_usage)
  local DEPLOYED_APPS=$(get_deployed_apps)
  local SSH_KEY_COUNT=$(get_ssh_key_count)
  local OPEN_PORTS=$(get_active_ports)
  local CURRENT_TAG=$(cat "$AGENT_VERSION_FILE" 2>/dev/null | tr -d '\n')
  # Read local settings (VPS source of truth)
  local SETTINGS_FILE="/etc/ellulai/settings.json"
  local LOCAL_TERMINAL=$(jq -r '.terminalEnabled // true' "$SETTINGS_FILE" 2>/dev/null || echo "true")
  local LOCAL_SSH=$(jq -r '.sshEnabled // false' "$SETTINGS_FILE" 2>/dev/null || echo "false")
  # Cryptographic audit chain head (Phase 4, Step 16: tamper-evident audit trail)
  local CHAIN_HEAD=$(cat /etc/ellulai/audit-chain-head 2>/dev/null || echo '{"seq":0,"hash":"genesis"}')
  # Agent telemetry
  local AGENT_STATUS=$(get_agent_status)
  local PAYLOAD=$(jq -n \
    --argjson activeSessions "$ACTIVE_SESSIONS" \
    --argjson deployments "$DEPLOYED_APPS" \
    --arg ramUsage "$RAM_USAGE" \
    --arg cpuUsage "$CPU_USAGE" \
    --arg securityTier "$(detect_security_tier)" \
    --arg sshKeyCount "$SSH_KEY_COUNT" \
    --arg openPorts "$OPEN_PORTS" \
    --arg currentTag "${CURRENT_TAG:-}" \
    --arg localTerminal "$LOCAL_TERMINAL" \
    --arg localSsh "$LOCAL_SSH" \
    --argjson auditChainHead "$CHAIN_HEAD" \
    --argjson agentStatus "$AGENT_STATUS" \
    '{activeSessions: $activeSessions, deployments: $deployments, ramUsage: ($ramUsage | tonumber), cpuUsage: ($cpuUsage | tonumber), securityTier: $securityTier, sshKeyCount: ($sshKeyCount | tonumber), open_ports: ($openPorts | split(",") | map(select(. != "") | tonumber)), currentTag: $currentTag, secretsLocal: true, localTerminalEnabled: ($localTerminal == "true"), localSshEnabled: ($localSsh == "true"), auditChainHead: $auditChainHead, agentStatus: $agentStatus}')

  # Ed25519 signature (Phase 4: asymmetric auth)
  compute_heartbeat_signature

  # POST telemetry, discard response body entirely (-o /dev/null)
  # Only capture HTTP status code — even a compromised API response is never read
  local HTTP_CODE=$(heartbeat_curl "$API_URL/api/servers/heartbeat" "$PAYLOAD")

  if [ "$HTTP_CODE" = "200" ]; then
    HEARTBEAT_FAILURES=0
  else
    HEARTBEAT_FAILURES=$((HEARTBEAT_FAILURES + 1))
    log "Heartbeat failed (HTTP $HTTP_CODE), failure count: $HEARTBEAT_FAILURES"
  fi

  # VPS-driven enforcement: reads LOCAL state only, never API response
  local TERMINAL_ENABLED=$(jq -r '.terminalEnabled // "true"' "$SETTINGS_FILE" 2>/dev/null || echo "true")
  local SSH_ENABLED=$(jq -r '.sshEnabled // "false"' "$SETTINGS_FILE" 2>/dev/null || echo "false")
  enforce_settings "$TERMINAL_ENABLED" "$SSH_ENABLED"
  ensure_daemon_port
}

# Raw heartbeat with full processing - writes local status for WebSocket broadcast
heartbeat_raw() {
  local TOKEN=$(get_token)
  [ -z "$TOKEN" ] && { log "Error: ELLULAI_AI_TOKEN not set"; return 1; }
  local ACTIVE_SESSIONS=$(get_active_sessions)
  local RAM_USAGE=$(get_ram_usage)
  local CPU_USAGE=$(get_cpu_usage)
  local DEPLOYED_APPS=$(get_deployed_apps)
  local SSH_KEY_COUNT=$(get_ssh_key_count)
  local OPEN_PORTS=$(get_active_ports)
  local CURRENT_TAG=$(cat "$AGENT_VERSION_FILE" 2>/dev/null | tr -d '\n')
  # Read local settings (VPS source of truth)
  local SETTINGS_FILE="/etc/ellulai/settings.json"
  local LOCAL_TERMINAL=$(jq -r '.terminalEnabled // true' "$SETTINGS_FILE" 2>/dev/null || echo "true")
  local LOCAL_SSH=$(jq -r '.sshEnabled // false' "$SETTINGS_FILE" 2>/dev/null || echo "false")
  # Cryptographic audit chain head (Phase 4, Step 16: tamper-evident audit trail)
  local CHAIN_HEAD=$(cat /etc/ellulai/audit-chain-head 2>/dev/null || echo '{"seq":0,"hash":"genesis"}')
  # Agent telemetry
  local AGENT_STATUS=$(get_agent_status)
  local PAYLOAD=$(jq -n \
    --argjson activeSessions "$ACTIVE_SESSIONS" \
    --argjson deployments "$DEPLOYED_APPS" \
    --arg ramUsage "$RAM_USAGE" \
    --arg cpuUsage "$CPU_USAGE" \
    --arg securityTier "$(detect_security_tier)" \
    --arg sshKeyCount "$SSH_KEY_COUNT" \
    --arg openPorts "$OPEN_PORTS" \
    --arg currentTag "${CURRENT_TAG:-}" \
    --arg localTerminal "$LOCAL_TERMINAL" \
    --arg localSsh "$LOCAL_SSH" \
    --argjson auditChainHead "$CHAIN_HEAD" \
    --argjson agentStatus "$AGENT_STATUS" \
    '{activeSessions: $activeSessions, deployments: $deployments, ramUsage: ($ramUsage | tonumber), cpuUsage: ($cpuUsage | tonumber), securityTier: $securityTier, sshKeyCount: ($sshKeyCount | tonumber), open_ports: ($openPorts | split(",") | map(select(. != "") | tonumber)), currentTag: $currentTag, secretsLocal: true, localTerminalEnabled: ($localTerminal == "true"), localSshEnabled: ($localSsh == "true"), auditChainHead: $auditChainHead, agentStatus: $agentStatus}')

  # Ed25519 signature (Phase 4: asymmetric auth)
  compute_heartbeat_signature

  # POST telemetry, discard response body entirely
  local HTTP_CODE=$(heartbeat_curl "$API_URL/api/servers/heartbeat" "$PAYLOAD")

  # VPS-driven enforcement MUST run regardless of heartbeat success/failure.
  # Moving this before the HTTP status check prevents SSH lockout when API is unreachable.
  local TERMINAL_ENABLED=$(jq -r '.terminalEnabled // "true"' "$SETTINGS_FILE" 2>/dev/null || echo "true")
  local SSH_ENABLED=$(jq -r '.sshEnabled // "false"' "$SETTINGS_FILE" 2>/dev/null || echo "false")
  enforce_settings "$TERMINAL_ENABLED" "$SSH_ENABLED"
  ensure_daemon_port

  if [ "$HTTP_CODE" = "200" ]; then
    HEARTBEAT_FAILURES=0
  else
    HEARTBEAT_FAILURES=$((HEARTBEAT_FAILURES + 1))
    log "Heartbeat failed (HTTP $HTTP_CODE), failure count: $HEARTBEAT_FAILURES"
    return 1
  fi

  # Write local status for WebSocket broadcast (only on successful heartbeat)
  write_local_status "$CPU_USAGE" "$RAM_USAGE" "$ACTIVE_SESSIONS" "$TERMINAL_ENABLED" "$SSH_ENABLED"
}
