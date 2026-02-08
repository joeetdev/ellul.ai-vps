#!/bin/bash
# Enforcer Lockdown Functions
# Emergency lockdown when heartbeat fails repeatedly (fail-closed security).

MAX_HEARTBEAT_FAILURES=5

# Emergency lockdown - triggered after MAX_HEARTBEAT_FAILURES consecutive failures
emergency_lockdown() {
  log "EMERGENCY LOCKDOWN: Heartbeat failed $MAX_HEARTBEAT_FAILURES consecutive times."
  log "  Possible causes: Network block by attacker, API down, or misconfiguration."

  # Remove JWT secret to block all token verification
  rm -f /etc/phonestack/jwt-secret
  log "  EMERGENCY: JWT secret removed."

  # Stop all terminal services (disable first to prevent Restart=always from undoing)
  stop_all_terminals

  # Close SSH port
  ufw delete allow 22/tcp 2>/dev/null || true
  systemctl stop sshd 2>/dev/null || true
  log "  EMERGENCY: SSH access disabled."

  # Kill all user processes
  pkill -u dev 2>/dev/null || true
  log "  EMERGENCY: All user processes terminated."

  # SECURITY: Purge persistence mechanisms (same as ownership lockdown)
  crontab -u dev -r 2>/dev/null || true
  rm -f /var/spool/cron/crontabs/dev 2>/dev/null || true
  log "  EMERGENCY: User cron jobs purged."

  for unit in /home/dev/.config/systemd/user/*.timer /home/dev/.config/systemd/user/*.service; do
    [ -f "$unit" ] || continue
    unit_name=$(basename "$unit")
    systemctl --user -M dev@ stop "$unit_name" 2>/dev/null || true
    rm -f "$unit" 2>/dev/null || true
  done
  log "  EMERGENCY: User systemd units removed."

  # Create lockdown marker for recovery detection
  echo "$(date -Iseconds)" > /etc/phonestack/.emergency-lockdown
  chmod 400 /etc/phonestack/.emergency-lockdown
  log "  EMERGENCY: Lockdown marker created. Manual intervention required."
}

# Emergency lockdown recovery loop
emergency_lockdown_loop() {
  # Keep daemon running but in lockdown state - wait for manual recovery
  while true; do
    log "EMERGENCY: In lockdown state. Waiting for recovery..."
    sleep 60
    # M4 FIX: Don't just check API reachability - verify ownership via heartbeat
    # This prevents attacker who blocked heartbeats from unblocking to auto-recover
    local TOKEN=$(get_token)
    if [ -n "$TOKEN" ]; then
      local RECOVERY_RESPONSE=$(curl -sS --connect-timeout 5 --max-time 10 \
        "$API_URL/api/servers/heartbeat" \
        -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"recoveryCheck":true}' 2>/dev/null)

      if [ -n "$RECOVERY_RESPONSE" ]; then
        local RECOVERY_USER_ID=$(echo "$RECOVERY_RESPONSE" | jq -r '.userId // ""')
        local LOCKED_OWNER=$(cat "$OWNER_LOCK_FILE" 2>/dev/null | tr -d '\n')

        if [ -n "$RECOVERY_USER_ID" ] && [ "$RECOVERY_USER_ID" != "null" ] && [ "$RECOVERY_USER_ID" = "$LOCKED_OWNER" ]; then
          log "EMERGENCY RECOVERY: Ownership verified ($RECOVERY_USER_ID). Lifting lockdown..."
          rm -f /etc/phonestack/.emergency-lockdown
          reset_failure_count
          # Restart the enforcer to restore normal operation
          exec "$0" daemon
        else
          log "EMERGENCY: API reachable but ownership mismatch (API: $RECOVERY_USER_ID, Lock: $LOCKED_OWNER). Staying in lockdown."
        fi
      fi
    fi
  done
}
