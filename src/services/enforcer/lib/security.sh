#!/bin/bash
# Enforcer Security Functions
# Security tier detection, identity pinning, and lockdown.

# Detect security tier based on system state
detect_security_tier() {
  local TERMINAL_DISABLED_MARKER="/etc/ellulai/.terminal-disabled"
  local SHIELD_ACTIVE=$(systemctl is-active ellulai-sovereign-shield 2>/dev/null || echo "inactive")
  local HAS_SSH_KEY=false
  local HAS_PASSKEY=false

  if [ -f /home/dev/.ssh/authorized_keys ] && [ -s /home/dev/.ssh/authorized_keys ]; then
    HAS_SSH_KEY=true
  fi

  # Check for passkey in local SQLite
  local CRED_COUNT=$(node -e "try{const d=require('/opt/ellulai/auth/node_modules/better-sqlite3')('/etc/ellulai/local-auth.db');console.log(d.prepare('SELECT COUNT(*) as c FROM credential').get().c)}catch(e){console.log(0)}" 2>/dev/null || echo "0")
  if [ "$CRED_COUNT" -gt 0 ]; then
    HAS_PASSKEY=true
  fi

  # SSH Only: Terminal completely disabled marker exists AND has SSH key
  if [ -f "$TERMINAL_DISABLED_MARKER" ] && [ "$HAS_SSH_KEY" = "true" ]; then
    echo "ssh_only"
  # Web Locked: Shield active with passkey registered
  elif [ "$SHIELD_ACTIVE" = "active" ] && [ "$HAS_PASSKEY" = "true" ]; then
    echo "web_locked"
  # Standard: Default tier (web terminal with JWT, no SSH)
  else
    echo "standard"
  fi
}

# Persist heartbeat failure counter across restarts
load_failure_count() {
  if [ -f "$HEARTBEAT_FAILURE_FILE" ]; then
    cat "$HEARTBEAT_FAILURE_FILE" 2>/dev/null || echo "0"
  else
    echo "0"
  fi
}

save_failure_count() {
  echo "$1" > "$HEARTBEAT_FAILURE_FILE"
}

reset_failure_count() {
  rm -f "$HEARTBEAT_FAILURE_FILE" 2>/dev/null || true
}

# Identity Pinning: Verify API-reported owner matches immutable lockfile
verify_owner() {
  local API_USER_ID="$1"
  local JWT_SECRET="$2"
  [ -z "$API_USER_ID" ] || [ "$API_USER_ID" = "null" ] && return 0

  if [ ! -f "$OWNER_LOCK_FILE" ]; then
    # First-write-wins: pool servers get owner.lock on first heartbeat with userId
    log "Owner lockfile missing — pinning owner to $API_USER_ID"
    echo "$API_USER_ID" > "$OWNER_LOCK_FILE"
    chmod 400 "$OWNER_LOCK_FILE"
    chattr +i "$OWNER_LOCK_FILE" 2>/dev/null || true
    return 0
  fi

  local LOCKED_OWNER=$(cat "$OWNER_LOCK_FILE" 2>/dev/null | tr -d '\n')
  local JWT_SECRET_FILE="/etc/ellulai/jwt-secret"

  if [ "$API_USER_ID" != "$LOCKED_OWNER" ]; then
    # MISMATCH: Hard Lockdown - restore to known-good state
    log "SECURITY CRITICAL: Ownership mismatch! API sends $API_USER_ID, Lock is $LOCKED_OWNER. Entering Lockdown."

    # Create lockdown marker
    echo "$(date -Iseconds)" > "$LOCKDOWN_MARKER"
    chmod 400 "$LOCKDOWN_MARKER"

    # Block access: destroy JWT secret (stops all token verification)
    if [ -f "$JWT_SECRET_FILE" ]; then
      rm -f "$JWT_SECRET_FILE"
      log "  LOCKDOWN: JWT secret removed (token verification disabled)."
    fi

    # Block access: kill active terminals
    stop_all_terminals

    # SECURITY: Purge user cron jobs (attacker persistence)
    crontab -u dev -r 2>/dev/null || true
    rm -f /var/spool/cron/crontabs/dev 2>/dev/null || true
    log "  LOCKDOWN: User cron jobs purged."

    # SECURITY: Disable and remove user-installed systemd timers/services
    for unit in /home/dev/.config/systemd/user/*.timer /home/dev/.config/systemd/user/*.service; do
      [ -f "$unit" ] || continue
      unit_name=$(basename "$unit")
      systemctl --user -M dev@ stop "$unit_name" 2>/dev/null || true
      systemctl --user -M dev@ disable "$unit_name" 2>/dev/null || true
      rm -f "$unit" 2>/dev/null || true
      log "  LOCKDOWN: Removed user systemd unit: $unit_name"
    done

    # SECURITY: Kill all user processes to terminate any running backdoors
    pkill -u dev 2>/dev/null || true
    log "  LOCKDOWN: All user processes terminated."

    # SECURITY: Close SSH port (will be re-enabled on recovery if keys exist)
    ufw delete allow 22/tcp 2>/dev/null || true
    systemctl stop sshd 2>/dev/null || true
    log "  LOCKDOWN: SSH access disabled."

    log "  LOCKDOWN: Hibernating until ownership restored."
    return 1
  fi

  # MATCH: Check if recovering from lockdown
  if [ -f "$LOCKDOWN_MARKER" ] && [ -n "$JWT_SECRET" ] && [ "$JWT_SECRET" != "null" ]; then
    log "RECOVERY: Ownership verified. Lifting lockdown..."

    # Restore JWT secret
    echo "$JWT_SECRET" > "$JWT_SECRET_FILE"
    chmod 600 "$JWT_SECRET_FILE"
    chown root:root "$JWT_SECRET_FILE"
    log "  RECOVERY: JWT secret restored."

    # Re-enable SSH if keys exist
    if [ -f /home/dev/.ssh/authorized_keys ] && [ -s /home/dev/.ssh/authorized_keys ]; then
      ufw allow 22/tcp comment 'SSH' 2>/dev/null || true
      systemctl start sshd 2>/dev/null || true
      log "  RECOVERY: SSH access restored."
    fi

    # Remove lockdown marker first so start_all_terminals works
    rm -f "$LOCKDOWN_MARKER"

    # Restart terminals
    start_all_terminals
    log "  RECOVERY: Terminals restarted."

    log "RECOVERY: Lockdown lifted. Services restored."
  fi

  return 0
}

# Get SSH key count from authorized_keys
get_ssh_key_count() {
  local AUTH_KEYS="/home/dev/.ssh/authorized_keys"
  if [ -f "$AUTH_KEYS" ] && [ -s "$AUTH_KEYS" ]; then
    grep -c '^ssh-' "$AUTH_KEYS" 2>/dev/null || echo "0"
  else
    echo "0"
  fi
}
