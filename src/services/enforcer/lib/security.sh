#!/bin/bash
# Enforcer Security Functions
# Security tier detection, identity pinning, and lockdown.

# Detect security tier based on system state
detect_security_tier() {
  local TERMINAL_DISABLED_MARKER="/etc/ellulai/.terminal-disabled"
  local SHIELD_ACTIVE=$(systemctl is-active ellulai-sovereign-shield 2>/dev/null || echo "inactive")
  local HAS_SSH_KEY=false
  local HAS_PASSKEY=false

  if [ -f "${SVC_HOME}/.ssh/authorized_keys" ] && [ -s "${SVC_HOME}/.ssh/authorized_keys" ]; then
    HAS_SSH_KEY=true
  fi

  # Check for passkey in local SQLite
  local CRED_COUNT=$(node -e "try{const d=require('/opt/ellulai/auth/node_modules/better-sqlite3')('/etc/ellulai/local-auth.db');console.log(d.prepare('SELECT COUNT(*) as c FROM credential').get().c)}catch(e){console.log(0)}" 2>/dev/null || echo "0")
  if [ "$CRED_COUNT" -gt 0 ]; then
    HAS_PASSKEY=true
  fi

  # Web Locked: Shield active with passkey registered
  if [ "$SHIELD_ACTIVE" = "active" ] && [ "$HAS_PASSKEY" = "true" ]; then
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

# Phase 4: verify_owner() REMOVED. Owner.lock is set once during cloud-init
# provisioning and is immutable (chattr +i). The API can no longer inject a
# userId that would trigger ownership lockdown. Identity pinning is still
# enforced — it's just set at boot, not verified against API on every heartbeat.

# Get SSH key count from authorized_keys
get_ssh_key_count() {
  local AUTH_KEYS="${SVC_HOME}/.ssh/authorized_keys"
  if [ -f "$AUTH_KEYS" ] && [ -s "$AUTH_KEYS" ]; then
    grep -c '^ssh-' "$AUTH_KEYS" 2>/dev/null || echo "0"
  else
    echo "0"
  fi
}
