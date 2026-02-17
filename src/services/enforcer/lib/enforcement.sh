#!/bin/bash
# Enforcer Enforcement Functions
# Settings enforcement (local settings.json application).
#
# Phase 4 cleanup: The following command handlers were moved to the
# sovereign-shield bridge and are no longer processed by the enforcer:
#   - execute_kill_orders()   — terminal session kills
#   - handle_security_action() — tier switching, shield updates
#   - handle_git_action()     — git setup/push/pull/teardown
#   - kill_dev_ports()        — dev port process killing
# These are now handled via WebSocket bridge commands routed through
# sovereign-shield (port 3005) instead of heartbeat polling.

# Enforce tier-based settings
enforce_settings() {
  local TERMINAL_ENABLED="$1"
  local SSH_ENABLED="$2"

  # Get current security tier
  local TIER=$(detect_security_tier)

  # Enforce tier-based rules (override platform settings if needed)
  case "$TIER" in
    standard)
      SSH_ENABLED="false"
      TERMINAL_ENABLED="true"
      ;;
    web_locked)
      TERMINAL_ENABLED="true"
      if [ -f "${SVC_HOME}/.ssh/authorized_keys" ] && [ -s "${SVC_HOME}/.ssh/authorized_keys" ]; then
        SSH_ENABLED="true"
      else
        SSH_ENABLED="false"
      fi
      ;;
  esac

  # SAFETY CHECK: Never close SSH if keys are present (prevents lockout)
  if [ -f "${SVC_HOME}/.ssh/authorized_keys" ] && [ -s "${SVC_HOME}/.ssh/authorized_keys" ]; then
    SSH_ENABLED="true"
    log "SSH keys present at ${SVC_HOME}/.ssh/authorized_keys - keeping SSH enabled regardless of tier"
  else
    log "WARN: No SSH keys found at ${SVC_HOME}/.ssh/authorized_keys (SVC_HOME=${SVC_HOME}) - SSH safety check did not trigger"
  fi

  # Enforce SSH state
  if [ "$SSH_ENABLED" = "false" ]; then
    fw_is_allowed 22 && fw_deny 22
  elif [ "$SSH_ENABLED" = "true" ]; then
    fw_is_allowed 22 || fw_allow 22 'SSH'
  fi

  local TERMINAL_DISABLED_MARKER="/etc/ellulai/shield-data/.terminal-disabled"
  if [ -f "$TERMINAL_DISABLED_MARKER" ]; then
    stop_all_terminals
  elif [ "$TERMINAL_ENABLED" = "false" ]; then
    stop_all_terminals
  elif [ "$TERMINAL_ENABLED" = "true" ]; then
    if [ -f /etc/ellulai/jwt-secret ] || [ "$TIER" = "web_locked" ]; then
      start_all_terminals
    fi
  fi

  echo "{\"terminalEnabled\": $TERMINAL_ENABLED, \"sshEnabled\": $SSH_ENABLED, \"tier\": \"$TIER\", \"enforcedAt\": \"$(date -Iseconds)\"}" > "$STATE_FILE"
}

# VPS-DRIVEN SECURITY: SSH keys are NEVER accepted from the platform.
# All SSH key management happens on the VPS via:
# - Standard tier: N/A (SSH disabled)
# - Web Locked tier: Via passkey-protected UI (/_auth/keys)
handle_keys() {
  local INSTALL_KEY="$1"
  [ -z "$INSTALL_KEY" ] || [ "$INSTALL_KEY" = "null" ] && return 0

  # BLOCKED: Platform should never push SSH keys
  log "SECURITY: Platform attempted SSH key injection. BLOCKED."
  log "  VPS is the source of truth for SSH keys. Manage keys via VPS only."
  return 0
}

# sync_secrets() — REMOVED (Phase 2: secrets managed locally by sovereign-shield)
# Secrets are now sent directly from browser to VPS via /_auth/secrets endpoints.
# The enforcer no longer receives or processes encrypted secrets.
