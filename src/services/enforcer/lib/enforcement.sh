#!/bin/bash
# Enforcer Enforcement Functions
# Settings enforcement, kill orders, and security actions.

# Execute kill orders from dashboard
execute_kill_orders() {
  local KILL_SESSIONS="$1"
  if [ "$KILL_SESSIONS" != "[]" ] && [ "$KILL_SESSIONS" != "null" ] && [ -n "$KILL_SESSIONS" ]; then
    echo "$KILL_SESSIONS" | jq -r '.[]' 2>/dev/null | while read -r SESSION; do
      if [ -n "$SESSION" ]; then
        log "Stopping session: $SESSION (dashboard request)"
        systemctl stop "ttyd@$SESSION" 2>/dev/null || true
      fi
    done
  fi
}

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
    ssh_only)
      SSH_ENABLED="true"
      TERMINAL_ENABLED="false"
      ;;
    web_locked)
      TERMINAL_ENABLED="true"
      if [ -f /home/dev/.ssh/authorized_keys ] && [ -s /home/dev/.ssh/authorized_keys ]; then
        SSH_ENABLED="true"
      else
        SSH_ENABLED="false"
      fi
      ;;
  esac

  # SAFETY CHECK: Never close SSH if keys are present (prevents lockout)
  if [ -f /home/dev/.ssh/authorized_keys ] && [ -s /home/dev/.ssh/authorized_keys ]; then
    SSH_ENABLED="true"
    log "SSH keys present - keeping SSH enabled regardless of tier"
  fi

  # Enforce SSH state
  if [ "$SSH_ENABLED" = "false" ]; then
    ufw status | grep -q "22/tcp.*ALLOW" && ufw delete allow 22/tcp 2>/dev/null || true
  elif [ "$SSH_ENABLED" = "true" ]; then
    ufw status | grep -q "22/tcp.*ALLOW" || ufw allow 22/tcp comment 'SSH' 2>/dev/null || true
  fi

  # Enforce terminal state (skip if in lockdown)
  if [ -f "$LOCKDOWN_MARKER" ] || [ -f /etc/ellulai/.emergency-lockdown ]; then
    log "In lockdown - skipping terminal enforcement"
    return 0
  fi

  local TERMINAL_DISABLED_MARKER="/etc/ellulai/.terminal-disabled"
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

# Handle security actions from platform
handle_security_action() {
  local ACTION="$1"
  local SHIELD_TOKEN="$2"
  [ -z "$ACTION" ] && return 0

  case "$ACTION" in
    bootstrap_ssh_only)
      # DEPRECATED: Use /_auth/upgrade-to-ssh-only instead
      log "SECURITY: [DEPRECATED] bootstrap_ssh_only"
      if [ -n "$SHIELD_TOKEN" ]; then
        echo "$SHIELD_TOKEN" > /etc/ellulai/.bootstrap-token
        chmod 600 /etc/ellulai/.bootstrap-token
      fi
      ;;

    set_tier_ssh_only:*)
      # VPS-DRIVEN: Platform cannot push SSH keys
      log "SECURITY: Platform attempted to push SSH key with tier change. BLOCKED."
      return 0
      ;;

    set_tier_ssh_only)
      # VPS-INITIATED: Delegates to unified tier switch endpoint
      log "SECURITY: Transitioning to ssh_only tier (VPS-initiated)"

      if ! curl -s -o /dev/null --max-time 2 http://localhost:3005/health 2>/dev/null; then
        log "ERROR: Sovereign Shield not responding"
        return 1
      fi

      local RESPONSE=$(curl -s --max-time 60 \
        -X POST http://localhost:3005/_auth/tier/switch \
        -H "Content-Type: application/json" \
        -d '{"targetTier":"ssh_only","source":"enforcer-daemon"}' 2>&1)

      if echo "$RESPONSE" | grep -q '"success":true'; then
        log "SECURITY: ssh_only tier activated"
        rm -f /etc/ellulai/.bootstrap-token /etc/ellulai/.bootstrap-session 2>/dev/null || true
        systemctl stop ellulai-agent-bridge 2>/dev/null || true
        stop_all_terminals
      else
        log "FATAL: Tier switch failed"
        return 1
      fi
      ;;

    set_tier_web_locked)
      # VPS-INITIATED: Delegates to unified tier switch endpoint
      log "SECURITY: Transitioning to web_locked tier (VPS-initiated)"

      if [ -n "$SHIELD_TOKEN" ]; then
        echo "$SHIELD_TOKEN" > /etc/ellulai/.sovereign-setup-token
        chmod 600 /etc/ellulai/.sovereign-setup-token
      fi

      if ! curl -s -o /dev/null --max-time 2 http://localhost:3005/health 2>/dev/null; then
        log "ERROR: Sovereign Shield not responding"
        return 1
      fi

      local RESPONSE=$(curl -s --max-time 60 \
        -X POST http://localhost:3005/_auth/tier/switch \
        -H "Content-Type: application/json" \
        -d '{"targetTier":"web_locked","source":"enforcer-daemon"}' 2>&1)

      if echo "$RESPONSE" | grep -q '"success":true'; then
        log "SECURITY: web_locked tier activated"
        if [ -f /home/dev/.ssh/authorized_keys ] && [ -s /home/dev/.ssh/authorized_keys ]; then
          log "  SSH keys present, enabling sshd..."
          ufw allow 22/tcp comment 'SSH' 2>/dev/null || true
          systemctl enable --now sshd 2>/dev/null || true
        else
          log "  No SSH keys, disabling sshd..."
          systemctl disable --now sshd 2>/dev/null || true
          ufw delete allow 22/tcp 2>/dev/null || true
        fi
      else
        local ERROR=$(echo "$RESPONSE" | grep -o '"error":"[^"]*"' | cut -d'"' -f4)
        log "FATAL: Tier switch failed - $ERROR"
        return 1
      fi
      ;;

    set_tier_standard)
      # DOWNGRADE to Standard tier: Re-enable web terminal, disable passkey gate
      # Delegates to unified tier switch endpoint for centralized safety logic

      # M5 FIX: If currently web_locked, require local passkey approval
      # The bridge creates this marker after successful passkey authentication
      # This prevents API from remotely downgrading without passkey verification
      local CURRENT_TIER=$(cat /etc/ellulai/security-tier 2>/dev/null || echo "standard")
      local DOWNGRADE_APPROVAL="/etc/ellulai/.downgrade-approved"

      if [ "$CURRENT_TIER" = "web_locked" ]; then
        if [ ! -f "$DOWNGRADE_APPROVAL" ]; then
          log "SECURITY: Blocked set_tier_standard from API - web_locked requires local passkey approval"
          log "  Downgrades from web_locked must be initiated via /_auth/bridge with passkey verification"
          return 0
        fi
        # Approval marker exists - consume it (single use)
        rm -f "$DOWNGRADE_APPROVAL"
        log "SECURITY: Passkey-approved downgrade from web_locked"
      fi

      log "SECURITY WARNING: Downgrading to standard tier - removing breach protection"

      # Check if sovereign-shield is running
      if ! curl -s -o /dev/null --max-time 2 http://localhost:3005/health 2>/dev/null; then
        log "ERROR: Sovereign Shield not responding - cannot perform tier switch"
        return 1
      fi

      # Call unified tier switch endpoint
      local RESPONSE=$(curl -s --max-time 60 \
        -X POST http://localhost:3005/_auth/tier/switch \
        -H "Content-Type: application/json" \
        -d '{"targetTier":"standard","source":"enforcer-daemon"}' 2>&1)

      if echo "$RESPONSE" | grep -q '"success":true'; then
        log "SECURITY WARNING: standard tier activated via unified endpoint - BREACH PROTECTION REMOVED"

        # Additional cleanup after successful switch
        rm -f /etc/ellulai/.sovereign-shield-active 2>/dev/null || true
        systemctl start ellulai-agent-bridge 2>/dev/null || true

        # Disable SSH (web terminal verified working by unified endpoint)
        log "  Disabling SSH access..."
        ufw delete allow 22/tcp 2>/dev/null || true
        ufw delete allow 22 2>/dev/null || true
      else
        local ERROR=$(echo "$RESPONSE" | grep -o '"error":"[^"]*"' | cut -d'"' -f4)
        log "FATAL: Tier switch failed - $ERROR"
        log "  SSH access preserved to prevent lockout"
        return 1
      fi
      ;;

    remove_ssh_key:*)
      # VPS-DRIVEN SECURITY: Platform should never remove SSH keys
      # All SSH key management happens on the VPS
      log "SECURITY: Platform attempted SSH key removal. BLOCKED."
      log "  VPS is the source of truth for SSH keys. Manage keys via VPS only."
      ;;

    lock_web_only)
      # Legacy action - redirect to web_locked
      log "SECURITY: Redirecting lock_web_only to set_tier_web_locked"
      handle_security_action "set_tier_web_locked" "$SHIELD_TOKEN"
      ;;

    activate_shield)
      # Legacy action - redirect to web_locked
      log "SECURITY: Redirecting activate_shield to set_tier_web_locked"
      handle_security_action "set_tier_web_locked" "$SHIELD_TOKEN"
      ;;

    update_shield)
      log "SECURITY: Updating Sovereign Shield auth script"
      local TOKEN=$(get_token)
      if [ -z "$TOKEN" ]; then
        log "ERROR: No token for shield update"
        return 1
      fi
      # Download new server.js from API
      local SCRIPT_CONTENT=$(curl -sS --connect-timeout 10 --max-time 30 \
        "$API_URL/api/servers/shield-script" \
        -H "Authorization: Bearer $TOKEN" 2>/dev/null)
      if [ -z "$SCRIPT_CONTENT" ] || ! echo "$SCRIPT_CONTENT" | grep -q "Sovereign Shield"; then
        log "ERROR: Failed to download shield script"
        return 1
      fi
      echo "$SCRIPT_CONTENT" > /opt/ellulai/auth/server.js
      log "Shield script updated"
      # Patch Caddyfile: ensure all X-Forwarded headers are present
      local CADDYFILE="/etc/caddy/Caddyfile"
      if [ -f "$CADDYFILE" ] && ! grep -q "X-Forwarded-Uri" "$CADDYFILE"; then
        # Use node to reliably add missing headers to shield gate blocks
        node -e '
const fs = require("fs");
let content = fs.readFileSync("/etc/caddy/Caddyfile", "utf8");

// Add missing X-Forwarded-* headers to shield gate blocks
content = content.replace(
  /(# SOVEREIGN SHIELD GATE[^}]*header_up Cookie[^\n]*)(\n[^}]*copy_headers)/g,
  (match, before, after) => {
    let result = before;
    if (!match.includes("X-Forwarded-Host")) {
      result += "\n            header_up X-Forwarded-Host {http.request.host}";
    }
    if (!match.includes("X-Forwarded-Uri")) {
      result += "\n            header_up X-Forwarded-Uri {http.request.uri}";
    }
    if (!match.includes("X-Forwarded-Proto")) {
      result += "\n            header_up X-Forwarded-Proto {http.request.scheme}";
    }
    return result + after;
  }
);

fs.writeFileSync("/etc/caddy/Caddyfile", content);
console.log("Caddyfile headers updated");
' 2>/dev/null && {
          caddy reload --config "$CADDYFILE" 2>/dev/null || caddy reload --config "$CADDYFILE" --adapter caddyfile 2>/dev/null
          log "Caddyfile patched with X-Forwarded headers"
        }
      fi
      # Restart Shield service
      systemctl restart ellulai-sovereign-shield 2>/dev/null || true
      sleep 2
      if systemctl is-active --quiet ellulai-sovereign-shield; then
        log "Sovereign Shield restarted successfully"
      else
        log "ERROR: Shield failed to restart after update"
        journalctl -u ellulai-sovereign-shield --no-pager -n 5 >> "$LOG_FILE"
      fi
      ;;

    *)
      log "SECURITY: Unknown action '$ACTION', ignoring"
      ;;
  esac
}

# VPS-DRIVEN SECURITY: SSH keys are NEVER accepted from the platform.
# All SSH key management happens on the VPS via:
# - Standard tier: N/A (SSH disabled)
# - SSH Only tier: Via SSH session (~/.ssh/authorized_keys)
# - Web Locked tier: Via passkey-protected UI (/_auth/keys)
handle_keys() {
  local INSTALL_KEY="$1"
  [ -z "$INSTALL_KEY" ] || [ "$INSTALL_KEY" = "null" ] && return 0

  # BLOCKED: Platform should never push SSH keys
  log "SECURITY: Platform attempted SSH key injection. BLOCKED."
  log "  VPS is the source of truth for SSH keys. Manage keys via VPS only."
  return 0
}

# Kill processes on dev ports
kill_dev_ports() {
  local PORTS_JSON="$1"
  [ -z "$PORTS_JSON" ] || [ "$PORTS_JSON" = "null" ] && return 0

  local PORTS=$(echo "$PORTS_JSON" | jq -r '.[]' 2>/dev/null)
  [ -z "$PORTS" ] && return 0

  log "Killing processes on dev ports..."
  local KILLED=0
  for PORT in $PORTS; do
    case "$PORT" in
      22|80|443|3002|7681|7682|7683|7684|7685|7686|7687|7688|7689|7690)
        log "SKIP: Refusing to kill system port $PORT"
        continue
        ;;
    esac

    if fuser -k -n tcp "$PORT" 2>/dev/null; then
      log "Killed process on port $PORT"
      KILLED=$((KILLED + 1))
    fi
  done
  log "Kill complete: $KILLED processes terminated"
}

# Sync secrets from platform
sync_secrets() {
  local SECRETS="$1"
  if [ "$SECRETS" != "[]" ] && [ "$SECRETS" != "null" ] && [ -n "$SECRETS" ]; then
    echo "# ellul.ai Environment" > "$ENV_FILE.tmp"
    echo "# Synced: $(date -Iseconds)" >> "$ENV_FILE.tmp"
    echo "" >> "$ENV_FILE.tmp"
    echo "$SECRETS" | jq -c '.[]' 2>/dev/null | while read -r SECRET; do
      NAME=$(echo "$SECRET" | jq -r '.name')
      ENC_KEY=$(echo "$SECRET" | jq -r '.encryptedKey')
      IV=$(echo "$SECRET" | jq -r '.iv')
      ENC_DATA=$(echo "$SECRET" | jq -r '.encryptedData')
      VALUE=$(/usr/local/bin/ellulai-decrypt "$ENC_KEY" "$IV" "$ENC_DATA" 2>/dev/null)
      [ -n "$VALUE" ] && echo "export $NAME=\"$VALUE\"" >> "$ENV_FILE.tmp"
    done
    mv "$ENV_FILE.tmp" "$ENV_FILE"
    chown dev:dev "$ENV_FILE"
    chmod 600 "$ENV_FILE"
  fi
}

# Handle git actions from the dashboard
handle_git_action() {
  local ACTION="$1"
  local ACTIVE_APP="$2"
  [ -z "$ACTION" ] || [ "$ACTION" = "null" ] && return 0

  # Resolve project directory from active app
  local PROJECT_DIR="/home/dev/projects"
  if [ -n "$ACTIVE_APP" ] && [ "$ACTIVE_APP" != "null" ] && [ -d "/home/dev/projects/$ACTIVE_APP" ]; then
    PROJECT_DIR="/home/dev/projects/$ACTIVE_APP"
  elif [ -d "/home/dev/projects/welcome" ]; then
    PROJECT_DIR="/home/dev/projects/welcome"
  fi

  # Persist active git app for credential helper
  if [ -n "$ACTIVE_APP" ] && [ "$ACTIVE_APP" != "null" ]; then
    echo "$ACTIVE_APP" > /etc/ellulai/.active-git-app
    chmod 644 /etc/ellulai/.active-git-app
  fi

  # Source environment with decrypted secrets
  source "$ENV_FILE" 2>/dev/null || true

  # Resolve per-app secrets to non-suffixed names
  # Frontend stores: __GIT_TOKEN__MY_APP, daemon scripts read: __GIT_TOKEN
  local GIT_ENV_CMD=""
  if [ -n "$ACTIVE_APP" ] && [ "$ACTIVE_APP" != "null" ]; then
    local APP_SUFFIX="__$(echo "$ACTIVE_APP" | tr '[:lower:]' '[:upper:]' | sed 's/[^A-Z0-9]/_/g' | sed 's/__*/_/g' | sed 's/^_//' | sed 's/_$//')"
    local EXPORTS=""
    for VAR_NAME in __GIT_TOKEN __GIT_PROVIDER __GIT_REPO_URL __GIT_USER_NAME __GIT_USER_EMAIL __GIT_DEFAULT_BRANCH; do
      local SUFFIXED_VAR="${VAR_NAME}${APP_SUFFIX}"
      local VAL="${!SUFFIXED_VAR:-}"
      if [ -n "$VAL" ]; then
        EXPORTS="${EXPORTS} ${VAR_NAME}='${VAL}'"
      fi
    done
    [ -n "$EXPORTS" ] && GIT_ENV_CMD="export${EXPORTS} &&"
  fi

  case "$ACTION" in
    setup)
      log "Git: Running setup for app '${ACTIVE_APP:-default}'..."
      if [ -x /usr/local/bin/ellulai-git-setup ]; then
        sudo -u dev bash -c "source $ENV_FILE && export ELLULAI_PROJECT_DIR='$PROJECT_DIR' && ${GIT_ENV_CMD} /usr/local/bin/ellulai-git-setup" 2>&1 | while IFS= read -r line; do
          log "[git-setup] $line"
        done
      else
        log "Git: ellulai-git-setup not found, skipping"
      fi
      ;;
    push|backup)
      log "Git: Pushing to remote..."
      sudo -u dev bash -c "source $ENV_FILE && ${GIT_ENV_CMD} cd '$PROJECT_DIR' && /usr/local/bin/ellulai-git-flow backup" 2>&1 | while IFS= read -r line; do
        log "[git-flow] $line"
      done
      ;;
    force-push)
      log "Git: Force-pushing to remote..."
      sudo -u dev bash -c "source $ENV_FILE && ${GIT_ENV_CMD} cd '$PROJECT_DIR' && /usr/local/bin/ellulai-git-flow force-backup" 2>&1 | while IFS= read -r line; do
        log "[git-flow] $line"
      done
      ;;
    pull)
      log "Git: Pulling from remote..."
      sudo -u dev bash -c "source $ENV_FILE && ${GIT_ENV_CMD} cd '$PROJECT_DIR' && /usr/local/bin/ellulai-git-flow pull" 2>&1 | while IFS= read -r line; do
        log "[git-flow] $line"
      done
      ;;
    teardown)
      log "Git: Tearing down git credentials..."
      sudo -u dev bash -c "cd '$PROJECT_DIR' && git remote remove origin 2>/dev/null; git config --global --unset credential.helper 2>/dev/null" || true
      rm -f /etc/ellulai/.active-git-app 2>/dev/null
      log "Git: Teardown complete"
      ;;
    *)
      log "Git: Unknown action '$ACTION'"
      ;;
  esac
}
