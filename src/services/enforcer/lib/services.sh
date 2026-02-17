#!/bin/bash
# Enforcer Services Functions
# Monitor and restart critical services.

# One-time boot validation — catches provisioning failures early.
# Runs once at enforcer startup before the main heartbeat loop.
validate_full_stack() {
  local FAILURES=0

  # Check warden if firewall mode requires it (Linux only — macOS BYOS uses relaxed mode)
  FIREWALL_MODE=$(cat /etc/ellulai/firewall-mode 2>/dev/null)
  if [ "$FIREWALL_MODE" = "partial_ironclad" ] || [ "$FIREWALL_MODE" = "full_ironclad" ]; then
    if ! svc_is_active ellulai-warden; then
      log "BOOT VALIDATION FAILED: warden not running"
      svc_start ellulai-warden
      sleep 2
      FAILURES=$((FAILURES + 1))
    else
      WARDEN_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" -m 3 http://localhost:8081/_health 2>/dev/null || echo "000")
      if [ "$WARDEN_HEALTH" != "200" ]; then
        log "BOOT VALIDATION FAILED: warden health check returned $WARDEN_HEALTH"
        svc_restart ellulai-warden
        sleep 2
        FAILURES=$((FAILURES + 1))
      fi
    fi

    # Verify dev user has outbound internet (catches warden misconfiguration)
    if ! run_as_user 'curl -sS --connect-timeout 5 -o /dev/null https://1.1.1.1' 2>/dev/null; then
      log "BOOT VALIDATION FAILED: $SVC_USER has no outbound internet"
      svc_restart ellulai-warden
      sleep 3
      FAILURES=$((FAILURES + 1))
    fi
  fi

  # Check sovereign-shield
  if ! curl -s --connect-timeout 3 -o /dev/null http://127.0.0.1:3005/_auth/health 2>/dev/null; then
    log "BOOT VALIDATION FAILED: sovereign-shield not responding"
    svc_restart ellulai-sovereign-shield
    sleep 2
    FAILURES=$((FAILURES + 1))
  fi

  # Check agent-bridge
  if ! svc_is_active ellulai-agent-bridge; then
    log "BOOT VALIDATION FAILED: agent-bridge not running"
    svc_restart ellulai-agent-bridge
    sleep 2
    FAILURES=$((FAILURES + 1))
  fi

  # OpenClaw gateway — warn only (may still be starting up)
  if ! curl -s --connect-timeout 3 -o /dev/null http://127.0.0.1:18790/__openclaw__/canvas/ 2>/dev/null; then
    log "BOOT VALIDATION WARNING: OpenClaw gateway not reachable (may still be starting)"
  fi

  if [ $FAILURES -eq 0 ]; then
    log "Boot validation passed — all critical services operational"
  else
    log "Boot validation completed with $FAILURES failures — remediation attempted"
  fi
}

# Check and restart critical services if needed
check_critical_services() {
  if ! svc_is_active ellulai-file-api; then
    log "CRITICAL: ellulai-file-api is down, restarting..."
    svc_restart ellulai-file-api
    sleep 2
    if svc_is_active ellulai-file-api; then
      log "ellulai-file-api recovered"
    else
      log "ERROR: ellulai-file-api failed to restart"
    fi
  else
    # Skip health check during migration — execFileSync blocks the event loop
    # while downloading the archive, making file-api unresponsive to health checks.
    # The lock file is created by file-api at migration start and removed on completion.
    if [ -f /tmp/ellulai-migration.lock ]; then
      return
    fi
    # Accept 200, 401 (web_locked auth required), or 403
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 2 http://localhost:3002/api/tree 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "401" ] && [ "$HTTP_CODE" != "403" ]; then
      log "CRITICAL: ellulai-file-api not responding, restarting..."
      svc_restart ellulai-file-api
      sleep 2
    fi
  fi

  if ! svc_is_active ellulai-preview; then
    log "WARN: ellulai-preview is down, restarting..."
    svc_restart ellulai-preview
  fi

  # Ensure all ttyd terminal services are running (for web_locked and standard modes)
  if [ ! -f /etc/ellulai/.terminal-disabled ]; then
    for svc in $ALL_TERMINALS; do
      if ! svc_is_active "$svc"; then
        log "WARN: $svc is down, starting..."
        svc_enable "$svc"
        svc_start "$svc"
      fi
    done
  fi

  # Ensure term-proxy is running
  if ! svc_is_active ellulai-term-proxy; then
    log "CRITICAL: ellulai-term-proxy is down, restarting..."
    svc_restart ellulai-term-proxy
  fi

  # Ensure sovereign-shield is running (serves /_auth/* including capabilities, passkeys, session)
  if ! svc_is_active ellulai-sovereign-shield; then
    log "CRITICAL: ellulai-sovereign-shield is down, restarting..."
    svc_restart ellulai-sovereign-shield
  fi

  # Ensure watchdog is running (agent process lifecycle — paid tiers only)
  if svc_is_enabled ellulai-watchdog; then
    if ! svc_is_active ellulai-watchdog; then
      log "CRITICAL: ellulai-watchdog is down, restarting..."
      svc_restart ellulai-watchdog
    fi
  fi

  # Ensure warden is running (network enforcement proxy)
  if svc_is_enabled ellulai-warden; then
    if ! svc_is_active ellulai-warden; then
      log "CRITICAL: ellulai-warden is down, restarting..."
      svc_restart ellulai-warden
      sleep 2
      if svc_is_active ellulai-warden; then
        log "ellulai-warden recovered"
      else
        log "ERROR: ellulai-warden failed to restart"
      fi
    else
      WARDEN_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" -m 2 http://localhost:8081/_health 2>/dev/null || echo "000")
      if [ "$WARDEN_HEALTH" != "200" ]; then
        log "CRITICAL: ellulai-warden not responding on health port, restarting..."
        svc_restart ellulai-warden
        sleep 2
      fi
    fi
  fi

  # Ensure agent-bridge is running (vibe mode chat)
  if ! svc_is_active ellulai-agent-bridge; then
    log "CRITICAL: ellulai-agent-bridge is down, restarting..."
    svc_restart ellulai-agent-bridge
  fi

  # Ensure OpenClaw gateway is running (PM2 managed)
  if command -v pm2 &>/dev/null 2>&1 || run_as_user 'command -v pm2' &>/dev/null 2>&1; then
    OC_STATUS=$(run_as_user 'pm2 jlist 2>/dev/null' 2>/dev/null | python3 -c "
import sys,json,re
try:
  raw=sys.stdin.read()
  m=re.search(r'\[\s*\{', raw)
  if not m:
    print('missing' if '[]' in raw else 'error')
  else:
    procs=json.loads(raw[m.start():])
    found=False
    for p in procs:
      if p.get('name')=='openclaw-gateway':
        print(p.get('pm2_env',{}).get('status','unknown'))
        found=True
        break
    if not found: print('missing')
except Exception: print('error')
" 2>/dev/null)
    if [ "$OC_STATUS" != "online" ]; then
      log "CRITICAL: openclaw-gateway PM2 status=$OC_STATUS, restarting..."
      # Check if binary exists; if not, attempt install (with cooldown)
      OPENCLAW_BIN=$(run_as_user 'which openclaw 2>/dev/null || echo "$HOME/.openclaw/bin/openclaw"' 2>/dev/null)
      if ! run_as_user "test -x \"$OPENCLAW_BIN\"" 2>/dev/null; then
        # Install with 10-minute cooldown to prevent spam
        COOLDOWN_FILE="/tmp/openclaw-install-cooldown"
        if [ ! -f "$COOLDOWN_FILE" ] || [ "$(( $(date +%s) - $(file_mtime "$COOLDOWN_FILE") ))" -gt 600 ]; then
          log "OpenClaw binary missing, attempting install..."
          touch "$COOLDOWN_FILE"
          # Clean npm cache first — stale tarballs cause ENOENT errors
          run_as_user 'npm cache clean --force' 2>/dev/null
          # Temporarily suspend NAT redirects for install (Linux only — macOS has no iptables)
          if [ "$IS_MACOS" != true ]; then
            # NOTE: iptables -S outputs numeric UIDs, not usernames
            PS_UID=$(id -u "$SVC_USER" 2>/dev/null)
            SAVED_NAT=$(iptables -t nat -S OUTPUT 2>/dev/null | grep "uid-owner $PS_UID" || true)
            if [ -n "$SAVED_NAT" ]; then
              echo "$SAVED_NAT" | sed 's/^-A/-D/' | while read -r rule; do
                iptables -t nat $rule 2>/dev/null || true
              done
            fi
          fi
          # Use npm install directly — the installer script's "setup" phase tries
          # to read /dev/tty which fails in non-interactive contexts.
          run_as_user 'npm install -g openclaw@latest' 2>&1 | tail -5
          # Restore NAT rules (Linux only)
          if [ "$IS_MACOS" != true ] && [ -n "${SAVED_NAT:-}" ]; then
            echo "$SAVED_NAT" | while read -r rule; do
              iptables -t nat $rule 2>/dev/null || true
            done
          fi
        fi
      fi
      run_as_user '
        OPENCLAW_BIN=$(which openclaw 2>/dev/null || echo "$HOME/.openclaw/bin/openclaw")
        if [ -x "$OPENCLAW_BIN" ]; then
          pm2 restart openclaw-gateway 2>/dev/null || pm2 start "$OPENCLAW_BIN" --name openclaw-gateway --interpreter none -- gateway --port 18790 2>/dev/null
        fi
      ' 2>/dev/null
      sleep 5
    fi
  fi
}
