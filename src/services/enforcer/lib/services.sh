#!/bin/bash
# Enforcer Services Functions
# Monitor and restart critical services.

# Check and restart critical services if needed
check_critical_services() {
  if ! systemctl is-active --quiet phonestack-file-api 2>/dev/null; then
    log "CRITICAL: phonestack-file-api is down, restarting..."
    systemctl restart phonestack-file-api 2>/dev/null
    sleep 2
    if systemctl is-active --quiet phonestack-file-api 2>/dev/null; then
      log "phonestack-file-api recovered"
    else
      log "ERROR: phonestack-file-api failed to restart"
    fi
  else
    # Accept 200, 401 (web_locked auth required), or 403 (ssh_only mode)
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 2 http://localhost:3002/api/tree 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "401" ] && [ "$HTTP_CODE" != "403" ]; then
      log "CRITICAL: phonestack-file-api not responding, restarting..."
      systemctl restart phonestack-file-api 2>/dev/null
      sleep 2
    fi
  fi

  if ! systemctl is-active --quiet phonestack-preview 2>/dev/null; then
    log "WARN: phonestack-preview is down, restarting..."
    systemctl restart phonestack-preview 2>/dev/null
  fi

  # Skip terminal health checks if in lockdown (don't undo lockdown!)
  if [ -f "$LOCKDOWN_MARKER" ] || [ -f /etc/phonestack/.emergency-lockdown ]; then
    return 0
  fi

  # Ensure all ttyd terminal services are running (for web_locked and standard modes)
  local TIER=$(cat /etc/phonestack/security-tier 2>/dev/null || echo "standard")
  if [ "$TIER" != "ssh_only" ] && [ ! -f /etc/phonestack/.terminal-disabled ]; then
    for svc in $ALL_TERMINALS; do
      if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
        log "WARN: $svc is down, starting..."
        systemctl enable "$svc" 2>/dev/null || true
        systemctl start "$svc" 2>/dev/null || true
      fi
    done
  fi

  # Ensure term-proxy is running
  if ! systemctl is-active --quiet phonestack-term-proxy 2>/dev/null; then
    log "CRITICAL: phonestack-term-proxy is down, restarting..."
    systemctl restart phonestack-term-proxy 2>/dev/null
  fi
}
