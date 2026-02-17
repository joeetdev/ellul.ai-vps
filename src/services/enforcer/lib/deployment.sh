#!/bin/bash
# Enforcer Deployment Functions
# Ensures daemon API port (3006) is available in Caddyfile.
# Ensures base CORS headers are present in Caddyfile.
#
# Phase 4 cleanup: switch_deployment_model() was moved to the sovereign-shield
# bridge and is no longer processed by the enforcer. Deployment model switching
# (Cloudflare Edge / Direct Connect) is now handled via WebSocket bridge commands
# routed through sovereign-shield (port 3005) instead of heartbeat polling.

# Ensure base CORS headers exist at the top of @code and @main handle blocks.
# Servers provisioned before the CORS fix (afd1d87) are missing these headers,
# causing browsers to block responses that don't go through a specific sub-handler
# (e.g., auth failures, 502s, catch-all routes).
# Runs on every heartbeat — idempotent, skips instantly if already patched.
ensure_cors_headers() {
  local CADDYFILE="/etc/caddy/Caddyfile"
  [ ! -f "$CADDYFILE" ] && return

  # Already patched? Skip.
  grep -q '# Base CORS for dashboard' "$CADDYFILE" 2>/dev/null && return

  # Only patch if the Caddyfile has handle blocks (skip bare/minimal configs)
  grep -q 'handle @code {' "$CADDYFILE" 2>/dev/null || grep -q 'handle @main {' "$CADDYFILE" 2>/dev/null || return

  log "CORS: Patching base CORS headers into Caddyfile..."

  local TMPFILE
  TMPFILE=$(mktemp)
  awk '
    /handle @code \{/ {
      print
      print "        # Base CORS for dashboard — ensure allow-origin on all responses"
      print "        header Access-Control-Allow-Origin \"https://console.ellul.ai\""
      print "        header Access-Control-Allow-Credentials \"true\""
      next
    }
    /handle @main \{/ {
      print
      print "        # Base CORS for dashboard — ensure allow-origin on all responses"
      print "        header Access-Control-Allow-Origin \"https://console.ellul.ai\""
      print "        header Access-Control-Allow-Credentials \"true\""
      next
    }
    { print }
  ' "$CADDYFILE" > "$TMPFILE"

  if caddy validate --config "$TMPFILE" --adapter caddyfile 2>/dev/null; then
    mv "$TMPFILE" "$CADDYFILE"
    caddy reload --config "$CADDYFILE" --adapter caddyfile 2>/dev/null || true
    log "CORS: Base headers patched and Caddy reloaded"
  else
    rm -f "$TMPFILE"
    log "CORS: WARNING — Caddy validation failed after patch, reverted"
  fi
}

# Ensure daemon API port (3006) is available for callDaemon RPC.
# Called on every heartbeat to bootstrap existing servers that were
# provisioned before daemon port was added to the payload.
# Uses origin cert (*.ellul.ai) for TLS when available.
# Auto-upgrades from tls internal → origin cert when available.
ensure_daemon_port() {
  local NEEDS_RELOAD=false
  mkdir -p /etc/caddy/sites-enabled

  # Detect public IP for TLS cert SAN (fallback mode only)
  local MY_IP=$(get_public_ip)

  if [ -z "$MY_IP" ]; then
    log "DAEMON: Could not detect public IP, skipping daemon port setup"
    return
  fi

  local HAS_ORIGIN_CERT=false
  if [ -f /etc/caddy/origin.crt ] && [ -f /etc/caddy/origin.key ]; then
    HAS_ORIGIN_CERT=true
  fi

  if [ ! -f /etc/caddy/sites-enabled/daemon.caddy ]; then
    # No daemon.caddy yet — create it
    if [ "$HAS_ORIGIN_CERT" = true ]; then
      log "DAEMON: Bootstrapping daemon API with origin cert (daemon.ellul.ai:3006)..."
      cat > /etc/caddy/sites-enabled/daemon.caddy << DAEMONEOF
daemon.ellul.ai:3006 {
    tls /etc/caddy/origin.crt /etc/caddy/origin.key
    @daemon path /api/mount-volume /api/flush-volume /api/migrate/* /api/update-identity /api/luks-init /api/luks-unlock /api/luks-close /api/backup-identity /api/restore-identity
    handle @daemon {
        reverse_proxy localhost:3002
    }
    handle_path /api/watchdog/* {
        reverse_proxy 127.0.0.1:7710
    }
    respond "Not Found" 404
}
DAEMONEOF
    else
      log "DAEMON: Bootstrapping daemon API site block (${MY_IP}:3006)..."
      cat > /etc/caddy/sites-enabled/daemon.caddy << DAEMONEOF
${MY_IP}:3006 {
    tls internal
    @daemon path /api/mount-volume /api/flush-volume /api/migrate/* /api/update-identity /api/luks-init /api/luks-unlock /api/luks-close /api/backup-identity /api/restore-identity
    handle @daemon {
        reverse_proxy localhost:3002
    }
    handle_path /api/watchdog/* {
        reverse_proxy 127.0.0.1:7710
    }
    respond "Not Found" 404
}
DAEMONEOF
    fi
    fw_allow 3006 'Daemon API'
    NEEDS_RELOAD=true
  elif [ "$HAS_ORIGIN_CERT" = true ] && grep -q 'tls internal' /etc/caddy/sites-enabled/daemon.caddy; then
    # Auto-upgrade: origin cert available but daemon.caddy still uses tls internal
    log "DAEMON: Upgrading daemon.caddy from tls internal to origin cert..."
    cat > /etc/caddy/sites-enabled/daemon.caddy << DAEMONEOF
daemon.ellul.ai:3006 {
    tls /etc/caddy/origin.crt /etc/caddy/origin.key
    @daemon path /api/mount-volume /api/flush-volume /api/migrate/* /api/update-identity /api/luks-init /api/luks-unlock /api/luks-close /api/backup-identity /api/restore-identity
    handle @daemon {
        reverse_proxy localhost:3002
    }
    handle_path /api/watchdog/* {
        reverse_proxy 127.0.0.1:7710
    }
    respond "Not Found" 404
}
DAEMONEOF
    NEEDS_RELOAD=true
  elif ! grep -q 'tls internal' /etc/caddy/sites-enabled/daemon.caddy && ! grep -q 'origin.crt' /etc/caddy/sites-enabled/daemon.caddy; then
    # Fix: missing TLS config entirely or port-only address
    log "DAEMON: Fixing daemon.caddy — adding TLS config (${MY_IP}:3006)..."
    cat > /etc/caddy/sites-enabled/daemon.caddy << DAEMONEOF
${MY_IP}:3006 {
    tls internal
    @daemon path /api/mount-volume /api/flush-volume /api/migrate/* /api/update-identity /api/luks-init /api/luks-unlock /api/luks-close /api/backup-identity /api/restore-identity
    handle @daemon {
        reverse_proxy localhost:3002
    }
    handle_path /api/watchdog/* {
        reverse_proxy 127.0.0.1:7710
    }
    respond "Not Found" 404
}
DAEMONEOF
    NEEDS_RELOAD=true
  # Auto-fix: daemon.caddy exists but is missing the watchdog proxy
  elif ! grep -q 'watchdog' /etc/caddy/sites-enabled/daemon.caddy; then
    log "DAEMON: Adding missing watchdog proxy to daemon.caddy..."
    # Insert watchdog handle_path before the respond line
    sed_inplace '/respond "Not Found" 404/i\    handle_path /api/watchdog/* {\n        reverse_proxy 127.0.0.1:7710\n    }' /etc/caddy/sites-enabled/daemon.caddy
    NEEDS_RELOAD=true
  fi

  if [ "$NEEDS_RELOAD" = true ]; then
    if caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>/dev/null; then
      caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile 2>/dev/null || true
    fi
  fi
}
