#!/bin/bash
# Enforcer Deployment Functions
# Ensures daemon API port (3006) is available in Caddyfile.
# Ensures base CORS headers are present in Caddyfile.
# Ensures gateway origin hostname is in Caddy site block addresses.
#
# Phase 4 cleanup: switch_deployment_model() was moved to the sovereign-shield
# bridge and is no longer processed by the enforcer. Deployment model switching
# (Cloudflare Edge / Direct Connect) is now handled via WebSocket bridge commands
# routed through sovereign-shield (port 3005) instead of heartbeat polling.

# Convert IPv4 address to hex tag (matches ipToTag() in gateway-kv.service.ts).
# e.g. 178.156.170.66 → b29caa42
ip_to_tag() {
  local ip="$1"
  if echo "$ip" | grep -q ':'; then
    echo -n "$ip" | md5sum | cut -c1-8
  else
    echo "$ip" | awk -F. '{printf "%02x%02x%02x%02x", $1, $2, $3, $4}'
  fi
}

# Ensure gateway origin hostname is in Caddy site block addresses.
# The gateway Worker uses resolveOverride which sends SNI as o-{ipTag}.{zone}.
# Caddy's strict SNI-Host enforcement (auto-enabled by mTLS) rejects connections
# if the SNI doesn't match any configured site block address.
# This adds the origin hostname so Caddy accepts the gateway Worker's connections.
# Only applies to gateway deployment model (auto_https off + no direct connect).
ensure_gateway_origin() {
  local CADDYFILE="/etc/caddy/Caddyfile"
  [ ! -f "$CADDYFILE" ] && return

  # Only for gateway/cloudflare model (has auto_https off and origin certs)
  grep -q 'auto_https off' "$CADDYFILE" 2>/dev/null || return
  grep -q 'origin-pull-ca.pem' "$CADDYFILE" 2>/dev/null || return

  local MY_IP=$(get_public_ip)
  [ -z "$MY_IP" ] && return

  local TAG=$(ip_to_tag "$MY_IP")
  local ORIGIN_AI="o-${TAG}.ellul.ai"
  local ORIGIN_APP="o-${TAG}.ellul.app"

  # Already patched? Skip.
  grep -q "$ORIGIN_AI" "$CADDYFILE" 2>/dev/null && return

  log "GATEWAY: Adding origin hostname ${ORIGIN_AI} to Caddyfile site blocks..."

  local TMPFILE
  TMPFILE=$(mktemp)

  # Add origin hostname to both site block address lines:
  # Before: srv.ellul.ai:443, code.ellul.ai:443 {
  # After:  srv.ellul.ai:443, code.ellul.ai:443, o-tag.ellul.ai:443 {
  # Before: dev.ellul.app:443 {
  # After:  dev.ellul.app:443, o-tag.ellul.app:443 {
  sed "s/\(\.ellul\.ai:443\) {$/\1, ${ORIGIN_AI}:443 {/" "$CADDYFILE" \
    | sed "s/\(\.ellul\.app:443\) {$/\1, ${ORIGIN_APP}:443 {/" \
    > "$TMPFILE"

  if caddy validate --config "$TMPFILE" --adapter caddyfile 2>/dev/null; then
    mv "$TMPFILE" "$CADDYFILE"
    caddy reload --config "$CADDYFILE" --adapter caddyfile 2>/dev/null || true
    log "GATEWAY: Origin hostname added and Caddy reloaded"
  else
    rm -f "$TMPFILE"
    log "GATEWAY: WARNING — Caddy validation failed after adding origin hostname, reverted"
  fi
}

# Ensure gateway Host rewrite is present.
# The gateway Worker sends X-Forwarded-Host with the original hostname because
# resolveOverride rewrites the Host header to the origin hostname (o-{tag}.{zone}).
# This request_header directive restores the original Host so @code/@main/@dev matchers work.
# Only applies to gateway deployment model (mTLS + auto_https off).
ensure_gateway_host_rewrite() {
  local CADDYFILE="/etc/caddy/Caddyfile"
  [ ! -f "$CADDYFILE" ] && return

  # Only for gateway/cloudflare model
  grep -q 'auto_https off' "$CADDYFILE" 2>/dev/null || return
  grep -q 'origin-pull-ca.pem' "$CADDYFILE" 2>/dev/null || return

  # Already patched? Skip.
  grep -q 'request_header @has_xfh Host' "$CADDYFILE" 2>/dev/null && return

  log "GATEWAY: Adding Host rewrite from X-Forwarded-Host to Caddyfile..."

  local TMPFILE
  TMPFILE=$(mktemp)

  # Insert the two-line rewrite after the first opening { of each site block with :443
  # Targets: lines like "srv.ellul.ai:443, code.ellul.ai:443, o-tag.ellul.ai:443 {"
  awk '
    /\.ellul\.(ai|app):443.*\{$/ && !done_block[NR] {
      print
      print "    @has_xfh header X-Forwarded-Host *"
      print "    request_header @has_xfh Host {http.request.header.X-Forwarded-Host}"
      done_block[NR] = 1
      next
    }
    { print }
  ' "$CADDYFILE" > "$TMPFILE"

  if caddy validate --config "$TMPFILE" --adapter caddyfile 2>/dev/null; then
    mv "$TMPFILE" "$CADDYFILE"
    caddy reload --config "$CADDYFILE" --adapter caddyfile 2>/dev/null || true
    log "GATEWAY: Host rewrite added and Caddy reloaded"
  else
    rm -f "$TMPFILE"
    log "GATEWAY: WARNING — Caddy validation failed after adding Host rewrite, reverted"
  fi
}

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
