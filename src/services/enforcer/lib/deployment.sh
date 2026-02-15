#!/bin/bash
# Enforcer Deployment Functions
# Ensures daemon API port (3006) is available in Caddyfile.
#
# Phase 4 cleanup: switch_deployment_model() was moved to the sovereign-shield
# bridge and is no longer processed by the enforcer. Deployment model switching
# (Cloudflare Edge / Direct Connect) is now handled via WebSocket bridge commands
# routed through sovereign-shield (port 3005) instead of heartbeat polling.

# Ensure daemon API port (3006) is available for callDaemon RPC.
# Called on every heartbeat to bootstrap existing servers that were
# provisioned before daemon port was added to the payload.
# Uses origin cert (*.ellul.ai) for TLS when available.
# Auto-upgrades from tls internal → origin cert when available.
ensure_daemon_port() {
  local NEEDS_RELOAD=false
  mkdir -p /etc/caddy/sites-enabled

  # Detect public IP for TLS cert SAN (fallback mode only)
  local MY_IP=$(curl -sf --connect-timeout 2 http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address 2>/dev/null \
    || curl -sf --connect-timeout 2 "http://169.254.169.254/hetzner/v1/metadata/public-ipv4" 2>/dev/null \
    || ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')

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
    respond "Not Found" 404
}
DAEMONEOF
    fi
    ufw allow 3006/tcp comment 'Daemon API' 2>/dev/null || true
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
    respond "Not Found" 404
}
DAEMONEOF
    NEEDS_RELOAD=true
  fi

  if [ "$NEEDS_RELOAD" = true ]; then
    if caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>/dev/null; then
      caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile 2>/dev/null || true
    fi
  fi
}
