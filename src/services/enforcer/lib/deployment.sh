#!/bin/bash
# Enforcer Deployment Functions
# Handles switching between Cloudflare Edge and Direct Connect deployment models.

# Switch deployment model based on heartbeat response
switch_deployment_model() {
  local RESPONSE="$1"
  local NEW_MODEL=$(echo "$RESPONSE" | jq -r '.switchDeploymentModel // ""')
  [ -z "$NEW_MODEL" ] && return 0

  local NEW_DOMAIN=$(echo "$RESPONSE" | jq -r '.newDomain // ""')
  local CF_ORIGIN_CERT=$(echo "$RESPONSE" | jq -r '.cfOriginCert // ""')
  local CF_ORIGIN_KEY=$(echo "$RESPONSE" | jq -r '.cfOriginKey // ""')

  log "DEPLOYMENT: Switching to $NEW_MODEL model (domain: $NEW_DOMAIN)"

  # Update stored domain
  echo "$NEW_DOMAIN" > /etc/phonestack/domain

  # Restart sovereign-shield to pick up new domain for WebAuthn + CORS
  log "DEPLOYMENT: Restarting sovereign-shield for new domain..."
  systemctl restart phonestack-sovereign-shield 2>/dev/null || true
  sleep 2

  # Compute code and dev domains from new domain
  local SHORT_ID=$(cat /etc/phonestack/server-id | head -c8)
  if [ "$NEW_MODEL" = "direct" ]; then
    local CODE_DOMAIN="${SHORT_ID}-dcode.phone-stack.app"
    local DEV_DOMAIN="${SHORT_ID}-ddev.phone-stack.app"
  else
    local CODE_DOMAIN="${SHORT_ID}-code.phone-stack.app"
    local DEV_DOMAIN="${SHORT_ID}-dev.phone-stack.app"
  fi

  if [ "$NEW_MODEL" = "direct" ]; then
    # --- Direct Connect Model ---
    # Server terminates TLS directly via Let's Encrypt ACME
    log "DEPLOYMENT: Generating Direct Connect Caddyfile (Let's Encrypt)..."

cat > /etc/caddy/Caddyfile << CADDYEOF
{
    email admin@phone-stack.app
}

import /etc/caddy/sites-enabled/*.caddy

$NEW_DOMAIN, $CODE_DOMAIN, $DEV_DOMAIN {
    @code host $CODE_DOMAIN
    handle @code {
        header Content-Security-Policy "frame-ancestors 'self' https://console.phone-stack.app https://phone-stack.app"
        header Access-Control-Allow-Origin "https://console.phone-stack.app"
        header Access-Control-Allow-Methods "GET, POST, OPTIONS"
        header Access-Control-Allow-Headers "Content-Type, Authorization, Cookie, X-Code-Token"
        header Access-Control-Allow-Credentials "true"

        @options method OPTIONS
        handle @options {
            respond "" 204
        }

        reverse_proxy localhost:3002 {
            header_down -Access-Control-Allow-Origin
            header_down -Access-Control-Allow-Methods
            header_down -Access-Control-Allow-Headers
        }
    }

    @dev host $DEV_DOMAIN
    handle @dev {
        @notAuth not path /_auth/*
        header @notAuth Content-Security-Policy "frame-ancestors 'self' https://console.phone-stack.app https://phone-stack.app"

        forward_auth localhost:3002 {
            uri /api/auth/check
            header_up Cookie {http.request.header.Cookie}
        }
        # Strip auth params before forwarding to user's app
        uri query -_shield_session
        reverse_proxy localhost:3000 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-For {remote_host}
            header_up X-Forwarded-Proto {scheme}
        }
    }

    @main host $NEW_DOMAIN
    handle @main {
        @notAuth not path /_auth/*
        header @notAuth Content-Security-Policy "frame-ancestors 'self' https://console.phone-stack.app https://phone-stack.app"

        # UNIFIED AUTH: Public auth endpoints (no forward_auth needed)
        @auth_public path /_auth/login* /_auth/logout /_auth/register* /_auth/session /_auth/terminal/* /_auth/code/* /_auth/agent/* /_auth/bridge/* /_auth/sessions* /_auth/audit /api/auth/*
        handle @auth_public {
            header Referrer-Policy "no-referrer"
            reverse_proxy localhost:3005
        }

        # Protected tier management endpoints (require authentication, go to file-api)
        @auth_protected path /_auth/upgrade-* /_auth/add-ssh-key /_auth/remove-ssh-key /_auth/api/keys /_auth/keys /_auth/tier
        handle @auth_protected {
            forward_auth localhost:3005 {
                uri /api/auth/session
                header_up Cookie {http.request.header.Cookie}
                header_up X-Forwarded-Host {http.request.host}
                header_up X-Forwarded-Uri {http.request.uri}
                header_up X-Forwarded-Proto {http.request.scheme}
                copy_headers X-Auth-User X-Auth-Session X-Auth-Tier
            }
            reverse_proxy localhost:3002
        }

        # Terminal sessions list - requires auth
        handle /terminal/sessions {
            forward_auth localhost:3005 {
                uri /api/auth/session
                header_up Cookie {http.request.header.Cookie}
                header_up Accept {http.request.header.Accept}
                header_up X-Forwarded-Uri {uri}
                header_up X-Forwarded-Host {host}
                copy_headers X-Auth-User X-Auth-Tier X-Auth-Session
            }
            reverse_proxy localhost:7701
        }
        # Close terminal session - requires auth
        handle /terminal/session/* {
            forward_auth localhost:3005 {
                uri /api/auth/session
                header_up Cookie {http.request.header.Cookie}
                header_up Accept {http.request.header.Accept}
                header_up X-Forwarded-Uri {uri}
                header_up X-Forwarded-Host {host}
                copy_headers X-Auth-User X-Auth-Tier X-Auth-Session
            }
            reverse_proxy localhost:7701
        }
        # Terminal routes - protected by auth gate
        handle /term/* {
            forward_auth localhost:3005 {
                uri /api/auth/session
                header_up Cookie {http.request.header.Cookie}
                header_up Accept {http.request.header.Accept}
                header_up X-Forwarded-Uri {uri}
                header_up X-Forwarded-Host {host}
                copy_headers X-Auth-User X-Auth-Tier X-Auth-Session
            }
            reverse_proxy localhost:7701
        }
        handle /ttyd/* {
            forward_auth localhost:3005 {
                uri /api/auth/session
                header_up Cookie {http.request.header.Cookie}
                header_up Accept {http.request.header.Accept}
                header_up X-Forwarded-Uri {uri}
                header_up X-Forwarded-Host {host}
                copy_headers X-Auth-User X-Auth-Tier X-Auth-Session
            }
            reverse_proxy localhost:7701
        }
        # Agent bridge - protected by auth gate
        handle /vibe {
            forward_auth localhost:3005 {
                uri /api/auth/session
                header_up Cookie {http.request.header.Cookie}
                header_up Accept {http.request.header.Accept}
                header_up X-Forwarded-Uri {uri}
                header_up X-Forwarded-Host {host}
                copy_headers X-Auth-User X-Auth-Tier X-Auth-Session
            }
            reverse_proxy localhost:7700
        }
        # Static files fallback
        handle {
            root * /var/www/phonestack
            rewrite * /index.html
            file_server
        }
    }

    log {
        output file /var/log/caddy/access.log
        format json
    }
}
CADDYEOF

  else
    # --- Cloudflare Edge Model ---
    # CF terminates public TLS, origin cert + Authenticated Origin Pulls
    log "DEPLOYMENT: Generating Cloudflare Edge Caddyfile (AOP)..."

    # Write origin cert if provided
    if [ -n "$CF_ORIGIN_CERT" ]; then
      echo "$CF_ORIGIN_CERT" > /etc/caddy/origin.crt
      chmod 644 /etc/caddy/origin.crt
      chown caddy:caddy /etc/caddy/origin.crt
    fi
    if [ -n "$CF_ORIGIN_KEY" ]; then
      echo "$CF_ORIGIN_KEY" > /etc/caddy/origin.key
      chmod 600 /etc/caddy/origin.key
      chown caddy:caddy /etc/caddy/origin.key
    fi

    # Download/refresh AOP CA cert
    curl -sS https://developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem -o /etc/caddy/cf-origin-pull-ca.pem
    chown caddy:caddy /etc/caddy/cf-origin-pull-ca.pem
    local CF_AOP_CA_BASE64=$(grep -v '^-----' /etc/caddy/cf-origin-pull-ca.pem | tr -d '\n')

cat > /etc/caddy/Caddyfile << CADDYEOF
{
    auto_https off
    email admin@phone-stack.app
}

import /etc/caddy/sites-enabled/*.caddy

$NEW_DOMAIN:443, $CODE_DOMAIN:443, $DEV_DOMAIN:443 {
    tls /etc/caddy/origin.crt /etc/caddy/origin.key {
        client_auth {
            mode require_and_verify
            trusted_ca_cert $CF_AOP_CA_BASE64
        }
    }

    @code host $CODE_DOMAIN
    handle @code {
        header Content-Security-Policy "frame-ancestors 'self' https://console.phone-stack.app https://phone-stack.app"
        header Access-Control-Allow-Origin "https://console.phone-stack.app"
        header Access-Control-Allow-Methods "GET, POST, OPTIONS"
        header Access-Control-Allow-Headers "Content-Type, Authorization, Cookie, X-Code-Token"
        header Access-Control-Allow-Credentials "true"

        @options method OPTIONS
        handle @options {
            respond "" 204
        }

        reverse_proxy localhost:3002 {
            header_down -Access-Control-Allow-Origin
            header_down -Access-Control-Allow-Methods
            header_down -Access-Control-Allow-Headers
        }
    }

    @dev host $DEV_DOMAIN
    handle @dev {
        @notAuth not path /_auth/*
        header @notAuth Content-Security-Policy "frame-ancestors 'self' https://console.phone-stack.app https://phone-stack.app"

        forward_auth localhost:3002 {
            uri /api/auth/check
            header_up Cookie {http.request.header.Cookie}
        }
        # Strip auth params before forwarding to user's app
        uri query -_shield_session
        reverse_proxy localhost:3000 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-For {remote_host}
            header_up X-Forwarded-Proto {scheme}
        }
    }

    @main host $NEW_DOMAIN
    handle @main {
        @notAuth not path /_auth/*
        header @notAuth Content-Security-Policy "frame-ancestors 'self' https://console.phone-stack.app https://phone-stack.app"

        # UNIFIED AUTH: Public auth endpoints (no forward_auth needed)
        @auth_public path /_auth/login* /_auth/logout /_auth/register* /_auth/session /_auth/terminal/* /_auth/code/* /_auth/agent/* /_auth/bridge/* /_auth/sessions* /_auth/audit /api/auth/*
        handle @auth_public {
            header Referrer-Policy "no-referrer"
            reverse_proxy localhost:3005
        }

        # Protected tier management endpoints (require authentication, go to file-api)
        @auth_protected path /_auth/upgrade-* /_auth/add-ssh-key /_auth/remove-ssh-key /_auth/api/keys /_auth/keys /_auth/tier
        handle @auth_protected {
            forward_auth localhost:3005 {
                uri /api/auth/session
                header_up Cookie {http.request.header.Cookie}
                header_up X-Forwarded-Host {http.request.host}
                header_up X-Forwarded-Uri {http.request.uri}
                header_up X-Forwarded-Proto {http.request.scheme}
                copy_headers X-Auth-User X-Auth-Session X-Auth-Tier
            }
            reverse_proxy localhost:3002
        }

        # Terminal sessions list - requires auth
        handle /terminal/sessions {
            forward_auth localhost:3005 {
                uri /api/auth/session
                header_up Cookie {http.request.header.Cookie}
                header_up Accept {http.request.header.Accept}
                header_up X-Forwarded-Uri {uri}
                header_up X-Forwarded-Host {host}
                copy_headers X-Auth-User X-Auth-Tier X-Auth-Session
            }
            reverse_proxy localhost:7701
        }
        # Close terminal session - requires auth
        handle /terminal/session/* {
            forward_auth localhost:3005 {
                uri /api/auth/session
                header_up Cookie {http.request.header.Cookie}
                header_up Accept {http.request.header.Accept}
                header_up X-Forwarded-Uri {uri}
                header_up X-Forwarded-Host {host}
                copy_headers X-Auth-User X-Auth-Tier X-Auth-Session
            }
            reverse_proxy localhost:7701
        }
        # Terminal routes - protected by auth gate
        handle /term/* {
            forward_auth localhost:3005 {
                uri /api/auth/session
                header_up Cookie {http.request.header.Cookie}
                header_up Accept {http.request.header.Accept}
                header_up X-Forwarded-Uri {uri}
                header_up X-Forwarded-Host {host}
                copy_headers X-Auth-User X-Auth-Tier X-Auth-Session
            }
            reverse_proxy localhost:7701
        }
        handle /ttyd/* {
            forward_auth localhost:3005 {
                uri /api/auth/session
                header_up Cookie {http.request.header.Cookie}
                header_up Accept {http.request.header.Accept}
                header_up X-Forwarded-Uri {uri}
                header_up X-Forwarded-Host {host}
                copy_headers X-Auth-User X-Auth-Tier X-Auth-Session
            }
            reverse_proxy localhost:7701
        }
        # Agent bridge - protected by auth gate
        handle /vibe {
            forward_auth localhost:3005 {
                uri /api/auth/session
                header_up Cookie {http.request.header.Cookie}
                header_up Accept {http.request.header.Accept}
                header_up X-Forwarded-Uri {uri}
                header_up X-Forwarded-Host {host}
                copy_headers X-Auth-User X-Auth-Tier X-Auth-Session
            }
            reverse_proxy localhost:7700
        }
        # Static files fallback
        handle {
            root * /var/www/phonestack
            rewrite * /index.html
            file_server
        }
    }

    log {
        output file /var/log/caddy/access.log
        format json
    }
}
CADDYEOF
  fi

  # Ensure sovereign-shield is running (required for all tiers)
  if ! systemctl is-active --quiet phonestack-sovereign-shield 2>/dev/null; then
    log "DEPLOYMENT: Starting sovereign-shield service..."
    systemctl enable --now phonestack-sovereign-shield 2>/dev/null || true
    sleep 1
  fi

  # Validate and reload Caddy
  if caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>/dev/null; then
    caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile 2>/dev/null || systemctl restart caddy
    log "DEPLOYMENT: Caddy reloaded with $NEW_MODEL config"
  else
    log "DEPLOYMENT ERROR: Invalid Caddyfile, keeping previous config"
    cat /etc/caddy/Caddyfile >> "$LOG_FILE"
  fi
}
