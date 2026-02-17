/**
 * Helper Scripts
 *
 * Privileged helper scripts deployed to /usr/local/bin/ on VPS servers.
 * These are called via sudo by the service user for specific operations.
 */

/**
 * Volume mount helper script.
 * Runs as root via sudo — mounts block volumes at the service user's home.
 * Called by file-api during wake from hibernation.
 */
export function getMountVolumeScript(): string {
  return `#!/bin/bash
# ellulai-mount-volume — Mount a block volume at the service user's home.
# Called by file-api via sudo during wake from hibernation.
# Only allows mounting validated device paths to the home directory.
set -euo pipefail

ACTION="\${1:-}"
DEVICE="\${2:-}"

# Determine service user/home from ellulai config
if [ -f /etc/default/ellulai ]; then
  source /etc/default/ellulai
fi
SVC_USER="\${PS_USER:-dev}"
SVC_HOME="/home/\${SVC_USER}"

case "\$ACTION" in
  mount)
    if [ -z "\$DEVICE" ]; then
      echo '{"success":false,"error":"Missing device parameter"}'
      exit 1
    fi

    # Validate device path: raw devices OR stable /dev/disk/by-id/ symlinks
    # DO: /dev/disk/by-id/scsi-0DO_Volume_*
    # Hetzner: /dev/disk/by-id/scsi-0HC_Volume_*
    # OVH: /dev/disk/by-id/virtio-*
    if [[ ! "\$DEVICE" =~ ^/dev/(sd|vd|xvd|nvme)[a-z0-9]+$ ]] && \\
       [[ ! "\$DEVICE" =~ ^/dev/disk/by-id/(scsi|virtio)-[a-zA-Z0-9_-]+$ ]]; then
      echo '{"success":false,"error":"Invalid device path"}'
      exit 1
    fi

    # Wait for device to appear (cloud attach is async — can take 30-60s under load)
    WAIT=0
    while [ ! -e "\$DEVICE" ] && [ \$WAIT -lt 60 ]; do
      sleep 1
      WAIT=\$((WAIT + 1))
    done

    if [ ! -e "\$DEVICE" ]; then
      echo "{\\"success\\":false,\\"error\\":\\"Device \${DEVICE} not found after 60s\\"}"
      exit 1
    fi

    # Already mounted?
    if mountpoint -q "\$SVC_HOME" 2>/dev/null; then
      echo '{"success":true,"alreadyMounted":true}'
      exit 0
    fi

    # Check filesystem and label. Our mkfs uses -L ellulai-home.
    # If label differs (or missing), volume was pre-formatted by cloud provider.
    FSTYPE=\$(blkid -o value -s TYPE "\$DEVICE" 2>/dev/null || echo "")
    LABEL=\$(blkid -o value -s LABEL "\$DEVICE" 2>/dev/null || echo "")
    FIRST_BOOT=false

    if [ -z "\$FSTYPE" ]; then
      # No filesystem — first boot
      FIRST_BOOT=true
      SKEL_TMP="/tmp/skel-backup-\$\$"
      cp -a "\${SVC_HOME}/." "\$SKEL_TMP/"
      mkfs.ext4 -L ellulai-home "\$DEVICE" >&2
    elif [ "\$LABEL" != "ellulai-home" ]; then
      # Pre-formatted by cloud provider — reformat with skeleton
      FIRST_BOOT=true
      SKEL_TMP="/tmp/skel-backup-\$\$"
      cp -a "\${SVC_HOME}/." "\$SKEL_TMP/"
      mkfs.ext4 -L ellulai-home "\$DEVICE" >&2
    fi

    # nosuid: prevent setuid binaries on user volumes (privilege escalation)
    # nodev: prevent device nodes on user volumes
    mount -o nosuid,nodev "\$DEVICE" "\$SVC_HOME"

    if [ "\$FIRST_BOOT" = "true" ]; then
      cp -a "\$SKEL_TMP/." "\$SVC_HOME/"
      rm -rf "\$SKEL_TMP"
    fi

    # Fix ownership
    chown -R \${SVC_USER}:\${SVC_USER} "\$SVC_HOME"
    [ -d "\$SVC_HOME/.ssh" ] && chmod 700 "\$SVC_HOME/.ssh"

    # Persist mount across reboots (with nosuid,nodev)
    if ! grep -q "\$DEVICE" /etc/fstab 2>/dev/null; then
      echo "\$DEVICE \${SVC_HOME} ext4 defaults,nosuid,nodev,nofail 0 2" >> /etc/fstab
    fi

    echo "{\\"success\\":true,\\"firstBoot\\":\${FIRST_BOOT},\\"device\\":\\"\${DEVICE}\\",\\"mountPoint\\":\\"\${SVC_HOME}\\"}"
    ;;

  flush)
    sync
    IS_MOUNTED=false
    IS_LUKS=false
    if mountpoint -q "\$SVC_HOME" 2>/dev/null; then
      IS_MOUNTED=true
      # Detect if mount source is a LUKS dm-crypt device
      MOUNT_SRC=\$(findmnt -n -o SOURCE "\$SVC_HOME" 2>/dev/null || echo "")
      if [[ "\$MOUNT_SRC" == /dev/mapper/luks-* ]]; then
        IS_LUKS=true
      fi
      if command -v fsfreeze &>/dev/null; then
        fsfreeze --freeze "\$SVC_HOME" 2>/dev/null || true
        fsfreeze --unfreeze "\$SVC_HOME" 2>/dev/null || true
      fi
    fi
    echo "{\\"success\\":true,\\"volumeMounted\\":\${IS_MOUNTED},\\"isLuks\\":\${IS_LUKS}}"
    ;;

  luks-close)
    sync
    fuser -kvm "\$SVC_HOME" 2>/dev/null || true
    sleep 1
    umount "\$SVC_HOME" 2>/dev/null || umount -l "\$SVC_HOME" 2>/dev/null || true
    [ -e /dev/mapper/luks-home ] && cryptsetup luksClose luks-home 2>/dev/null || true
    echo '{"success":true}'
    ;;

  *)
    echo '{"success":false,"error":"Unknown action. Use: mount <device> | flush | luks-close"}'
    exit 1
    ;;
esac`;
}

/**
 * Server identity update script.
 * Runs as root via sudo — updates identity files after tier migration.
 * Called by file-api's /api/update-identity daemon endpoint.
 *
 * Updates: server-id, domain, owner.lock, billing-tier.
 * Regenerates Ed25519 heartbeat keypair and restarts enforcer.
 */
export function getUpdateIdentityScript(): string {
  return `#!/bin/bash
set -euo pipefail

# Parse arguments
SERVER_ID=""
DOMAIN=""
USER_ID=""
BILLING_TIER=""
DEPLOYMENT_MODEL=""

while [ \$# -gt 0 ]; do
  case "\$1" in
    --server-id=*) SERVER_ID="\${1#*=}" ;;
    --domain=*) DOMAIN="\${1#*=}" ;;
    --user-id=*) USER_ID="\${1#*=}" ;;
    --billing-tier=*) BILLING_TIER="\${1#*=}" ;;
    --deployment-model=*) DEPLOYMENT_MODEL="\${1#*=}" ;;
    *) echo '{"success":false,"error":"Unknown argument: '\$1'"}'; exit 1 ;;
  esac
  shift
done

if [ -z "\$SERVER_ID" ]; then
  echo '{"success":false,"error":"Missing --server-id"}'
  exit 1
fi

# Validate server-id format (UUID-like or alphanumeric)
if ! [[ "\$SERVER_ID" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo '{"success":false,"error":"Invalid server-id format"}'
  exit 1
fi

# Update server-id (used by heartbeat signing + vps-event webhooks)
echo -n "\$SERVER_ID" > /etc/ellulai/server-id

# Update domain if provided
if [ -n "\$DOMAIN" ]; then
  echo -n "\$DOMAIN" > /etc/ellulai/domain
fi

# Update owner.lock (used by sovereign-shield for ownership verification)
# File may be immutable (chattr +i) — remove flag first, write, re-lock
if [ -n "\$USER_ID" ]; then
  chattr -i /etc/ellulai/owner.lock 2>/dev/null || true
  echo -n "\$USER_ID" > /etc/ellulai/owner.lock
  chmod 400 /etc/ellulai/owner.lock
  chattr +i /etc/ellulai/owner.lock 2>/dev/null || true
fi

# Update billing tier
if [ -n "\$BILLING_TIER" ]; then
  echo -n "\$BILLING_TIER" > /etc/ellulai/billing-tier
fi

# Update metadata.json to keep it consistent with identity files
if [ -f /opt/ellulai/metadata.json ]; then
  jq --arg sid "\$SERVER_ID" \\
     --arg dom "\${DOMAIN:-\$(jq -r '.domain // empty' /opt/ellulai/metadata.json)}" \\
     --arg uid "\${USER_ID:-\$(jq -r '.user_id // empty' /opt/ellulai/metadata.json)}" \\
     --arg dm "\${DEPLOYMENT_MODEL:-\$(jq -r '.deployment_model // empty' /opt/ellulai/metadata.json)}" \\
     '.server_id=\$sid | .domain=\$dom | .user_id=\$uid | .deployment_model=\$dm' \\
     /opt/ellulai/metadata.json > /opt/ellulai/metadata.json.tmp \\
  && mv /opt/ellulai/metadata.json.tmp /opt/ellulai/metadata.json \\
  && chmod 600 /opt/ellulai/metadata.json \\
  || true
fi

# Regenerate Ed25519 heartbeat keypair (new identity = new keys)
openssl genpkey -algorithm Ed25519 -out /etc/ellulai/heartbeat.key 2>/dev/null
openssl pkey -in /etc/ellulai/heartbeat.key -pubout -out /etc/ellulai/heartbeat.pub 2>/dev/null
chmod 600 /etc/ellulai/heartbeat.key
chmod 644 /etc/ellulai/heartbeat.pub

# ============================================================
# SERVICE RESTART
# ============================================================
#
# Restart order (dependency-aware):
#   1. ellulai-enforcer         — server-id, heartbeat keypair
#   2. ellulai-sovereign-shield — domain (WebAuthn RP ID + CORS)
#   3. caddy                    — reverse proxy (@main host matcher)
#
# No restart needed (read identity on-demand per request):
#   - ellulai-file-api, ellulai-agent-bridge
#
# Safety invariant: Caddy must NEVER be left stopped. If this
# script crashes mid-restart, the EXIT trap restarts Caddy so
# the server stays reachable.
# ============================================================

log() { echo "[update-identity] \$*" >&2; }

# Trap: if the script exits for ANY reason (crash, OOM kill signal,
# set -e failure), make sure Caddy is running. A stopped Caddy means
# the server is completely unreachable — no SSH, no bridge, nothing.
cleanup() {
  if ! systemctl is-active --quiet caddy 2>/dev/null; then
    log "EXIT TRAP: Caddy is not running — forcing restart"
    systemctl restart caddy 2>/dev/null || systemctl start caddy 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Restart a systemd service with retry + stabilization check.
# Args: <service-name> <max-attempts> <stabilize-seconds>
# Returns 0 if service is confirmed active, 1 if all attempts failed.
restart_svc() {
  local svc=\$1
  local max_attempts=\${2:-3}
  local stabilize=\${3:-5}
  local attempt=1

  while [ \$attempt -le \$max_attempts ]; do
    log "Restarting \$svc (attempt \$attempt/\$max_attempts)"

    # timeout prevents hanging if service is stuck in stop/start phase
    if timeout 30 systemctl restart "\$svc" >/dev/null 2>&1; then
      # systemctl restart returned 0, but the process could crash instantly.
      # Poll is-active to catch immediate crashes before declaring success.
      local elapsed=0
      while [ \$elapsed -lt \$stabilize ]; do
        sleep 1
        elapsed=\$((elapsed + 1))
        if ! systemctl is-active --quiet "\$svc" 2>/dev/null; then
          log "WARNING: \$svc crashed \${elapsed}s after start"
          break
        fi
      done

      if systemctl is-active --quiet "\$svc" 2>/dev/null; then
        log "\$svc is active (stable for \${stabilize}s)"
        return 0
      fi
    else
      log "WARNING: systemctl restart \$svc failed (attempt \$attempt)"
    fi

    attempt=\$((attempt + 1))
    if [ \$attempt -le \$max_attempts ]; then
      log "Retrying in 3s..."
      sleep 3
    fi
  done

  log "ERROR: \$svc failed after \$max_attempts attempts"
  return 1
}

FAILURES=""

# --- Phase 1: Regenerate Caddyfile BEFORE restarting anything ---
# Config must be on disk before Caddy starts, or it boots with stale domain.
CADDY_REGEN=false
if [ -n "\$DOMAIN" ]; then
  SHORT_ID="\${SERVER_ID:0:8}"

  # Resolve deployment model: explicit param → metadata.json → Caddyfile heuristic
  MODEL="\$DEPLOYMENT_MODEL"
  if [ -z "\$MODEL" ] && [ -f /opt/ellulai/metadata.json ]; then
    MODEL=\$(jq -r '.deployment_model // empty' /opt/ellulai/metadata.json 2>/dev/null)
  fi
  if [ -z "\$MODEL" ]; then
    # Legacy fallback: detect from Caddyfile (kept for backwards compat with old API)
    MODEL="cloudflare"
    if [ -f /etc/caddy/Caddyfile ]; then
      if ! grep -q "auto_https off" /etc/caddy/Caddyfile 2>/dev/null; then
        MODEL="direct"
      fi
    fi
  fi

  if [ "\$MODEL" = "direct" ]; then
    CODE_DOMAIN="\${SHORT_ID}-dcode.ellul.ai"
    DEV_DOMAIN="\${SHORT_ID}-ddev.ellul.app"
  else
    CODE_DOMAIN="\${SHORT_ID}-code.ellul.ai"
    DEV_DOMAIN="\${SHORT_ID}-dev.ellul.app"
  fi

  # Atomic write: generate to .tmp, validate, then mv into place.
  # stdout -> .tmp (the Caddyfile), stderr -> script stderr (visible in logs)
  if node /usr/local/bin/ellulai-caddy-gen --model "\$MODEL" --main-domain "\$DOMAIN" --code-domain "\$CODE_DOMAIN" --dev-domain "\$DEV_DOMAIN" > /etc/caddy/Caddyfile.tmp; then
    # Validate BEFORE moving — never overwrite with a broken config
    if caddy validate --config /etc/caddy/Caddyfile.tmp --adapter caddyfile >/dev/null 2>&1; then
      mv /etc/caddy/Caddyfile.tmp /etc/caddy/Caddyfile
      CADDY_REGEN=true
      log "Caddyfile regenerated and validated (model=\$MODEL)"
    else
      log "ERROR: generated Caddyfile failed validation, keeping existing"
      rm -f /etc/caddy/Caddyfile.tmp
      FAILURES="\${FAILURES} caddy-config"
    fi
  else
    log "ERROR: caddy-gen failed, keeping existing Caddyfile"
    rm -f /etc/caddy/Caddyfile.tmp
    FAILURES="\${FAILURES} caddy-gen"
  fi
fi

# --- Phase 2: Restart upstreams (Caddy stays running) ---
# Caddy is NOT stopped — the daemon port (3006 → file-api:3002) must
# stay alive so callDaemon gets its response. The main site (443) may
# briefly 502 during shield restart (~3-5s) — acceptable during migration.

# 1. Enforcer — heartbeat signing, independent of Caddy
restart_svc ellulai-enforcer 3 3 || FAILURES="\${FAILURES} enforcer"

# 2. Sovereign-shield — main site forward_auth depends on this
restart_svc ellulai-sovereign-shield 3 5 || FAILURES="\${FAILURES} shield"

# --- Phase 3: Reload Caddy (graceful, no connection drop) ---
# caddy reload applies the new Caddyfile without dropping existing
# connections — the callDaemon TLS session on port 3006 stays alive.
if [ "\$CADDY_REGEN" = "true" ] || [ -n "\$DOMAIN" ]; then
  log "Reloading Caddy with new config..."
  if caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
    sleep 2
    if systemctl is-active --quiet caddy 2>/dev/null; then
      log "Caddy reloaded successfully"
    else
      log "WARNING: Caddy not active after reload, restarting..."
      restart_svc caddy 3 3 || FAILURES="\${FAILURES} caddy"
    fi
  else
    log "WARNING: Caddy reload failed, falling back to restart..."
    restart_svc caddy 3 3 || FAILURES="\${FAILURES} caddy"
  fi
fi

# --- Phase 4: Final verification ---
FAILED_SVCS=""
for svc in ellulai-enforcer ellulai-sovereign-shield caddy; do
  if ! systemctl is-active --quiet "\$svc" 2>/dev/null; then
    FAILED_SVCS="\${FAILED_SVCS} \$svc"
  fi
done

if [ -n "\$FAILED_SVCS" ]; then
  log "CRITICAL: services not running after restart:\$FAILED_SVCS"
  echo '{"success":true,"serverId":"'\$SERVER_ID'","warnings":"services not active:'\$FAILED_SVCS'"}'
else
  log "All services verified active"
  echo '{"success":true,"serverId":"'\$SERVER_ID'"}'
fi`;
}

/**
 * Identity restore script.
 * Runs as root via sudo — restores passkey DB from volume backup after wake.
 * Called by file-api's /api/restore-identity daemon endpoint.
 *
 * Copies $HOME/.ellulai-identity/local-auth.db → /etc/ellulai/shield-data/local-auth.db
 * Sets permissions so sovereign-shield ($SVC_USER) can read/write it.
 * Restores .web_locked_activated marker if it was set at backup time.
 * Restarts sovereign-shield to pick up restored passkey DB.
 */
export function getRestoreIdentityScript(): string {
  return `#!/bin/bash
set -euo pipefail

# Determine service user/home from ellulai config
if [ -f /etc/default/ellulai ]; then
  source /etc/default/ellulai
fi
SVC_USER="\${PS_USER:-dev}"
SVC_HOME="/home/\${SVC_USER}"

BACKUP_DIR="\${SVC_HOME}/.ellulai-identity"
TARGET_DIR="/etc/ellulai/shield-data"
RESTORED=false

if [ ! -d "\$BACKUP_DIR" ]; then
  echo '{"success":true,"restored":false,"reason":"no_backup_dir"}'
  exit 0
fi

if [ ! -f "\${BACKUP_DIR}/local-auth.db" ]; then
  echo '{"success":true,"restored":false,"reason":"no_backup_file"}'
  exit 0
fi

# Copy passkey DB files
cp -f "\${BACKUP_DIR}/local-auth.db" "\${TARGET_DIR}/local-auth.db"
[ -f "\${BACKUP_DIR}/local-auth.db-wal" ] && cp -f "\${BACKUP_DIR}/local-auth.db-wal" "\${TARGET_DIR}/local-auth.db-wal"
[ -f "\${BACKUP_DIR}/local-auth.db-shm" ] && cp -f "\${BACKUP_DIR}/local-auth.db-shm" "\${TARGET_DIR}/local-auth.db-shm"

# Set permissions: owned by service user (shield-data dir is $SVC_USER-owned)
chown \${SVC_USER}:\${SVC_USER} "\${TARGET_DIR}/local-auth.db"
chmod 600 "\${TARGET_DIR}/local-auth.db"
[ -f "\${TARGET_DIR}/local-auth.db-wal" ] && chown \${SVC_USER}:\${SVC_USER} "\${TARGET_DIR}/local-auth.db-wal" && chmod 600 "\${TARGET_DIR}/local-auth.db-wal"
[ -f "\${TARGET_DIR}/local-auth.db-shm" ] && chown \${SVC_USER}:\${SVC_USER} "\${TARGET_DIR}/local-auth.db-shm" && chmod 600 "\${TARGET_DIR}/local-auth.db-shm"

RESTORED=true

# Restore security tier marker if it was web_locked at backup time
if [ -f "\${BACKUP_DIR}/.web_locked_activated" ]; then
  echo "web_locked" > /etc/ellulai/security-tier
  chmod 644 /etc/ellulai/security-tier
  chown \${SVC_USER}:\${SVC_USER} /etc/ellulai/security-tier
fi

# Restart sovereign-shield to pick up restored passkey DB
systemctl restart ellulai-sovereign-shield 2>/dev/null || true

echo "{\\"success\\":true,\\"restored\\":\${RESTORED}}"`;
}

/**
 * Migration pull helper script.
 * Runs as root via sudo — downloads and extracts a migration archive
 * from a source server. Running as root bypasses Warden's iptables
 * redirect (which intercepts dev user's outbound TCP through its MITM
 * proxy, breaking TLS verification against the Cloudflare Origin CA).
 *
 * Called by file-api's /api/migrate/pull endpoint.
 */
export function getMigratePullScript(): string {
  return `#!/bin/bash
set -euo pipefail

# Usage: echo <token> | ellulai-migrate-pull <download_url> <source_ip> <home_dir>
# Token is read from stdin to avoid exposure in ps output.
# All arguments are validated by file-api before calling this script.

# Progress log — all steps written to stderr for diagnostics
log() { echo "[migrate-pull] \$*" >&2; }

URL="\${1:-}"
SOURCE_IP="\${2:-}"
TARGET_DIR="\${3:-}"

log "START url=\${URL:0:80} src=\$SOURCE_IP dir=\$TARGET_DIR"

# Read token from stdin (single line)
read -r TOKEN
log "token read (\${#TOKEN} chars)"

if [ -z "\$URL" ] || [ -z "\$TOKEN" ] || [ -z "\$TARGET_DIR" ]; then
  echo '{"success":false,"error":"Missing required arguments"}' >&2
  exit 1
fi

# Validate target directory (must be a home dir, prevent path traversal)
if [[ ! "\$TARGET_DIR" =~ ^/home/[a-z_][a-z0-9_-]*$ ]]; then
  echo '{"success":false,"error":"Invalid target directory"}' >&2
  exit 1
fi

# Validate URL format (must be daemon API endpoint)
if [[ ! "\$URL" =~ ^https://(daemon\\.ellul\\.ai|[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+):3006/ ]]; then
  echo '{"success":false,"error":"Invalid source URL"}' >&2
  exit 1
fi

# Download to temp file (avoids pipefail masking curl errors, better diagnostics)
TMPFILE="/tmp/migrate-download-\$\$.tar.gz"

# Strict TLS: verify source server's origin cert against CF Origin CA.
if [ -z "\$SOURCE_IP" ]; then
  echo '{"success":false,"error":"SOURCE_IP is required for secure transfer"}' >&2
  exit 1
fi

if [ ! -f /etc/caddy/cf-origin-ca.pem ]; then
  echo '{"success":false,"error":"CF Origin CA cert missing at /etc/caddy/cf-origin-ca.pem"}' >&2
  exit 1
fi

# Verify CA cert is parseable before attempting download
log "verifying CA cert..."
if ! openssl x509 -in /etc/caddy/cf-origin-ca.pem -noout 2>/dev/null; then
  echo '{"success":false,"error":"CF Origin CA cert is not valid PEM"}' >&2
  exit 1
fi
log "CA cert OK"

# Download with verbose error reporting
CURL_STDERR="/tmp/migrate-curl-err-\$\$.log"
trap "rm -f \$TMPFILE \$CURL_STDERR" EXIT

log "starting download..."
set +e
curl -sSf --max-time 300 \\
  --resolve "daemon.ellul.ai:3006:\$SOURCE_IP" \\
  --cacert /etc/caddy/cf-origin-ca.pem \\
  -H "Authorization: Bearer \$TOKEN" \\
  -o "\$TMPFILE" "\$URL" 2>"\$CURL_STDERR"
CURL_EXIT=\$?
set -e

log "curl exit=\$CURL_EXIT"

if [ \$CURL_EXIT -ne 0 ]; then
  CURL_ERR=\$(cat "\$CURL_STDERR" 2>/dev/null | head -5 | tr '\\n' ' ')
  log "curl FAILED: exit=\$CURL_EXIT err=\$CURL_ERR"
  echo "curl exit \$CURL_EXIT: \$CURL_ERR" >&2
  exit 1
fi

# Validate download (must be non-empty)
DLSIZE=\$(stat -c%s "\$TMPFILE" 2>/dev/null || echo 0)
log "downloaded \$DLSIZE bytes"
if [ ! -s "\$TMPFILE" ]; then
  echo '{"success":false,"error":"Downloaded file is empty"}' >&2
  exit 1
fi

# Extract archive
log "extracting..."
tar -xzf "\$TMPFILE" --no-same-owner -C "\$TARGET_DIR"
log "extracted OK"

# Fix ownership (tar --no-same-owner uses running user, which is root here)
if [ -f /etc/default/ellulai ]; then
  source /etc/default/ellulai
fi
SVC_USER="\${PS_USER:-dev}"
chown -R \${SVC_USER}:\${SVC_USER} "\$TARGET_DIR"

log "DONE — ownership set to \$SVC_USER"
echo '{"success":true}'`;
}

/**
 * Safe package installer script.
 * Runs as root via sudo — wraps apt-get install with input validation.
 * Prevents command injection via carefully validated package names.
 */
export function getAptInstallScript(): string {
  return `#!/bin/bash
set -euo pipefail

if [ \$# -eq 0 ]; then
  echo "Usage: sudo ellulai-apt-install <package> [package ...]"
  exit 1
fi

# Validate each argument: must be a valid Debian package name
for arg in "\$@"; do
  # Reject flags
  if [[ "\$arg" == -* ]]; then
    echo "Error: flags not allowed. Use: sudo ellulai-apt-install <package-name>"
    exit 1
  fi
  # Reject paths and .deb files
  if [[ "\$arg" == */* ]] || [[ "\$arg" == *.deb ]]; then
    echo "Error: local paths not allowed. Use: sudo ellulai-apt-install <package-name>"
    exit 1
  fi
  # Must match Debian package name pattern
  if ! [[ "\$arg" =~ ^[a-zA-Z0-9][a-zA-Z0-9.+\\-]*$ ]]; then
    echo "Error: invalid package name '\$arg'"
    exit 1
  fi
done

export DEBIAN_FRONTEND=noninteractive
exec apt-get install -y \\
  -o Dpkg::Options::="--force-confdef" \\
  -o Dpkg::Options::="--force-confold" \\
  "\$@"`;
}
