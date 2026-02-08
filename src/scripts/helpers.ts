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
# phonestack-mount-volume — Mount a block volume at the service user's home.
# Called by file-api via sudo during wake from hibernation.
# Only allows mounting validated device paths to the home directory.
set -euo pipefail

ACTION="\${1:-}"
DEVICE="\${2:-}"

# Determine service user/home from phonestack config
if [ -f /etc/default/phonestack ]; then
  source /etc/default/phonestack
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

    # Wait for device to appear (cloud attach is async)
    WAIT=0
    while [ ! -e "\$DEVICE" ] && [ \$WAIT -lt 30 ]; do
      sleep 1
      WAIT=\$((WAIT + 1))
    done

    if [ ! -e "\$DEVICE" ]; then
      echo "{\\"success\\":false,\\"error\\":\\"Device \${DEVICE} not found after 30s\\"}"
      exit 1
    fi

    # Already mounted?
    if mountpoint -q "\$SVC_HOME" 2>/dev/null; then
      echo '{"success":true,"alreadyMounted":true}'
      exit 0
    fi

    # Check filesystem and label. Our mkfs uses -L phonestack-home.
    # If label differs (or missing), volume was pre-formatted by cloud provider.
    FSTYPE=\$(blkid -o value -s TYPE "\$DEVICE" 2>/dev/null || echo "")
    LABEL=\$(blkid -o value -s LABEL "\$DEVICE" 2>/dev/null || echo "")
    FIRST_BOOT=false

    if [ -z "\$FSTYPE" ]; then
      # No filesystem — first boot
      FIRST_BOOT=true
      SKEL_TMP="/tmp/skel-backup-\$\$"
      cp -a "\${SVC_HOME}/." "\$SKEL_TMP/"
      mkfs.ext4 -L phonestack-home "\$DEVICE"
    elif [ "\$LABEL" != "phonestack-home" ]; then
      # Pre-formatted by cloud provider — reformat with skeleton
      FIRST_BOOT=true
      SKEL_TMP="/tmp/skel-backup-\$\$"
      cp -a "\${SVC_HOME}/." "\$SKEL_TMP/"
      mkfs.ext4 -L phonestack-home "\$DEVICE"
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
    if mountpoint -q "\$SVC_HOME" 2>/dev/null; then
      IS_MOUNTED=true
      if command -v fsfreeze &>/dev/null; then
        fsfreeze --freeze "\$SVC_HOME" 2>/dev/null || true
        fsfreeze --unfreeze "\$SVC_HOME" 2>/dev/null || true
      fi
    fi
    echo "{\\"success\\":true,\\"volumeMounted\\":\${IS_MOUNTED}}"
    ;;

  *)
    echo '{"success":false,"error":"Unknown action. Use: mount <device> | flush"}'
    exit 1
    ;;
esac`;
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
  echo "Usage: sudo phonestack-apt-install <package> [package ...]"
  exit 1
fi

# Validate each argument: must be a valid Debian package name
for arg in "\$@"; do
  # Reject flags
  if [[ "\$arg" == -* ]]; then
    echo "Error: flags not allowed. Use: sudo phonestack-apt-install <package-name>"
    exit 1
  fi
  # Reject paths and .deb files
  if [[ "\$arg" == */* ]] || [[ "\$arg" == *.deb ]]; then
    echo "Error: local paths not allowed. Use: sudo phonestack-apt-install <package-name>"
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
