/**
 * Lock-web-only script - permanently disables SSH key installation
 * without installing a key. Creates sovereign lock with port 22 blocked.
 * One-way operation.
 *
 * SAFETY: Verifies web terminal is accessible before blocking SSH to prevent bricking.
 */
export function getLockWebOnlyScript(): string {
  return `#!/bin/bash
set -e

[ -f /etc/default/ellulai ] && source /etc/default/ellulai
SVC_USER="\${PS_USER:-dev}"
SVC_HOME="/home/\${SVC_USER}"

LOCK_FILE="/etc/ellulai/shield-data/.sovereign-keys"

# Check if already locked
if [ -f "$LOCK_FILE" ]; then
  echo "ERROR: Sovereign Lock is already active."
  exit 1
fi

# Check for existing SSH keys
if [ -f \$SVC_HOME/.ssh/authorized_keys ] && [ -s \$SVC_HOME/.ssh/authorized_keys ]; then
  echo "ERROR: SSH keys already exist on this server."
  echo "Cannot lock to web-only mode with existing SSH keys."
  exit 1
fi

# SAFETY CHECK: Verify web terminal is running before proceeding
if ! systemctl is-active --quiet ttyd@main 2>/dev/null; then
  echo "ERROR: Web terminal (ttyd@main) is not running!"
  echo "Cannot lock to web-only mode without working web terminal."
  echo "This would brick the server."
  exit 1
fi

# SAFETY CHECK: Verify web terminal is accessible
TERM_CHECK=\$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:7681/ 2>/dev/null || echo "000")
if ! echo "\$TERM_CHECK" | grep -qE "200|401|302"; then
  echo "ERROR: Web terminal is not responding (HTTP \$TERM_CHECK)!"
  echo "Cannot lock to web-only mode without accessible web terminal."
  echo "This would brick the server."
  exit 1
fi

echo "Web terminal verified running and accessible."

# Support --force for daemon-triggered execution
if [ "\${1:-}" != "--force" ]; then
  echo ""
  echo "LOCK TO WEB-ONLY MODE"
  echo ""
  echo "  This will PERMANENTLY disable SSH key installation."
  echo ""
  echo "  + Protects against key injection if platform breached"
  echo "  - You can NEVER add SSH access to this server"
  echo "  - Cannot be undone"
  echo ""
  read -p "Type LOCK to confirm: " CONFIRM
  if [ "$CONFIRM" != "LOCK" ]; then
    echo "Aborted."
    exit 0
  fi
fi

# Create the sovereign lock (empty - no key installed)
touch "$LOCK_FILE"
chmod 400 "$LOCK_FILE"
chattr +i "$LOCK_FILE" 2>/dev/null || true

# Ensure port 22 stays closed (web terminal verified working above)
ufw delete allow 22/tcp 2>/dev/null || true
ufw deny 22/tcp 2>/dev/null || true

echo ""
echo "Locked to Web-Only mode."
echo "SSH key installation permanently disabled."
echo "Port 22 blocked."`;
}
