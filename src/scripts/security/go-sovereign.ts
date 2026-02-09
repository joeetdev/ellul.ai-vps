/**
 * Go sovereign script - disables web terminal and ellul.ai access.
 * User maintains SSH-only access after running this.
 * Requires SSH key to be installed first (Tier 2B prerequisite).
 *
 * SAFETY: Verifies SSH is running and port is open before disabling web terminal.
 */
export function getGoSovereignScript(): string {
  return `#!/bin/bash
set -e

SOVEREIGN_MARKER="/etc/ellulai/.sovereign-mode"

if [ -f "$SOVEREIGN_MARKER" ]; then
  echo "Already in Sovereign Mode."
  echo "To restore web terminal: sudo restore-terminal"
  exit 0
fi

# Require SSH key
if [ ! -f /home/dev/.ssh/authorized_keys ] || [ ! -s /home/dev/.ssh/authorized_keys ]; then
  echo "ERROR: SSH key required before going sovereign."
  echo ""
  echo "Sovereign Mode removes ALL platform access."
  echo "SSH will be your ONLY way into this server."
  echo ""
  echo "First, add and test your SSH key:"
  echo "  1. Add key via dashboard or: sudo setup-ssh-key 'ssh-ed25519 AAAA...'"
  echo "  2. Verify: ssh dev@$(hostname -I | awk '{print $1}')"
  echo "  3. Then retry: sudo go-sovereign"
  exit 1
fi

# SAFETY CHECK: Verify sshd is running
if ! systemctl is-active --quiet sshd 2>/dev/null; then
  echo "ERROR: SSH daemon (sshd) is not running!"
  echo ""
  echo "Cannot go sovereign without working SSH access."
  echo "Start sshd first: sudo systemctl start sshd"
  exit 1
fi
echo "SSH daemon verified running."

# SAFETY CHECK: Verify port 22 is open in firewall
if ! ufw status | grep -q "22/tcp.*ALLOW"; then
  echo "ERROR: SSH port (22) is not open in firewall!"
  echo ""
  echo "Cannot go sovereign without SSH access."
  echo "Open SSH port first: sudo ufw allow 22/tcp"
  exit 1
fi
echo "SSH port verified open."

echo ""
echo "SOVEREIGN MODE - POINT OF NO RETURN"
echo ""
echo "  This will:"
echo "    - DESTROY the JWT secret (web terminal dies)"
echo "    - STOP the enforcer daemon (no platform control)"
echo "    - DISABLE Sovereign Shield if active"
echo "    - REMOVE all platform communication"
echo ""
echo "  After this, SSH is your ONLY way in."
echo "  ellul.ai cannot help you recover access."
echo ""
echo "  Before continuing, verify SSH works in another terminal:"
echo "    ssh dev@$(hostname -I | awk '{print $1}')"
echo ""
read -p "Type SOVEREIGN to confirm: " CONFIRM
if [ "$CONFIRM" != "SOVEREIGN" ]; then
  echo "Aborted."
  exit 0
fi

# 1. Stop terminal services
systemctl stop 'ttyd@*' 2>/dev/null || true
systemctl disable 'ttyd@*' 2>/dev/null || true

# 2. Stop and disable enforcer
systemctl stop ellulai-enforcer 2>/dev/null || true
systemctl disable ellulai-enforcer 2>/dev/null || true

# 3. Stop Sovereign Shield if running
systemctl stop ellulai-sovereign-shield 2>/dev/null || true
systemctl disable ellulai-sovereign-shield 2>/dev/null || true

# 4. Destroy JWT secret
rm -f /etc/ellulai/jwt-secret

# 5. Destroy synced secrets
rm -f /home/dev/.ellulai-env

# 6. Create sovereign mode marker
touch "$SOVEREIGN_MARKER"
chmod 400 "$SOVEREIGN_MARKER"

echo ""
echo "SOVEREIGN MODE ACTIVE"
echo ""
echo "  JWT secret destroyed."
echo "  Enforcer daemon disabled."
echo "  Web terminal disabled."
echo ""
echo "  ellul.ai now has ZERO access to this server."
echo "  Your only access: ssh dev@$(hostname -I | awk '{print $1}')"
echo ""
echo "  To restore web terminal (via SSH): sudo restore-terminal"`;
}
