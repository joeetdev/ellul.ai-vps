/**
 * SSH key setup script - allows users to add SSH keys after provisioning.
 * Creates the sovereign lock file after first key install, preventing
 * future key injection via the platform.
 */
export function getSetupSshKeyScript(): string {
  return `#!/bin/bash
set -e

LOCK_FILE="/etc/ellulai/.sovereign-keys"
SSH_KEY="$1"

# Check if already locked
if [ -f "$LOCK_FILE" ]; then
  echo "ERROR: Sovereign Lock is active."
  echo "SSH key installation is permanently disabled via platform."
  echo ""
  echo "To add more keys via SSH:"
  echo "  ellulai-add-key 'ssh-ed25519 AAAA...'"
  exit 1
fi

if [ -z "$SSH_KEY" ]; then
  echo "Usage: sudo setup-ssh-key \\"ssh-ed25519 AAAA...\\""
  exit 1
fi

if ! echo "$SSH_KEY" | grep -qE '^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp256) '; then
  echo "ERROR: Invalid SSH key format."
  echo "Key must start with: ssh-ed25519, ssh-rsa, or ecdsa-sha2-nistp256"
  exit 1
fi

# Install the key
mkdir -p /home/dev/.ssh
chmod 700 /home/dev/.ssh
echo "$SSH_KEY" >> /home/dev/.ssh/authorized_keys
chmod 600 /home/dev/.ssh/authorized_keys
chown -R dev:dev /home/dev/.ssh

# Lock down authorized_keys (prevents tampering even by root)
chattr +i /home/dev/.ssh/authorized_keys 2>/dev/null || true

# Create the sovereign lock (prevents future platform key injection)
touch "$LOCK_FILE"
chmod 400 "$LOCK_FILE"
chattr +i "$LOCK_FILE" 2>/dev/null || true

# Open port 22
ufw allow 22/tcp comment 'SSH' >/dev/null 2>&1
systemctl restart sshd 2>/dev/null || systemctl restart ssh

PUBLIC_IP=$(hostname -I | awk '{print $1}')
echo ""
echo "SSH key installed successfully."
echo "Sovereign Lock engaged (no further keys can be added via platform)."
echo "authorized_keys locked (chattr +i). Use sudo chattr -i to modify."
echo "Port 22 opened."
echo ""
echo "Connect with: ssh dev@$PUBLIC_IP"`;
}

/**
 * Helper script for users to add additional SSH keys after sovereign lock.
 * Handles the chattr unlock/lock cycle automatically.
 */
export function getAddSshKeyScript(): string {
  return `#!/bin/bash
set -e

SSH_KEY="$1"

if [ -z "$SSH_KEY" ]; then
  echo "Usage: ellulai-add-key 'ssh-ed25519 AAAA...'"
  exit 1
fi

if ! echo "$SSH_KEY" | grep -qE '^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp256) '; then
  echo "ERROR: Invalid SSH key format."
  echo "Key must start with: ssh-ed25519, ssh-rsa, or ecdsa-sha2-nistp256"
  exit 1
fi

sudo chattr -i /home/dev/.ssh/authorized_keys
echo "$SSH_KEY" >> /home/dev/.ssh/authorized_keys
sudo chattr +i /home/dev/.ssh/authorized_keys
echo "Key added and file re-locked."`;
}
