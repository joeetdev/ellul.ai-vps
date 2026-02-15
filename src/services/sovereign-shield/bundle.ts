/**
 * Sovereign Shield Bundle Generator
 *
 * Bundles the modular TypeScript source files into a deployable JavaScript
 * script using esbuild. This replaces the monolithic 7,000+ line template.
 *
 * Usage:
 *   import { getSovereignShieldScript, getSovereignShieldService } from './bundle';
 *   const script = getSovereignShieldScript(hostname);
 */

import * as esbuild from 'esbuild';
import * as path from 'path';
import * as fs from 'fs';
import { fileURLToPath } from 'url';
import { VERSION } from '../../version';

// Cache for bundled script
let cachedBundle: string | null = null;

/**
 * Get the source directory path.
 * Works whether running from src/ (dev) or dist/ (production).
 */
function getSourceDir(): string {
  const currentFile = fileURLToPath(import.meta.url);
  const currentDir = path.dirname(currentFile);

  // If we're in dist (compiled), go up to package root and into src/
  if (currentDir.includes('/dist/') || currentDir.endsWith('/dist')) {
    const packageRoot = currentDir.replace(/\/dist(\/.*)?$/, '');
    return path.join(packageRoot, 'src', 'services', 'sovereign-shield');
  }

  // Already in src/
  return currentDir;
}

/**
 * Bundle the modular TypeScript files into a single JavaScript file.
 */
async function bundleModular(): Promise<string> {
  if (cachedBundle) return cachedBundle;

  const sourceDir = getSourceDir();
  const entryPoint = path.join(sourceDir, 'src', 'main.ts');

  const result = await esbuild.build({
    entryPoints: [entryPoint],
    bundle: true,
    platform: 'node',
    target: 'node18',
    format: 'cjs',
    minify: false, // Keep readable for debugging on VPS
    write: false,
    external: [
      // Node built-ins
      'fs', 'path', 'crypto', 'http', 'https', 'url', 'events', 'stream', 'util', 'os',
      // Runtime dependencies (installed on VPS)
      'hono', '@hono/node-server', 'better-sqlite3', '@simplewebauthn/server',
    ],
    plugins: [{
      name: 'static-text',
      setup(build) {
        // Load .html and .js files from static/ directories as text strings
        build.onLoad({ filter: /[/\\]static[/\\][^/\\]+\.(html|js)$/ }, async (args) => ({
          contents: `export default ${JSON.stringify(fs.readFileSync(args.path, 'utf8'))}`,
          loader: 'js',
        }));
      },
    }],
  });

  if (!result.outputFiles?.[0]) {
    throw new Error('esbuild produced no output');
  }

  cachedBundle = result.outputFiles[0].text;
  return cachedBundle;
}

/**
 * Get the sovereign shield script for VPS deployment.
 * Returns JavaScript code that runs the auth service.
 */
export async function getSovereignShieldScript(hostname: string): Promise<string> {
  const bundledCode = await bundleModular();

  // Wrap in IIFE with hostname injection
  return `// Sovereign Shield v${VERSION.components.sovereignShield}
// ellul.ai VPS Authentication Service
// Generated from modular source

// Hostname configuration
process.env.ELLULAI_HOSTNAME = ${JSON.stringify(hostname)};

${bundledCode}
`;
}

/**
 * Get the sovereign shield script synchronously (for compatibility).
 * Uses pre-bundled output if available.
 */
export function getSovereignShieldScriptSync(hostname: string): string {
  // For synchronous use, read from pre-bundled file if available
  const preBundledPath = path.join(__dirname, 'dist', 'server.js');
  if (fs.existsSync(preBundledPath)) {
    const bundledCode = fs.readFileSync(preBundledPath, 'utf8');
    return `// Sovereign Shield v${VERSION.components.sovereignShield}
// ellul.ai VPS Authentication Service
process.env.ELLULAI_HOSTNAME = ${JSON.stringify(hostname)};
${bundledCode}
`;
  }

  // Fallback: throw error indicating async bundle is needed
  throw new Error('Pre-bundled sovereign-shield not found. Run build first or use async getSovereignShieldScript()');
}

/**
 * Generate the systemd service file for sovereign-shield.
 */
export function getSovereignShieldService(): string {
  return `[Unit]
Description=ellul.ai Sovereign Shield (Passkey Auth)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ellulai/auth
ExecStart=/usr/bin/node /opt/ellulai/auth/server.js
Restart=on-failure
RestartSec=5
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
`;
}

/**
 * Generate the ellulai-downgrade script.
 */
export function getDowngradeScript(): string {
  return `#!/bin/bash
set -e

TIER_FILE="/etc/ellulai/security-tier"
LOG_FILE="/var/log/ellulai-enforcer.log"
[ -f /etc/default/ellulai ] && source /etc/default/ellulai
SVC_USER="\${PS_USER:-dev}"
SVC_HOME="/home/\${SVC_USER}"
SSH_AUTH_KEYS="\${SVC_HOME}/.ssh/authorized_keys"

log() { echo "[$(date -Iseconds)] DOWNGRADE: $1" >> "$LOG_FILE"; echo "$1"; }

CURRENT_TIER="standard"
if [ -f "$TIER_FILE" ]; then
  CURRENT_TIER=$(cat "$TIER_FILE")
fi

if [ "$CURRENT_TIER" = "standard" ]; then
  log "Already at Standard tier"
  exit 0
fi

if [ "$CURRENT_TIER" = "web_locked" ]; then
  log "ERROR: Web Locked tier requires passkey auth for downgrade"
  log "Use the dashboard to downgrade from Web Locked"
  exit 1
fi

log "Downgrading to Standard..."

# =============================================================================
# ATOMIC DOWNGRADE: Ensure web access works BEFORE removing SSH access
# Order matters: we must not lock the user out if something fails
# =============================================================================

# Step 1: Enable web terminal FIRST (remove disabled marker)
# This ensures web access will work once tier switches
log "Step 1: Enabling web terminal..."
rm -f /etc/ellulai/.terminal-disabled

# Step 2: Switch tier via API - this enables web terminal access
# If this fails, user still has SSH access (safe state)
log "Step 2: Switching tier to standard..."
SWITCH_RESULT=$(curl -s -X POST http://127.0.0.1:3005/_auth/tier/switch \\
  -H "Content-Type: application/json" \\
  -H "X-Internal-Request: enforcer" \\
  -d '{"tier":"standard","source":"cli"}' 2>&1)

if echo "$SWITCH_RESULT" | grep -q '"error"'; then
  log "ERROR: Tier switch failed: $SWITCH_RESULT"
  log "Aborting - SSH access preserved for safety"
  # Restore terminal disabled marker since tier switch failed
  touch /etc/ellulai/.terminal-disabled
  exit 1
fi

# Step 3: Verify web terminal is accessible before removing SSH
# Give services a moment to restart
log "Step 3: Verifying web access..."
sleep 2
systemctl restart ellulai-enforcer 2>/dev/null || true
sleep 2

# Check that sovereign-shield is responding (web access works)
if ! curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3005/health | grep -q '200'; then
  log "WARNING: Web service health check failed, but tier already switched"
  log "Proceeding with SSH cleanup - web terminal should recover"
fi

# Step 4: NOW safe to remove SSH access (web terminal is available)
# SECURITY: Remove all SSH keys - they could be compromised
log "Step 4: Removing SSH keys for security..."
if [ -f "$SSH_AUTH_KEYS" ]; then
  # Backup keys just in case (will be cleaned up by enforcer later)
  cp "$SSH_AUTH_KEYS" "/etc/ellulai/.ssh-keys-backup-$(date +%s)" 2>/dev/null || true
  rm -f "$SSH_AUTH_KEYS"
  log "SSH authorized_keys removed"
fi

# Step 5: Disable SSH service
log "Step 5: Disabling SSH access..."
ufw delete allow 22/tcp 2>/dev/null || true
systemctl stop sshd 2>/dev/null || true
systemctl disable sshd 2>/dev/null || true

log "Downgrade complete - web terminal enabled, SSH access removed"
log "SECURITY: All SSH keys have been removed. Add new keys if you upgrade again."
`;
}

/**
 * Generate the web-locked switch script.
 * From Standard with existing passkey: switches directly
 * Without passkey: generates setup token and outputs link for passkey registration
 */
export function getWebLockedSwitchScript(): string {
  return `#!/bin/bash
set -e

TIER_FILE="/etc/ellulai/security-tier"
DOMAIN_FILE="/etc/ellulai/domain"
SETUP_TOKEN_FILE="/etc/ellulai/.sovereign-setup-token"
SETUP_EXPIRY_FILE="/etc/ellulai/.sovereign-setup-expiry"
LOG_FILE="/var/log/ellulai-enforcer.log"
[ -f /etc/default/ellulai ] && source /etc/default/ellulai
SVC_USER="\${PS_USER:-dev}"
SVC_HOME="/home/\${SVC_USER}"
SSH_AUTH_KEYS="\${SVC_HOME}/.ssh/authorized_keys"

log() { echo "[$(date -Iseconds)] WEB_LOCKED: $1" >> "$LOG_FILE"; echo "$1"; }

CURRENT_TIER=$(cat "$TIER_FILE" 2>/dev/null || echo "standard")
DOMAIN=$(cat "$DOMAIN_FILE" 2>/dev/null || echo "")

if [ -z "$DOMAIN" ]; then
  echo "ERROR: Domain not configured"
  exit 1
fi

# Check if passkey already exists using the tier/current endpoint (localhost only)
TIER_INFO=$(curl -s -H "X-Internal-Request: enforcer" http://127.0.0.1:3005/_auth/tier/current 2>/dev/null)
HAS_PASSKEYS=$(echo "$TIER_INFO" | grep -o '"hasPasskeys":true' || echo "")

if [ -n "$HAS_PASSKEYS" ]; then
  # ==========================================================================
  # ATOMIC SWITCH: Passkey exists - switch directly with verification
  # ==========================================================================
  log "Passkey found, switching to Web Locked tier..."

  # Step 1: Attempt tier switch
  SWITCH_RESULT=$(curl -s -X POST http://127.0.0.1:3005/_auth/tier/switch \\
    -H "Content-Type: application/json" \\
    -H "X-Internal-Request: enforcer" \\
    -d '{"tier":"web_locked","source":"cli"}' 2>&1)

  if echo "$SWITCH_RESULT" | grep -q '"error"'; then
    log "ERROR: Tier switch failed: $SWITCH_RESULT"
    echo "ERROR: Failed to switch to Web Locked tier"
    echo "Current access methods preserved."
    exit 1
  fi

  # Step 2: Verify the switch succeeded
  sleep 1
  NEW_TIER=$(cat "$TIER_FILE" 2>/dev/null || echo "unknown")
  if [ "$NEW_TIER" != "web_locked" ]; then
    log "WARNING: Tier file not updated to web_locked (shows: $NEW_TIER)"
  fi

  # Step 3: Verify web access works (passkey gate should be active)
  if curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3005/health | grep -q '200'; then
    log "Web Locked switch complete - sovereign-shield responding"
    echo "Web Locked mode enabled successfully."
    echo "Passkey authentication is now required for web access."
  else
    log "WARNING: Health check failed but tier switched"
    echo "Web Locked mode enabled (health check pending)."
  fi
else
  # ==========================================================================
  # NO PASSKEY: Generate setup link for browser registration
  # User must complete registration in browser to finish upgrade
  # ==========================================================================
  log "No passkey found - generating setup link..."

  # Generate random token
  TOKEN=$(openssl rand -hex 32)
  EXPIRY=$(($(date +%s) + 600))  # 10 minutes

  # Write token files atomically
  echo "$TOKEN" > "$SETUP_TOKEN_FILE.tmp"
  echo "$EXPIRY" > "$SETUP_EXPIRY_FILE.tmp"
  chmod 600 "$SETUP_TOKEN_FILE.tmp" "$SETUP_EXPIRY_FILE.tmp"
  mv "$SETUP_TOKEN_FILE.tmp" "$SETUP_TOKEN_FILE"
  mv "$SETUP_EXPIRY_FILE.tmp" "$SETUP_EXPIRY_FILE"

  echo ""
  echo "========================================"
  echo "  WEB LOCKED SETUP"
  echo "========================================"
  echo ""
  echo "Open this link in your browser to register a passkey:"
  echo ""
  echo "  https://$DOMAIN/_auth/ssh-only-upgrade?token=$TOKEN"
  echo ""
  echo "This link expires in 10 minutes."
  echo ""
  echo "After registering your passkey, Web Locked mode will be enabled."
  echo "========================================"

  log "Setup link generated for passkey registration"
fi
`;
}

/**
 * Generate the reset auth script.
 */
export function getResetAuthScript(): string {
  return `#!/bin/bash
set -e

AUTH_DB="/etc/ellulai/local-auth.db"
TIER_FILE="/etc/ellulai/security-tier"
LOG_FILE="/var/log/ellulai-enforcer.log"
[ -f /etc/default/ellulai ] && source /etc/default/ellulai
SVC_USER="\${PS_USER:-dev}"
SVC_HOME="/home/\${SVC_USER}"
SSH_AUTH_KEYS="\${SVC_HOME}/.ssh/authorized_keys"

log() { echo "[$(date -Iseconds)] RESET_AUTH: $1" >> "$LOG_FILE"; echo "$1"; }

CURRENT_TIER=$(cat "$TIER_FILE" 2>/dev/null || echo "standard")

# =============================================================================
# SAFETY CHECK: Prevent lockout - must have alternative access
# =============================================================================

# Check for SSH keys
HAS_SSH_KEYS=false
if [ -f "$SSH_AUTH_KEYS" ] && [ -s "$SSH_AUTH_KEYS" ]; then
  HAS_SSH_KEYS=true
fi

# Check if SSH is running
SSH_RUNNING=false
if systemctl is-active --quiet sshd 2>/dev/null; then
  SSH_RUNNING=true
fi

# Safety logic based on current tier
if [ "$CURRENT_TIER" = "web_locked" ]; then
  if [ "$HAS_SSH_KEYS" != "true" ] || [ "$SSH_RUNNING" != "true" ]; then
    log "ERROR: Cannot reset auth in web_locked without working SSH access"
    echo "ERROR: Resetting auth would lock you out!"
    echo ""
    echo "You are in Web Locked tier - passkeys are required for web access."
    echo "Resetting auth would clear passkeys with no way to log back in."
    echo ""
    echo "To proceed safely:"
    echo "  1. Add an SSH key first: sudo ellulai-add-ssh-key 'ssh-ed25519 ...'"
    echo "  2. Verify SSH works: ssh \$SVC_USER@\$(hostname -I | awk '{print \$1}')"
    echo "  3. Then retry: sudo ellulai-reset-auth"
    exit 1
  fi
  log "SSH access verified - safe to reset auth"
  echo "WARNING: SSH access detected - you can recover via SSH after reset."
fi

if [ ! -f "$AUTH_DB" ]; then
  log "No auth database found"
  echo "No auth database found - nothing to reset."
  exit 0
fi

echo ""
echo "AUTH RESET - THIS WILL CLEAR ALL AUTHENTICATION DATA"
echo ""
echo "  This will delete:"
echo "    - All passkeys (Face ID / Touch ID registrations)"
echo "    - All active sessions"
echo "    - All recovery codes"
echo "    - Audit log"
echo ""
if [ "$CURRENT_TIER" = "web_locked" ]; then
  echo "  IMPORTANT: You are in Web Locked tier."
  echo "  After reset, you must re-register a passkey to access web terminal."
  echo "  SSH access will remain available for recovery."
fi
echo ""
read -p "Type RESET to confirm: " CONFIRM
if [ "$CONFIRM" != "RESET" ]; then
  echo "Aborted."
  exit 0
fi

log "Resetting all authentication data..."

# Backup current database
BACKUP_FILE="$AUTH_DB.backup.$(date +%s)"
cp "$AUTH_DB" "$BACKUP_FILE"
log "Database backed up to $BACKUP_FILE"

# Clear all tables but keep schema
sqlite3 "$AUTH_DB" <<EOF
DELETE FROM sessions;
DELETE FROM credential;
DELETE FROM recovery_codes;
DELETE FROM audit_log;
DELETE FROM auth_attempts;
DELETE FROM recovery_attempts;
DELETE FROM recovery_sessions;
DELETE FROM pop_nonces;
EOF

# Remove web_locked marker since passkeys are cleared
rm -f /etc/ellulai/.web_locked_activated

# If in web_locked, downgrade to standard (no passkeys = can't stay web_locked)
if [ "$CURRENT_TIER" = "web_locked" ]; then
  log "Passkeys cleared - switching to standard tier"
  echo "standard" > "$TIER_FILE"
  systemctl restart ellulai-enforcer 2>/dev/null || true
fi

log "Auth reset complete. All sessions, passkeys, and recovery codes cleared."
echo ""
echo "Auth reset complete."
echo "  - Database backed up to: $BACKUP_FILE"
if [ "$CURRENT_TIER" = "web_locked" ]; then
  echo "  - Tier changed to: standard (passkeys required for web_locked)"
  echo "  - Re-register a passkey to return to Web Locked mode"
fi
echo "  - User will need to re-register on next access."
`;
}

/**
 * Generate the tier switch helper script.
 */
export function getTierSwitchHelperScript(): string {
  return `#!/bin/bash
# Tier Switch Helper - called by enforcer after API confirms switch
# This is a low-level helper; prefer using the tier switch API directly

set -e

TIER_FILE="/etc/ellulai/security-tier"
LOG_FILE="/var/log/ellulai-enforcer.log"
NEW_TIER="$1"

log() { echo "[$(date -Iseconds)] TIER_HELPER: $1" >> "$LOG_FILE"; }

if [ -z "$NEW_TIER" ]; then
  echo "Usage: tier-switch.sh <standard|web_locked>"
  exit 1
fi

# Validate tier value
if [ "$NEW_TIER" != "standard" ] && [ "$NEW_TIER" != "web_locked" ]; then
  echo "ERROR: Invalid tier '$NEW_TIER'"
  echo "Valid tiers: standard, web_locked"
  exit 1
fi

CURRENT_TIER=$(cat "$TIER_FILE" 2>/dev/null || echo "unknown")
log "Switching tier: $CURRENT_TIER -> $NEW_TIER"

# Write atomically
echo "$NEW_TIER" > "$TIER_FILE.tmp"
chmod 644 "$TIER_FILE.tmp"
mv "$TIER_FILE.tmp" "$TIER_FILE"

# Verify write succeeded
WRITTEN_TIER=$(cat "$TIER_FILE" 2>/dev/null || echo "failed")
if [ "$WRITTEN_TIER" != "$NEW_TIER" ]; then
  log "ERROR: Tier file write verification failed (expected: $NEW_TIER, got: $WRITTEN_TIER)"
  echo "ERROR: Failed to write tier file"
  exit 1
fi

log "Tier file updated successfully"

# Restart services based on new tier
systemctl restart ellulai-enforcer 2>/dev/null || {
  log "WARNING: Failed to restart enforcer"
}

log "Tier switch complete: $NEW_TIER"
echo "Tier switched to: $NEW_TIER"
`;
}

/**
 * Generate the SSH setup script.
 */
export function getSshSetupScript(): string {
  return `#!/bin/bash
set -e

[ -f /etc/default/ellulai ] && source /etc/default/ellulai
SVC_USER="\${PS_USER:-dev}"
SVC_HOME="/home/\${SVC_USER}"
SSH_DIR="\${SVC_HOME}/.ssh"
AUTH_KEYS="$SSH_DIR/authorized_keys"

mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"
touch "$AUTH_KEYS"
chmod 600 "$AUTH_KEYS"
chown -R \${SVC_USER}:\${SVC_USER} "$SSH_DIR"
`;
}

/**
 * Get the version of the sovereign shield module.
 */
export function getSovereignShieldVersion(): string {
  return VERSION.components.sovereignShield;
}

// Legacy aliases for compatibility
export { getSovereignShieldScript as getVpsAuthScript };
export { getSovereignShieldService as getVpsAuthService };
