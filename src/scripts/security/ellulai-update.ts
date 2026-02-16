/**
 * ellulai-update — Verified Git Pull Update Script
 *
 * Standalone script at /usr/local/bin/ellulai-update that performs
 * cryptographically verified updates from a public Git repository.
 *
 * Security model:
 *   - All release tags are GPG-signed offline by the founder's key
 *   - VPS verifies tag signatures against a hardcoded public key
 *   - GPG key fingerprint is pinned at build time (supply chain defense)
 *   - Version rollback is rejected (forward-only)
 *   - Zero API trust: verification is fully local
 */

import { RELEASE_GPG_FINGERPRINT } from '../../version';

export function getEllulaiUpdateScript(): string {
  return `#!/bin/bash
set -euo pipefail

# ─── Configuration ──────────────────────────────────────────────────
PUBKEY_PATH="/etc/ellulai/release.gpg"
RELEASE_GPG_FINGERPRINT="${RELEASE_GPG_FINGERPRINT}"
REPO_DIR="/opt/ellulai"
VERSION_FILE="/etc/ellulai/current-version"
GNUPG_HOME="/etc/ellulai/.gnupg"
LOG_FILE="/var/log/ellulai-update.log"
LOCK_FILE="/var/run/ellulai-update.lock"

# Services to restart after a successful update
AGENT_SERVICES="ellulai-sovereign-shield ellulai-file-api ellulai-agent-bridge"

# ─── Helpers ────────────────────────────────────────────────────────

log() {
  local MSG="[$(date -Iseconds)] $*"
  echo "$MSG" | tee -a "$LOG_FILE"
}

die() {
  log "FAILED: $*"
  echo ""
  echo "  Update aborted. No changes were made."
  cleanup_lock
  exit 1
}

cleanup_lock() {
  rm -f "$LOCK_FILE"
}

# ─── Input Validation ──────────────────────────────────────────────

TARGET_TAG="\${1:-}"

if [ -z "$TARGET_TAG" ]; then
  echo "Usage: ellulai-update <tag>"
  echo "  e.g. ellulai-update v1.2.0"
  exit 1
fi

# Validate tag format (vMAJOR.MINOR.PATCH)
if ! echo "$TARGET_TAG" | grep -qE '^v[0-9]+\\.[0-9]+\\.[0-9]+$'; then
  die "Invalid tag format: $TARGET_TAG (expected vX.Y.Z)"
fi

# ─── Concurrency Guard ─────────────────────────────────────────────
# Prevent two updates from running simultaneously.

if [ -f "$LOCK_FILE" ]; then
  LOCK_PID=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
  if [ -n "$LOCK_PID" ] && kill -0 "$LOCK_PID" 2>/dev/null; then
    die "Another update is already running (PID $LOCK_PID)"
  fi
  # Stale lock file — remove it
  rm -f "$LOCK_FILE"
fi

echo $$ > "$LOCK_FILE"
trap cleanup_lock EXIT

# ─── Pre-flight Checks ─────────────────────────────────────────────

log "=== ellulai-update: $TARGET_TAG ==="

if [ ! -f "$PUBKEY_PATH" ]; then
  die "GPG public key not found at $PUBKEY_PATH. Cannot verify updates."
fi

if [ ! -d "$REPO_DIR/.git" ]; then
  die "Git repository not found at $REPO_DIR"
fi

# ─── Step 1: Ensure GPG keyring is ready ────────────────────────────
# Use a dedicated GNUPGHOME so we never trust system-wide keys.

mkdir -p "$GNUPG_HOME"
chmod 700 "$GNUPG_HOME"
export GNUPGHOME="$GNUPG_HOME"

# Import the trusted public key (idempotent — safe to run every time)
if ! gpg --batch --quiet --import "$PUBKEY_PATH" 2>/dev/null; then
  die "Failed to import GPG public key from $PUBKEY_PATH"
fi

# SECURITY: Verify the imported key matches the pinned fingerprint.
# This prevents a root-level attacker from swapping release.gpg with their own key.
# The fingerprint is embedded at build time from version.ts — it cannot be changed
# without rebuilding the daemon from signed source.
if [ -n "$RELEASE_GPG_FINGERPRINT" ]; then
  GPG_KEYS=$(gpg --batch --with-colons --fingerprint 2>/dev/null || echo "")
  # Extract fingerprint lines (fpr:::::::::FINGERPRINT:) and strip formatting
  FOUND_FPR=$(echo "$GPG_KEYS" | grep "^fpr:" | awk -F: '{print $10}' | head -1)
  if [ -z "$FOUND_FPR" ]; then
    die "No GPG key fingerprint found after import. Keyring may be corrupt."
  fi
  if [ "$FOUND_FPR" != "$RELEASE_GPG_FINGERPRINT" ]; then
    log "EXPECTED: $RELEASE_GPG_FINGERPRINT"
    log "FOUND:    $FOUND_FPR"
    die "GPG key fingerprint mismatch! Possible supply chain attack — release.gpg has been tampered with."
  fi
  log "GPG fingerprint verified: $RELEASE_GPG_FINGERPRINT"
else
  log "WARN: No release GPG fingerprint configured — skipping pin check"
fi

# ─── Step 2: Fetch latest tags from origin ──────────────────────────

log "Fetching tags from origin..."
cd "$REPO_DIR"

if ! git fetch --tags --force --quiet 2>/dev/null; then
  die "git fetch failed. Check network connectivity."
fi

# Verify the target tag exists
if ! git rev-parse "$TARGET_TAG" >/dev/null 2>&1; then
  die "Tag $TARGET_TAG does not exist in the repository"
fi

# ─── Step 3: Verify GPG signature on the tag ────────────────────────
# This is the core supply-chain protection. The tag must be signed by
# the offline release key. A compromised API can tell us a tag name,
# but it cannot forge a valid GPG signature.

log "Verifying GPG signature on $TARGET_TAG..."

VERIFY_OUTPUT=$(git verify-tag "$TARGET_TAG" 2>&1) || {
  log "--- SIGNATURE VERIFICATION OUTPUT ---"
  log "$VERIFY_OUTPUT"
  log "--- END OUTPUT ---"
  die "GPG signature verification FAILED for $TARGET_TAG. Possible supply chain attack."
}

# Confirm we got a GOODSIG from gpg
if ! echo "$VERIFY_OUTPUT" | grep -qi "good signature"; then
  log "$VERIFY_OUTPUT"
  die "Tag $TARGET_TAG signature did not produce 'Good signature'"
fi

log "Signature verified: $TARGET_TAG"

# ─── Step 4: Anti-Rollback Check ───────────────────────────────────
# Read the current version and reject downgrades. A compromised API
# could try to roll us back to a version with known vulnerabilities.

CURRENT_VERSION=""
if [ -f "$VERSION_FILE" ]; then
  CURRENT_VERSION=$(cat "$VERSION_FILE" | tr -d '\\n')
fi

# Fallback: read from git describe if version file is missing
if [ -z "$CURRENT_VERSION" ]; then
  CURRENT_VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
fi

# Already at this version?
if [ "$CURRENT_VERSION" = "$TARGET_TAG" ]; then
  log "Already at $TARGET_TAG — nothing to do"
  exit 0
fi

# Compare versions with sort -V (version sort).
# The "highest" version must be TARGET_TAG for this to be an upgrade.
HIGHEST=$(printf '%s\\n' "$CURRENT_VERSION" "$TARGET_TAG" | sort -V | tail -1)

if [ "$HIGHEST" != "$TARGET_TAG" ]; then
  die "Rollback rejected: $CURRENT_VERSION -> $TARGET_TAG. Forward-only updates enforced."
fi

log "Version check passed: $CURRENT_VERSION -> $TARGET_TAG"

# ─── Step 5: Clean workspace and checkout ───────────────────────────
# Reset any local modifications. The repo is read-only application code;
# user data lives elsewhere (/home/dev, /etc/ellulai, etc).

log "Checking out $TARGET_TAG..."

# Discard any local changes (should be none, but defensive)
git reset --hard HEAD --quiet 2>/dev/null || true
# Clean untracked files but preserve runtime directories managed outside git
git clean -fd --quiet -e auth/ 2>/dev/null || true

# Checkout the verified tag (detached HEAD is expected)
if ! git checkout "$TARGET_TAG" --quiet 2>/dev/null; then
  die "git checkout $TARGET_TAG failed"
fi

# ─── Step 6: Install dependencies ──────────────────────────────────

if [ -f "$REPO_DIR/package.json" ]; then
  log "Installing dependencies..."
  cd "$REPO_DIR"

  if command -v bun >/dev/null 2>&1; then
    bun install --frozen-lockfile --production 2>/dev/null || {
      log "WARN: bun install --frozen-lockfile failed, trying without flag"
      bun install --production 2>/dev/null || log "WARN: bun install failed"
    }
  elif command -v npm >/dev/null 2>&1; then
    npm ci --omit=dev 2>/dev/null || {
      log "WARN: npm ci failed, trying npm install"
      npm install --omit=dev 2>/dev/null || log "WARN: npm install failed"
    }
  fi
fi

# ─── Step 6b: Rebuild ALL deployed files ─────────────────────────────
# Bundle and run rebuild-all.ts to regenerate every script, config,
# service file, and Node.js bundle from source.

REBUILD_ENTRY="$REPO_DIR/src/scripts/security/rebuild-all.ts"
REBUILD_OUT="/tmp/ellulai-rebuild-all.js"

ESBUILD_BIN="$REPO_DIR/node_modules/.bin/esbuild"
if [ ! -x "$ESBUILD_BIN" ]; then
  ESBUILD_BIN=$(command -v esbuild 2>/dev/null || echo "")
fi

if [ -f "$REBUILD_ENTRY" ] && [ -n "$ESBUILD_BIN" ]; then
  log "Rebuilding all deployed files..."

  # Ensure auth dir and package.json exist for shield rebuild
  mkdir -p "$REPO_DIR/auth"
  if [ ! -f "$REPO_DIR/auth/package.json" ]; then
    echo '{"type":"commonjs"}' > "$REPO_DIR/auth/package.json"
  fi

  # Install shield runtime deps if missing
  if [ ! -d "$REPO_DIR/auth/node_modules/hono" ]; then
    log "Installing shield runtime dependencies..."
    cd "$REPO_DIR/auth"
    npm install --omit=dev hono @hono/node-server @simplewebauthn/server better-sqlite3 2>/dev/null || {
      log "WARN: Shield dependency install failed"
    }
    cd "$REPO_DIR"
  fi

  # Bundle rebuild-all.ts and run it
  if "$ESBUILD_BIN" "$REBUILD_ENTRY" --bundle --platform=node --target=node18 --format=cjs \\
    --external:fs --external:path --external:crypto --external:child_process \\
    --external:os --external:url --external:util --external:http --external:https \\
    --external:events --external:stream --external:esbuild \\
    --external:ws --external:chokidar --external:node-pty \\
    --external:hono --external:@hono/node-server --external:better-sqlite3 \\
    --external:@simplewebauthn/server \\
    --outfile="$REBUILD_OUT" 2>/dev/null; then
    node "$REBUILD_OUT" && {
      log "All files rebuilt successfully"
    } || {
      log "WARN: rebuild-all execution failed"
    }
    rm -f "$REBUILD_OUT"
  else
    log "WARN: rebuild-all bundle failed"
  fi
else
  log "WARN: rebuild-all.ts or esbuild not found — skipping full rebuild"
fi

# ─── Step 7: Record version and restart ─────────────────────────────

echo "$TARGET_TAG" > "$VERSION_FILE"
chmod 644 "$VERSION_FILE"

log "Restarting services..."

# Restart all services (not just the 3 Node.js ones)
AGENT_SERVICES="ellulai-sovereign-shield ellulai-file-api ellulai-agent-bridge ellulai-enforcer ellulai-term-proxy ellulai-perf-monitor ellulai-watchdog"

RESTARTED=0
for SVC in $AGENT_SERVICES; do
  if systemctl is-active --quiet "$SVC" 2>/dev/null; then
    systemctl restart "$SVC" 2>/dev/null && {
      log "  Restarted $SVC"
      RESTARTED=$((RESTARTED + 1))
    } || {
      log "  WARN: Failed to restart $SVC"
    }
  fi
done

log "Update complete: $CURRENT_VERSION -> $TARGET_TAG ($RESTARTED services restarted)"
echo ""
echo "  Update complete: $CURRENT_VERSION -> $TARGET_TAG"
`;
}
