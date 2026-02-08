#!/bin/bash
# Enforcer Update Functions
# Delegates to /usr/local/bin/phonestack-update for verified git-based updates.
#
# SECURITY MODEL (Verified Git Pull):
#   - API sends a target tag (e.g., v1.2.0) in the heartbeat response
#   - VPS independently verifies the GPG signature on the git tag
#   - VPS rejects downgrades (forward-only)
#   - Zero API trust: no code is downloaded from the API

# Check for updates and delegate to the standalone update script.
# Called from the main daemon loop every 10 heartbeats.
check_for_update() {
  local RESPONSE="$1"

  # Extract target tag from heartbeat response
  local TARGET_TAG=$(echo "$RESPONSE" | jq -r '.targetTag // ""')

  if [ -z "$TARGET_TAG" ] || [ "$TARGET_TAG" = "null" ]; then
    return 0
  fi

  # Quick check: are we already at this version?
  local CURRENT_VERSION=""
  if [ -f "$AGENT_VERSION_FILE" ]; then
    CURRENT_VERSION=$(cat "$AGENT_VERSION_FILE" 2>/dev/null | tr -d '\n')
  fi

  if [ "$CURRENT_VERSION" = "$TARGET_TAG" ]; then
    return 0
  fi

  log "Update signal received: ${CURRENT_VERSION:-unknown} -> $TARGET_TAG"

  # Delegate to the standalone update script.
  # It handles: fetch, GPG verify, rollback check, checkout, restart.
  if [ -x /usr/local/bin/phonestack-update ]; then
    /usr/local/bin/phonestack-update "$TARGET_TAG" 2>&1 | while IFS= read -r line; do
      log "[update] $line"
    done
  else
    log "ERROR: /usr/local/bin/phonestack-update not found or not executable"
  fi
}
