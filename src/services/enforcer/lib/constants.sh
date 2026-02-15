#!/bin/bash
# Enforcer Constants
# Configuration variables and paths for the state enforcer daemon.

# API_URL resolution: config file > environment > baked-in value from bundle.ts
# This ensures the enforcer works even if the script was installed with stale/placeholder values
if [ -f /etc/ellulai/api-url ]; then
  API_URL="$(cat /etc/ellulai/api-url 2>/dev/null | tr -d '\n')"
fi
API_URL="${API_URL:-}"
TOKEN="${ELLULAI_AI_TOKEN:-}"
# Derive service user from PS_USER (loaded by systemd EnvironmentFile from /etc/default/ellulai)
SVC_USER="${PS_USER:-dev}"
SVC_HOME="/home/${SVC_USER}"
ENV_FILE="${SVC_HOME}/.ellulai-env"
STATE_FILE="/etc/ellulai/access-state.json"
STATUS_FILE="${SVC_HOME}/.ellulai/server-status.json"
LOG_FILE="/var/log/ellulai-enforcer.log"
SOVEREIGN_MARKER="/etc/ellulai/.sovereign-mode"
SOVEREIGN_KEYS_LOCK="/etc/ellulai/.sovereign-keys"
OWNER_LOCK_FILE="/etc/ellulai/owner.lock"
HEARTBEAT_FAILURE_FILE="/etc/ellulai/.heartbeat-failures"
HEARTBEAT_INTERVAL=30
ENFORCER_PID_FILE="/run/ellulai-enforcer.pid"
# DAEMON_VERSION is injected by bundle.ts from version.ts

# Verified Git Pull update constants
AGENT_REPO_DIR="/opt/ellulai"
AGENT_VERSION_FILE="/etc/ellulai/current-version"

# All terminal services - used for lockdown and health checks
ALL_TERMINALS="ttyd@main ttyd@opencode ttyd@claude ttyd@codex ttyd@gemini ttyd@aider ttyd@git ttyd@branch ttyd@save ttyd@ship ttyd@undo ttyd@logs ttyd@clean"
