#!/bin/bash
# Enforcer Constants
# Configuration variables and paths for the state enforcer daemon.

API_URL="${API_URL:-}"
TOKEN="${ELLULAI_AI_TOKEN:-}"
ENV_FILE="/home/dev/.ellulai-env"
STATE_FILE="/etc/ellulai/access-state.json"
STATUS_FILE="/home/dev/.ellulai/server-status.json"
LOG_FILE="/var/log/ellulai-enforcer.log"
SOVEREIGN_MARKER="/etc/ellulai/.sovereign-mode"
SOVEREIGN_KEYS_LOCK="/etc/ellulai/.sovereign-keys"
OWNER_LOCK_FILE="/etc/ellulai/owner.lock"
LOCKDOWN_MARKER="/etc/ellulai/.in_lockdown"
HEARTBEAT_FAILURE_FILE="/etc/ellulai/.heartbeat-failures"
HEARTBEAT_INTERVAL=30
ENFORCER_PID_FILE="/run/ellulai-enforcer.pid"
# DAEMON_VERSION is injected by bundle.ts from version.ts

# Verified Git Pull update constants
AGENT_REPO_DIR="/opt/ellulai"
AGENT_VERSION_FILE="/etc/ellulai/current-version"

# All terminal services - used for lockdown and health checks
ALL_TERMINALS="ttyd@main ttyd@opencode ttyd@claude ttyd@codex ttyd@gemini ttyd@aider ttyd@git ttyd@branch ttyd@save ttyd@ship ttyd@undo ttyd@logs ttyd@clean"
