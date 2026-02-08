#!/bin/bash
# Enforcer Constants
# Configuration variables and paths for the state enforcer daemon.

API_URL="${API_URL:-}"
TOKEN="${PHONESTACK_AI_TOKEN:-}"
ENV_FILE="/home/dev/.phonestack-env"
STATE_FILE="/etc/phonestack/access-state.json"
STATUS_FILE="/home/dev/.phonestack/server-status.json"
LOG_FILE="/var/log/phonestack-enforcer.log"
SOVEREIGN_MARKER="/etc/phonestack/.sovereign-mode"
SOVEREIGN_KEYS_LOCK="/etc/phonestack/.sovereign-keys"
OWNER_LOCK_FILE="/etc/phonestack/owner.lock"
LOCKDOWN_MARKER="/etc/phonestack/.in_lockdown"
HEARTBEAT_FAILURE_FILE="/etc/phonestack/.heartbeat-failures"
HEARTBEAT_INTERVAL=30
ENFORCER_PID_FILE="/run/phonestack-enforcer.pid"
# DAEMON_VERSION is injected by bundle.ts from version.ts

# Verified Git Pull update constants
AGENT_REPO_DIR="/opt/phonestack"
AGENT_VERSION_FILE="/etc/phonestack/current-version"

# All terminal services - used for lockdown and health checks
ALL_TERMINALS="ttyd@main ttyd@opencode ttyd@claude ttyd@codex ttyd@gemini ttyd@aider ttyd@git ttyd@branch ttyd@save ttyd@ship ttyd@undo ttyd@logs ttyd@clean"
