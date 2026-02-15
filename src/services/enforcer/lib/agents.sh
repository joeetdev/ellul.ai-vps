#!/bin/bash
# Enforcer Agent Status Functions
# Reads agent status from Watchdog's status file for heartbeat telemetry.

AGENT_STATUS_FILE="/etc/ellulai/agent-status.json"

# Get agent status array from Watchdog's status file.
# Watchdog writes this every 30s with container health data.
# Returns JSON array or empty array if file missing/invalid.
get_agent_status() {
  if [ -f "$AGENT_STATUS_FILE" ]; then
    cat "$AGENT_STATUS_FILE" 2>/dev/null || echo "[]"
  else
    echo "[]"
  fi
}
