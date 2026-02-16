#!/bin/bash
# Enforcer Agent Status Functions
# Reads agent status from the watchdog wrapper for heartbeat telemetry.

AGENT_STATUS_URL="http://127.0.0.1:7710/agents"

# Get agent status from the wrapper's /agents endpoint.
# Returns JSON array or empty array if wrapper is unreachable.
get_agent_status() {
  local response
  response=$(curl -s -m 2 "$AGENT_STATUS_URL" 2>/dev/null)
  if [ -n "$response" ]; then
    echo "$response" | jq -r '.agents // []' 2>/dev/null || echo "[]"
  else
    echo "[]"
  fi
}
