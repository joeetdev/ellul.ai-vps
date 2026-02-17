#!/bin/bash
# Enforcer Terminal Management
# Functions for managing terminal services.

# Stop and disable all terminals (for lockdown - prevents systemd Restart=always from undoing)
stop_all_terminals() {
  for svc in $ALL_TERMINALS; do
    svc_disable "$svc"
    svc_stop "$svc"
  done
  # Clear 'failed' state so stopped services show as 'inactive (dead)'
  # rather than 'failed'. RestartPreventExitStatus=SIGTERM causes services
  # killed by stop (SIGTERM) to enter failed state instead of inactive.
  svc_reset_failed $ALL_TERMINALS
  log "All terminal services stopped and disabled"
}

# Start and enable all terminals (only if not in lockdown)
# NOTE: Static ttyd services are DEPRECATED. Terminal sessions are now created
# dynamically by agent-bridge with per-project scoping. This function now only
# ensures agent-bridge and term-proxy are running.
start_all_terminals() {
  [ -f /etc/ellulai/.terminal-disabled ] && return 0

  # Dynamic terminal sessions are handled by agent-bridge and term-proxy
  # These services create sessions on-demand with proper project scoping
  svc_start ellulai-agent-bridge
  svc_start ellulai-term-proxy
}

# Get active terminal sessions (queries agent-bridge for dynamic sessions)
get_active_sessions() {
  # Query agent-bridge for active dynamic sessions
  local response
  response=$(curl -s http://127.0.0.1:7700/terminal/sessions 2>/dev/null)
  if [ -n "$response" ] && [ "$response" != "{\"sessions\":[]}" ]; then
    # Extract unique session types from dynamic sessions
    echo "$response" | grep -o '"type":"[^"]*"' | sed 's/"type":"//g;s/"//g' | sort -u | \
      awk 'BEGIN{printf "["} NR>1{printf ","} {printf "\"%s\"", $0} END{printf "]"}'
  else
    echo "[]"
  fi
}
