/**
 * PTY Wrap Script
 *
 * Simple wrapper that runs commands in a pseudo-terminal using the `script` utility.
 * Required for interactive CLI tools (claude login, codex login, etc.) that need
 * proper terminal emulation when spawned from agent-bridge.
 */

/**
 * Get the pty-wrap script content.
 * Uses the Unix `script` command to provide PTY wrapping.
 */
export function getPtyWrapScript(): string {
  return `#!/bin/bash
# pty-wrap: Wraps a command in a PTY using the script utility
# Usage: pty-wrap command [args...]
#
# This enables interactive CLI tools to work properly when spawned
# from non-terminal contexts (like the agent-bridge WebSocket server).

if [ $# -eq 0 ]; then
  echo "Usage: pty-wrap command [args...]" >&2
  exit 1
fi

# Use script to provide PTY wrapping
# -q: quiet mode (no "Script started/done" messages)
# -c: command to execute
# /dev/null: don't save typescript file
exec script -q -c "$*" /dev/null
`;
}
