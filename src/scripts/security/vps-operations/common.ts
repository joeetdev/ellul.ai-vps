/**
 * Shared bash preamble for VPS operation scripts.
 *
 * Every SSH Only script needs:
 * - Color codes
 * - Root check
 * - Server ID, API URL, token loading
 * - Tier guard (standard/web_locked redirect to dashboard)
 */

interface PreambleOptions {
  /** Script name for usage messages, e.g. "phonestack-delete" */
  scriptName: string;
  /** Usage suffix after the script name, e.g. "<cloudflare|direct>" */
  usageSuffix?: string;
  /** Platform API base URL */
  apiUrl: string;
  /** Dashboard action description for standard tier, e.g. "delete this server" */
  standardAction: string;
  /** Dashboard action description for web_locked tier, e.g. "delete" */
  webLockedAction: string;
}

/**
 * Generate the common bash preamble shared by all VPS operation scripts.
 *
 * Returns a string containing: shebang, color codes, root check,
 * credential loading (server ID, token), and tier guard.
 *
 * After this preamble, the following variables are available:
 * - $RED, $GREEN, $YELLOW, $CYAN, $NC (colors)
 * - $SERVER_ID, $TOKEN, $API_URL, $TIER
 */
export function getScriptPreamble(opts: PreambleOptions): string {
  const usage = opts.usageSuffix
    ? `sudo ${opts.scriptName} ${opts.usageSuffix}`
    : `sudo ${opts.scriptName}`;

  return `#!/bin/bash
#
# ${opts.scriptName} - For SSH Only tier servers
#
# Usage: ${usage}
#

set -e

RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
CYAN='\\033[0;36m'
NC='\\033[0m'

if [ "$(id -u)" -ne 0 ]; then
    echo -e "\${RED}Error: This command must be run with sudo\${NC}"
    echo "Usage: ${usage}"
    exit 1
fi

SERVER_ID_FILE="/etc/phonestack/server-id"
API_URL="${opts.apiUrl}"
TIER_FILE="/etc/phonestack/security-tier"

if [ ! -f "$SERVER_ID_FILE" ]; then
    echo -e "\${RED}Error: Server ID not found\${NC}"
    exit 1
fi
SERVER_ID=$(cat "$SERVER_ID_FILE")

TOKEN_FILE="/etc/phonestack/ai-proxy-token"
if [ -f "$TOKEN_FILE" ]; then
    TOKEN=$(cat "$TOKEN_FILE")
else
    TOKEN=$(grep PHONESTACK_AI_TOKEN /home/dev/.bashrc 2>/dev/null | cut -d'"' -f2 || true)
fi
if [ -z "$TOKEN" ]; then
    echo -e "\${RED}Error: AI proxy token not found\${NC}"
    echo "This server may not be properly provisioned."
    exit 1
fi

if [ -f "$TIER_FILE" ]; then
    TIER=$(cat "$TIER_FILE")
else
    TIER="standard"
fi

if [ "$TIER" = "standard" ]; then
    echo -e "\${YELLOW}Note: Your server is in Standard tier.\${NC}"
    echo "You can ${opts.standardAction} directly from the dashboard."
    exit 0
fi

if [ "$TIER" = "web_locked" ]; then
    echo -e "\${YELLOW}Note: Your server is in Web Locked tier.\${NC}"
    echo "Use the dashboard and confirm with your passkey to ${opts.webLockedAction}."
    exit 0
fi
`;
}
