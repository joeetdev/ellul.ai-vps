/**
 * phonestack-settings - Toggle server access settings
 *
 * Controls SSH and terminal access via platform API.
 * Changes take effect on next daemon heartbeat (~5-10s).
 */

import { getScriptPreamble } from "./common";

export function getSettingsScript(apiUrl: string): string {
  const preamble = getScriptPreamble({
    scriptName: "phonestack-settings",
    usageSuffix: "<ssh|terminal> <on|off>",
    apiUrl,
    standardAction: "change settings",
    webLockedAction: "change settings",
  });

  return `${preamble}
SETTING="$1"
VALUE="$2"

if [ -z "$SETTING" ] || [ -z "$VALUE" ]; then
    echo -e "\${RED}Error: Missing arguments\${NC}"
    echo ""
    echo "Usage: sudo phonestack-settings <setting> <on|off>"
    echo ""
    echo "Settings:"
    echo "  ssh       - Toggle SSH access (firewall port 22)"
    echo "  terminal  - Toggle web terminal access"
    echo ""
    echo "Examples:"
    echo "  sudo phonestack-settings ssh on"
    echo "  sudo phonestack-settings terminal off"
    exit 1
fi

case "$SETTING" in
    ssh|terminal) ;;
    *)
        echo -e "\${RED}Error: Invalid setting '$SETTING'\${NC}"
        echo "Valid settings: ssh, terminal"
        exit 1
        ;;
esac

case "$VALUE" in
    on|off) ;;
    *)
        echo -e "\${RED}Error: Invalid value '$VALUE'\${NC}"
        echo "Valid values: on, off"
        exit 1
        ;;
esac

BOOL_VALUE="false"
if [ "$VALUE" = "on" ]; then
    BOOL_VALUE="true"
fi

if [ "$SETTING" = "ssh" ]; then
    JSON_BODY="{\\"sshEnabled\\":$BOOL_VALUE}"
    DISPLAY_NAME="SSH access"
else
    JSON_BODY="{\\"terminalEnabled\\":$BOOL_VALUE}"
    DISPLAY_NAME="Web terminal"
fi

echo ""
echo -e "\${CYAN}Setting $DISPLAY_NAME to $VALUE...\${NC}"

RESPONSE=$(curl -sS --connect-timeout 30 --max-time 60 \\
    -X PATCH \\
    "$API_URL/api/servers/$SERVER_ID/settings" \\
    -H "Authorization: Bearer $TOKEN" \\
    -H "Content-Type: application/json" \\
    -d "$JSON_BODY" \\
    -w "\\n%{http_code}" 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '\$d')

if [ "$HTTP_CODE" = "200" ]; then
    echo ""
    echo -e "\${GREEN}$DISPLAY_NAME set to $VALUE.\${NC}"
    echo "Changes take effect within 5-10 seconds (next daemon heartbeat)."
    echo ""
elif [ "$HTTP_CODE" = "403" ]; then
    echo -e "\${RED}Error: Not authorized\${NC}"
    echo "$BODY"
    exit 1
else
    echo -e "\${RED}Error: Failed to update settings (HTTP $HTTP_CODE)\${NC}"
    echo "$BODY"
    exit 1
fi
`;
}
