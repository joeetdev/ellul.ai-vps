/**
 * ellulai-rollback - Rollback to pre-update snapshot
 *
 * Restores server to its state before the last update.
 * Snapshots expire after 24 hours.
 */

import { getScriptPreamble } from "./common";

export function getRollbackScript(apiUrl: string): string {
  const preamble = getScriptPreamble({
    scriptName: "ellulai-rollback",
    apiUrl,
    standardAction: "rollback",
    webLockedAction: "rollback",
  });

  return `${preamble}
echo ""
echo -e "\${YELLOW}════════════════════════════════════════════════════════════\${NC}"
echo -e "\${YELLOW}  SERVER ROLLBACK\${NC}"
echo -e "\${YELLOW}════════════════════════════════════════════════════════════\${NC}"
echo ""
echo "  This will restore your server to the pre-update snapshot."
echo "  All changes made since the last update will be lost."
echo ""
echo -e "\${YELLOW}════════════════════════════════════════════════════════════\${NC}"
echo ""

read -p "Type 'ROLLBACK' to confirm: " CONFIRM

if [ "$CONFIRM" != "ROLLBACK" ]; then
    echo -e "\${YELLOW}Rollback cancelled.\${NC}"
    exit 0
fi

echo ""
echo -e "\${CYAN}Contacting platform...\${NC}"

RESPONSE=$(curl -sS --connect-timeout 30 --max-time 120 \\
    -X POST \\
    "$API_URL/api/servers/$SERVER_ID/rollback" \\
    -H "Authorization: Bearer $TOKEN" \\
    -H "Content-Type: application/json" \\
    -d '{}' \\
    -w "\\n%{http_code}" 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '\$d')

if [ "$HTTP_CODE" = "200" ]; then
    echo ""
    echo -e "\${GREEN}════════════════════════════════════════════════════════════\${NC}"
    echo -e "\${GREEN}  Rollback initiated successfully!\${NC}"
    echo -e "\${GREEN}════════════════════════════════════════════════════════════\${NC}"
    echo ""
    echo "  Your server is being restored to the pre-update snapshot."
    echo "  This may take a few minutes."
    echo ""
    echo "  This SSH connection will be terminated shortly."
    echo ""
elif [ "$HTTP_CODE" = "400" ]; then
    echo -e "\${YELLOW}$BODY\${NC}"
    exit 1
elif [ "$HTTP_CODE" = "403" ]; then
    echo -e "\${RED}Error: Not authorized\${NC}"
    echo "$BODY"
    exit 1
else
    echo -e "\${RED}Error: Failed to rollback server (HTTP $HTTP_CODE)\${NC}"
    echo "$BODY"
    exit 1
fi
`;
}
