/**
 * phonestack-delete - Permanently delete this server
 *
 * Proves SSH access by requiring terminal execution.
 * Calls platform API to destroy server and cancel subscription.
 */

import { getScriptPreamble } from "./common";

export function getDeleteScript(apiUrl: string): string {
  const preamble = getScriptPreamble({
    scriptName: "phonestack-delete",
    apiUrl,
    standardAction: "delete this server",
    webLockedAction: "delete",
  });

  return `${preamble}
# Display warning
echo ""
echo -e "\${RED}════════════════════════════════════════════════════════════\${NC}"
echo -e "\${RED}  WARNING: PERMANENT SERVER DELETION\${NC}"
echo -e "\${RED}════════════════════════════════════════════════════════════\${NC}"
echo ""
echo -e "  This will \${RED}PERMANENTLY DESTROY\${NC} this server!"
echo ""
echo "  - All data will be deleted"
echo "  - All SSH keys and configurations will be lost"
echo "  - Your subscription will be cancelled"
echo "  - This action cannot be undone"
echo ""
echo -e "\${RED}════════════════════════════════════════════════════════════\${NC}"
echo ""

# Prompt for confirmation
read -p "Type 'DELETE' to confirm: " CONFIRM

if [ "$CONFIRM" != "DELETE" ]; then
    echo -e "\${YELLOW}Deletion cancelled.\${NC}"
    exit 0
fi

# Second confirmation
echo ""
read -p "Are you absolutely sure? This cannot be undone. [y/N] " FINAL_CONFIRM

if [ "$FINAL_CONFIRM" != "y" ] && [ "$FINAL_CONFIRM" != "Y" ]; then
    echo -e "\${YELLOW}Deletion cancelled.\${NC}"
    exit 0
fi

echo ""
echo -e "\${CYAN}Contacting platform...\${NC}"

# Call the platform API to delete the server
RESPONSE=$(curl -sS --connect-timeout 30 --max-time 60 \\
    -X DELETE \\
    "$API_URL/api/servers/$SERVER_ID" \\
    -H "Authorization: Bearer $TOKEN" \\
    -H "Content-Type: application/json" \\
    -w "\\n%{http_code}" 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    echo ""
    echo -e "\${GREEN}════════════════════════════════════════════════════════════\${NC}"
    echo -e "\${GREEN}  Server deletion initiated successfully!\${NC}"
    echo -e "\${GREEN}════════════════════════════════════════════════════════════\${NC}"
    echo ""
    echo "  Your server is being destroyed."
    echo "  Your subscription has been cancelled."
    echo ""
    echo "  This SSH connection will be terminated shortly."
    echo ""
elif [ "$HTTP_CODE" = "403" ]; then
    echo -e "\${RED}Error: Not authorized\${NC}"
    echo "$BODY"
    exit 1
else
    echo -e "\${RED}Error: Failed to delete server (HTTP $HTTP_CODE)\${NC}"
    echo "$BODY"
    exit 1
fi
`;
}
