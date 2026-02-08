/**
 * phonestack-rebuild - Rebuild this server with fresh OS
 *
 * Wipes all data and re-provisions. Server resets to Standard tier.
 * Returns new AI proxy token on success.
 */

import { getScriptPreamble } from "./common";

export function getRebuildScript(apiUrl: string): string {
  const preamble = getScriptPreamble({
    scriptName: "phonestack-rebuild",
    apiUrl,
    standardAction: "rebuild this server",
    webLockedAction: "rebuild",
  });

  return `${preamble}
# Display warning
echo ""
echo -e "\${RED}════════════════════════════════════════════════════════════\${NC}"
echo -e "\${RED}  WARNING: SERVER REBUILD - DATA DESTRUCTION\${NC}"
echo -e "\${RED}════════════════════════════════════════════════════════════\${NC}"
echo ""
echo -e "  This will \${RED}DELETE ALL DATA\${NC} on this server!"
echo ""
echo "  - All files and projects will be deleted"
echo "  - All SSH keys will be removed"
echo "  - All passkeys will be removed"
echo "  - Server will reset to Standard tier"
echo "  - You will receive a NEW AI proxy token"
echo ""
echo "  The server will be re-provisioned with a fresh OS."
echo "  Your IP address and DNS will remain the same."
echo ""
echo -e "\${RED}════════════════════════════════════════════════════════════\${NC}"
echo ""

# Prompt for confirmation
read -p "Type 'REBUILD' to confirm: " CONFIRM

if [ "$CONFIRM" != "REBUILD" ]; then
    echo -e "\${YELLOW}Rebuild cancelled.\${NC}"
    exit 0
fi

# Second confirmation
echo ""
read -p "Are you absolutely sure? All data will be lost. [y/N] " FINAL_CONFIRM

if [ "$FINAL_CONFIRM" != "y" ] && [ "$FINAL_CONFIRM" != "Y" ]; then
    echo -e "\${YELLOW}Rebuild cancelled.\${NC}"
    exit 0
fi

echo ""
echo -e "\${CYAN}Contacting platform...\${NC}"

# Call the platform API to rebuild the server
RESPONSE=$(curl -sS --connect-timeout 30 --max-time 60 \\
    -X POST \\
    "$API_URL/api/servers/$SERVER_ID/rebuild" \\
    -H "Authorization: Bearer $TOKEN" \\
    -H "Content-Type: application/json" \\
    -d '{}' \\
    -w "\\n%{http_code}" 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '\$d')

if [ "$HTTP_CODE" = "200" ]; then
    # Extract the new AI proxy token from the response
    NEW_TOKEN=$(echo "$BODY" | grep -o '"aiProxyToken":"[^"]*"' | cut -d'"' -f4 || true)

    echo ""
    echo -e "\${GREEN}════════════════════════════════════════════════════════════\${NC}"
    echo -e "\${GREEN}  Server rebuild initiated successfully!\${NC}"
    echo -e "\${GREEN}════════════════════════════════════════════════════════════\${NC}"
    echo ""
    echo "  Your server is being rebuilt."
    echo "  This will take a few minutes."
    echo ""
    if [ -n "$NEW_TOKEN" ]; then
        echo -e "  \${YELLOW}IMPORTANT: Your new AI proxy token:\${NC}"
        echo ""
        echo -e "  \${CYAN}$NEW_TOKEN\${NC}"
        echo ""
        echo "  Save this token! Your old token is now invalid."
    fi
    echo ""
    echo "  After rebuild, your server will be in Standard tier."
    echo "  You can upgrade to SSH Only again if desired."
    echo ""
    echo "  This SSH connection will be terminated shortly."
    echo ""
elif [ "$HTTP_CODE" = "403" ]; then
    echo -e "\${RED}Error: Not authorized\${NC}"
    echo "$BODY"
    exit 1
else
    echo -e "\${RED}Error: Failed to rebuild server (HTTP $HTTP_CODE)\${NC}"
    echo "$BODY"
    exit 1
fi
`;
}
