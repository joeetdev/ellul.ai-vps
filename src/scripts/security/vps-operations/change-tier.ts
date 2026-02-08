/**
 * phonestack-change-tier - Change server billing tier
 *
 * Involves billing changes (Stripe) and potentially infrastructure
 * migration if moving between cloud providers.
 */

import { getScriptPreamble } from "./common";

export function getChangeTierScript(apiUrl: string): string {
  const preamble = getScriptPreamble({
    scriptName: "phonestack-change-tier",
    usageSuffix: "<starter|pro|plus|business|scale>",
    apiUrl,
    standardAction: "change tiers",
    webLockedAction: "change tier",
  });

  return `${preamble}
NEW_TIER="$1"
if [ -z "$NEW_TIER" ]; then
    echo -e "\${RED}Error: No tier specified\${NC}"
    echo ""
    echo "Usage: sudo phonestack-change-tier <tier>"
    echo ""
    echo "Available tiers:"
    echo "  starter   - 2 GB RAM"
    echo "  pro       - 4 GB RAM"
    echo "  plus      - 8 GB RAM"
    echo "  business  - 16 GB RAM"
    echo "  scale     - 32 GB RAM"
    exit 1
fi

case "$NEW_TIER" in
    starter|pro|plus|business|scale) ;;
    *)
        echo -e "\${RED}Error: Invalid tier '$NEW_TIER'\${NC}"
        echo "Valid tiers: starter, pro, plus, business, scale"
        exit 1
        ;;
esac

echo ""
echo -e "\${YELLOW}════════════════════════════════════════════════════════════\${NC}"
echo -e "\${YELLOW}  TIER CHANGE\${NC}"
echo -e "\${YELLOW}════════════════════════════════════════════════════════════\${NC}"
echo ""
echo "  Changing to: \${CYAN}$NEW_TIER\${NC}"
echo ""
echo "  - Your billing will be updated immediately"
echo "  - Server may experience brief downtime during resize"
echo "  - If migration is required, this could take 5-10 minutes"
echo ""
echo -e "\${YELLOW}════════════════════════════════════════════════════════════\${NC}"
echo ""

read -p "Proceed with tier change? [y/N] " CONFIRM

if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo -e "\${YELLOW}Tier change cancelled.\${NC}"
    exit 0
fi

echo ""
echo -e "\${CYAN}Contacting platform...\${NC}"

RESPONSE=$(curl -sS --connect-timeout 30 --max-time 300 \\
    -X POST \\
    "$API_URL/api/servers/$SERVER_ID/change-tier" \\
    -H "Authorization: Bearer $TOKEN" \\
    -H "Content-Type: application/json" \\
    -d "{\\"newTier\\":\\"$NEW_TIER\\"}" \\
    -w "\\n%{http_code}" 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '\$d')

if [ "$HTTP_CODE" = "200" ]; then
    NEW_TOKEN=$(echo "$BODY" | grep -o '"aiProxyToken":"[^"]*"' | cut -d'"' -f4 || true)

    echo ""
    echo -e "\${GREEN}════════════════════════════════════════════════════════════\${NC}"
    echo -e "\${GREEN}  Tier change successful!\${NC}"
    echo -e "\${GREEN}════════════════════════════════════════════════════════════\${NC}"
    echo ""
    echo "  Your server is now on the \${CYAN}$NEW_TIER\${NC} tier."
    echo ""
    if [ -n "$NEW_TOKEN" ]; then
        echo -e "  \${YELLOW}IMPORTANT: Your new AI proxy token:\${NC}"
        echo ""
        echo -e "  \${CYAN}$NEW_TOKEN\${NC}"
        echo ""
        echo "  Save this token! Your old token is now invalid."
        echo ""
    fi
elif [ "$HTTP_CODE" = "402" ]; then
    echo -e "\${RED}Error: Payment failed\${NC}"
    echo "$BODY"
    exit 1
elif [ "$HTTP_CODE" = "403" ]; then
    echo -e "\${RED}Error: Not authorized\${NC}"
    echo "$BODY"
    exit 1
else
    echo -e "\${RED}Error: Failed to change tier (HTTP $HTTP_CODE)\${NC}"
    echo "$BODY"
    exit 1
fi
`;
}
