/**
 * phonestack-deployment - Switch deployment model
 *
 * Switches between Cloudflare Edge (CF terminates TLS) and
 * Direct Connect (VPS terminates TLS via Let's Encrypt).
 */

import { getScriptPreamble } from "./common";

export function getDeploymentScript(apiUrl: string): string {
  const preamble = getScriptPreamble({
    scriptName: "phonestack-deployment",
    usageSuffix: "<cloudflare|direct>",
    apiUrl,
    standardAction: "switch deployment",
    webLockedAction: "switch deployment",
  });

  return `${preamble}
MODEL="$1"
if [ -z "$MODEL" ]; then
    echo -e "\${RED}Error: No deployment model specified\${NC}"
    echo ""
    echo "Usage: sudo phonestack-deployment <model>"
    echo ""
    echo "Models:"
    echo "  cloudflare - Cloudflare Edge (CF terminates TLS, DDoS protection)"
    echo "  direct     - Direct Connect (VPS terminates TLS via Let's Encrypt)"
    exit 1
fi

case "$MODEL" in
    cloudflare|direct) ;;
    *)
        echo -e "\${RED}Error: Invalid model '$MODEL'\${NC}"
        echo "Valid models: cloudflare, direct"
        exit 1
        ;;
esac

if [ "$MODEL" = "cloudflare" ]; then
    MODEL_NAME="Cloudflare Edge"
else
    MODEL_NAME="Direct Connect"
fi

echo ""
echo -e "\${YELLOW}════════════════════════════════════════════════════════════\${NC}"
echo -e "\${YELLOW}  DEPLOYMENT MODEL SWITCH\${NC}"
echo -e "\${YELLOW}════════════════════════════════════════════════════════════\${NC}"
echo ""
echo "  Switching to: \${CYAN}$MODEL_NAME\${NC}"
echo ""
if [ "$MODEL" = "direct" ]; then
    echo "  - VPS will terminate TLS via Let's Encrypt"
    echo "  - No Cloudflare proxy (direct IP connection)"
else
    echo "  - Cloudflare will terminate TLS and proxy traffic"
    echo "  - DDoS protection enabled"
fi
echo "  - DNS will be updated immediately"
echo "  - Caddyfile regenerated on next heartbeat (~10s)"
echo ""
echo -e "\${YELLOW}════════════════════════════════════════════════════════════\${NC}"
echo ""

read -p "Proceed? [y/N] " CONFIRM

if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo -e "\${YELLOW}Deployment switch cancelled.\${NC}"
    exit 0
fi

echo ""
echo -e "\${CYAN}Contacting platform...\${NC}"

RESPONSE=$(curl -sS --connect-timeout 30 --max-time 60 \\
    -X POST \\
    "$API_URL/api/servers/$SERVER_ID/deployment" \\
    -H "Authorization: Bearer $TOKEN" \\
    -H "Content-Type: application/json" \\
    -d "{\\"model\\":\\"$MODEL\\"}" \\
    -w "\\n%{http_code}" 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '\$d')

if [ "$HTTP_CODE" = "200" ]; then
    echo ""
    echo -e "\${GREEN}════════════════════════════════════════════════════════════\${NC}"
    echo -e "\${GREEN}  Deployment switch initiated!\${NC}"
    echo -e "\${GREEN}════════════════════════════════════════════════════════════\${NC}"
    echo ""
    echo "  DNS updated. Caddyfile will regenerate on next heartbeat (~10s)."
    echo ""
elif [ "$HTTP_CODE" = "429" ]; then
    echo -e "\${YELLOW}Error: Rate limited\${NC}"
    echo "$BODY"
    exit 1
elif [ "$HTTP_CODE" = "403" ]; then
    echo -e "\${RED}Error: Not authorized\${NC}"
    echo "$BODY"
    exit 1
else
    echo -e "\${RED}Error: Failed to switch deployment (HTTP $HTTP_CODE)\${NC}"
    echo "$BODY"
    exit 1
fi
`;
}
