import { generateBashStackDetect } from '../../services/shared/framework';

/**
 * Expose tool — thin client that delegates to Sovereign Shield.
 *
 * All privileged logic (Caddy config generation, tier enforcement,
 * file writes, service reload) runs server-side in sovereign-shield
 * via POST /api/workflow/expose.
 *
 * This script only does local-only validation and stack detection
 * before sending the request.
 */
export function getExposeScript(): string {
  return `#!/bin/bash
set -e

NAME="$1"
PORT="$2"
CUSTOM_DOMAIN="$3"

GREEN='\\033[32m'
CYAN='\\033[36m'
RED='\\033[31m'
YELLOW='\\033[33m'
NC='\\033[0m'

error() { echo -e "\${RED}x\${NC} $1" >&2; exit 1; }

# ── Usage ─────────────────────────────────────────────────────────
if [ -z "$NAME" ]; then
  echo ""
  echo -e "\${CYAN}ellul.ai Expose\${NC}"
  echo ""
  echo "Usage: ellulai-expose <app_name> [port] [custom_domain]"
  echo ""
  echo "Examples:"
  echo "  ellulai-expose blog"
  echo "  ellulai-expose api 4000"
  echo "  ellulai-expose shop 3001 shop.example.com"
  echo ""
  exit 1
fi

# Default port if not provided
if [ -z "$PORT" ]; then
  PORT=3001
fi

# ── Local-only validation (runs in user space) ────────────────────
NAME=$(echo "$NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]//g')

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1024 ] || [ "$PORT" -gt 65535 ]; then
  error "Invalid port: $PORT (must be 1024-65535)"
fi

\${generateBashStackDetect()}

# ── Send to privileged service ────────────────────────────────────
BODY="{\\"name\\":\\"$NAME\\",\\"port\\":$PORT"
if [ -n "$CUSTOM_DOMAIN" ]; then
  BODY="$BODY,\\"customDomain\\":\\"$CUSTOM_DOMAIN\\""
fi
BODY="$BODY,\\"projectPath\\":\\"$PROJECT_PATH\\",\\"stack\\":\\"$STACK\\"}"

RESULT=$(curl -sf --max-time 45 -X POST http://localhost:3005/api/workflow/expose \\
  -H "Content-Type: application/json" \\
  -d "$BODY" 2>&1)

if [ $? -ne 0 ] || [ -z "$RESULT" ]; then
  # Try to extract error from JSON response
  ERROR_MSG=$(echo "$RESULT" | jq -r '.error // empty' 2>/dev/null)
  if [ -n "$ERROR_MSG" ]; then
    error "$ERROR_MSG"
  fi
  error "Failed to contact system agent. Is sovereign-shield running?"
fi

# Check for error in JSON response
ERROR_MSG=$(echo "$RESULT" | jq -r '.error // empty' 2>/dev/null)
if [ -n "$ERROR_MSG" ]; then
  error "$ERROR_MSG"
fi

# Display result from server
MESSAGE=$(echo "$RESULT" | jq -r '.message // empty' 2>/dev/null)
if [ -n "$MESSAGE" ]; then
  echo -e "$MESSAGE"
else
  echo "$RESULT"
fi`;
}
