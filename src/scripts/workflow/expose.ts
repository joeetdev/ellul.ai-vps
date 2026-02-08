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
if [ -z "$NAME" ] || [ -z "$PORT" ]; then
  echo ""
  echo -e "\${CYAN}Phone Stack Expose\${NC}"
  echo ""
  echo "Usage: phonestack-expose <app_name> <port> [custom_domain]"
  echo ""
  echo "Examples:"
  echo "  phonestack-expose blog 3000"
  echo "  phonestack-expose api 4000"
  echo "  phonestack-expose shop 3000 shop.example.com"
  echo ""
  exit 1
fi

# ── Local-only validation (runs in user space) ────────────────────
NAME=$(echo "$NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]//g')

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1024 ] || [ "$PORT" -gt 65535 ]; then
  error "Invalid port: $PORT (must be 1024-65535)"
fi

# Verify the port is actually listening
if ! ss -tlnp 2>/dev/null | grep -q ":$PORT "; then
  error "Port $PORT is not listening. Start your app first, then expose it."
fi

# ── Detect stack (harmless, runs in user space) ───────────────────
PROJECT_PATH="$(pwd)"
STACK="Unknown"
if [ -f "$PROJECT_PATH/package.json" ]; then
  if grep -q '"next"' "$PROJECT_PATH/package.json" 2>/dev/null; then
    STACK="Next.js"
  elif grep -q '"nuxt"' "$PROJECT_PATH/package.json" 2>/dev/null; then
    STACK="Nuxt"
  elif grep -q '"svelte"' "$PROJECT_PATH/package.json" 2>/dev/null; then
    STACK="Svelte"
  elif grep -q '"vue"' "$PROJECT_PATH/package.json" 2>/dev/null; then
    STACK="Vue"
  elif grep -q '"react"' "$PROJECT_PATH/package.json" 2>/dev/null; then
    STACK="React"
  elif grep -q '"express"' "$PROJECT_PATH/package.json" 2>/dev/null; then
    STACK="Express"
  elif grep -q '"hono"' "$PROJECT_PATH/package.json" 2>/dev/null; then
    STACK="Hono"
  elif grep -q '"fastify"' "$PROJECT_PATH/package.json" 2>/dev/null; then
    STACK="Fastify"
  else
    STACK="Node.js"
  fi
  if [ -f "$PROJECT_PATH/tsconfig.json" ]; then
    STACK="$STACK/TS"
  fi
elif [ -f "$PROJECT_PATH/requirements.txt" ] || [ -f "$PROJECT_PATH/pyproject.toml" ]; then
  if grep -q "fastapi" "$PROJECT_PATH/requirements.txt" 2>/dev/null; then
    STACK="FastAPI"
  elif grep -q "flask" "$PROJECT_PATH/requirements.txt" 2>/dev/null; then
    STACK="Flask"
  elif grep -q "django" "$PROJECT_PATH/requirements.txt" 2>/dev/null; then
    STACK="Django"
  else
    STACK="Python"
  fi
elif [ -f "$PROJECT_PATH/go.mod" ]; then
  STACK="Go"
elif [ -f "$PROJECT_PATH/Cargo.toml" ]; then
  STACK="Rust"
fi

# ── Send to privileged service ────────────────────────────────────
BODY="{\\"name\\":\\"$NAME\\",\\"port\\":$PORT"
if [ -n "$CUSTOM_DOMAIN" ]; then
  BODY="$BODY,\\"customDomain\\":\\"$CUSTOM_DOMAIN\\""
fi
BODY="$BODY,\\"projectPath\\":\\"$PROJECT_PATH\\",\\"stack\\":\\"$STACK\\"}"

RESULT=$(curl -sf -X POST http://localhost:3005/api/workflow/expose \\
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
