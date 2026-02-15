/**
 * Apps list tool - shows deployed applications.
 */
export function getAppsScript(): string {
  return `#!/bin/bash
APPS_DIR="$HOME/.ellulai/apps"
DOMAIN=$(cat /etc/ellulai/domain 2>/dev/null)

GREEN='\\033[32m'
CYAN='\\033[36m'
NC='\\033[0m'

shopt -s nullglob

if [ "$1" = "--json" ]; then
  echo "["
  FIRST=true
  for f in "$APPS_DIR"/*.json; do
    [ -f "$f" ] || continue
    [ "$FIRST" = true ] || echo ","
    FIRST=false
    cat "$f"
  done
  echo "]"
else
  echo ""
  echo -e "\${CYAN}ellul.ai Apps\${NC}"
  echo ""
  if ! ls "$APPS_DIR"/*.json &>/dev/null; then
    echo "  No apps deployed yet."
    echo ""
    echo "  To deploy an app:"
    echo "    1. Build your project"
    echo "    2. Start it with PM2 on a unique port"
    echo "    3. Run: ellulai-expose <name> <port>"
    echo ""
  else
    for f in "$APPS_DIR"/*.json; do
      [ -f "$f" ] || continue
      NAME=$(jq -r '.name' "$f")
      PORT=$(jq -r '.port' "$f")
      URL=$(jq -r '.url' "$f")
      STACK=$(jq -r '.stack // "Unknown"' "$f")
      SUMMARY=$(jq -r '.summary // ""' "$f")
      echo -e "  \${GREEN}$NAME\${NC} [\${CYAN}$STACK\${NC}] :$PORT"
      if [ -n "$SUMMARY" ] && [ "$SUMMARY" != "null" ]; then
        echo -e "    $SUMMARY"
      fi
      echo -e "    $URL"
      echo ""
    done
  fi
fi`;
}

/**
 * Inspect tool - AI-powered app analysis.
 */
export function getInspectScript(): string {
  return `#!/bin/bash
APPS_DIR="$HOME/.ellulai/apps"
TARGET_APP="$1"

log() { echo "[inspect] $1"; }
success() { echo "* $1"; }

generate_summary() {
  local APP_FILE="$1"
  local APP_NAME=$(jq -r '.name' "$APP_FILE")
  local PROJECT_PATH=$(jq -r '.projectPath' "$APP_FILE")
  local CURRENT_SUMMARY=$(jq -r '.summary // ""' "$APP_FILE")
  if [ -n "$CURRENT_SUMMARY" ] && [ "$CURRENT_SUMMARY" != "null" ] && [ "$CURRENT_SUMMARY" != "" ]; then
    return 0
  fi
  log "Analyzing $APP_NAME..."
  CONTEXT=""
  if [ -f "$PROJECT_PATH/package.json" ]; then
    CONTEXT="$CONTEXT
PACKAGE.JSON:
$(jq '{name, description, dependencies: (.dependencies // {} | keys)}' "$PROJECT_PATH/package.json" 2>/dev/null)"
  fi
  if [ -f "$PROJECT_PATH/README.md" ]; then
    CONTEXT="$CONTEXT

README:
$(head -20 "$PROJECT_PATH/README.md" 2>/dev/null)"
  fi
  for entry in "$PROJECT_PATH/src/app/page.tsx" "$PROJECT_PATH/src/index.ts" "$PROJECT_PATH/app.py" "$PROJECT_PATH/main.go"; do
    if [ -f "$entry" ]; then
      CONTEXT="$CONTEXT

MAIN FILE ($entry):
$(head -30 "$entry" 2>/dev/null)"
      break
    fi
  done
  if [ -z "$CONTEXT" ]; then
    SUMMARY="A web application running on ellul.ai."
  else
    PROMPT="Based on this project, write a 1-sentence summary (max 15 words). Focus on what the app DOES, not the tech stack. Reply with ONLY the summary, no quotes.

$CONTEXT"
    SUMMARY=$(echo "$PROMPT" | timeout 30 opencode --no-cache 2>/dev/null | tail -1 | tr -d '\\"' | head -c 150)
    if [ -z "$SUMMARY" ] || [ \${#SUMMARY} -lt 10 ] || [ \${#SUMMARY} -gt 150 ]; then
      SUMMARY="A custom application deployed on ellul.ai."
    fi
  fi
  jq --arg summary "$SUMMARY" '.summary = $summary' "$APP_FILE" > "$APP_FILE.tmp" && mv "$APP_FILE.tmp" "$APP_FILE"
  chown "$USER:$USER" "$APP_FILE"
  success "$APP_NAME: $SUMMARY"
}

if [ -n "$TARGET_APP" ]; then
  APP_FILE="$APPS_DIR/$TARGET_APP.json"
  if [ -f "$APP_FILE" ]; then
    generate_summary "$APP_FILE"
  else
    log "App not found: $TARGET_APP"
    exit 1
  fi
else
  if ! ls "$APPS_DIR"/*.json &>/dev/null; then
    log "No apps to inspect"
    exit 0
  fi
  for APP_FILE in "$APPS_DIR"/*.json; do
    [ -f "$APP_FILE" ] || continue
    generate_summary "$APP_FILE"
  done
fi
success "Inspection complete"`;
}
