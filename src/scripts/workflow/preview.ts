/**
 * Preview server script - serves user-selected app on port 3000.
 * Auto-detects framework and runs appropriate dev command.
 */
export function getPreviewScript(): string {
  return `#!/bin/bash
# Smart Preview Server - serves user-selected app on port 3000
# User selects app via Preview tab UI -> writes to ~/.phonestack/preview-app
# Supports: Next.js, Nuxt, Vite, Vue, CRA, Svelte, Astro, Gatsby, Remix, static HTML

PORT=3000
PROJECTS_DIR="/home/dev/projects"
CHECK_INTERVAL=5
APP_FILE="/home/dev/.phonestack/preview-app"
SCRIPT_FILE="/home/dev/.phonestack/preview-script"

log() { echo "[$(date -Iseconds)] $1"; }

detect_framework() {
  local dir="$1"
  [ ! -f "$dir/package.json" ] && echo "static" && return
  local pkg=$(cat "$dir/package.json" 2>/dev/null)
  if echo "$pkg" | grep -q '"next"'; then echo "next"
  elif echo "$pkg" | grep -q '"nuxt"'; then echo "nuxt"
  elif echo "$pkg" | grep -q '"vite"'; then echo "vite"
  elif echo "$pkg" | grep -q '"vue"'; then echo "vue"
  elif echo "$pkg" | grep -q '"react-scripts"'; then echo "cra"
  elif echo "$pkg" | grep -q '"svelte"'; then echo "svelte"
  elif echo "$pkg" | grep -q '"astro"'; then echo "astro"
  elif echo "$pkg" | grep -q '"gatsby"'; then echo "gatsby"
  elif echo "$pkg" | grep -q '"remix"'; then echo "remix"
  elif echo "$pkg" | grep -q '"scripts"' && echo "$pkg" | grep -q '"dev"'; then echo "npm-dev"
  else echo "static"
  fi
}

get_dev_command() {
  local framework="$1"
  case "$framework" in
    next)     echo "npm run dev -- -p $PORT" ;;
    nuxt)     echo "npm run dev -- --port $PORT" ;;
    vite)     echo "npm run dev -- --port $PORT --host" ;;
    vue)      echo "npm run serve -- --port $PORT" ;;
    cra)      echo "PORT=$PORT npm start" ;;
    svelte)   echo "npm run dev -- --port $PORT" ;;
    astro)    echo "npm run dev -- --port $PORT" ;;
    gatsby)   echo "npm run develop -- -p $PORT" ;;
    remix)    echo "npm run dev" ;;
    npm-dev)  echo "npm run dev" ;;
    *)        echo "npx -y serve -l $PORT -n" ;;
  esac
}

port_in_use_by_other() {
  local pids=$(lsof -ti :$PORT 2>/dev/null)
  for pid in $pids; do
    [ "$pid" != "$$" ] && [ "$pid" != "$DEV_PID" ] && return 0
  done
  return 1
}

DEV_PID=""
CURRENT_APP=""
CURRENT_SCRIPT=""

cleanup() {
  log "Shutting down preview server..."
  [ -n "$DEV_PID" ] && kill $DEV_PID 2>/dev/null
  exit 0
}
trap cleanup SIGTERM SIGINT

log "Preview Server starting (waiting for app selection)..."

while true; do
  SELECTED_APP=""
  SELECTED_SCRIPT=""
  [ -f "$APP_FILE" ] && SELECTED_APP=$(cat "$APP_FILE" 2>/dev/null | tr -d '\\n')
  [ -f "$SCRIPT_FILE" ] && SELECTED_SCRIPT=$(cat "$SCRIPT_FILE" 2>/dev/null | tr -d '\\n')

  if [ -z "$SELECTED_APP" ]; then
    if [ -n "$DEV_PID" ]; then
      log "No app selected, stopping server"
      kill $DEV_PID 2>/dev/null
      DEV_PID=""
      CURRENT_APP=""
    fi
    sleep $CHECK_INTERVAL
    continue
  fi

  PROJECT_DIR="$PROJECTS_DIR/$SELECTED_APP"

  if [ ! -d "$PROJECT_DIR" ]; then
    log "Selected app not found: $SELECTED_APP"
    sleep $CHECK_INTERVAL
    continue
  fi

  if port_in_use_by_other; then
    if [ -n "$DEV_PID" ]; then
      log "User server detected, stopping auto-server"
      kill $DEV_PID 2>/dev/null
      DEV_PID=""
    fi
    sleep $CHECK_INTERVAL
    continue
  fi

  if [ "$SELECTED_APP" != "$CURRENT_APP" ] || [ "$SELECTED_SCRIPT" != "$CURRENT_SCRIPT" ]; then
    [ -n "$DEV_PID" ] && kill $DEV_PID 2>/dev/null && sleep 1
    DEV_PID=""
    CURRENT_APP="$SELECTED_APP"
    CURRENT_SCRIPT="$SELECTED_SCRIPT"
    log "App changed to: $SELECTED_APP"
  fi

  if [ -z "$DEV_PID" ] || ! kill -0 $DEV_PID 2>/dev/null; then
    cd "$PROJECT_DIR"

    if [ -n "$SELECTED_SCRIPT" ]; then
      DEV_CMD="npm run $SELECTED_SCRIPT"
      log "Using custom script: $DEV_CMD"
    else
      FRAMEWORK=$(detect_framework "$PROJECT_DIR")
      DEV_CMD=$(get_dev_command "$FRAMEWORK")
      log "Detected: $FRAMEWORK -> $DEV_CMD"
    fi

    [ -f "package.json" ] && [ ! -d "node_modules" ] && npm install 2>&1 | tail -3

    eval "$DEV_CMD &"
    DEV_PID=$!
    log "Dev server started (PID: $DEV_PID)"
  fi

  sleep $CHECK_INTERVAL
done`;
}

/**
 * Preview server systemd service.
 */
export function getPreviewService(): string {
  return `[Unit]
Description=Phone Stack Preview Server
After=network.target phonestack-file-api.service

[Service]
Type=simple
User=dev
ExecStart=/usr/local/bin/phonestack-preview
Restart=always
RestartSec=5
Environment=PATH=/home/dev/.nvm/versions/node/v20.20.0/bin:/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=multi-user.target`;
}
