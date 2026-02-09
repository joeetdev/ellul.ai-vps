/**
 * AI flow script - context-aware save and ship operations.
 *
 * @param apiUrl - The ellul.ai API URL
 */
export function getAiFlowScript(apiUrl: string): string {
  return `#!/bin/bash
set -e
ACTION="$1"
PROJECT_DIR="\${2:-/home/dev/projects/welcome}"

GREEN='\\033[32m'
CYAN='\\033[36m'
YELLOW='\\033[33m'
RED='\\033[31m'
NC='\\033[0m'

CONTEXT_DIR="/home/dev/.ellulai/context"
GLOBAL_CTX="$CONTEXT_DIR/global.md"
CURRENT_CTX="$CONTEXT_DIR/current.md"
PROXY_URL="${apiUrl}/api/ai"
PROXY_TOKEN="$ELLULAI_AI_TOKEN"

log() { echo -e "\${CYAN}[ai-flow]\${NC} $1"; }
success() { echo -e "\${GREEN}*\${NC} $1"; }
warn() { echo -e "\${YELLOW}!\${NC} $1"; }
error() { echo -e "\${RED}x\${NC} $1"; exit 1; }

cd "$PROJECT_DIR" 2>/dev/null || error "Project not found: $PROJECT_DIR"

refresh_context() {
  log "Generating AI context..."
  /usr/local/bin/ellulai-ctx "$(pwd)" >/dev/null 2>&1
  success "Context ready"
}

ensure_gitignore() {
  if [ ! -f .gitignore ]; then
    log "Creating .gitignore..."
    cat > .gitignore <<'GITIGNORE'
.env
.env.*
!.env.example
node_modules/
.next/
dist/
build/
GITIGNORE
    git add .gitignore
    success "Created .gitignore"
  fi
}

select_aider_model() {
  AIDER_ARGS=""
  AIDER_MODEL=""
  if [ -n "$ANTHROPIC_API_KEY" ]; then
    AIDER_MODEL="claude-sonnet-4-20250514"
    AIDER_ARGS="--model $AIDER_MODEL"
    log "Using Anthropic Claude Sonnet"
    return 0
  fi
  if [ -n "$OPENAI_API_KEY" ]; then
    AIDER_MODEL="gpt-4o"
    AIDER_ARGS="--model $AIDER_MODEL"
    log "Using OpenAI GPT-4o"
    return 0
  fi
  if [ -n "$DEEPSEEK_API_KEY" ]; then
    AIDER_MODEL="deepseek/deepseek-chat"
    AIDER_ARGS="--model $AIDER_MODEL"
    export DEEPSEEK_API_KEY
    log "Using DeepSeek (direct)"
    return 0
  fi
  log "Using ellul.ai Proxy (free tier)"
  export OPENAI_API_BASE="$PROXY_URL"
  export OPENAI_API_KEY="$PROXY_TOKEN"
  AIDER_MODEL="openai/deepseek-chat"
  AIDER_ARGS="--model $AIDER_MODEL"
  return 0
}

cmd_save() {
  refresh_context
  ensure_gitignore
  log "Preparing to save changes..."
  if git diff --quiet && git diff --cached --quiet && [ -z "$(git ls-files --others --exclude-standard)" ]; then
    warn "No changes to save."
    return 0
  fi
  git add -A
  success "Staged all changes"
  echo ""
  log "Changes to commit:"
  git diff --cached --stat
  echo ""
  log "Generating commit message..."
  DIFF=$(git diff --cached --no-color | head -200)
  FILES_CHANGED=$(git diff --cached --name-only | tr '\\n' ', ' | sed 's/,$//')
  if command -v opencode &>/dev/null && [ -n "$DIFF" ]; then
    AI_PROMPT="Generate a single-line conventional commit (feat/fix/chore/docs/refactor).
Files: $FILES_CHANGED
Diff (truncated):
$DIFF
Reply with ONLY the commit message."
    MSG=$(echo "$AI_PROMPT" | timeout 30 opencode --no-cache 2>/dev/null | tail -1 | tr -d '\\n' || true)
    if [ -z "$MSG" ] || [ \${#MSG} -gt 100 ] || [ \${#MSG} -lt 5 ]; then
      MSG="chore: sync changes ($FILES_CHANGED)"
    fi
  else
    TIMESTAMP=$(date '+%m-%d %H:%M')
    MSG="chore: sync $TIMESTAMP ($FILES_CHANGED)"
  fi
  log "Committing: $MSG"
  if git commit -m "$MSG"; then
    success "Committed!"
  else
    error "Commit failed (check pre-commit hook output)"
  fi
  log "Pushing to remote..."
  BRANCH=$(git branch --show-current)
  if git push origin "$BRANCH" 2>/dev/null; then
    success "Pushed to origin/$BRANCH"
  else
    log "Setting upstream..."
    git push --set-upstream origin "$BRANCH"
    success "Pushed to origin/$BRANCH"
  fi
  echo ""
  success "Changes saved!"
}

select_project() {
  PROJECTS_DIR="/home/dev/projects"
  mkdir -p "$PROJECTS_DIR"
  echo ""
  echo -e "\${CYAN}PROJECT SELECTOR\${NC}"
  echo ""
  EXISTING_PROJECTS=$(ls -d "$PROJECTS_DIR"/*/ 2>/dev/null | xargs -n1 basename 2>/dev/null || true)
  if [ -n "$EXISTING_PROJECTS" ]; then
    echo -e "\${CYAN}Existing projects:\${NC}"
    echo "$EXISTING_PROJECTS" | while read -r proj; do
      echo "  * $proj"
    done
    echo ""
  fi
  echo -e "What would you like to do?"
  echo ""
  echo -e "  \${GREEN}1)\${NC} Work on current directory (\${CYAN}$(basename "$(pwd)")\${NC})"
  echo -e "  \${GREEN}2)\${NC} Create a \${YELLOW}new\${NC} project"
  echo ""
  read -p "Choose [1/2]: " CHOICE
  echo ""
  case "$CHOICE" in
    2|new|n)
      read -p "Project name (e.g., shop, blog, api): " NEW_PROJECT_NAME
      NEW_PROJECT_NAME=$(echo "$NEW_PROJECT_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/--*/-/g' | sed 's/^-//;s/-$//')
      if [ -z "$NEW_PROJECT_NAME" ]; then
        error "Invalid project name"
      fi
      NEW_PROJECT_PATH="$PROJECTS_DIR/$NEW_PROJECT_NAME"
      if [ -d "$NEW_PROJECT_PATH" ]; then
        warn "Project already exists: $NEW_PROJECT_NAME"
        log "Switching to existing project..."
        cd "$NEW_PROJECT_PATH"
      else
        log "Creating new project: $NEW_PROJECT_NAME"
        mkdir -p "$NEW_PROJECT_PATH"
        cd "$NEW_PROJECT_PATH"
        git init --quiet
        success "Initialized git repository"
      fi
      PROJECT_DIR="$NEW_PROJECT_PATH"
      echo ""
      success "Working in: $PROJECT_DIR"
      echo ""
      ;;
    *)
      log "Working in current directory: $(pwd)"
      PROJECT_DIR="$(pwd)"
      ;;
  esac
}

find_available_port() {
  local PORT=3000
  local USED_PORTS=$(pm2 jlist 2>/dev/null | jq -r '.[].pm2_env.PORT // empty' | sort -n)
  while echo "$USED_PORTS" | grep -q "^$PORT$" || netstat -tuln 2>/dev/null | grep -q ":$PORT "; do
    PORT=$((PORT + 1))
    if [ $PORT -ge 7681 ] && [ $PORT -le 7692 ]; then
      PORT=7693
    fi
  done
  echo $PORT
}

get_app_name() {
  local DIR_NAME=$(basename "$(pwd)")
  echo "$DIR_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/--*/-/g' | sed 's/^-//;s/-$//'
}

get_existing_deployment() {
  # Check if current directory already has a deployment
  # Matches by exact projectPath first, then by directory name as fallback
  local APPS_DIR="/home/dev/.ellulai/apps"
  local CURRENT_PATH="$(pwd)"
  local DIR_NAME=$(basename "$CURRENT_PATH")

  [ -d "$APPS_DIR" ] || return 1

  # First pass: exact projectPath match
  for app_file in "$APPS_DIR"/*.json; do
    [ -f "$app_file" ] || continue
    local APP_PATH=$(jq -r '.projectPath // empty' "$app_file" 2>/dev/null)
    if [ "$APP_PATH" = "$CURRENT_PATH" ]; then
      local APP_NAME=$(jq -r '.name // empty' "$app_file" 2>/dev/null)
      local APP_PORT=$(jq -r '.port // empty' "$app_file" 2>/dev/null)
      local APP_URL=$(jq -r '.url // empty' "$app_file" 2>/dev/null)
      echo "$APP_NAME|$APP_PORT|$APP_URL"
      return 0
    fi
  done

  # Second pass: match by app name == directory name (handles path mismatches)
  for app_file in "$APPS_DIR"/*.json; do
    [ -f "$app_file" ] || continue
    local APP_NAME=$(jq -r '.name // empty' "$app_file" 2>/dev/null)
    if [ "$APP_NAME" = "$DIR_NAME" ]; then
      local APP_PORT=$(jq -r '.port // empty' "$app_file" 2>/dev/null)
      local APP_URL=$(jq -r '.url // empty' "$app_file" 2>/dev/null)
      echo "$APP_NAME|$APP_PORT|$APP_URL"
      return 0
    fi
  done

  return 1
}

cmd_ship() {
  select_project
  refresh_context

  # Check for existing deployment
  EXISTING=$(get_existing_deployment)
  if [ -n "$EXISTING" ]; then
    EXISTING_NAME=$(echo "$EXISTING" | cut -d'|' -f1)
    EXISTING_PORT=$(echo "$EXISTING" | cut -d'|' -f2)
    EXISTING_URL=$(echo "$EXISTING" | cut -d'|' -f3)
    echo ""
    success "Found existing deployment: $EXISTING_NAME"
    echo -e "  URL: $EXISTING_URL"
    echo -e "  Port: $EXISTING_PORT"
    echo ""
    log "Updating existing deployment..."
    DEPLOY_MODE="update"
    APP_NAME="$EXISTING_NAME"
    PORT="$EXISTING_PORT"
  else
    log "New deployment (no existing app found)"
    DEPLOY_MODE="create"
    APP_NAME=""
    PORT=""
  fi

  echo ""
  if ! git diff --quiet || ! git diff --cached --quiet; then
    warn "Stashing uncommitted changes..."
    git stash push -m "pre-ship-$(date +%s)"
  fi

  if [ "$DEPLOY_MODE" = "update" ]; then
    # Direct update - no AI needed for existing apps
    cmd_ship_update "$APP_NAME" "$PORT"
  else
    # New deployment - use AI or manual
    AIDER_PATH="$HOME/.local/bin/aider"
    if [ -x "$AIDER_PATH" ] || command -v aider &>/dev/null; then
      select_aider_model
      log "Launching Aider with model: $AIDER_MODEL"
      echo ""
      aider \\
        $AIDER_ARGS \\
        --read "$GLOBAL_CTX" \\
        --read "$CURRENT_CTX" \\
        --yes \\
        --auto-commits \\
        --message "
MISSION: Deploy this NEW app to ellul.ai (multi-app system)

STEPS:
1. Determine a SHORT unique name for this app (e.g., 'blog', 'shop', 'api', 'dash').
   Use the project directory name as a hint. Keep it simple and memorable.

2. Find an unused port. Start at 3000 and check if taken.
   Command: netstat -tuln | grep ':<port>'
   Skip ports 7681-7692 (reserved for terminals).

3. Pull latest and install dependencies:
   git pull origin HEAD --rebase || true
   npm ci || pnpm install --frozen-lockfile || npm install

4. Build the production bundle:
   npm run build

5. Start with PM2 on the chosen port:
   pm2 delete <app_name> 2>/dev/null || true
   pm2 start npm --name '<app_name>' -- start -- -p <port>
   pm2 save

6. EXPOSE IT (this maps subdomain -> port):
   sudo ellulai-expose <app_name> <port>

IMPORTANT:
- The app will be live at https://<app_name>-<domain>
- Do NOT commit any changes - this is a deploy operation.
- If ecosystem.config.js exists, use it with a unique name/port.
" \\
        2>&1 || {
          warn "Aider failed, using manual deploy..."
          cmd_ship_manual
        }
    else
      log "Aider not found, using manual deploy..."
      cmd_ship_manual
    fi
  fi
}

cmd_ship_update() {
  local APP_NAME="$1"
  local PORT="$2"
  local DOMAIN=$(cat /etc/ellulai/domain 2>/dev/null || echo "your-domain")

  log "Updating: $APP_NAME (port $PORT)"
  log "Pulling latest..."
  git pull origin "$(git branch --show-current)" --rebase || true

  log "Installing dependencies..."
  if [ -f "pnpm-lock.yaml" ]; then
    pnpm install --frozen-lockfile
  elif [ -f "package-lock.json" ]; then
    npm ci
  else
    npm install
  fi

  log "Building..."
  npm run build

  log "Restarting PM2 process..."
  pm2 restart "$APP_NAME" 2>/dev/null || {
    warn "Process not found in PM2, starting fresh..."
    pm2 delete "$APP_NAME" 2>/dev/null || true
    pm2 start npm --name "$APP_NAME" -- start -- -p "$PORT"
  }
  pm2 save

  echo ""
  success "App updated!"
  echo ""
  echo -e "  \${GREEN}Live at:\${NC} https://$APP_NAME.$DOMAIN"
  echo ""
}

cmd_ship_manual() {
  local APP_NAME=$(get_app_name)
  local PORT=$(find_available_port)
  local DOMAIN=$(cat /etc/ellulai/domain 2>/dev/null || echo "your-domain")
  log "App: $APP_NAME"
  log "Port: $PORT"
  log "Pulling latest..."
  git pull origin "$(git branch --show-current)" --rebase || true
  log "Installing dependencies..."
  if [ -f "pnpm-lock.yaml" ]; then
    pnpm install --frozen-lockfile
  elif [ -f "package-lock.json" ]; then
    npm ci
  else
    npm install
  fi
  log "Building..."
  npm run build
  log "Starting with PM2..."
  pm2 delete "$APP_NAME" 2>/dev/null || true
  pm2 start npm --name "$APP_NAME" -- start -- -p "$PORT"
  pm2 save
  log "Exposing to subdomain..."
  sudo /usr/local/bin/ellulai-expose "$APP_NAME" "$PORT"
  echo ""
  success "App deployed!"
  echo ""
  echo -e "  \${GREEN}Live at:\${NC} https://$APP_NAME.$DOMAIN"
  echo ""
}

cmd_help() {
  echo ""
  echo -e "\${CYAN}ellul.ai AI Flow\${NC}"
  echo ""
  echo "Commands:"
  echo "  save   - AI-powered commit & push"
  echo "  ship   - Context-aware deploy to production"
  echo ""
}

case "$ACTION" in
  save) cmd_save ;;
  ship) cmd_ship ;;
  help|--help|-h) cmd_help ;;
  *) cmd_help ;;
esac`;
}
