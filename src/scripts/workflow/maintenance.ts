/**
 * Undo/rollback tool - time machine for projects.
 */
export function getUndoScript(): string {
  return `#!/bin/bash
PROJECTS_DIR="/home/dev/projects"
TARGET_PROJECT="$1"

GREEN='\\033[32m'
CYAN='\\033[36m'
YELLOW='\\033[33m'
RED='\\033[31m'
NC='\\033[0m'

log() { echo -e "\${CYAN}[undo]\${NC} $1"; }
success() { echo -e "\${GREEN}*\${NC} $1"; }
warn() { echo -e "\${YELLOW}!\${NC} $1"; }
error() { echo -e "\${RED}x\${NC} $1" >&2; exit 1; }

rollback_project() {
  local PROJECT_PATH="$1"
  local PROJECT_NAME=$(basename "$PROJECT_PATH")
  echo ""
  echo -e "\${CYAN}TIME MACHINE: UNDO\${NC}"
  echo ""
  cd "$PROJECT_PATH" || error "Project not found: $PROJECT_PATH"
  if ! git rev-parse --is-inside-work-tree &>/dev/null; then
    error "Not a git repository: $PROJECT_PATH"
  fi
  log "Project: $PROJECT_NAME"
  log "Location: $PROJECT_PATH"
  echo ""
  echo -e "\${CYAN}Recent history:\${NC}"
  git log --oneline -5 --pretty=format:"  %C(yellow)%h%Creset %s %C(dim)(%cr)%Creset" 2>/dev/null || true
  echo ""
  echo ""
  echo -e "\${YELLOW}This will reset to the previous commit (HEAD@{1})\${NC}"
  echo -e "  All uncommitted changes will be \${RED}LOST\${NC}."
  echo ""
  read -p "Type 'UNDO' to confirm: " CONFIRM
  echo ""
  if [ "$CONFIRM" != "UNDO" ]; then
    log "Rollback cancelled."
    exit 0
  fi
  log "Rolling back git..."
  if git reset --hard HEAD@{1} 2>/dev/null; then
    success "Git reset complete"
  else
    warn "Reflog not available, resetting to HEAD~1..."
    git reset --hard HEAD~1 || error "Git reset failed"
    success "Git reset complete"
  fi
  if [ -f "package.json" ]; then
    log "Reinstalling dependencies..."
    if [ -f "pnpm-lock.yaml" ]; then
      pnpm install --frozen-lockfile 2>/dev/null || pnpm install
    elif [ -f "package-lock.json" ]; then
      npm ci 2>/dev/null || npm install
    else
      npm install
    fi
    success "Dependencies installed"
  fi
  if pm2 describe "$PROJECT_NAME" &>/dev/null; then
    log "Restarting PM2 process..."
    pm2 restart "$PROJECT_NAME"
    success "PM2 restarted"
  fi
  echo ""
  success "Rolled back to previous version!"
  echo ""
  log "New HEAD:"
  git log --oneline -1 --pretty=format:"  %C(yellow)%h%Creset %s" 2>/dev/null
  echo ""
  echo ""
}

if [ -n "$TARGET_PROJECT" ]; then
  if [ -d "$TARGET_PROJECT" ]; then
    rollback_project "$TARGET_PROJECT"
  elif [ -d "$PROJECTS_DIR/$TARGET_PROJECT" ]; then
    rollback_project "$PROJECTS_DIR/$TARGET_PROJECT"
  else
    error "Project not found: $TARGET_PROJECT"
  fi
else
  echo ""
  echo -e "\${CYAN}Available projects:\${NC}"
  echo ""
  PROJECTS=$(ls -d "$PROJECTS_DIR"/*/ 2>/dev/null | xargs -n1 basename 2>/dev/null || true)
  if [ -z "$PROJECTS" ]; then
    log "No projects found in $PROJECTS_DIR"
    exit 0
  fi
  INDEX=1
  echo "$PROJECTS" | while read -r proj; do
    echo "  $INDEX) $proj"
    INDEX=$((INDEX + 1))
  done
  readarray -t PROJECT_ARRAY <<< "$PROJECTS"
  echo ""
  read -p "Select project number: " SELECTION
  if [ -z "$SELECTION" ] || ! [[ "$SELECTION" =~ ^[0-9]+$ ]]; then
    error "Invalid selection"
  fi
  SELECTED_INDEX=$((SELECTION - 1))
  if [ $SELECTED_INDEX -lt 0 ] || [ $SELECTED_INDEX -ge \${#PROJECT_ARRAY[@]} ]; then
    error "Invalid selection"
  fi
  SELECTED_PROJECT="\${PROJECT_ARRAY[$SELECTED_INDEX]}"
  rollback_project "$PROJECTS_DIR/$SELECTED_PROJECT"
fi`;
}

/**
 * Clean/janitor tool - disk cleanup.
 */
export function getCleanScript(): string {
  return `#!/bin/bash
FORCE=false
[ "$1" = "--force" ] || [ "$1" = "-f" ] && FORCE=true

GREEN='\\033[32m'
CYAN='\\033[36m'
YELLOW='\\033[33m'
NC='\\033[0m'

log() { echo -e "\${CYAN}[janitor]\${NC} $1"; }
success() { echo -e "\${GREEN}*\${NC} $1"; }

get_disk_usage() {
  df -h / | awk 'NR==2 {print $5}'
}

get_free_mb() {
  df -m / | awk 'NR==2 {print $4}'
}

echo ""
echo -e "\${CYAN}ELLUL.AI JANITOR\${NC}"
echo ""

BEFORE_MB=$(get_free_mb)
log "Disk usage: $(get_disk_usage) used"
log "Free space: \${BEFORE_MB}MB"
echo ""

if [ "$FORCE" = false ]; then
  echo "This will clean:"
  echo "  * NPM cache"
  echo "  * Git garbage collection"
  echo "  * Old log files (> 7 days)"
  echo "  * Build artifacts (.next, dist, build)"
  echo "  * Python cache (__pycache__)"
  echo "  * PM2 logs (truncate to 1000 lines)"
  echo ""
  read -p "Continue? [y/N] " CONFIRM
  [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ] && exit 0
  echo ""
fi

log "Cleaning NPM cache..."
su - dev -c 'source ~/.nvm/nvm.sh && npm cache clean --force' 2>/dev/null
success "NPM cache cleaned"

log "Running git gc on all projects..."
for dir in /home/dev/projects/*/; do
  if [ -d "$dir/.git" ]; then
    (cd "$dir" && git gc --prune=now --quiet 2>/dev/null)
  fi
done
success "Git repos optimized"

log "Cleaning old log files..."
find /var/log -type f -name "*.log" -mtime +7 -delete 2>/dev/null || true
find /var/log -type f -name "*.gz" -delete 2>/dev/null || true
find /home/dev/.pm2/logs -type f -name "*.log" -mtime +3 -delete 2>/dev/null || true
success "Old logs removed"

log "Truncating PM2 logs..."
for logfile in /home/dev/.pm2/logs/*.log; do
  if [ -f "$logfile" ]; then
    tail -1000 "$logfile" > "$logfile.tmp" && mv "$logfile.tmp" "$logfile"
  fi
done
success "PM2 logs truncated"

log "Cleaning build artifacts..."
find /home/dev/projects -type d -name ".next" -exec rm -rf {} + 2>/dev/null || true
find /home/dev/projects -type d -name "dist" -exec rm -rf {} + 2>/dev/null || true
find /home/dev/projects -type d -name "build" -exec rm -rf {} + 2>/dev/null || true
find /home/dev/projects -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find /home/dev/projects -type d -name ".cache" -exec rm -rf {} + 2>/dev/null || true
success "Build artifacts cleaned"

log "Cleaning temp files..."
rm -rf /tmp/npm-* 2>/dev/null || true
rm -rf /tmp/v8-compile-cache-* 2>/dev/null || true
rm -rf /home/dev/.npm/_cacache 2>/dev/null || true
success "Temp files cleaned"

log "Vacuuming journal logs..."
journalctl --vacuum-time=3d --quiet 2>/dev/null || true
success "Journal logs cleaned"

echo ""
AFTER_MB=$(get_free_mb)
FREED_MB=$((AFTER_MB - BEFORE_MB))

if [ $FREED_MB -gt 0 ]; then
  success "Freed \${FREED_MB}MB of disk space!"
else
  log "Disk was already clean (freed < 1MB)"
fi

echo ""
log "Disk usage now: $(get_disk_usage) used"
log "Free space: \${AFTER_MB}MB"
echo ""`;
}
