/**
 * Git flow script - branch, save, and ship commands.
 */
export function getGitFlowScript(): string {
  return `#!/bin/bash
set -e
cd /home/dev/projects/welcome 2>/dev/null || cd /home/dev/projects

GREEN='\\033[32m'
CYAN='\\033[36m'
YELLOW='\\033[33m'
RED='\\033[31m'
NC='\\033[0m'

log() { echo -e "\${CYAN}[git-flow]\${NC} $1"; }
success() { echo -e "\${GREEN}*\${NC} $1"; }
warn() { echo -e "\${YELLOW}!\${NC} $1"; }
error() { echo -e "\${RED}x\${NC} $1"; }

cmd_branch() {
  log "Creating feature branch..."
  echo -e "\${CYAN}Enter branch name (or leave empty to cancel):\${NC}"
  read -r BRANCH_NAME
  if [ -z "$BRANCH_NAME" ]; then
    warn "No branch name provided. Cancelled."
    return 0
  fi
  BRANCH_NAME=$(echo "$BRANCH_NAME" | tr ' ' '-' | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]//g')
  if git rev-parse --verify "$BRANCH_NAME" >/dev/null 2>&1; then
    warn "Branch '$BRANCH_NAME' already exists."
    echo -e "\${CYAN}Switch to existing branch? [y/N]\${NC}"
    read -r CONFIRM
    if [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ]; then
      git checkout "$BRANCH_NAME"
      success "Switched to branch: $BRANCH_NAME"
    fi
    return 0
  fi
  git checkout -b "$BRANCH_NAME"
  success "Created and switched to: $BRANCH_NAME"
  echo -e "\${CYAN}Push branch to remote? [Y/n]\${NC}"
  read -r PUSH_CONFIRM
  if [ "$PUSH_CONFIRM" != "n" ] && [ "$PUSH_CONFIRM" != "N" ]; then
    git push -u origin "$BRANCH_NAME"
    success "Pushed branch to remote"
  fi
}

cmd_save() {
  log "Saving changes to Git..."
  if git diff --quiet && git diff --cached --quiet; then
    warn "No changes to save."
    return 0
  fi
  git add -A
  success "Staged all changes"
  TIMESTAMP=$(date '+%Y-%m-%d %H:%M')
  CHANGED_FILES=$(git diff --cached --name-only | head -5 | tr '\\n' ', ' | sed 's/,$//')
  MSG="Sync: $TIMESTAMP ($CHANGED_FILES)"
  git commit -m "$MSG"
  success "Committed: $MSG"
  if git remote -v | grep -q origin; then
    git push origin HEAD
    success "Synced to Git."
  else
    warn "No remote configured. Changes saved locally."
  fi
}

cmd_ship() {
  log "Shipping to Production..."
  CURRENT_BRANCH=$(git branch --show-current)
  if [ "$CURRENT_BRANCH" != "main" ]; then
    log "Switching to main branch..."
    git checkout main
    if [ -n "$CURRENT_BRANCH" ]; then
      log "Merging $CURRENT_BRANCH into main..."
      git merge "$CURRENT_BRANCH" --no-edit || {
        error "Merge conflict! Please resolve manually."
        return 1
      }
    fi
  fi
  if git remote -v | grep -q origin; then
    log "Pulling latest changes..."
    git pull origin main --rebase || true
  fi
  log "Installing dependencies..."
  npm ci --prefer-offline 2>/dev/null || npm install
  log "Building production bundle..."
  npm run build
  log "Restarting production server on port 3001..."
  if [ -f ecosystem.config.js ]; then
    pm2 startOrRestart ecosystem.config.js --env production
  else
    pm2 delete prod 2>/dev/null || true
    pm2 start npm --name "prod" -- start -- -p 3001
  fi
  pm2 save
  success "Shipped to Production!"
  echo ""
  log "Live at: https://$(cat /etc/phonestack/domain 2>/dev/null || echo 'your-domain')/"
}

cmd_backup() {
  log "Backing up code to remote..."
  git add -A
  if git diff --cached --quiet; then
    warn "No changes to back up."
    if git remote -v | grep -q origin; then
      log "Pushing any unpushed commits..."
      git push -u origin HEAD 2>/dev/null || warn "Nothing to push."
    fi
    return 0
  fi
  TIMESTAMP=$(date '+%Y-%m-%d %H:%M')
  git commit -m "Backup from Phone Stack ($TIMESTAMP)"
  success "Committed changes"
  if git remote -v | grep -q origin; then
    if ! git push -u origin HEAD 2>&1; then
      error "Push rejected — the remote has changes that aren't on this device."
      error "Use 'git-flow force-backup' to overwrite the remote (your VPS is the source of truth)."
      return 1
    fi
    success "Code backed up to remote!"
  else
    error "No remote configured. Run git-setup first."
    return 1
  fi
}

cmd_force_backup() {
  log "Force-backing up code to remote (VPS is source of truth)..."
  git add -A
  if ! git diff --cached --quiet; then
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M')
    git commit -m "Backup from Phone Stack ($TIMESTAMP)"
    success "Committed changes"
  fi
  if git remote -v | grep -q origin; then
    git push -u origin HEAD --force-with-lease
    success "Code force-pushed to remote!"
  else
    error "No remote configured. Run git-setup first."
    return 1
  fi
}

cmd_pull_latest() {
  log "Pulling latest from remote..."
  if ! git remote -v | grep -q origin; then
    error "No remote configured. Run git-setup first."
    return 1
  fi
  git pull origin HEAD --rebase || {
    error "Pull failed. You may have conflicts to resolve."
    return 1
  }
  success "Pulled latest changes!"
}

case "$1" in
  branch) cmd_branch ;;
  save) cmd_save ;;
  ship) cmd_ship ;;
  backup) cmd_backup ;;
  force-backup) cmd_force_backup ;;
  pull) cmd_pull_latest ;;
  *)
    echo ""
    echo -e "\${CYAN}Phone Stack Git Flow\${NC}"
    echo ""
    echo "  branch       - Create a feature branch"
    echo "  save         - Commit and sync changes to Git"
    echo "  ship         - Build and deploy to production"
    echo "  backup       - Back up code to remote"
    echo "  force-backup - Overwrite remote with local code"
    echo "  pull         - Pull latest from remote"
    echo ""
    ;;
esac`;
}
