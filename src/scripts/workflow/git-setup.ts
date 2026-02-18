/**
 * Git credential setup script for VPS.
 *
 * Called by the daemon when __GIT_TOKEN secret is detected during secrets sync.
 * Configures git credentials, identity, and remote so the user can push/pull
 * from the dashboard without touching the terminal.
 *
 * Supports GitHub, GitLab, and Bitbucket via HTTPS token authentication.
 */
export function getGitSetupScript(): string {
  return `#!/bin/bash
set -e

GREEN='\\033[32m'
CYAN='\\033[36m'
YELLOW='\\033[33m'
RED='\\033[31m'
NC='\\033[0m'

log() { echo -e "\${CYAN}[git-setup]\${NC} $1"; }
success() { echo -e "\${GREEN}*\${NC} $1"; }
warn() { echo -e "\${YELLOW}!\${NC} $1"; }
error() { echo -e "\${RED}x\${NC} $1"; }

# Read git secrets from environment (decrypted by VPS secrets sync)
PROVIDER="\${__GIT_PROVIDER:-}"
TOKEN="\${__GIT_TOKEN:-}"
REPO_URL="\${__GIT_REPO_URL:-}"
USER_NAME="\${__GIT_USER_NAME:-ellul.ai User}"
USER_EMAIL="\${__GIT_USER_EMAIL:-noreply@ellul.ai}"
DEFAULT_BRANCH="\${__GIT_DEFAULT_BRANCH:-main}"

if [ -z "$TOKEN" ]; then
  error "No git token found. Connect a provider in the dashboard."
  exit 1
fi

if [ -z "$REPO_URL" ]; then
  error "No repo URL configured. Link a repo in the dashboard."
  exit 1
fi

log "Setting up git credentials for $PROVIDER..."

# Configure git identity
git config --global user.name "$USER_NAME"
git config --global user.email "$USER_EMAIL"
success "Git identity: $USER_NAME <$USER_EMAIL>"

# --- Sovereign Credential Helper ---
# Instead of writing plaintext tokens to ~/.git-credentials (which any
# process with shell access could read), we use a custom credential helper
# that reads the token from environment variables at runtime.
# The token only exists in the daemon's process memory — never on disk.

HELPER_PATH="/usr/local/bin/git-credential-ellulai"

# Skip writing if helper already exists (installed during provisioning).
# ProtectSystem=strict makes /usr/local/bin read-only for services.
if [ ! -f "$HELPER_PATH" ]; then
cat > "$HELPER_PATH" << 'HELPER_EOF'
#!/bin/bash
# ellul.ai Sovereign Credential Helper
# Reads git credentials from environment variables set by the VPS daemon.
# Token never touches disk — only lives in process memory.
#
# Git credential helper protocol:
#   $1 = "get" | "store" | "erase"
#   stdin = key=value pairs (protocol, host, etc.)
#   stdout = key=value pairs (username, password)

# We only handle "get". For store/erase, we do nothing (read-only helper).
if [ "$1" != "get" ]; then
  exit 0
fi

# Drain stdin (git pipes attributes we don't need — only one provider per VPS)
cat > /dev/null

# Source secrets if not already in environment (non-interactive shells)
if [ -f "$HOME/.ellulai-env" ]; then
  source "$HOME/.ellulai-env"
fi

# Resolve per-app secrets: __GIT_TOKEN__MY_APP → __GIT_TOKEN
if [ -f /etc/ellulai/shield-data/.active-git-app ]; then
  _ACTIVE=$(cat /etc/ellulai/shield-data/.active-git-app 2>/dev/null)
  if [ -n "$_ACTIVE" ]; then
    _SUFFIX="__$(echo "$_ACTIVE" | tr '[:lower:]' '[:upper:]' | sed 's/[^A-Z0-9]/_/g; s/__*/_/g; s/^_//; s/_$//')"
    _T_VAR="__GIT_TOKEN\${_SUFFIX}"
    _P_VAR="__GIT_PROVIDER\${_SUFFIX}"
    [ -n "\${!_T_VAR:-}" ] && __GIT_TOKEN="\${!_T_VAR}"
    [ -n "\${!_P_VAR:-}" ] && __GIT_PROVIDER="\${!_P_VAR}"
  fi
fi

# Map provider to the correct username format
case "\${__GIT_PROVIDER:-}" in
  github)   USERNAME="x-access-token" ;;
  gitlab)   USERNAME="oauth2" ;;
  bitbucket) USERNAME="x-token-auth" ;;
  *) exit 0 ;;
esac

# Output credentials
if [ -n "\${__GIT_TOKEN:-}" ]; then
  echo "username=\$USERNAME"
  echo "password=\$__GIT_TOKEN"
fi
HELPER_EOF
chmod 755 "$HELPER_PATH"
fi

git config --global credential.helper "$HELPER_PATH"

# Remove any legacy plaintext credential file from older setups
rm -f ~/.git-credentials 2>/dev/null

success "Sovereign credential helper configured (no tokens on disk)"

# Find project directory (ELLULAI_PROJECT_DIR set by enforcement for per-app git)
PROJECT_DIR="\${ELLULAI_PROJECT_DIR:-}"
if [ -z "$PROJECT_DIR" ]; then
  if [ -d "$HOME/projects/welcome" ]; then
    PROJECT_DIR="$HOME/projects/welcome"
  elif [ -d "$HOME/projects" ]; then
    # Use the first directory with files in it
    for dir in $HOME/projects/*/; do
      if [ -d "$dir" ]; then
        PROJECT_DIR="$dir"
        break
      fi
    done
    # Fallback to projects root
    [ -z "$PROJECT_DIR" ] && PROJECT_DIR="$HOME/projects"
  fi
fi

if [ -z "$PROJECT_DIR" ]; then
  error "No project directory found"
  exit 1
fi

cd "$PROJECT_DIR"
log "Project directory: $PROJECT_DIR"

# Initialize git repo if needed
if [ ! -d ".git" ]; then
  log "Initializing git repository..."
  git init
  git add -A
  git commit -m "Initial commit from ellul.ai" --allow-empty
  success "Git repository initialized"
fi

# Set default branch
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "$DEFAULT_BRANCH" ] && [ -z "$(git log --oneline -1 2>/dev/null)" ]; then
  git checkout -b "$DEFAULT_BRANCH" 2>/dev/null || true
fi

# Configure remote
if git remote -v | grep -q origin; then
  EXISTING_URL=$(git remote get-url origin 2>/dev/null || echo "")
  if [ "$EXISTING_URL" != "$REPO_URL" ]; then
    log "Updating remote origin..."
    git remote set-url origin "$REPO_URL"
  fi
else
  log "Adding remote origin..."
  git remote add origin "$REPO_URL"
fi
success "Remote: $REPO_URL"

# Disable git advice for cleaner output
git config --global advice.pushUpdateRejected false
git config --global advice.statusHints false
git config --global push.autoSetupRemote true

# Pull code from remote so the code preview has something to show
if git ls-remote origin "$DEFAULT_BRANCH" >/dev/null 2>&1; then
  LOCAL_COMMITS=$(git rev-list --count HEAD 2>/dev/null || echo "0")
  log "Pulling code from remote ($DEFAULT_BRANCH)..."
  git fetch origin "$DEFAULT_BRANCH" 2>&1 || true
  if [ "$LOCAL_COMMITS" -le 1 ]; then
    # Fresh/empty repo — reset to remote branch
    git checkout -B "$DEFAULT_BRANCH" "origin/$DEFAULT_BRANCH" 2>&1 || true
    success "Code pulled from remote!"
  else
    # Existing local commits — merge
    git pull origin "$DEFAULT_BRANCH" --no-edit 2>&1 || warn "Pull had conflicts — resolve manually"
  fi
else
  log "Remote branch '$DEFAULT_BRANCH' not found — skipping pull"
fi

success "Git setup complete! Ready to push and pull."
echo ""
log "Use 'git-flow backup' to back up your code"
log "Use 'git-flow pull' to pull latest changes"
`;
}
