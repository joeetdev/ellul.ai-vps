/**
 * Lazy AI installer - installs AI tools in the background after provisioning.
 */
export function getLazyAiInstallerScript(): string {
  return `#!/bin/bash
LOG="/var/log/lazy-ai-install.log"
FLAG_DIR="/var/lib/phone-stack"
FLAG_FILE="$FLAG_DIR/lazy-ai-ready"

log() { echo "[$(date -Iseconds)] $1" >> "$LOG"; }

mkdir -p "$FLAG_DIR"
log "Installing AI tools..."
sleep 15
su - dev -c 'source ~/.nvm/nvm.sh && npm install -g @anthropic-ai/claude-code' >> "$LOG" 2>&1 || log "!claude"
su - dev -c 'source ~/.nvm/nvm.sh && npm install -g @openai/codex' >> "$LOG" 2>&1 || log "!codex"
su - dev -c 'source ~/.nvm/nvm.sh && npm install -g @google/gemini-cli' >> "$LOG" 2>&1 || log "!gemini"
su - dev -c 'pipx install aider-chat' >> "$LOG" 2>&1 || log "!aider"
touch "$FLAG_FILE"
log "Done"
wall "AI tools ready" 2>/dev/null || true`;
}

/**
 * Lazy AI shims - shell functions that wait for AI tools to install.
 */
export function getLazyAiShimsScript(): string {
  return `#!/bin/bash
FLAG_FILE="/var/lib/phone-stack/lazy-ai-ready"
ENV_FILE="$HOME/.phonestack-env"

_reload_secrets() {
  [ -f "$ENV_FILE" ] && source "$ENV_FILE"
}

_ai_shim() {
  local tool="$1"
  shift
  _reload_secrets
  if [ -f "$FLAG_FILE" ] || command -v "$tool" &>/dev/null; then
    command "$tool" "$@"
  else
    echo "$tool installing..."
  fi
}

opencode() { _ai_shim opencode "$@"; }

claude() { _ai_shim claude "$@"; }
codex() { _ai_shim codex "$@"; }
gemini() { _ai_shim gemini "$@"; }
aider() {
  _reload_secrets
  if [ -f "$FLAG_FILE" ] || [ -x "$HOME/.local/bin/aider" ]; then
    "$HOME/.local/bin/aider" "$@"
  else
    _ai_shim aider "$@"
  fi
}

export -f opencode claude codex gemini aider _ai_shim _reload_secrets 2>/dev/null || true`;
}
