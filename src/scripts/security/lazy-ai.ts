/**
 * Lazy AI installer - installs AI tools in the background after provisioning.
 */
export function getLazyAiInstallerScript(): string {
  return `#!/bin/bash
LOG="/var/log/lazy-ai-install.log"
FLAG_DIR="/var/lib/ellul.ai"
FLAG_FILE="$FLAG_DIR/lazy-ai-ready"

[ -f /etc/default/ellulai ] && source /etc/default/ellulai
SVC_USER="\${PS_USER:-dev}"

log() { echo "[$(date -Iseconds)] $1" >> "$LOG"; }

# Retry wrapper: tries up to 3 times with 30s backoff
install_with_retry() {
  local label="$1"
  local cmd="$2"
  local attempt=1
  while [ $attempt -le 3 ]; do
    log "$label: attempt $attempt/3"
    if runuser -l $SVC_USER -c "$cmd" >> "$LOG" 2>&1; then
      log "$label: OK"
      return 0
    fi
    log "$label: attempt $attempt failed"
    attempt=$((attempt + 1))
    [ $attempt -le 3 ] && sleep 30
  done
  log "!$label (all attempts failed)"
  return 1
}

mkdir -p "$FLAG_DIR"
log "Installing AI tools as $SVC_USER..."
sleep 15
install_with_retry "claude" 'source ~/.nvm/nvm.sh && npm install -g @anthropic-ai/claude-code'
install_with_retry "codex" 'source ~/.nvm/nvm.sh && npm install -g @openai/codex'
install_with_retry "gemini" 'source ~/.nvm/nvm.sh && npm install -g @google/gemini-cli'
runuser -l $SVC_USER -c 'pipx install aider-chat' >> "$LOG" 2>&1 || log "!aider"
touch "$FLAG_FILE"
log "Done"
wall "AI tools ready" 2>/dev/null || true`;
}

/**
 * Lazy AI shims - shell functions that wait for AI tools to install.
 */
export function getLazyAiShimsScript(): string {
  return `#!/bin/bash
FLAG_FILE="/var/lib/ellul.ai/lazy-ai-ready"
ENV_FILE="$HOME/.ellulai-env"

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
