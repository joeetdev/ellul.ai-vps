/**
 * Bash Configuration
 *
 * Bashrc and MOTD for the service user.
 */

/**
 * Bashrc configuration for the service user.
 *
 * @param aiProxyToken - The server's AI proxy token
 * @param svcUser - The service user name (coder for free tier, dev for paid)
 */
export function getBashrcConfig(aiProxyToken: string, svcUser: string = "dev"): string {
  const svcHome = `/home/${svcUser}`;
  return `# PATH exports BEFORE interactive check - needed for tmux/ttyd commands
export PATH="${svcHome}/.node/bin:${svcHome}/.opencode/bin:${svcHome}/.local/bin:$PATH"

case $- in
    *i*) ;;
      *) return;;
esac

HISTCONTROL=ignoreboth
HISTSIZE=10000
HISTFILESIZE=20000
shopt -s histappend
shopt -s checkwinsize

export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \\. "$NVM_DIR/nvm.sh"
[ -s "$NVM_DIR/bash_completion" ] && \\. "$NVM_DIR/bash_completion"

export PATH="$HOME/.local/bin:$PATH"
# AI token loaded from protected file (chmod 640) — not embedded in .bashrc for security
[ -f /etc/ellulai/ai-proxy-token ] && export ELLULAI_AI_TOKEN="$(cat /etc/ellulai/ai-proxy-token 2>/dev/null)"
export PORT=3000

[ -f ~/.ellulai-env ] && source ~/.ellulai-env

# Lazy AI shims (fallback for non-login shells where /etc/profile.d is not sourced)
[ -f /etc/profile.d/99-lazy-ai-shims.sh ] && source /etc/profile.d/99-lazy-ai-shims.sh

eval "$(starship init bash)"
eval "$(zoxide init bash)"

alias ls='eza --icons --group-directories-first'
alias ll='eza -la --icons --group-directories-first'
alias la='eza -a --icons --group-directories-first'
alias lt='eza --tree --icons --level=2'

alias cat='bat --paging=never --style=plain'
alias catn='bat --paging=never'

alias c='clear'
alias projects='cd ~/projects'
alias grep='rg'

alias reload='source ~/.ellulai-env && echo "Secrets reloaded"'

export FZF_DEFAULT_OPTS='--color=fg:#00ff00,bg:#0a0a0a,hl:#00ff00 --color=fg+:#00ff00,bg+:#1a1a1a,hl+:#00ff00 --color=info:#00ff00,prompt:#00ff00,pointer:#00ff00 --color=marker:#00ff00,spinner:#00ff00,header:#00ff00'

cd ~/projects 2>/dev/null || true`;
}

/**
 * MOTD (Message of the Day) script.
 */
export function getMotdScript(svcUser: string = "dev"): string {
  const svcHome = `/home/${svcUser}`;
  return `#!/bin/bash
# Only show MOTD for interactive shells (non-interactive login shells
# like runuser -l would corrupt PM2 jlist JSON output with ANSI text)
[[ $- != *i* ]] && return
SERVER_DOMAIN=$(cat /etc/ellulai/domain 2>/dev/null || echo "$(hostname -I | awk '{print $1}' | tr '.' '-').sslip.io")
APPS_DIR="${svcHome}/.ellulai/apps"

echo ""
echo -e "  \\033[1;32mELLUL.AI\\033[0m - Multi-App Vibe Coding"
echo ""

if ls "$APPS_DIR"/*.json &>/dev/null 2>&1; then
  echo -e "  \\033[32mDeployed Apps:\\033[0m"
  for f in "$APPS_DIR"/*.json; do
    [ -f "$f" ] || continue
    APP_NAME=$(jq -r '.name' "$f" 2>/dev/null)
    APP_STACK=$(jq -r '.stack // ""' "$f" 2>/dev/null)
    echo -e "    \\033[1;32m*\\033[0m \${APP_NAME} [\\033[36m\${APP_STACK}\\033[0m] -> https://\${APP_NAME}.\${SERVER_DOMAIN}"
  done
  echo ""
else
  echo -e "  \\033[90mNo apps yet. Deploy with: ellulai-expose <name> <port>\\033[0m"
  echo ""
fi

echo -e "  \\033[32mAI:\\033[0m opencode claude codex gemini aider"
if [ ! -f /var/lib/ellul.ai/lazy-ai-ready ]; then
  echo -e "  \\033[33mTools installing...\\033[0m"
fi
echo -e "  \\033[32mCmds:\\033[0m ellulai-apps | \\033[32mTools:\\033[0m z, bat, rg, fzf"
echo ""`;
}
