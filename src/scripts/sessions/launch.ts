/**
 * Session launcher script - uses explicit PATH since .bashrc exits early for non-interactive shells.
 * Handles launching different terminal sessions (main, opencode, claude, etc.)
 * @param svcUser - Service user name (coder for free tier, dev for paid)
 */
export function getSessionLauncherScript(svcUser: string = "dev"): string {
  const svcHome = `/home/${svcUser}`;
  return `#!/bin/bash
SESSION="$1"
CONTEXT_FILE="${svcHome}/.ellulai/context/world.md"
export PATH="${svcHome}/.node/bin:${svcHome}/.opencode/bin:${svcHome}/.local/bin:$PATH"

# Load NVM so npm-installed CLIs (claude, codex, gemini) are in PATH
export NVM_DIR="${svcHome}/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"

# Load lazy-ai shims (shows "installing..." instead of "command not found")
[ -f /etc/profile.d/99-lazy-ai-shims.sh ] && . /etc/profile.d/99-lazy-ai-shims.sh

refresh_context() {
  /usr/local/bin/ellulai-ctx >/dev/null 2>&1 || true
}

case "$SESSION" in
  main)
    exec tmux new-session -A -s main
    ;;
  opencode)
    refresh_context
    exec tmux new-session -A -s opencode "cd ${svcHome}/projects/welcome && opencode; exec bash"
    ;;
  claude)
    refresh_context
    exec tmux new-session -A -s claude "cd ${svcHome}/projects/welcome && claude; exec bash"
    ;;
  codex)
    refresh_context
    exec tmux new-session -A -s codex "cd ${svcHome}/projects/welcome && codex; exec bash"
    ;;
  gemini)
    refresh_context
    exec tmux new-session -A -s gemini "cd ${svcHome}/projects/welcome && gemini; exec bash"
    ;;
  aider)
    refresh_context
    exec tmux new-session -A -s aider "cd ${svcHome}/projects/welcome && aider; exec bash"
    ;;
  git)
    exec tmux new-session -A -s git "cd ${svcHome}/projects/welcome && lazygit; exec bash"
    ;;
  save)
    exec tmux new-session -A -s save "ellulai-ai-flow save; exec bash"
    ;;
  ship)
    exec tmux new-session -A -s ship "ellulai-ai-flow ship; exec bash"
    ;;
  branch)
    exec tmux new-session -A -s branch "cd ${svcHome}/projects/welcome && ellulai-git-flow branch; exec bash"
    ;;
  undo)
    exec tmux new-session -A -s undo "ellulai-undo; exec bash"
    ;;
  logs)
    exec tmux new-session -A -s logs "echo -e '\\033[32mLIVE LOGS - Press Ctrl+C to exit\\033[0m' && pm2 logs --lines 50; exec bash"
    ;;
  clean)
    exec tmux new-session -A -s clean "sudo ellulai-clean; exec bash"
    ;;
  *)
    echo "Unknown: $SESSION"
    exec tmux new-session -A -s main
    ;;
esac`;
}
