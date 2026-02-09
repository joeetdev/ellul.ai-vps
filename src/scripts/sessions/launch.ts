/**
 * Session launcher script - uses explicit PATH since .bashrc exits early for non-interactive shells.
 * Handles launching different terminal sessions (main, opencode, claude, etc.)
 */
export function getSessionLauncherScript(): string {
  return `#!/bin/bash
SESSION="$1"
CONTEXT_FILE="/home/dev/.ellulai/context/world.md"
export PATH="/home/dev/.nvm/versions/node/v20.20.0/bin:/home/dev/.opencode/bin:/home/dev/.local/bin:$PATH"

refresh_context() {
  /usr/local/bin/ellulai-ctx >/dev/null 2>&1 || true
}

case "$SESSION" in
  main)
    exec tmux new-session -A -s main
    ;;
  opencode)
    refresh_context
    exec tmux new-session -A -s opencode "cd /home/dev/projects/welcome && opencode; exec bash"
    ;;
  claude)
    refresh_context
    exec tmux new-session -A -s claude "cd /home/dev/projects/welcome && claude; exec bash"
    ;;
  codex)
    refresh_context
    exec tmux new-session -A -s codex "cd /home/dev/projects/welcome && codex; exec bash"
    ;;
  gemini)
    refresh_context
    exec tmux new-session -A -s gemini "cd /home/dev/projects/welcome && gemini; exec bash"
    ;;
  aider)
    refresh_context
    exec tmux new-session -A -s aider "cd /home/dev/projects/welcome && aider; exec bash"
    ;;
  git)
    exec tmux new-session -A -s git "cd /home/dev/projects/welcome && lazygit; exec bash"
    ;;
  save)
    exec tmux new-session -A -s save "ellulai-ai-flow save; exec bash"
    ;;
  ship)
    exec tmux new-session -A -s ship "ellulai-ai-flow ship; exec bash"
    ;;
  branch)
    exec tmux new-session -A -s branch "cd /home/dev/projects/welcome && ellulai-git-flow branch; exec bash"
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
