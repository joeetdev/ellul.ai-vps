/**
 * Tmux configuration for Phone Stack terminal sessions.
 * Mouse OFF so browser handles selection/copy natively.
 */
export function getTmuxConfig(): string {
  return `set -g default-terminal "xterm-256color"
set -ga terminal-overrides ",xterm-256color:Tc"
set -g history-limit 50000
set -g mouse off
set -g status-position top
set -g status-style "bg=#0a0a0a,fg=#00ff00"
set -g status-left "#[fg=#00ff00,bold] PHONESTACK "
set -g status-right "#[fg=#00ff00] %H:%M "
set -g pane-border-style "fg=#333333"
set -g pane-active-border-style "fg=#00ff00"
set -g message-style "bg=#0a0a0a,fg=#00ff00"

# Mouse is OFF - browser handles text selection and copy/paste
# For scrolling: use Ctrl+B [ to enter copy mode, then arrows/PgUp/PgDn
# Exit copy mode with q or Escape`;
}

/**
 * Starship prompt configuration - optimized for speed.
 */
export function getStarshipConfig(): string {
  return `# Fast minimal prompt - no lag
command_timeout = 200
scan_timeout = 100

format = """$directory$git_branch$character"""

add_newline = false

[character]
success_symbol = "[>](bold bright-green)"
error_symbol = "[>](bold red)"

[directory]
style = "bold bright-green"
format = "[$path]($style) "
truncation_length = 2
truncate_to_repo = true

[git_branch]
style = "bold green"
format = "[$branch]($style) "
only_attached = true

# Disabled for speed - these cause lag
[git_status]
disabled = true

[nodejs]
disabled = true

[python]
disabled = true

[rust]
disabled = true

[aws]
disabled = true

[gcloud]
disabled = true

[docker_context]
disabled = true

[package]
disabled = true`;
}
