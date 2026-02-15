/**
 * ttyd wrapper script - maps session names to ports and launches ttyd.
 */
export function getTtydWrapperScript(): string {
  return `#!/bin/bash
SESSION="$1"

case "$SESSION" in
  main)     PORT=7681 ;;
  opencode) PORT=7682 ;;
  claude)   PORT=7683 ;;
  codex)    PORT=7684 ;;
  gemini)   PORT=7685 ;;
  aider)    PORT=7686 ;;
  git)      PORT=7687 ;;
  branch)   PORT=7690 ;;
  save)     PORT=7691 ;;
  ship)     PORT=7692 ;;
  undo)     PORT=7693 ;;
  logs)     PORT=7694 ;;
  clean)    PORT=7695 ;;
  *)
    echo "Unknown session: $SESSION"
    exit 1
    ;;
esac

exec /usr/bin/ttyd \\
  --base-path /term/$SESSION/ \\
  -p $PORT \\
  -i 127.0.0.1 \\
  -W \\
  -t disableLeaveAlert=true \\
  -t rightClickSelectsWord=true \\
  /usr/local/bin/ellulai-launch "$SESSION"`;
}

/**
 * ttyd systemd service template.
 * @param svcUser - Service user name (coder for free tier, dev for paid)
 */
export function getTtydSystemdTemplate(svcUser: string = "dev"): string {
  const svcHome = `/home/${svcUser}`;
  return `[Unit]
Description=ttyd - Terminal Session %i
After=network.target

[Service]
Type=simple
User=${svcUser}
Group=${svcUser}
WorkingDirectory=${svcHome}/projects
ExecStart=/usr/local/bin/ellulai-ttyd-wrapper %i
ExecStop=/usr/bin/tmux kill-session -t %i
ExecStopPost=/bin/bash -c 'pkill -f "ellulai-launch %i" 2>/dev/null || true'
Restart=always
RestartSec=5
RestartPreventExitStatus=SIGTERM

[Install]
WantedBy=multi-user.target`;
}
