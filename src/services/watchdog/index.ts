/**
 * Watchdog Service Exports
 *
 * Provides the systemd service file for the provisioning payload.
 * The server.js file is deployed via the git-cloned repo at
 * /opt/ellulai/src/services/watchdog/ on the VPS.
 */

/**
 * Get the Watchdog systemd service file.
 * Runs the thin PM2 wrapper (server.js) that manages OpenClaw agents.
 */
export function getWatchdogService(): string {
  return `[Unit]
Description=ellul.ai OpenClaw Agent Wrapper
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/ellulai/src/services/watchdog
ExecStart=/usr/bin/node /opt/ellulai/src/services/watchdog/server.js
Restart=always
RestartSec=5
User=root
Environment=SVC_HOME=/home/dev
Environment=SVC_USER=dev
StandardOutput=append:/var/log/ellulai-watchdog.log
StandardError=append:/var/log/ellulai-watchdog.log

[Install]
WantedBy=multi-user.target`;
}
