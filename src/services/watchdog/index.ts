/**
 * Watchdog Service Exports
 *
 * Provides the systemd service file for the provisioning payload.
 * Python source files are deployed via the git-cloned repo at
 * /opt/ellulai/src/services/watchdog/ on the VPS.
 */

/**
 * Get the Watchdog systemd service file.
 */
export function getWatchdogService(): string {
  return `[Unit]
Description=ellul.ai Fishbowl Watchdog
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
WorkingDirectory=/opt/ellulai/src/services/watchdog
ExecStart=/usr/bin/python3 /opt/ellulai/src/services/watchdog/watchdog.py
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
