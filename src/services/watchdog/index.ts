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
export function getWatchdogService(svcUser: string = "dev"): string {
  const svcHome = `/home/${svcUser}`;
  return `[Unit]
Description=ellul.ai OpenClaw Agent Wrapper
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/ellulai/src/services/watchdog
ExecStart=/usr/bin/node /opt/ellulai/src/services/watchdog/server.cjs
Restart=always
RestartSec=5
User=${svcUser}
Group=${svcUser}
Environment=SVC_HOME=${svcHome}
Environment=SVC_USER=${svcUser}
StandardOutput=append:/var/log/ellulai-watchdog.log
StandardError=append:/var/log/ellulai-watchdog.log

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true

[Install]
WantedBy=multi-user.target`;
}
