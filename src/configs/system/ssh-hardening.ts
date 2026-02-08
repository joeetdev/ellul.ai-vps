/**
 * SSH hardening configuration for Phone Stack servers.
 * Disables password auth and root login, enforces key-based auth.
 */
export function getSshHardeningConfig(): string {
  return `PasswordAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server`;
}

/**
 * Fail2ban configuration for SSH protection.
 */
export function getFail2banConfig(): string {
  return `[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600`;
}

/**
 * Unattended upgrades configuration for automatic security updates.
 */
export function getUnattendedUpgradesConfig(): string {
  return `Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
};
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Automatic-Reboot "false";`;
}

/**
 * Auto-upgrades periodic configuration.
 */
export function getAutoUpgradesConfig(): string {
  return `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";`;
}
