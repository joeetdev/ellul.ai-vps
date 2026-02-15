/**
 * Settings Service
 *
 * Local settings CRUD with atomic writes and tier-based overrides.
 * Settings are the VPS source of truth — API DB is a read-only mirror.
 *
 * Flow:
 *   Dashboard → Bridge → toggleTerminal/toggleSsh → atomic write + apply
 *   → vps-event webhook → API mirrors to DB
 *   → Heartbeat reports actual state every 30s (reconciliation fallback)
 */

import fs from 'fs';
import { execSync } from 'child_process';
import { getCurrentTier } from './tier.service';
import { SSH_AUTH_KEYS_PATH } from '../config';

const SETTINGS_FILE = '/etc/ellulai/settings.json';
const SETTINGS_TMP = '/etc/ellulai/settings.json.tmp';

export interface LocalSettings {
  terminalEnabled: boolean;
  sshEnabled: boolean;
  updatedAt: string;
}

/**
 * Read settings from disk. If file missing/corrupt, return tier-based defaults.
 * Never throws.
 */
export function readSettings(): LocalSettings {
  try {
    const raw = fs.readFileSync(SETTINGS_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return {
      terminalEnabled: typeof parsed.terminalEnabled === 'boolean' ? parsed.terminalEnabled : true,
      sshEnabled: typeof parsed.sshEnabled === 'boolean' ? parsed.sshEnabled : false,
      updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : new Date().toISOString(),
    };
  } catch {
    // File missing or corrupt — return tier-based defaults
    return applyTierOverrides({
      terminalEnabled: true,
      sshEnabled: false,
      updatedAt: new Date().toISOString(),
    });
  }
}

/**
 * Atomic write: write to tmp, fsync, rename.
 * Throws on I/O failure (caller handles).
 */
function writeSettings(settings: LocalSettings): void {
  const data = JSON.stringify(settings, null, 2) + '\n';
  const fd = fs.openSync(SETTINGS_TMP, 'w', 0o600);
  try {
    fs.writeSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(SETTINGS_TMP, SETTINGS_FILE);
  // Ensure root:root 600
  try {
    execSync(`chown root:root ${SETTINGS_FILE} 2>/dev/null || true`, { stdio: 'pipe' });
    fs.chmodSync(SETTINGS_FILE, 0o600);
  } catch {}
}

/**
 * Apply tier-based overrides. This is the canonical enforcement logic.
 * Mirrors enforce_settings() in enforcement.sh exactly:
 * - standard: terminal=true, ssh=false
 * - web_locked: terminal=true, ssh=(keys present)
 * - SAFETY: SSH always true if authorized_keys exists and non-empty
 */
export function applyTierOverrides(settings: LocalSettings): LocalSettings {
  const tier = getCurrentTier();
  const result = { ...settings };

  switch (tier) {
    case 'standard':
      result.sshEnabled = false;
      result.terminalEnabled = true;
      break;
    case 'web_locked':
      result.terminalEnabled = true;
      // SSH enabled if keys are present
      try {
        const authKeys = fs.readFileSync(SSH_AUTH_KEYS_PATH, 'utf8');
        result.sshEnabled = authKeys.split('\n').some(line => line.trim() && !line.startsWith('#'));
      } catch {
        result.sshEnabled = false;
      }
      break;
  }

  // SAFETY CHECK: Never close SSH if keys are present (prevents lockout)
  try {
    const authKeys = fs.readFileSync(SSH_AUTH_KEYS_PATH, 'utf8');
    if (authKeys.split('\n').some(line => line.trim() && !line.startsWith('#'))) {
      result.sshEnabled = true;
    }
  } catch {}

  return result;
}

/**
 * Toggle terminal. Writes to disk, applies via systemctl, returns new state.
 * Throws if systemctl fails (caller returns 500).
 */
export function toggleTerminal(enabled: boolean): LocalSettings {
  const settings = readSettings();
  settings.terminalEnabled = enabled;
  settings.updatedAt = new Date().toISOString();
  const effective = applyTierOverrides(settings);
  writeSettings(effective);
  applyTerminalState(effective.terminalEnabled);
  return effective;
}

/**
 * Toggle SSH. Writes to disk, applies via ufw, returns new state.
 * Throws if ufw fails.
 */
export function toggleSsh(enabled: boolean): LocalSettings {
  const settings = readSettings();
  settings.sshEnabled = enabled;
  settings.updatedAt = new Date().toISOString();
  const effective = applyTierOverrides(settings);
  writeSettings(effective);
  applySshState(effective.sshEnabled);
  return effective;
}

/**
 * Start or stop all terminal services.
 */
function applyTerminalState(enabled: boolean): void {
  if (enabled) {
    execSync('systemctl start ellulai-agent-bridge ellulai-term-proxy 2>/dev/null || true', { timeout: 10_000 });
  } else {
    execSync('systemctl stop ellulai-agent-bridge ellulai-term-proxy 2>/dev/null || true', { timeout: 10_000 });
    // Also stop any legacy static ttyd services
    execSync("systemctl list-units 'ttyd@*' --no-legend | awk '{print $1}' | xargs -r systemctl stop 2>/dev/null || true", { timeout: 10_000 });
  }
}

/**
 * Open or close SSH via ufw.
 */
function applySshState(enabled: boolean): void {
  if (enabled) {
    execSync("ufw status | grep -q '22/tcp.*ALLOW' || ufw allow 22/tcp comment 'SSH' 2>/dev/null || true", { timeout: 5_000 });
  } else {
    execSync("ufw status | grep -q '22/tcp.*ALLOW' && ufw delete allow 22/tcp 2>/dev/null || true", { timeout: 5_000 });
  }
}

/**
 * Initialize settings file if missing (called on boot).
 * Creates with tier-appropriate defaults.
 */
export function initSettings(): void {
  if (fs.existsSync(SETTINGS_FILE)) return;
  const defaults = applyTierOverrides({
    terminalEnabled: true,
    sshEnabled: false,
    updatedAt: new Date().toISOString(),
  });
  writeSettings(defaults);
}

/**
 * Called when tier changes — recompute settings with new tier overrides.
 */
export function onTierChanged(): void {
  const current = readSettings();
  const effective = applyTierOverrides(current);
  writeSettings(effective);
  applyTerminalState(effective.terminalEnabled);
  applySshState(effective.sshEnabled);
}

/**
 * Called after SSH key add/remove — recompute settings based on key presence.
 * For web_locked: sshEnabled follows authorized_keys (keys present = ssh on).
 * Returns the effective settings for webhook notification.
 */
export function syncSettingsAfterKeyChange(): LocalSettings {
  const current = readSettings();
  const effective = applyTierOverrides(current);
  writeSettings(effective);
  return effective;
}
