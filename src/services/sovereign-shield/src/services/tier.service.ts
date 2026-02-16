/**
 * Tier Service
 *
 * Security tier management and platform notifications.
 *
 * SECURITY: Tier is derived from ground truth (passkeys, markers) not just a file.
 * Uses tamper-proof caching for performance with periodic revalidation.
 */

import crypto from 'crypto';
import fs from 'fs';
import type Database from 'better-sqlite3';
import {
  TIER_FILE,
  TERMINAL_DISABLED_FILE,
  SERVER_ID_FILE,
  API_URL_FILE,
  SVC_HOME,
} from '../config';
import type { SecurityTier } from '../config';

// SECURITY: Marker file that indicates web_locked was intentionally activated
// This file can ONLY be removed via explicit downgrade (SSH or authenticated request)
// Prevents accidental downgrade if DB is corrupted/cleared
const WEB_LOCKED_MARKER = '/etc/ellulai/.web_locked_activated';

// Transition lock file — prevents concurrent tier switches and aids crash recovery
const TIER_TRANSITION_LOCK = '/etc/ellulai/.tier-transition';

// Database will be injected to avoid circular dependencies
let db: Database;

/**
 * Invalidate tier state - call this when tier state changes
 * (Kept for API compatibility, but tier is now computed on-demand)
 */
export function invalidateTierCache(): void {
  // No-op: tier is computed from ground truth on every call
  // Marker file check is instant, so no caching needed
}

export function setDatabase(database: Database): void {
  db = database;
}

export interface ServerCredentials {
  serverId: string;
  apiUrl: string;
  token: string | null;
}

/**
 * Get current security tier
 *
 * SECURITY: Always derive tier from ground truth, never trust the tier file alone.
 * No caching - marker file check is instant and provides fail-secure guarantee.
 *
 * Priority order (highest security wins):
 * 1. Web Locked marker exists → web_locked (instant, fail-secure)
 * 2. Web Locked: Passkey exists in database
 * 3. Standard: No passkeys, no markers
 */
export function getCurrentTier(): SecurityTier {
  return computeTierFromGroundTruth();
}

/**
 * Compute tier from ground truth state
 * This is the source of truth for security tier determination.
 *
 * SECURITY PRINCIPLE: Fail secure, not fail open.
 * - If web_locked marker exists, we ALWAYS return web_locked (instant check)
 * - This prevents DB corruption from being an attack vector
 * - The marker can ONLY be removed via explicit authenticated downgrade
 *
 * PERFORMANCE: Marker check is first (fs.existsSync is ~0.1ms)
 * - web_locked users: 1 file check, done
 * - standard users: 1 file check + 1 DB query
 */
function computeTierFromGroundTruth(): SecurityTier {
  // ==========================================================================
  // FAST PATH: Check web_locked marker FIRST (instant, fail-secure)
  // ==========================================================================
  const webLockedMarkerExists = fs.existsSync(WEB_LOCKED_MARKER);

  if (webLockedMarkerExists) {
    // Marker exists = web_locked, period. No DB check needed for security.
    // Even if DB is corrupted/empty, we stay web_locked (fail secure)
    return 'web_locked';
  }

  // ==========================================================================
  // CROSS-CHECK: Read the immutable tier file as a safety net.
  // If the tier file says "web_locked" but marker is missing (crash recovery,
  // filesystem inconsistency, chattr race), trust the tier file and restore
  // the marker. The tier file is protected by chattr +i so it can't be
  // tampered with via SSH.
  // ==========================================================================
  try {
    const tierFileValue = fs.readFileSync(TIER_FILE, 'utf8').trim();
    if (tierFileValue === 'web_locked') {
      // Tier file says web_locked — restore missing marker (crash recovery)
      try {
        fs.writeFileSync(WEB_LOCKED_MARKER, Date.now().toString());
        fs.chmodSync(WEB_LOCKED_MARKER, 0o400);
        console.log('[shield] SECURITY: Tier file says web_locked, restored missing marker (crash recovery)');
      } catch (e) {
        console.error('[shield] SECURITY: Could not restore marker, but tier file is authoritative:', (e as Error).message);
      }
      return 'web_locked';
    }
  } catch {
    // Tier file missing or unreadable — continue to DB check
  }

  // ==========================================================================
  // SLOW PATH: No marker, tier file doesn't say web_locked, check actual state
  // ==========================================================================

  // Check for passkeys (only if no marker - new setup or never upgraded)
  let hasPasskey = false;
  try {
    if (db) {
      hasPasskey = (db.prepare('SELECT COUNT(*) as c FROM credential').get() as { c: number }).c > 0;
    }
  } catch (e) {
    // DB error with no marker and tier file not web_locked = standard
    console.error('[shield] DB query failed, no web_locked marker or tier file - defaulting to standard');
  }

  if (hasPasskey) {
    // Passkey exists but no marker - create marker now (first-time setup)
    try {
      fs.writeFileSync(WEB_LOCKED_MARKER, Date.now().toString());
      fs.chmodSync(WEB_LOCKED_MARKER, 0o400);
      console.log('[shield] SECURITY: Passkey found, created web_locked marker');
    } catch {}
    return 'web_locked';
  }

  // No marker, tier file not web_locked, no passkeys = standard
  return 'standard';
}

/**
 * Set security tier
 */
export function setTier(tier: SecurityTier): void {
  fs.writeFileSync(TIER_FILE, tier);
}

/**
 * Check if a tier has the requirements to be active
 */
export function canActivateTier(tier: SecurityTier): boolean {
  if (tier === 'standard') return true;

  if (tier === 'web_locked') {
    // Need at least one passkey
    const count = (db.prepare('SELECT COUNT(*) as c FROM credential').get() as { c: number }).c;
    return count > 0;
  }

  return false;
}

/**
 * Read server credentials for platform notifications
 */
export function getServerCredentials(): ServerCredentials | null {
  try {
    const serverId = fs.readFileSync(SERVER_ID_FILE, 'utf8').trim();
    const apiUrl = fs.existsSync(API_URL_FILE)
      ? fs.readFileSync(API_URL_FILE, 'utf8').trim()
      : 'https://api.ellul.ai';
    // Read token from bashrc
    const bashrc = fs.readFileSync(`${SVC_HOME}/.bashrc`, 'utf8');
    const tokenMatch = bashrc.match(/ELLULAI_AI_TOKEN="([^"]+)"/);
    const token = tokenMatch && tokenMatch[1] ? tokenMatch[1] : null;
    return { serverId, apiUrl, token };
  } catch {
    return null;
  }
}

/**
 * Notify platform about tier change
 */
export async function notifyPlatformTierChange(
  fromTier: SecurityTier,
  toTier: SecurityTier,
  ipAddress?: string,
  userAgent?: string
): Promise<void> {
  const creds = getServerCredentials();
  if (!creds || !creds.token) return;

  try {
    await fetch(`${creds.apiUrl}/api/servers/${creds.serverId}/vps-event`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${creds.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        event: 'tier_changed',
        data: {
          fromTier,
          tier: toTier,
          ipAddress: ipAddress || 'unknown',
          userAgent: userAgent || 'unknown',
        },
        timestamp: Date.now(),
        nonce: crypto.randomBytes(16).toString('hex'),
      }),
    });
  } catch (e) {
    console.error('[shield] Failed to notify platform of tier change:', (e as Error).message);
  }
}

/**
 * Notify platform about settings change (terminal/SSH toggle)
 * Fire-and-forget — heartbeat reconciles within 30s on failure.
 */
export async function notifyPlatformSettingsChange(
  settings: { terminalEnabled: boolean; sshEnabled: boolean },
  ipAddress: string,
  userAgent: string
): Promise<void> {
  const creds = getServerCredentials();
  if (!creds || !creds.token) return;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  try {
    const res = await fetch(`${creds.apiUrl}/api/servers/${creds.serverId}/vps-event`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${creds.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        event: 'settings_changed',
        data: {
          terminalEnabled: settings.terminalEnabled,
          sshEnabled: settings.sshEnabled,
          ipAddress,
          userAgent,
        },
        timestamp: Date.now(),
        nonce: crypto.randomBytes(16).toString('hex'),
      }),
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!res.ok) {
      console.warn('[shield] Settings webhook returned', res.status);
    }
  } catch (err: any) {
    clearTimeout(timeout);
    if (err.name !== 'AbortError') throw err;
    console.warn('[shield] Settings webhook timed out');
  }
}

/**
 * Notify platform about SSH key changes
 */
export async function notifyPlatformSshKeyChange(
  action: 'added' | 'removed',
  fingerprint: string,
  name: string,
  publicKey?: string
): Promise<void> {
  const creds = getServerCredentials();
  if (!creds || !creds.token) return;

  const event = action === 'added' ? 'ssh_key_added' : 'ssh_key_removed';

  try {
    await fetch(`${creds.apiUrl}/api/servers/${creds.serverId}/vps-event`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${creds.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        event,
        data: { fingerprint, name, publicKey },
        timestamp: Date.now(),
        nonce: crypto.randomBytes(16).toString('hex'),
      }),
    });
  } catch (e) {
    console.error('[shield] Failed to notify platform of SSH key change:', (e as Error).message);
  }
}

/**
 * Notify platform about passkey registration
 * Also invalidates tier cache since passkey existence affects tier
 */
export async function notifyPlatformPasskeyRegistered(credentialId: string, name: string): Promise<void> {
  // Passkey added = tier may change to web_locked
  invalidateTierCache();

  const creds = getServerCredentials();
  if (!creds || !creds.token) return;

  try {
    await fetch(`${creds.apiUrl}/api/servers/${creds.serverId}/vps-event`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${creds.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        event: 'passkey_registered',
        data: { credentialId, name },
        timestamp: Date.now(),
        nonce: crypto.randomBytes(16).toString('hex'),
      }),
    });
  } catch (e) {
    console.error('[shield] Failed to notify platform of passkey registration:', (e as Error).message);
  }
}

/**
 * Notify platform about passkey removal
 * Also invalidates tier cache since passkey existence affects tier
 */
export async function notifyPlatformPasskeyRemoved(credentialId: string, name: string): Promise<void> {
  // Passkey removed = tier may change from web_locked
  invalidateTierCache();

  const creds = getServerCredentials();
  if (!creds || !creds.token) return;

  try {
    await fetch(`${creds.apiUrl}/api/servers/${creds.serverId}/vps-event`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${creds.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        event: 'passkey_removed',
        data: { credentialId, name },
        timestamp: Date.now(),
        nonce: crypto.randomBytes(16).toString('hex'),
      }),
    });
  } catch (e) {
    console.error('[shield] Failed to notify platform of passkey removal:', (e as Error).message);
  }
}

/**
 * Notify platform to clear stored heartbeat public key.
 * Called after keypair regeneration so next heartbeat re-registers via TOFU.
 */
export async function notifyPlatformHeartbeatKeyReset(): Promise<void> {
  const creds = getServerCredentials();
  if (!creds || !creds.token) return;

  try {
    await fetch(`${creds.apiUrl}/api/servers/${creds.serverId}/vps-event`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${creds.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        event: 'heartbeat_key_reset',
        data: {},
        timestamp: Date.now(),
        nonce: crypto.randomBytes(16).toString('hex'),
      }),
    });
  } catch (e) {
    console.error('[shield] Failed to notify platform of heartbeat key reset:', (e as Error).message);
  }
}

/**
 * Execute a tier switch with pre-flight checks and rollback on failure
 *
 * This is the single source of truth for all tier changes.
 * It includes:
 * - Pre-flight safety checks (verify new access works before closing old)
 * - Tier file updates with verification
 * - Rollback on failure
 * - Platform notification
 */
export async function executeTierSwitch(
  targetTier: SecurityTier,
  ipAddress: string,
  userAgent: string
): Promise<void> {
  const { execSync, spawnSync } = await import('child_process');
  const currentTier = getCurrentTier();

  // Prevent concurrent tier transitions
  if (fs.existsSync(TIER_TRANSITION_LOCK)) {
    try {
      const lockData = JSON.parse(fs.readFileSync(TIER_TRANSITION_LOCK, 'utf8'));
      const lockAge = Date.now() - (lockData.startedAt || 0);
      // Stale lock (>60s) — previous transition crashed, allow override
      if (lockAge < 60_000) {
        throw new Error('Tier transition already in progress');
      }
      console.log('[shield] Clearing stale transition lock (age:', lockAge, 'ms)');
    } catch (e) {
      if ((e as Error).message === 'Tier transition already in progress') throw e;
      // Corrupt lock file — clear it
    }
  }

  // Write transition lock
  fs.writeFileSync(TIER_TRANSITION_LOCK, JSON.stringify({
    from: currentTier,
    to: targetTier,
    startedAt: Date.now(),
  }));

  try {

  // Helper to verify a service is running
  const isServiceRunning = (service: string): boolean => {
    try {
      const result = spawnSync('systemctl', ['is-active', '--quiet', service]);
      return result.status === 0;
    } catch { return false; }
  };

  // Helper to write tier file with immutability protection
  const writeTierFile = (tier: string): void => {
    // Remove immutable flag before writing
    try { execSync(`chattr -i ${TIER_FILE} 2>/dev/null || true`, { stdio: 'pipe' }); } catch {}
    fs.writeFileSync(TIER_FILE, tier);
    if (fs.readFileSync(TIER_FILE, 'utf8').trim() !== tier) {
      throw new Error(`Failed to update tier file to ${tier}`);
    }
    // Re-apply immutable flag to prevent tampering via SSH
    try { execSync(`chattr +i ${TIER_FILE} 2>/dev/null || true`, { stdio: 'pipe' }); } catch {}
    console.log(`[shield] Tier file updated to ${tier} (verified + immutable)`);
  };

  // Helper to write marker file with immutability
  const writeImmutableMarker = (path: string, content: string): void => {
    try { execSync(`chattr -i ${path} 2>/dev/null || true`, { stdio: 'pipe' }); } catch {}
    fs.writeFileSync(path, content);
    fs.chmodSync(path, 0o400);
    try { execSync(`chattr +i ${path} 2>/dev/null || true`, { stdio: 'pipe' }); } catch {}
  };

  // Helper to remove immutable marker file
  const removeImmutableMarker = (path: string): void => {
    try { execSync(`chattr -i ${path} 2>/dev/null || true`, { stdio: 'pipe' }); } catch {}
    try { fs.unlinkSync(path); } catch {}
  };

  switch (targetTier) {
    case 'standard':
      // =================================================================
      // DOWNGRADE TO STANDARD - Must verify web terminal works BEFORE closing SSH
      // =================================================================

      // STEP 1: Start terminal services FIRST (before any destructive changes)
      // Dynamic terminal sessions are provided by agent-bridge and term-proxy
      execSync('/usr/local/bin/ellulai-unlock 2>&1 || true', { stdio: 'pipe' });
      execSync('systemctl start ellulai-agent-bridge ellulai-term-proxy 2>/dev/null || true', { stdio: 'pipe' });

      // STEP 2: Wait and verify terminal services are running BEFORE closing SSH
      await new Promise(r => setTimeout(r, 2000));
      if (!isServiceRunning('ellulai-agent-bridge') || !isServiceRunning('ellulai-term-proxy')) {
        console.error('[shield] FATAL: Terminal services failed to start! Aborting downgrade.');
        throw new Error('Terminal services failed to start - downgrade aborted, SSH still available');
      }
      console.log('[shield] Terminal services (agent-bridge, term-proxy) verified running');

      // STEP 3: Remove web_locked marker and clear passkey credentials
      // Both must succeed: if marker is gone but passkeys remain,
      // computeTierFromGroundTruth() recreates the marker and tier snaps back.
      // SAFETY: Only clear credentials AFTER confirming marker is gone.
      // If marker removal fails, keep credentials so user can still authenticate.
      removeImmutableMarker(WEB_LOCKED_MARKER);
      if (fs.existsSync(WEB_LOCKED_MARKER)) {
        console.error('[shield] CRITICAL: web_locked marker could not be removed — aborting downgrade');
        throw new Error('Failed to remove web_locked marker — downgrade aborted, passkeys preserved');
      }
      console.log('[shield] SECURITY: web_locked marker removed (explicit downgrade)');
      // Marker confirmed gone — clear credentials in a transaction.
      // If the DB operation fails, restore the marker so the user can still
      // authenticate with their existing passkeys (fail-secure).
      try {
        db.exec('BEGIN');
        db.prepare('DELETE FROM sessions').run();
        db.prepare('DELETE FROM credential').run();
        db.exec('COMMIT');
        console.log('[shield] Passkey credentials and sessions cleared (standard downgrade)');
      } catch (e) {
        db.exec('ROLLBACK');
        // Restore marker — credentials still exist, user can still auth
        writeImmutableMarker(WEB_LOCKED_MARKER, Date.now().toString());
        console.error('[shield] Failed to clear credentials, restored web_locked marker:', (e as Error).message);
        throw new Error('Failed to clear credentials — web_locked state restored');
      }

      // STEP 4: Update tier file (after security state is consistent)
      writeTierFile('standard');

      // STEP 5: FINAL - Only close SSH port after everything else succeeded
      // User now has verified web terminal access
      execSync('ufw deny 22/tcp 2>/dev/null || true', { stdio: 'pipe' });
      console.log('[shield] SSH port closed (standard tier)');
      break;

    case 'web_locked':
      // =================================================================
      // UPGRADE TO WEB LOCKED - Passkey gate should already be active
      // =================================================================

      // STEP 0: Ensure SSH stays closed (no SSH fallback)
      execSync('ufw deny 22/tcp 2>/dev/null || true', { stdio: 'pipe' });
      console.log('[shield] SSH port closed (web_locked from standard - passkey + recovery codes only)');

      // STEP 1: Verify we're running (sovereign-shield must be active for web_locked)
      console.log('[shield] Sovereign Shield is active (self-verified)');

      // STEP 2: Create web_locked activation marker (SECURITY: prevents accidental downgrade)
      writeImmutableMarker(WEB_LOCKED_MARKER, Date.now().toString());
      console.log('[shield] SECURITY: web_locked marker created (fail-secure + immutable)');

      // STEP 3: Update tier file
      writeTierFile('web_locked');

      // STEP 4: Remove terminal disabled marker if present
      try { fs.unlinkSync(TERMINAL_DISABLED_FILE); } catch {}
      break;
  }

  // Invalidate tier cache immediately after state change
  invalidateTierCache();

  // Recompute settings with new tier overrides
  const { onTierChanged } = await import('./settings.service');
  onTierChanged();

  // Notify platform
  await notifyPlatformTierChange(currentTier, targetTier, ipAddress, userAgent);
  } finally {
    // Always release transition lock
    try { fs.unlinkSync(TIER_TRANSITION_LOCK); } catch {}
  }
}
