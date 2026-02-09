/**
 * VPS Version & Capabilities
 *
 * This file has two systems that serve different purposes:
 *
 * 1. CAPABILITIES — what this VPS supports (endpoints + feature flags).
 *    Exposed at GET /_auth/capabilities. The dashboard and API read this
 *    at runtime to decide which UI to show and which endpoints to call.
 *    This is the capability-based versioning system.
 *
 * 2. VERSION — semver component versions for the heartbeat/update system.
 *    The daemon reports these to the platform API every ~30s so the
 *    platform knows which release each server is running and whether
 *    an update is available.
 *
 * They are independent: CAPABILITIES drives runtime feature discovery,
 * VERSION drives update status and compatibility checks.
 */

export interface ComponentVersions {
  api: string;
  frontend: string;
  payload: string;
  daemon: string;
  sovereignShield: string;
  fileApi: string;
  agentBridge: string;
  termProxy: string;
}

export interface VersionManifest {
  /**
   * The unified release version (e.g., "2.0.0").
   * Used for user-facing version display.
   */
  release: string;

  /**
   * Individual component versions.
   * May differ from release version during development.
   */
  components: ComponentVersions;

  /**
   * Minimum compatible versions for upgrade paths.
   * Servers below these versions may need full reprovision.
   */
  minCompatible: {
    payload: string;
    daemon: string;
    sovereignShield: string;
  };
}

/**
 * GPG Release Signing Key Fingerprint.
 *
 * This fingerprint is embedded in every VPS daemon during provisioning.
 * The daemon uses it to verify that updates were signed by this exact key.
 *
 * To generate a release signing key:
 *   gpg --full-generate-key  (choose Ed25519, no expiry for release key)
 *   gpg --armor --export <KEY_ID> > release-signing.gpg
 *   gpg --fingerprint <KEY_ID>  (copy the fingerprint here)
 *
 * Store the private key OFFLINE (e.g., YubiKey or air-gapped machine).
 * The public key is deployed to VPS at /etc/ellulai/release-signing.gpg
 */
export const RELEASE_GPG_FINGERPRINT = "F5AC1C503485C8126F33EDAADC097B8D45768452";

// ---------------------------------------------------------------------------
// 1. CAPABILITIES — runtime feature discovery (GET /_auth/capabilities)
//
// Rules: add freely, edit carefully (bump endpoint version), remove never.
// ---------------------------------------------------------------------------

export const CAPABILITIES = {
  endpoints: {
    '/_auth/session': 1,
    '/_auth/terminal/authorize': 1,
    '/_auth/terminal/validate': 1,
    '/_auth/code/authorize': 1,
    '/_auth/code/validate': 1,
    '/_auth/agent/authorize': 1,
    '/_auth/agent/validate': 1,
    '/_auth/tier/switch': 1,
    '/_auth/tier/current': 1,
    '/_auth/keys': 1,
    '/_auth/passkey/register-options': 1,
    '/_auth/passkey/register': 1,
    '/_auth/passkey/auth-options': 1,
    '/_auth/passkey/auth': 1,
    '/_auth/pop/bind': 1,
    '/_auth/bridge': 1,
    '/_auth/server/can-delete': 1,
    '/_auth/server/authorize-delete': 1,
    '/_auth/git/authorize-link': 1,
    '/_auth/git/verify-link-token': 1,
    '/_auth/git/authorize-unlink': 1,
    '/_auth/git/verify-unlink-token': 1,
  },
  features: [
    'passkey',
    'pop',
    'ssh-keys',
    'tier-switch',
    'terminal-tokens',
    'code-browser',
    'agent-bridge',
    'git-link-passkey',
  ] as const,
};

export type VpsCapabilities = {
  version: string;
  endpoints: Record<string, number>;
  features: string[];
};

/**
 * Human-readable descriptions for each capability feature.
 * Used by the dashboard to show users what they're missing on older VPS versions.
 */
export const FEATURE_DESCRIPTIONS: Record<(typeof CAPABILITIES.features)[number], string> = {
  'passkey': 'Passkey authentication (Face ID / Touch ID)',
  'pop': 'Proof-of-Presence device binding',
  'ssh-keys': 'SSH key management from dashboard',
  'tier-switch': 'Security tier switching (Standard / SSH-Only / Web-Locked)',
  'terminal-tokens': 'Secure terminal session tokens',
  'code-browser': 'In-browser code editor',
  'agent-bridge': 'AI agent bridge for tool access',
  'git-link-passkey': 'Passkey confirmation for git repo linking (Web Locked)',
};

// ---------------------------------------------------------------------------
// 2. VERSION — semver manifest for heartbeat / update system
//
// The daemon reports these to the platform API. The platform uses them to
// show "update available" and to reject incompatible servers.
// ---------------------------------------------------------------------------

export const VERSION: VersionManifest = {
  release: "1.0.0",

  components: {
    api: "1.0.0",
    frontend: "1.0.0",
    payload: "1.0.0",
    daemon: "1.0.0",
    sovereignShield: "1.0.0",
    fileApi: "1.0.0",
    agentBridge: "1.0.0",
    termProxy: "1.0.0",
  },

  minCompatible: {
    payload: "1.0.0",
    daemon: "1.0.0",
    sovereignShield: "1.0.0",
  },
};

/**
 * Check if a version is compatible with the current platform.
 */
export function isVersionCompatible(
  component: keyof VersionManifest["minCompatible"],
  version: string | null | undefined
): boolean {
  if (!version) return false;

  const minVersion = VERSION.minCompatible[component];
  return compareVersions(version, minVersion) >= 0;
}

/**
 * Check if a component needs an update.
 */
export function needsUpdate(
  component: keyof ComponentVersions,
  currentVersion: string | null | undefined
): boolean {
  if (!currentVersion) return true;

  const latestVersion = VERSION.components[component];
  return compareVersions(currentVersion, latestVersion) < 0;
}

/**
 * Compare two semver versions.
 * Returns: -1 if a < b, 0 if a == b, 1 if a > b
 */
export function compareVersions(a: string, b: string): number {
  const partsA = a.split(".").map((n) => parseInt(n, 10) || 0);
  const partsB = b.split(".").map((n) => parseInt(n, 10) || 0);

  for (let i = 0; i < 3; i++) {
    const numA = partsA[i] || 0;
    const numB = partsB[i] || 0;

    if (numA < numB) return -1;
    if (numA > numB) return 1;
  }

  return 0;
}

/**
 * Get update status for a server based on reported versions.
 */
export function getUpdateStatus(reportedVersions: {
  daemonVersion?: string | null;
  shieldVersion?: string | null;
  fileApiVersion?: string | null;
}): "current" | "update_available" | "incompatible" {
  const { daemonVersion, shieldVersion } = reportedVersions;

  // If no versions reported, assume current (daemon doesn't support version reporting yet)
  if (!daemonVersion && !shieldVersion) {
    return "current";
  }

  // Check for incompatible versions
  if (daemonVersion && !isVersionCompatible("daemon", daemonVersion)) {
    return "incompatible";
  }
  if (shieldVersion && !isVersionCompatible("sovereignShield", shieldVersion)) {
    return "incompatible";
  }

  // Check if any component needs update (only if version was reported)
  if (daemonVersion && needsUpdate("daemon", daemonVersion)) {
    return "update_available";
  }
  if (shieldVersion && needsUpdate("sovereignShield", shieldVersion)) {
    return "update_available";
  }

  return "current";
}
