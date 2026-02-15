/**
 * Infrastructure Confirmation Token Service
 *
 * Passkey-gated one-time tokens for dangerous daemon operations.
 * The platform API must obtain a confirmation token via the bridge
 * (which requires a passkey session) before calling dangerous
 * daemon endpoints like /api/migrate/pull or /api/migrate/pack.
 *
 * Flow:
 * 1. Dashboard calls bridge: confirm_infra { operation: 'migrate' }
 * 2. Bridge (passkey-authenticated) calls /_auth/bridge/confirm-infra
 * 3. Returns { token, expiresAt } to dashboard
 * 4. Dashboard sends token to platform API
 * 5. Platform API includes token in X-Infra-Confirm header when calling daemon
 * 6. file-api validates token via /_internal/validate-infra-token (localhost-only)
 */

import crypto from 'crypto';

interface PendingConfirmation {
  operation: string;
  token: string;
  expiresAt: number;
  used: boolean;
}

const pendingConfirmations = new Map<string, PendingConfirmation>();

// Clean expired tokens periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, conf] of pendingConfirmations) {
    if (conf.expiresAt < now || conf.used) pendingConfirmations.delete(key);
  }
}, 60_000);

export function createConfirmation(operation: string): { token: string; expiresAt: string } {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
  pendingConfirmations.set(token, { operation, token, expiresAt, used: false });
  return { token, expiresAt: new Date(expiresAt).toISOString() };
}

export function validateConfirmation(token: string, operation: string): boolean {
  const conf = pendingConfirmations.get(token);
  if (!conf) return false;
  if (conf.used) return false;
  if (conf.expiresAt < Date.now()) { pendingConfirmations.delete(token); return false; }
  if (conf.operation !== operation) return false;
  conf.used = true; // Single-use
  return true;
}
