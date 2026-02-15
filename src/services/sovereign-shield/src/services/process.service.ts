/**
 * Process Service
 *
 * Kill processes on development ports. Ported from enforcer
 * kill_dev_ports() in enforcement.sh.
 *
 * Called via bridge endpoint (passkey-authenticated).
 */

import { execSync } from 'child_process';

/** System ports that must never be killed */
const SYSTEM_PORTS = new Set([
  22,    // SSH
  80,    // HTTP
  443,   // HTTPS
  3002,  // file-api
  3005,  // sovereign-shield
  3006,  // daemon (Caddy → file-api)
  7681, 7682, 7683, 7684, 7685, 7686, 7687, 7688, 7689, 7690, // ttyd range
  7700,  // agent-bridge
]);

/** Default dev ports to kill (mirrors operations.routes.ts DEV_PORTS) */
export const DEV_PORTS = [3000, 3001, 4000, 5000, 5173, 8000, 8080, 8888, 9000];

/**
 * Kill processes listening on the given ports.
 * Refuses to kill system ports. Returns count of killed + skipped.
 */
export function killPorts(ports: number[]): { killed: number; skipped: number[] } {
  const skipped: number[] = [];
  let killed = 0;

  for (const port of ports) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) continue;

    if (SYSTEM_PORTS.has(port)) {
      skipped.push(port);
      continue;
    }

    try {
      execSync(`fuser -k -n tcp ${port} 2>/dev/null`, { timeout: 5_000 });
      killed++;
    } catch {
      // No process on port or already dead — not an error
    }
  }

  return { killed, skipped };
}
