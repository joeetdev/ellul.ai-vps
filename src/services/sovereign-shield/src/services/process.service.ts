/**
 * Process Service
 *
 * Kill processes on development ports. Ported from enforcer
 * kill_dev_ports() in enforcement.sh.
 *
 * Called via bridge endpoint (passkey-authenticated).
 */

import { execSync } from 'child_process';
import { RESERVED_PORTS } from '../../../shared/constants';

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

    if (RESERVED_PORTS.has(port)) {
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
