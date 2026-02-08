/**
 * Processes Service
 *
 * Process management for dev servers.
 */

import { execSync } from 'child_process';

// System ports that should NEVER be killed
const SYSTEM_PORTS = [22, 80, 443, 3002, 7681, 7682, 7683, 7684, 7685, 7686, 7687, 7688, 7689, 7690];

/**
 * Kill result for a single port.
 */
export interface KillResult {
  port: number;
  status: 'killed' | 'failed';
  error?: string;
}

/**
 * Kill processes on specified ports.
 */
export function killProcessesOnPorts(ports: number[]): {
  success: boolean;
  results: KillResult[];
  error?: string;
} {
  // Filter out system ports
  const safePorts = ports.filter((p) => {
    const port = parseInt(String(p), 10);
    return !isNaN(port) && port > 0 && port < 65536 && !SYSTEM_PORTS.includes(port);
  });

  if (safePorts.length === 0) {
    return { success: false, results: [], error: 'No valid user ports to kill' };
  }

  const results: KillResult[] = [];
  for (const port of safePorts) {
    try {
      execSync(`fuser -k -n tcp ${port} 2>/dev/null || true`, { timeout: 5000 });
      results.push({ port, status: 'killed' });
    } catch (e) {
      const error = e as Error;
      results.push({ port, status: 'failed', error: error.message });
    }
  }

  console.log(`[kill-ports] Killed processes on ports: ${safePorts.join(', ')}`);
  return { success: true, results };
}

/**
 * Restart essential services.
 */
export function restartServices(tier: string): {
  success: boolean;
  agentBridge: boolean;
  ttyd: boolean;
  tier: string;
} {
  const results = { agentBridge: false, ttyd: false, tier, success: true };

  try {
    if (tier !== 'ssh_only') {
      execSync(
        'sudo systemctl restart phonestack-agent-bridge 2>/dev/null || sudo systemctl start phonestack-agent-bridge',
        { stdio: 'ignore' }
      );
      results.agentBridge = true;
    }
    if (tier === 'standard' || tier === 'web_locked') {
      // Dynamic terminal sessions are handled by term-proxy (not static ttyd services)
      execSync('sudo systemctl restart phonestack-term-proxy 2>/dev/null || sudo systemctl start phonestack-term-proxy', {
        stdio: 'ignore',
      });
      results.ttyd = true; // Renamed for backwards compatibility, actually refers to term-proxy now
    }
  } catch {
    results.success = false;
  }

  return results;
}
