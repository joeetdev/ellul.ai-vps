/**
 * Progress reporter script - reports provisioning progress to the API.
 *
 * @param apiUrl - The ellul.ai API URL
 * @param aiProxyToken - The server's AI proxy token
 */
export function getReportProgressScript(
  apiUrl: string,
  aiProxyToken: string
): string {
  return `#!/bin/bash
STEP="$1"
curl -sS -X POST "${apiUrl}/api/servers/provision-progress" \\
  -H "Content-Type: application/json" \\
  -d '{"token": "${aiProxyToken}", "step": "'"$STEP"'"}' \\
  >> /var/log/ellulai-provision.log 2>&1 || true`;
}
