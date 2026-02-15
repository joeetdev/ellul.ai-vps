/**
 * ellulai-settings - Settings are managed via the dashboard
 *
 * Terminal and SSH settings require passkey authentication (physical device).
 * This prevents AI agents from changing settings programmatically.
 */

export function getSettingsScript(): string {
  return `#!/bin/bash
echo ""
echo "Settings are managed via the dashboard."
echo "Terminal and SSH access require passkey authentication."
echo ""
echo "To change settings, use the Security panel in your dashboard."
echo ""
`;
}
