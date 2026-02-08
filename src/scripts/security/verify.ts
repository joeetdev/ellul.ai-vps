/**
 * Verification script - outputs server security status.
 */
export function getVerifyScript(): string {
  return `#!/bin/bash
JSON_OUTPUT=false
[ "$1" = "--json" ] && JSON_OUTPUT=true

CLOUD_INIT_FILE="/var/lib/cloud/instance/user-data.txt"
if [ -f "$CLOUD_INIT_FILE" ]; then
  CLOUD_INIT_HASH=$(sha256sum "$CLOUD_INIT_FILE" | awk '{print $1}')
else
  CLOUD_INIT_HASH="NOT_FOUND"
fi

ROOT_SECURE=true
[ -s /root/.ssh/authorized_keys ] && ROOT_SECURE=false

TTYD_STATUS=$(systemctl is-active ttyd@main 2>/dev/null || echo "inactive")
CADDY_STATUS=$(systemctl is-active caddy 2>/dev/null || echo "inactive")
ENFORCER_STATUS=$(systemctl is-active phonestack-enforcer 2>/dev/null || echo "inactive")

if [ "$JSON_OUTPUT" = true ]; then
  echo "{\\"cloudInitHash\\": \\"$CLOUD_INIT_HASH\\", \\"rootSecure\\": $ROOT_SECURE, \\"services\\": {\\"ttyd\\": \\"$TTYD_STATUS\\", \\"caddy\\": \\"$CADDY_STATUS\\", \\"enforcer\\": \\"$ENFORCER_STATUS\\"}}"
else
  echo "Hash: $CLOUD_INIT_HASH"
  echo "Root: $ROOT_SECURE | ttyd=$TTYD_STATUS caddy=$CADDY_STATUS"
fi`;
}
