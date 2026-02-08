/**
 * Pre-commit hook that blocks commits containing secrets or sensitive files.
 * Installed globally via git config core.hooksPath.
 */
export function getPreCommitHook(): string {
  return `#!/bin/bash
RED='\\033[31m'
YELLOW='\\033[33m'
GREEN='\\033[32m'
NC='\\033[0m'

error() { echo -e "\${RED}BLOCKED:\${NC} $1" >&2; }
BLOCKED=0

ENV_FILES=$(git diff --cached --name-only | grep -E '^\\.env' || true)
if [ -n "$ENV_FILES" ]; then
  error "Attempting to commit environment files!"
  echo "$ENV_FILES" | while read f; do echo "  * $f"; done
  echo "$ENV_FILES" | xargs git reset HEAD -- 2>/dev/null || true
  BLOCKED=1
fi

KEY_FILES=$(git diff --cached --name-only | grep -E '\\.(pem|key|p12|pfx)$|id_rsa|id_ed25519' || true)
if [ -n "$KEY_FILES" ]; then
  error "Private key files!"
  echo "$KEY_FILES" | while read f; do echo "  * $f"; done
  echo "$KEY_FILES" | xargs git reset HEAD -- 2>/dev/null || true
  BLOCKED=1
fi

KEY_PATTERNS='(sk-proj-[a-zA-Z0-9]{20,}|sk-ant-[a-zA-Z0-9]{20,}|sk-[a-zA-Z0-9]{40,}|ghp_[a-zA-Z0-9]{36,}|gho_[a-zA-Z0-9]{36,}|xoxb-[a-zA-Z0-9-]+|xoxp-[a-zA-Z0-9-]+|AKIA[A-Z0-9]{16}|sk_live_[a-zA-Z0-9]{24,}|rk_live_[a-zA-Z0-9]{24,})'
SECRETS_FOUND=$(git diff --cached | grep -oE "$KEY_PATTERNS" | head -5 || true)
if [ -n "$SECRETS_FOUND" ]; then
  error "API keys detected!"
  echo "$SECRETS_FOUND" | while read s; do
    REDACTED=$(echo "$s" | sed 's/\\(.\\{8\\}\\).*\\(.\\{4\\}\\)$/\\1...\\2/')
    echo "  * $REDACTED"
  done
  BLOCKED=1
fi

if [ $BLOCKED -eq 1 ]; then
  echo -e "\${RED}COMMIT BLOCKED - Security violation\${NC}"
  exit 1
fi

echo -e "\${GREEN}*\${NC} Security scan passed"
exit 0`;
}
