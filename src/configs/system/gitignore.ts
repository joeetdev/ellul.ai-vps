/**
 * Global gitignore configuration for Phone Stack servers.
 * Prevents accidental commits of secrets and common generated files.
 */
export function getGlobalGitignore(): string {
  return `# === SECRETS (NEVER COMMIT) ===
.env
.env.*
!.env.example
*.pem
*.key
*.p12
*.pfx
id_rsa
id_rsa.pub
id_ed25519
id_ed25519.pub
credentials.json
service-account*.json

# === DEPENDENCIES ===
node_modules/
.pnpm-store/
vendor/
__pycache__/
*.pyc
.venv/
venv/

# === BUILD OUTPUTS ===
.next/
dist/
build/
out/
.turbo/
.vercel/
.netlify/

# === LOGS & TEMP ===
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*
.npm/
*.tmp
*.temp

# === OS & IDE ===
.DS_Store
Thumbs.db
.vscode/
.idea/
*.swp
*.swo
*~`;
}
