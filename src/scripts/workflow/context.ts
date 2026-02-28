/**
 * Context manager script - generates AI context for Claude/Codex/Gemini/OpenCode.
 */
export function getContextScript(): string {
  return `#!/bin/bash
# Detect tier and set paths accordingly
TIER=$(cat /etc/ellulai/billing-tier 2>/dev/null || echo "paid")
if [ "$TIER" = "free" ]; then
  HOME_DIR="/home/coder"
  USER_NAME="coder"
else
  HOME_DIR="/home/dev"
  USER_NAME="dev"
fi

TARGET_DIR="\${1:-$HOME_DIR/projects/welcome}"
TARGET_DIR="\${TARGET_DIR%/}"
CONTEXT_DIR="$HOME_DIR/.ellulai/context"
GLOBAL_FILE="$CONTEXT_DIR/global.md"
CURRENT_FILE="$CONTEXT_DIR/current.md"

mkdir -p "$CONTEXT_DIR"

generate_global() {
  DOMAIN=$(cat /etc/ellulai/domain 2>/dev/null || echo "YOUR-DOMAIN")
  SHORT_ID=$(echo "$DOMAIN" | grep -o '^[a-f0-9]\\{8\\}')
  DEV_DOMAIN=$(cat /etc/ellulai/dev-domain 2>/dev/null || echo "dev.$DOMAIN")

  if [ "$TIER" = "free" ]; then
    generate_global_free
    return
  fi

  # Build list of deployed apps
  APPS_DIR="$HOME_DIR/.ellulai/apps"
  DEPLOYED_LIST=""
  if [ -d "$APPS_DIR" ]; then
    for app_file in "$APPS_DIR"/*.json; do
      [ -f "$app_file" ] || continue
      APP_NAME=$(jq -r '.name // empty' "$app_file" 2>/dev/null)
      APP_URL=$(jq -r '.url // empty' "$app_file" 2>/dev/null)
      APP_PORT=$(jq -r '.port // empty' "$app_file" 2>/dev/null)
      if [ -n "$APP_NAME" ]; then
        DEPLOYED_LIST="$DEPLOYED_LIST
- $APP_NAME: $APP_URL (port $APP_PORT)"
      fi
    done
  fi

  cat <<GLOBAL_EOF > "$GLOBAL_FILE"
# ellul.ai Server ($DOMAIN)

## RULES (ALWAYS FOLLOW)
1. **WORKSPACE BOUNDARY**: All work MUST stay inside your assigned project directory. NEVER create new directories under ~/projects/. NEVER modify files outside your project.
2. **NAME PROTECTION**: The "name" field in ellulai.json and package.json is USER-DEFINED. NEVER change it.
3. **SECURITY**: NEVER touch /etc/ellulai/*, ~/.ssh/authorized_keys, /var/lib/sovereign-shield/*. Tampering = PERMANENT LOCKOUT.
4. **NO AUTO-DEPLOY**: NEVER run \\\`ellulai-expose\\\` unless the user explicitly asks to deploy/publish/go live. Code changes should only affect the dev preview. The user may be testing and does NOT want their live site updated.

## Preview vs Deployed (two separate things)
- **Preview** (port 3000) = live source code. Every code edit is reflected here immediately.
- **Deployed** (port 3001+) = frozen snapshot. A copy-in-time taken by \\\`ellulai-expose\\\`. Code edits do NOT change it.
Editing code ONLY updates the preview. The deployed site is a completely separate copy and is NEVER affected by code changes.
Do NOT deploy or redeploy unless the user explicitly asks — they may just be iterating on the preview.

### Currently deployed:
\${DEPLOYED_LIST:-"(none)"}

## Project Setup (within your assigned directory)
1. Create/edit project files
2. **REQUIRED**: Create \\\`ellulai.json\\\` in the project root (see Metadata below)
3. **MANDATORY FIRST**: ALWAYS run \\\`npm install --include=dev\\\` BEFORE any other step — even if you just created the project. Framework CLIs (create-next-app, create-vite, etc.) sometimes skip installing all deps.
   - If using Vite/React/Vue: verify the framework binary exists: \\\`npx vite --version\\\` or \\\`npx next --version\\\`. If it fails, run \\\`npm install --include=dev\\\` again.
   - For static HTML without a framework: use \\\`npx -y serve -l 3000\\\` (the \\\`-y\\\` flag auto-installs serve)
4. **REQUIRED**: Configure dev server (bind 0.0.0.0:3000)
5. **REQUIRED CSS RESET**: ALWAYS create a CSS file (index.css or globals.css) with: \\\`*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; } html, body, #root { width: 100%; height: 100%; }\\\` and import it in your entry point (main.jsx/main.tsx). NEVER put resets as inline styles on <body> — Vite strips them.
6. **REQUIRED**: ALWAYS \\\`pm2 delete preview 2>/dev/null\\\` before starting a new preview to avoid stale processes
7. **REQUIRED**: Start with pm2 (e.g., \\\`pm2 start npm --name preview -- run dev\\\` or \\\`pm2 start "npx serve -l 3000" --name preview\\\`)
8. **REQUIRED**: Wait for startup: \\\`sleep 3\\\`
9. **REQUIRED**: Run the FULL verification protocol below — do NOT skip any step

## Deployment (ONLY when user EXPLICITLY asks — never assume)
The preview (port 3000) = live source code. The deployed site (port 3001+) = frozen snapshot.
Code edits ONLY affect the preview. The deployed site is NEVER updated by code changes.
**Each deploy is a one-time action, NOT a standing mode.** If the user asked to deploy earlier in the conversation and then asks for a code change, do NOT redeploy — just update the source code and report the preview URL. A new deploy requires a new explicit request.
Only deploy/redeploy when the CURRENT message says "deploy", "redeploy", "go live", "publish", "ship it", or similar.
"Make a change", "update the code", "fix this", "change X to Y" = NOT a deploy request. Only update source and report the preview URL.

### New deployment:
1. Build: \\\`npm run build\\\` (if applicable — skip for static HTML)
2. \\\`ellulai-expose APP_NAME 3001\\\` — snapshots source, starts PM2, configures Caddy
3. Verify: \\\`ellulai-apps\\\`

### Redeploy (update existing deployment):
1. Read \\\`ellulai.json\\\` in the project root for the existing app name and port
2. Build: \\\`npm run build\\\` (if applicable — skip for static HTML)
3. \\\`ellulai-expose NAME PORT\\\` — using the SAME name and port from ellulai.json
4. Verify: \\\`curl -s https://DEPLOYED_URL | head -5\\\`
The command handles everything: fresh snapshot, PM2 restart, Caddy reload. Do NOT manually restart PM2 or copy files.

## Metadata (CRITICAL - dashboard won't detect app without this)
ALWAYS create a \\\`ellulai.json\\\` file in the project root:
\\\`{ "type": "frontend", "previewable": true, "name": "My App", "summary": "..." }\\\`
- type: "frontend" | "backend" | "library"
- previewable: true if it has a web UI, false otherwise
- name: display name for the dashboard (USER-DEFINED - NEVER overwrite if already set)
- summary: brief description of the app
**IMPORTANT: The "name" field is set by the user. NEVER change it if it already exists in ellulai.json.**
After deployment, \\\`ellulai-expose\\\` adds: deployedUrl, deployedDomain, deployedPort (these are frozen snapshots — code edits do NOT change the deployed site)

## Backend Apps — OpenAPI Spec (REQUIRED)
When creating or setting up a backend/API app, you MUST add an OpenAPI spec endpoint so the dashboard can render interactive API documentation in the Preview tab. Without this, the preview shows a blank fallback.

**For Express:**
\\\`\\\`\\\`js
// Add to your main file — serves spec at GET /openapi.json
const openapiSpec = {
  openapi: "3.0.0",
  info: { title: "My API", version: "1.0.0", description: "..." },
  paths: {
    // Define all your routes here with parameters, request bodies, and responses
    // Use $ref to components/schemas for reusable models
  },
  components: { schemas: { /* your models */ } }
};
app.get("/openapi.json", (req, res) => res.json(openapiSpec));
\\\`\\\`\\\`

**For other frameworks:**
- Fastify: \\\`@fastify/swagger\\\` → serves at \\\`/documentation/json\\\`
- NestJS: \\\`@nestjs/swagger\\\` → serves at \\\`/api-json\\\`
- Hono: \\\`@hono/zod-openapi\\\` → serves at \\\`/doc\\\`
- FastAPI: built-in at \\\`/openapi.json\\\`
- Flask: \\\`flask-smorest\\\` → serves at \\\`/api/openapi.json\\\`

The spec MUST include: all endpoints with methods, path/query parameters, request body schemas with property types and descriptions, response schemas for each status code, and reusable model definitions in components/schemas. Do NOT create a minimal/empty spec — include full details for every endpoint so the dashboard renders complete documentation.

## Framework Setup Checklist (CRITICAL — preview won't work without this)
The preview system auto-detects your framework from package.json. Follow the checklist for your framework:

**Vite + React/Vue/Svelte:**
- \\\`index.html\\\` at project root with \\\`<script type="module" src="/src/main.tsx">\\\` (or .jsx/.vue)
- \\\`src/main.tsx\\\` (or .jsx) entry point that renders to \\\`#root\\\`
- \\\`vite.config.ts\\\` with: \\\`server: { host: true, port: 3000, allowedHosts: true }\\\` and framework plugin
- Install plugin: \\\`npm install -D @vitejs/plugin-react\\\` (or vue/svelte equivalent)

**Next.js (App Router):**
- \\\`app/layout.tsx\\\` and \\\`app/page.tsx\\\` (REQUIRED — Next.js won't serve anything without these)
- \\\`tsconfig.json\\\` (REQUIRED for TypeScript — Next.js auto-creates it, but verify it exists)
- \\\`next.config.mjs\\\` (recommended)
- Dev script: \\\`"dev": "next dev -H 0.0.0.0 -p 3000"\\\`

**Next.js (Pages Router):**
- \\\`pages/index.tsx\\\` (or .jsx/.js) as the home route
- \\\`tsconfig.json\\\` for TypeScript
- Dev script: \\\`"dev": "next dev -H 0.0.0.0 -p 3000"\\\`

**Astro:**
- \\\`src/pages/index.astro\\\` (REQUIRED — at least one page)
- \\\`astro.config.mjs\\\` with \\\`server: { host: '0.0.0.0', port: 3000 }\\\`

**Nuxt:**
- \\\`app.vue\\\` OR \\\`pages/index.vue\\\` (at least one)
- \\\`nuxt.config.ts\\\` with \\\`devServer: { host: '0.0.0.0', port: 3000 }\\\`

**CRA (Create React App):**
- \\\`public/index.html\\\` and \\\`src/index.tsx\\\` (or .jsx)
- Dev server uses PORT env var automatically

**Remix:**
- \\\`app/root.tsx\\\` and route files in \\\`app/routes/\\\`
- Vite config with Remix plugin

**General rule:** bind to 0.0.0.0:3000. Preview URL: https://$DEV_DOMAIN

## MANDATORY: Pre-Completion Verification Protocol
You MUST complete ALL of these checks before reporting ANY task as done.
Skipping verification = broken app for the user.

STEP 1 — Dependency check:
  \\\`ls node_modules/.bin/ | head -5\\\` → must show binaries (vite, next, etc.)
  If empty or node_modules missing: \\\`npm install --include=dev\\\` and retry

STEP 2 — Process check:
  \\\`pm2 list\\\` → your app must show status "online"
  If "errored" or "stopped": \\\`pm2 logs preview --nostream --lines 20\\\` → fix the error → restart

STEP 3 — HTTP check (with retry):
  \\\`for i in 1 2 3 4 5; do STATUS=\\\$(curl -s -o /dev/null -w '%{http_code}' localhost:3000); [ "\\\$STATUS" = "200" ] && break; sleep 2; done\\\`
  If still not 200 after 5 attempts: \\\`pm2 logs preview --nostream --lines 30\\\` → diagnose → fix → restart

STEP 4 — Content check:
  \\\`curl -s -o /dev/null -w '%{http_code}' localhost:3000\\\` → must return 200
  If 404: route files are missing (Next.js needs app/page.tsx, Astro needs src/pages/index.astro, etc.)
  If 500: check \\\`pm2 logs preview --nostream --lines 30\\\` for compilation errors
  \\\`curl -s localhost:3000 | head -5\\\` → must contain actual HTML (<!DOCTYPE or <html>), NOT an error page

STEP 5 — Report to user:
  Get a one-time preview link: \\\`curl -s http://localhost:3005/api/preview-url | jq -r '.url'\\\`
  Give the user this tokenized URL — it works for 60 seconds without authentication.
  Only mention a deployed/production URL when the user explicitly deploys with ellulai-expose.

ALL 5 steps must pass. Do NOT tell the user "it's live" until they do.

## Ports
- Dev/Preview: 3000 (→ https://$DEV_DOMAIN)
- Production: 3001+ (→ https://<app-name>-$SHORT_ID.ellul.app)
- Reserved: 7681-7700

## Secrets
NEVER create .env files (git hook blocks). Secrets are managed in Dashboard → sync to ~/.ellulai-env → access via process.env.

## Uploads
Images → public/ | Data → data/ | Dashboard icon → .ellulai/icon.png (copy, don't move)

## Git (Code Backup)
Git is managed from the ellul.ai dashboard in two steps:
1. Connect a provider (GitHub/GitLab/Bitbucket) — user links their account via OAuth
2. Link a repo to this server — this delivers encrypted credentials to the VPS automatically
To check if git is ready: test if a remote exists with \\\`git remote -v\\\`. If no remote is configured, tell the user to link a repo from the Dashboard → Git tab.
Once a repo is linked, credentials are pre-configured. Use these commands:
- git-flow backup: commit all changes + push to remote (fails safely if remote diverged)
- git-flow force-backup: commit + force push with lease (VPS is source of truth)
- git-flow pull: pull latest from remote with rebase
- git-flow save: stage, commit with timestamp, push
- git-flow ship: merge to main, build, deploy to production via PM2
- git-flow branch: create and push a feature branch
Standard git commands also work (git add, git commit, git push, etc.) — credentials are handled automatically.
NEVER configure git credentials manually (no git config, no SSH keys, no tokens). The dashboard handles everything.

## Commands
- ellulai-expose NAME PORT: deploy + expose with SSL (creates DNS + SSL automatically)
- ellulai-apps: list deployed apps
- ellulai-install postgres|redis|mysql: install DB
- pm2 logs|restart|delete NAME: manage processes

## CRITICAL SECURITY - DO NOT MODIFY
The following files and directories are security-critical. Modifying, deleting, or tampering with them can permanently brick the server or create security vulnerabilities:

**NEVER modify these files:**
- /etc/ellulai/shield-data/.web_locked_activated - Security tier marker (tampering = permanent lockout or security breach)
- /etc/ellulai/security-tier - Security tier state
- /etc/ellulai/shield-data/.terminal-disabled - Terminal access control
- /etc/ellulai/domain - Server domain configuration
- /etc/ellulai/server_id - Server identity
- \${HOME_DIR}/.ssh/authorized_keys - SSH authentication (tampering = permanent lockout)
- /var/lib/sovereign-shield/ - Authentication database and state

**NEVER run commands that:**
- Delete or modify files in /etc/ellulai/
- Change SSH authorized_keys without explicit user request
- Stop or disable sovereign-shield, sshd, or core services
- Modify systemd service files for security services

**Why this matters:**
If the server is in "Web Locked" mode (passkey + PoP required), tampering with security files can permanently lock out the user with NO recovery path except server rebuild. The security system is designed to fail-secure - if in doubt, it denies access.
GLOBAL_EOF

  # Detect Vercel integration
  if [ -f "$HOME_DIR/.ellulai/vercel-linked" ]; then
    cat <<'VERCEL_EOF' >> "$GLOBAL_FILE"

## Deployment (Vercel)
This project deploys to Vercel. Push to git → auto-deploy.
Or deploy from the ellul.ai dashboard.
For Next.js: do NOT set output: 'standalone' (Vercel handles builds).
Environment variables: set via ellul.ai dashboard integrations.
VERCEL_EOF
  fi

  # Detect DATABASE_URL (Supabase or any PostgreSQL)
  if grep -q "DATABASE_URL" "$HOME_DIR/.ellulai-env" 2>/dev/null; then
    cat <<'DB_EOF' >> "$GLOBAL_FILE"

## Database (PostgreSQL via Supabase)
DATABASE_URL is configured in the environment. Use Drizzle ORM with postgres adapter:
- \\\`import { drizzle } from 'drizzle-orm/postgres-js'\\\`
- \\\`import postgres from 'postgres'\\\`
- \\\`const client = postgres(process.env.DATABASE_URL!)\\\`
- \\\`const db = drizzle(client)\\\`
Schema: \\\`src/db/schema.ts\\\` | Config: \\\`drizzle.config.ts\\\`
Push: \\\`npx drizzle-kit push\\\`
DB_EOF
  fi
}

generate_global_free() {
  cat <<GLOBAL_FREE_EOF > "$GLOBAL_FILE"
# ellul.ai Free Tier ($DOMAIN)

## RULES (ALWAYS FOLLOW)
1. **WORKSPACE BOUNDARY**: All work MUST stay inside your assigned project directory. NEVER create new directories under ~/projects/. NEVER modify files outside your project.
2. **NAME PROTECTION**: The "name" field in ellulai.json and package.json is USER-DEFINED. NEVER change it.
3. **SECURITY**: NEVER touch /etc/ellulai/*, /etc/warden/*, /var/lib/sovereign-shield/*. Tampering = PERMANENT LOCKOUT.

## Project Setup (within your assigned directory)
1. Create/edit project files
2. **REQUIRED**: Create \\\`ellulai.json\\\` in the project root (see Metadata below)
3. **MANDATORY FIRST**: ALWAYS run \\\`npm install --include=dev\\\` BEFORE any other step — even if you just created the project. Framework CLIs (create-next-app, create-vite, etc.) sometimes skip installing all deps.
   - If using Vite/React/Vue: verify the framework binary exists: \\\`npx vite --version\\\` or \\\`npx next --version\\\`. If it fails, run \\\`npm install --include=dev\\\` again.
   - For static HTML without a framework: use \\\`npx -y serve -l 3000\\\` (the \\\`-y\\\` flag auto-installs serve)
4. **REQUIRED**: Configure dev server (bind 0.0.0.0:3000)
5. **REQUIRED CSS RESET**: ALWAYS create a CSS file (index.css or globals.css) with: \\\`*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; } html, body, #root { width: 100%; height: 100%; }\\\` and import it in your entry point (main.jsx/main.tsx). NEVER put resets as inline styles on <body> — Vite strips them.
6. **REQUIRED**: ALWAYS \\\`pm2 delete preview 2>/dev/null\\\` before starting a new preview to avoid stale processes
7. **REQUIRED**: Start with pm2 (e.g., \\\`pm2 start npm --name preview -- run dev\\\` or \\\`pm2 start "npx serve -l 3000" --name preview\\\`)
8. **REQUIRED**: Wait for startup: \\\`sleep 3\\\`
9. **REQUIRED**: Run the FULL verification protocol below — do NOT skip any step

## Metadata (CRITICAL - dashboard won't detect app without this)
ALWAYS create a \\\`ellulai.json\\\` file in the project root:
\\\`{ "type": "frontend", "previewable": true, "name": "My App", "summary": "..." }\\\`
- type: "frontend" | "backend" | "library"
- previewable: true if it has a web UI, false otherwise
- name: display name for the dashboard (USER-DEFINED - NEVER overwrite if already set)
- summary: brief description of the app
**IMPORTANT: The "name" field is set by the user. NEVER change it if it already exists in ellulai.json.**

## Backend Apps — OpenAPI Spec (REQUIRED)
When creating a backend/API app, ALWAYS add an OpenAPI spec endpoint (e.g. \\\`GET /openapi.json\\\`) so the dashboard renders interactive API docs in the Preview tab. Include all endpoints with parameters, request bodies, response schemas, and model definitions. See the global context for framework-specific examples.

## Framework Setup Checklist (CRITICAL — preview won't work without this)
The preview system auto-detects your framework from package.json. Follow the checklist for your framework:

**Vite + React/Vue/Svelte:**
- \\\`index.html\\\` at project root with \\\`<script type="module" src="/src/main.tsx">\\\` (or .jsx/.vue)
- \\\`src/main.tsx\\\` (or .jsx) entry point that renders to \\\`#root\\\`
- \\\`vite.config.ts\\\` with: \\\`server: { host: true, port: 3000, allowedHosts: true }\\\` and framework plugin
- Install plugin: \\\`npm install -D @vitejs/plugin-react\\\` (or vue/svelte equivalent)

**Next.js (App Router):**
- \\\`app/layout.tsx\\\` and \\\`app/page.tsx\\\` (REQUIRED — Next.js won't serve anything without these)
- \\\`tsconfig.json\\\` (REQUIRED for TypeScript — Next.js auto-creates it, but verify it exists)
- \\\`next.config.mjs\\\` (recommended)
- Dev script: \\\`"dev": "next dev -H 0.0.0.0 -p 3000"\\\`

**Next.js (Pages Router):**
- \\\`pages/index.tsx\\\` (or .jsx/.js) as the home route
- \\\`tsconfig.json\\\` for TypeScript
- Dev script: \\\`"dev": "next dev -H 0.0.0.0 -p 3000"\\\`

**Astro:**
- \\\`src/pages/index.astro\\\` (REQUIRED — at least one page)
- \\\`astro.config.mjs\\\` with \\\`server: { host: '0.0.0.0', port: 3000 }\\\`

**Nuxt:**
- \\\`app.vue\\\` OR \\\`pages/index.vue\\\` (at least one)
- \\\`nuxt.config.ts\\\` with \\\`devServer: { host: '0.0.0.0', port: 3000 }\\\`

**CRA (Create React App):**
- \\\`public/index.html\\\` and \\\`src/index.tsx\\\` (or .jsx)
- Dev server uses PORT env var automatically

**Remix:**
- \\\`app/root.tsx\\\` and route files in \\\`app/routes/\\\`
- Vite config with Remix plugin

**General rule:** bind to 0.0.0.0:3000. Preview URL: https://$DEV_DOMAIN

## MANDATORY: Pre-Completion Verification Protocol
You MUST complete ALL of these checks before reporting ANY task as done.
Skipping verification = broken app for the user.

STEP 1 — Dependency check:
  \\\`ls node_modules/.bin/ | head -5\\\` → must show binaries (vite, next, etc.)
  If empty or node_modules missing: \\\`npm install --include=dev\\\` and retry

STEP 2 — Process check:
  \\\`pm2 list\\\` → your app must show status "online"
  If "errored" or "stopped": \\\`pm2 logs preview --nostream --lines 20\\\` → fix the error → restart

STEP 3 — HTTP check (with retry):
  \\\`for i in 1 2 3 4 5; do STATUS=\\\$(curl -s -o /dev/null -w '%{http_code}' localhost:3000); [ "\\\$STATUS" = "200" ] && break; sleep 2; done\\\`
  If still not 200 after 5 attempts: \\\`pm2 logs preview --nostream --lines 30\\\` → diagnose → fix → restart

STEP 4 — Content check:
  \\\`curl -s -o /dev/null -w '%{http_code}' localhost:3000\\\` → must return 200
  If 404: route files are missing (Next.js needs app/page.tsx, Astro needs src/pages/index.astro, etc.)
  If 500: check \\\`pm2 logs preview --nostream --lines 30\\\` for compilation errors
  \\\`curl -s localhost:3000 | head -5\\\` → must contain actual HTML (<!DOCTYPE or <html>), NOT an error page

STEP 5 — Report to user:
  Get a one-time preview link: \\\`curl -s http://localhost:3005/api/preview-url | jq -r '.url'\\\`
  Give the user this tokenized URL — it works for 60 seconds without authentication.
  Only mention a deployed/production URL when the user explicitly deploys with ellulai-expose.

ALL 5 steps must pass. Do NOT tell the user "it's live" until they do.

## Ports
- Dev/Preview: 3000 (→ https://$DEV_DOMAIN)
- Reserved: 7681-7700

## Secrets
NEVER create .env files (git hook blocks). Secrets are managed in Dashboard → sync to ~/.ellulai-env → access via process.env.

## Uploads
Images → public/ | Data → data/ | Dashboard icon → .ellulai/icon.png (copy, don't move)

## Git
Git clone and pull are available for importing code. Push is blocked on the free tier.
Standard local git commands work (add, commit, log, diff, branch, etc.).
NEVER configure git credentials manually (no SSH keys, no tokens).

## Free Tier Limitations
- No deployment — preview only
- Git: clone and pull only — outbound push is blocked
- No database installation
- No SSH access
- No custom domains

Upgrade to Sovereign for full features: https://coemad.com/pricing

## Commands
- pm2 start|logs|restart|delete NAME: manage processes

## CRITICAL SECURITY - DO NOT MODIFY
The following files and directories are security-critical. Modifying, deleting, or tampering with them can permanently brick the server or create security vulnerabilities:

**NEVER modify these files:**
- /etc/ellulai/* - Server configuration (tier, domain, server_id)
- /etc/warden/* - Network proxy rules
- /var/lib/sovereign-shield/ - Authentication database and state

**NEVER run commands that:**
- Delete or modify files in /etc/ellulai/ or /etc/warden/
- Stop or disable sovereign-shield, warden, or core services
- Modify systemd service files for security services
GLOBAL_FREE_EOF
}

generate_current() {
  cd "$TARGET_DIR" 2>/dev/null || {
    echo "Error: Directory not found: $TARGET_DIR" >&2
    exit 1
  }
  PROJECT_NAME=$(basename "$TARGET_DIR")
  PROJECT_TYPE="unknown"
  FRAMEWORK=""
  if [ -f "package.json" ]; then
    PROJECT_TYPE="node"
    grep -q '"next"' package.json 2>/dev/null && FRAMEWORK="next.js"
    grep -q '"react"' package.json 2>/dev/null && [ -z "$FRAMEWORK" ] && FRAMEWORK="react"
    grep -q '"express"' package.json 2>/dev/null && FRAMEWORK="express"
    grep -q '"hono"' package.json 2>/dev/null && FRAMEWORK="hono"
  elif [ -f "requirements.txt" ] || [ -f "pyproject.toml" ]; then
    PROJECT_TYPE="python"
    [ -f "manage.py" ] && FRAMEWORK="django"
    grep -q "fastapi" requirements.txt 2>/dev/null && FRAMEWORK="fastapi"
    grep -q "flask" requirements.txt 2>/dev/null && FRAMEWORK="flask"
  elif [ -f "go.mod" ]; then
    PROJECT_TYPE="go"
  elif [ -f "Cargo.toml" ]; then
    PROJECT_TYPE="rust"
  fi
  GIT_BRANCH=$(git branch --show-current 2>/dev/null || echo "none")
  GIT_CHANGES=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')
  FILE_TREE=""
  if command -v tree &>/dev/null; then
    FILE_TREE=$(tree -L 2 -I 'node_modules|.next|.git|dist|build|__pycache__|.venv' --noreport 2>/dev/null | head -40)
  else
    FILE_TREE=$(find . -maxdepth 2 -type f -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/.next/*' 2>/dev/null | head -30)
  fi
  NPM_SCRIPTS=""
  if [ -f "package.json" ] && command -v jq &>/dev/null; then
    NPM_SCRIPTS=$(jq -r '.scripts | to_entries | .[] | "- \\(.key): \\(.value)"' package.json 2>/dev/null | head -10)
  fi
  PM2_STATUS=""
  if command -v pm2 &>/dev/null; then
    PM2_STATUS=$(pm2 jlist 2>/dev/null | jq -r --arg name "$PROJECT_NAME" '.[] | select(.name | contains($name)) | "\\(.name): \\(.pm2_env.status)"' 2>/dev/null)
    [ -z "$PM2_STATUS" ] && PM2_STATUS="No PM2 process"
  fi
  cat <<CURRENT_EOF > "$CURRENT_FILE"
# PROJECT: $PROJECT_NAME

Type: $PROJECT_TYPE\${FRAMEWORK:+ ($FRAMEWORK)}
Branch: $GIT_BRANCH
Changes: $GIT_CHANGES files
PM2: $PM2_STATUS

## Structure
\\\`\\\`\\\`
$FILE_TREE
\\\`\\\`\\\`
CURRENT_EOF
  if [ -n "$NPM_SCRIPTS" ]; then
    cat <<SCRIPTS_EOF >> "$CURRENT_FILE"

## Scripts
$NPM_SCRIPTS
SCRIPTS_EOF
  fi
  if [ -f ".env" ]; then
    ENV_KEYS=$(grep -E '^[A-Z_]+=' .env 2>/dev/null | cut -d= -f1 | head -10 | tr '\\n' ', ' | sed 's/,$//')
    if [ -n "$ENV_KEYS" ]; then
      echo "" >> "$CURRENT_FILE"
      echo "## Env Vars (in .env)" >> "$CURRENT_FILE"
      echo "$ENV_KEYS" >> "$CURRENT_FILE"
    fi
  fi

  # Check for existing deployment
  DEPLOYMENT_INFO=$(get_current_deployment)
  if [ -n "$DEPLOYMENT_INFO" ]; then
    echo "" >> "$CURRENT_FILE"
    echo "$DEPLOYMENT_INFO" >> "$CURRENT_FILE"
  fi
}

get_current_deployment() {
  # Scan ~/.ellulai/apps/*.json for a match on projectPath
  # Free tier has no deployments, skip entirely
  [ "$TIER" = "free" ] && return 0

  APPS_DIR="$HOME_DIR/.ellulai/apps"
  CURRENT_PATH="$(pwd)"

  [ -d "$APPS_DIR" ] || return 0

  for app_file in "$APPS_DIR"/*.json; do
    [ -f "$app_file" ] || continue

    APP_PATH=$(jq -r '.projectPath // empty' "$app_file" 2>/dev/null)

    if [ "$APP_PATH" = "$CURRENT_PATH" ]; then
      APP_NAME=$(jq -r '.name // empty' "$app_file" 2>/dev/null)
      APP_URL=$(jq -r '.url // empty' "$app_file" 2>/dev/null)
      APP_PORT=$(jq -r '.port // empty' "$app_file" 2>/dev/null)
      APP_DOMAIN=$(jq -r '.domain // empty' "$app_file" 2>/dev/null)

      echo "## Deployed App (frozen snapshot — separate from preview)"
      echo "Name: $APP_NAME | Live: $APP_URL | Port: $APP_PORT"
      echo "The deployed site is a frozen snapshot taken by ellulai-expose. Code edits ONLY affect the preview (port 3000), NOT the deployed site."
      echo "Do NOT redeploy unless the user explicitly asks — they may just be testing changes in the preview."
      echo ""
      echo "### To redeploy (ONLY when user asks to deploy/redeploy/publish):"
      echo "\\\`cd $CURRENT_PATH && ellulai-expose $APP_NAME $APP_PORT\\\`"
      echo "Verify: \\\`curl -s https://$APP_DOMAIN | head -5\\\`"
      return 0
    fi
  done

  return 0
}

generate_context_files() {
  # Generate CLAUDE.md, AGENTS.md, and GEMINI.md in the project directory
  # Uses marker-based approach to preserve user content
  DOMAIN=$(cat /etc/ellulai/domain 2>/dev/null || echo "YOUR-DOMAIN")
  SHORT_ID=$(echo "$DOMAIN" | grep -o '^[a-f0-9]\\{8\\}')
  DIR_NAME=$(basename "$TARGET_DIR")
  DEV_DOMAIN=$(cat /etc/ellulai/dev-domain 2>/dev/null || echo "dev.$DOMAIN")

  # Read app name from ellulai.json if it exists
  APP_NAME=""
  if [ -f "$TARGET_DIR/ellulai.json" ]; then
    APP_NAME=$(jq -r '.name // empty' "$TARGET_DIR/ellulai.json" 2>/dev/null)
  fi
  APP_NAME_LINE=""
  if [ -n "$APP_NAME" ]; then
    APP_NAME_LINE="2. **NAME PROTECTION**: This app is named \\"$APP_NAME\\". The \\"name\\" field in ellulai.json is USER-DEFINED. NEVER change it. NEVER change the \\"name\\" field in package.json either."
  else
    APP_NAME_LINE="2. **NAME PROTECTION**: The \\"name\\" field in ellulai.json and package.json is USER-DEFINED. NEVER change it."
  fi

  if [ "$TIER" = "free" ]; then
    # Free tier: no deploy, no push, no databases, no ship, no git-flow
    GENERATED_BLOCK="<!-- ELLULAI:START — Auto-generated rules. Do not edit between these markers. -->
# ellul.ai Free Tier ($DOMAIN)
Preview: https://$DEV_DOMAIN (port 3000) — deployment not available on free tier.

## RULES (ALWAYS FOLLOW)
1. **WORKSPACE BOUNDARY**: All work MUST stay inside this directory ($TARGET_DIR). NEVER create new directories under ~/projects/. NEVER modify files in other projects.
$APP_NAME_LINE
3. **SECURITY**: NEVER touch /etc/ellulai/*, /etc/warden/*, /var/lib/sovereign-shield/*. Tampering = PERMANENT LOCKOUT with no recovery.
4. **PREFER ACTION**: When the choice is ambiguous (e.g. framework, language), prefer the most popular/common option (Node.js + Express for backends, React + Vite for frontends) and proceed. Only ask the user if the choice fundamentally changes the project direction.

## Setup (within THIS project)
1. Create/edit project files
2. If ellulai.json missing: create it with \\\`{ \\"type\\": \\"frontend\\", \\"previewable\\": true, \\"name\\": \\"My App\\", \\"summary\\": \\"...\\" }\\\`
   **The \\"name\\" field is USER-DEFINED. If ellulai.json already exists, NEVER change the \\"name\\" field — leave it as the user set it.**
3. **MANDATORY FIRST**: ALWAYS run \\\`npm install --include=dev\\\` BEFORE any other step — even if you just created the project. Framework CLIs sometimes skip installing all deps.
   - If using Vite/React/Vue: verify the binary exists: \\\`npx vite --version\\\` or \\\`npx next --version\\\`. If it fails, run \\\`npm install --include=dev\\\` again.
   - For static HTML without a framework: use \\\`npx -y serve -l 3000\\\` (the \\\`-y\\\` flag auto-installs serve)
4. ALWAYS \\\`pm2 delete preview 2>/dev/null\\\` before starting a new preview to avoid stale processes
5. PM2: \\\`pm2 start npm --name preview -- run dev\\\` or \\\`pm2 start \\"npx serve -l 3000\\" --name preview\\\`
6. Wait for startup: \\\`sleep 3\\\`
7. Run the FULL verification protocol below — do NOT skip any step

## Backend Apps — OpenAPI Spec (REQUIRED)
When creating a backend/API app, ALWAYS add an OpenAPI spec endpoint (e.g. \\\`GET /openapi.json\\\`) so the dashboard renders interactive API docs in the Preview tab. Include all endpoints with parameters, request bodies, response schemas, and model definitions. See the global context for framework-specific examples.

## Framework Setup Checklist (CRITICAL — preview won't work without this)
The preview system auto-detects your framework from package.json. Follow the checklist for your framework:

**Vite + React/Vue/Svelte:**
- \\\`index.html\\\` at project root with \\\`<script type=\\"module\\" src=\\"/src/main.tsx\\">\\\` (or .jsx/.vue)
- \\\`src/main.tsx\\\` (or .jsx) entry point that renders to \\\`#root\\\`
- \\\`vite.config.ts\\\` with: \\\`server: { host: true, port: 3000, allowedHosts: true }\\\` and framework plugin
- Install plugin: \\\`npm install -D @vitejs/plugin-react\\\` (or vue/svelte equivalent)

**Next.js (App Router):**
- \\\`app/layout.tsx\\\` and \\\`app/page.tsx\\\` (REQUIRED — Next.js won't serve anything without these)
- \\\`tsconfig.json\\\` (REQUIRED for TypeScript)
- Dev script: \\\`\\"dev\\": \\"next dev -H 0.0.0.0 -p 3000\\"\\\`

**Next.js (Pages Router):**
- \\\`pages/index.tsx\\\` (or .jsx/.js) as the home route
- Dev script: \\\`\\"dev\\": \\"next dev -H 0.0.0.0 -p 3000\\"\\\`

**Astro:**
- \\\`src/pages/index.astro\\\` (REQUIRED — at least one page)
- \\\`astro.config.mjs\\\` with \\\`server: { host: '0.0.0.0', port: 3000 }\\\`

**Nuxt:**
- \\\`app.vue\\\` OR \\\`pages/index.vue\\\` (at least one)
- \\\`nuxt.config.ts\\\` with \\\`devServer: { host: '0.0.0.0', port: 3000 }\\\`

**CRA:** \\\`public/index.html\\\` and \\\`src/index.tsx\\\` — PORT env var used automatically

**Remix:** \\\`app/root.tsx\\\` + route files in \\\`app/routes/\\\` + Vite config with Remix plugin

**General rule:** bind to 0.0.0.0:3000

## MANDATORY: Pre-Completion Verification Protocol
You MUST complete ALL of these checks before reporting ANY task as done.
Skipping verification = broken app for the user.

STEP 1 — Dependency check:
  \\\`ls node_modules/.bin/ | head -5\\\` → must show binaries (vite, next, etc.)
  If empty or node_modules missing: \\\`npm install --include=dev\\\` and retry

STEP 2 — Process check:
  \\\`pm2 list\\\` → your app must show status \\"online\\"
  If \\"errored\\" or \\"stopped\\": \\\`pm2 logs preview --nostream --lines 20\\\` → fix the error → restart

STEP 3 — HTTP check (with retry):
  \\\`for i in 1 2 3 4 5; do STATUS=\\$(curl -s -o /dev/null -w '%{http_code}' localhost:3000); [ \\"\\$STATUS\\" = \\"200\\" ] && break; sleep 2; done\\\`
  If still not 200 after 5 attempts: \\\`pm2 logs preview --nostream --lines 30\\\` → diagnose → fix → restart

STEP 4 — Content check:
  \\\`curl -s -o /dev/null -w '%{http_code}' localhost:3000\\\` → must return 200
  If 404: route files are missing (Next.js needs app/page.tsx, Astro needs src/pages/index.astro, etc.)
  If 500: check \\\`pm2 logs preview --nostream --lines 30\\\` for compilation errors
  \\\`curl -s localhost:3000 | head -5\\\` → must contain actual HTML (<!DOCTYPE or <html>), NOT an error page

STEP 5 — Report to user:
  Get a one-time preview link: \\\`curl -s http://localhost:3005/api/preview-url | jq -r '.url'\\\`
  Give the user this tokenized URL — it works for 60 seconds without authentication.
  Only mention a deployed/production URL when the user explicitly deploys with ellulai-expose.

ALL 5 steps must pass. Do NOT tell the user \\"it's live\\" until they do.

## Rules
- Secrets: NEVER .env files (git hook blocks commits with them). Use Dashboard → process.env
- Ports: Dev=3000, Reserved=7681-7700
- Git: clone and pull only — push is blocked on the free tier

## Free Tier Limitations
Deployment, outbound push, database installation, and SSH are not available.
Upgrade to Sovereign for full features: https://coemad.com/pricing

## Commands
pm2 start|logs|restart|delete NAME
<!-- ELLULAI:END -->"
  else
    # Check if this project is already deployed (paid tier only)
    APPS_DIR="$HOME_DIR/.ellulai/apps"
    DEPLOYMENT_SECTION=""
    if [ -d "$APPS_DIR" ]; then
      for app_file in "$APPS_DIR"/*.json; do
        [ -f "$app_file" ] || continue
        APP_PATH=$(jq -r '.projectPath // empty' "$app_file" 2>/dev/null)
        if [ "$APP_PATH" = "$TARGET_DIR" ]; then
          DEP_NAME=$(jq -r '.name // empty' "$app_file" 2>/dev/null)
          DEP_URL=$(jq -r '.url // empty' "$app_file" 2>/dev/null)
          DEP_PORT=$(jq -r '.port // empty' "$app_file" 2>/dev/null)
          DEPLOYMENT_SECTION="
## Deployed App (frozen snapshot — separate from preview)
Name: $DEP_NAME | Live: $DEP_URL | Port: $DEP_PORT
The deployed site is a frozen snapshot. Code edits ONLY affect the preview (port 3000), NOT the deployed site.
Do NOT redeploy unless the user explicitly asks — they may just be testing changes in the preview.

### To redeploy (ONLY when user asks to deploy/redeploy/publish):
\\\`cd $TARGET_DIR && ellulai-expose $DEP_NAME $DEP_PORT\\\`
Verify: \\\`curl -s $DEP_URL | head -5\\\`
"
          break
        fi
      done
    fi

    # Paid tier: full content
    GENERATED_BLOCK="<!-- ELLULAI:START — Auto-generated rules. Do not edit between these markers. -->
# ellul.ai ($DOMAIN)
Preview: https://$DEV_DOMAIN (port 3000) | Production: https://$DIR_NAME-$SHORT_ID.ellul.app

## RULES (ALWAYS FOLLOW)
1. **WORKSPACE BOUNDARY**: All work MUST stay inside this directory ($TARGET_DIR). NEVER create new directories under ~/projects/. NEVER modify files in other projects.
$APP_NAME_LINE
3. **SECURITY**: NEVER touch /etc/ellulai/*, ~/.ssh/authorized_keys, /var/lib/sovereign-shield/*, sovereign-shield/sshd services. Tampering = PERMANENT LOCKOUT with no recovery.
4. **NO AUTO-DEPLOY**: Only run \\\`ellulai-expose\\\` when the user explicitly asks to deploy/redeploy/publish. Code changes only affect the dev preview.
5. **PREFER ACTION**: When the choice is ambiguous (e.g. framework, language), prefer the most popular/common option (Node.js + Express for backends, React + Vite for frontends) and proceed. Only ask the user if the choice fundamentally changes the project direction.
$DEPLOYMENT_SECTION
## Setup (within THIS project)
1. Create/edit project files
2. If ellulai.json missing: create it with \\\`{ \\"type\\": \\"frontend\\", \\"previewable\\": true, \\"name\\": \\"My App\\", \\"summary\\": \\"...\\" }\\\`
   **The \\"name\\" field is USER-DEFINED. If ellulai.json already exists, NEVER change the \\"name\\" field — leave it as the user set it.**
3. **MANDATORY FIRST**: ALWAYS run \\\`npm install --include=dev\\\` BEFORE any other step — even if you just created the project. Framework CLIs sometimes skip installing all deps.
   - If using Vite/React/Vue: verify the binary exists: \\\`npx vite --version\\\` or \\\`npx next --version\\\`. If it fails, run \\\`npm install --include=dev\\\` again.
   - For static HTML without a framework: use \\\`npx -y serve -l 3000\\\` (the \\\`-y\\\` flag auto-installs serve)
4. ALWAYS \\\`pm2 delete preview 2>/dev/null\\\` before starting a new preview to avoid stale processes
5. PM2: \\\`pm2 start npm --name preview -- run dev\\\` or \\\`pm2 start \\"npx serve -l 3000\\" --name preview\\\`
6. Wait for startup: \\\`sleep 3\\\`
7. Run the FULL verification protocol below — do NOT skip any step

## Backend Apps — OpenAPI Spec (REQUIRED)
When creating a backend/API app, ALWAYS add an OpenAPI spec endpoint (e.g. \\\`GET /openapi.json\\\`) so the dashboard renders interactive API docs in the Preview tab. Include all endpoints with parameters, request bodies, response schemas, and model definitions. See the global context for framework-specific examples.

## Framework Setup Checklist (CRITICAL — preview won't work without this)
The preview system auto-detects your framework from package.json. Follow the checklist for your framework:

**Vite + React/Vue/Svelte:**
- \\\`index.html\\\` at project root with \\\`<script type=\\"module\\" src=\\"/src/main.tsx\\">\\\` (or .jsx/.vue)
- \\\`src/main.tsx\\\` (or .jsx) entry point that renders to \\\`#root\\\`
- \\\`vite.config.ts\\\` with: \\\`server: { host: true, port: 3000, allowedHosts: true }\\\` and framework plugin
- Install plugin: \\\`npm install -D @vitejs/plugin-react\\\` (or vue/svelte equivalent)

**Next.js (App Router):**
- \\\`app/layout.tsx\\\` and \\\`app/page.tsx\\\` (REQUIRED — Next.js won't serve anything without these)
- \\\`tsconfig.json\\\` (REQUIRED for TypeScript)
- Dev script: \\\`\\"dev\\": \\"next dev -H 0.0.0.0 -p 3000\\"\\\`

**Next.js (Pages Router):**
- \\\`pages/index.tsx\\\` (or .jsx/.js) as the home route
- Dev script: \\\`\\"dev\\": \\"next dev -H 0.0.0.0 -p 3000\\"\\\`

**Astro:**
- \\\`src/pages/index.astro\\\` (REQUIRED — at least one page)
- \\\`astro.config.mjs\\\` with \\\`server: { host: '0.0.0.0', port: 3000 }\\\`

**Nuxt:**
- \\\`app.vue\\\` OR \\\`pages/index.vue\\\` (at least one)
- \\\`nuxt.config.ts\\\` with \\\`devServer: { host: '0.0.0.0', port: 3000 }\\\`

**CRA:** \\\`public/index.html\\\` and \\\`src/index.tsx\\\` — PORT env var used automatically

**Remix:** \\\`app/root.tsx\\\` + route files in \\\`app/routes/\\\` + Vite config with Remix plugin

**General rule:** bind to 0.0.0.0:3000

## MANDATORY: Pre-Completion Verification Protocol
You MUST complete ALL of these checks before reporting ANY task as done.
Skipping verification = broken app for the user.

STEP 1 — Dependency check:
  \\\`ls node_modules/.bin/ | head -5\\\` → must show binaries (vite, next, etc.)
  If empty or node_modules missing: \\\`npm install --include=dev\\\` and retry

STEP 2 — Process check:
  \\\`pm2 list\\\` → your app must show status \\"online\\"
  If \\"errored\\" or \\"stopped\\": \\\`pm2 logs preview --nostream --lines 20\\\` → fix the error → restart

STEP 3 — HTTP check (with retry):
  \\\`for i in 1 2 3 4 5; do STATUS=\\$(curl -s -o /dev/null -w '%{http_code}' localhost:3000); [ \\"\\$STATUS\\" = \\"200\\" ] && break; sleep 2; done\\\`
  If still not 200 after 5 attempts: \\\`pm2 logs preview --nostream --lines 30\\\` → diagnose → fix → restart

STEP 4 — Content check:
  \\\`curl -s -o /dev/null -w '%{http_code}' localhost:3000\\\` → must return 200
  If 404: route files are missing (Next.js needs app/page.tsx, Astro needs src/pages/index.astro, etc.)
  If 500: check \\\`pm2 logs preview --nostream --lines 30\\\` for compilation errors
  \\\`curl -s localhost:3000 | head -5\\\` → must contain actual HTML (<!DOCTYPE or <html>), NOT an error page

STEP 5 — Report to user:
  Get a one-time preview link: \\\`curl -s http://localhost:3005/api/preview-url | jq -r '.url'\\\`
  Give the user this tokenized URL — it works for 60 seconds without authentication.
  Only mention a deployed/production URL when the user explicitly deploys with ellulai-expose.

ALL 5 steps must pass. Do NOT tell the user \\"it's live\\" until they do.

## Rules
- Secrets: NEVER .env files (git hook blocks commits with them). Use Dashboard → process.env
- Ports: Dev=3000, Prod=3001+, Reserved=7681-7700
- Backend first: expose backend with \\\`ellulai-expose NAME PORT\\\` before frontend depends on it
- Databases: \\\`ellulai-install postgres|redis|mysql\\\` (warn user about RAM usage)
- DB GUI: user runs \\\`ssh -L 5432:localhost:5432 $USER_NAME@$DOMAIN\\\` from their machine
- Only deploy/redeploy when the user explicitly asks. Creating an app = preview only.

## Deployment (ONLY when user EXPLICITLY asks — never assume)
The preview (port 3000) = live source code. The deployed site (port 3001+) = frozen snapshot.
Code edits ONLY affect the preview. The deployed site is NEVER updated by code changes.
**Each deploy is a one-time action, NOT a standing mode.** If the user asked to deploy earlier in the conversation and then asks for a code change, do NOT redeploy — just update the source code and report the preview URL. A new deploy requires a new explicit request.
Only deploy/redeploy when the CURRENT message says \\"deploy\\", \\"redeploy\\", \\"go live\\", \\"publish\\", \\"ship it\\", or similar.
\\"Make a change\\", \\"update the code\\", \\"fix this\\", \\"change X to Y\\" = NOT a deploy request. Only update source and report the preview URL.

### New deployment:
1. Build: \\\`npm run build\\\` (if applicable — skip for static HTML)
2. \\\`ellulai-expose APP_NAME 3001\\\`
3. Verify: \\\`ellulai-apps\\\`

### Redeploy (update existing deployment):
1. Read \\\`ellulai.json\\\` in the project root for the existing app name and port
2. Build: \\\`npm run build\\\` (if applicable — skip for static HTML)
3. \\\`ellulai-expose NAME PORT\\\` — using the SAME name and port from ellulai.json
4. Verify: \\\`curl -s https://DEPLOYED_URL | head -5\\\`
The command handles everything: fresh snapshot, PM2 restart, Caddy reload. Do NOT manually restart PM2 or copy files.

## Git (Code Backup)
Check \\\`git remote -v\\\` — if a remote exists, credentials are ready. If not, tell user to link a repo from Dashboard → Git tab.
\\\`git-flow backup\\\` | \\\`git-flow force-backup\\\` | \\\`git-flow pull\\\` | \\\`git-flow save\\\` | \\\`git-flow ship\\\` | \\\`git-flow branch\\\`
Standard git commands also work. NEVER configure git credentials manually (no SSH keys, no tokens).

## Commands
ellulai-expose NAME PORT | ellulai-apps | ellulai-install postgres|redis|mysql | pm2 logs|restart|delete NAME
<!-- ELLULAI:END -->"
  fi

  # Write to each context file using marker-based approach
  for CTX_FILE in "CLAUDE.md" "AGENTS.md" "GEMINI.md"; do
    FILE_PATH="$TARGET_DIR/$CTX_FILE"
    write_marker_file "$FILE_PATH" "$GENERATED_BLOCK"
    chown $USER_NAME:$USER_NAME "$FILE_PATH" 2>/dev/null || true
  done

  # Also set up global context files
  # ~/.gemini/GEMINI.md for global Gemini context
  GEMINI_GLOBAL_DIR="$HOME_DIR/.gemini"
  mkdir -p "$GEMINI_GLOBAL_DIR"
  GEMINI_GLOBAL_FILE="$GEMINI_GLOBAL_DIR/GEMINI.md"
  write_marker_file "$GEMINI_GLOBAL_FILE" "$GENERATED_BLOCK"
  chown -R $USER_NAME:$USER_NAME "$GEMINI_GLOBAL_DIR" 2>/dev/null || true

  # AGENTS.md at projects root alongside CLAUDE.md
  PROJECTS_AGENTS_FILE="$HOME_DIR/projects/AGENTS.md"
  write_marker_file "$PROJECTS_AGENTS_FILE" "$GENERATED_BLOCK"
  chown $USER_NAME:$USER_NAME "$PROJECTS_AGENTS_FILE" 2>/dev/null || true
}

write_marker_file() {
  # Write generated block to file using ELLULAI markers
  # $1 = file path, $2 = generated block content
  local FILE_PATH="$1"
  local BLOCK="$2"
  local MARKER_START="<!-- ELLULAI:START"
  local MARKER_END="<!-- ELLULAI:END -->"

  if [ -f "$FILE_PATH" ]; then
    if grep -q "$MARKER_START" "$FILE_PATH" 2>/dev/null; then
      # File exists WITH markers — replace content between markers
      # Use awk to replace between markers
      awk -v block="$BLOCK" '
        /<!-- ELLULAI:START/ { found=1; print block; next }
        /<!-- ELLULAI:END -->/ { found=0; next }
        !found { print }
      ' "$FILE_PATH" > "$FILE_PATH.tmp"
      mv "$FILE_PATH.tmp" "$FILE_PATH"
    else
      # File exists WITHOUT markers — prepend generated block above existing content
      EXISTING=$(cat "$FILE_PATH")
      printf '%s\\n\\n%s\\n' "$BLOCK" "$EXISTING" > "$FILE_PATH"
    fi
  else
    # File doesn't exist — create new file with generated block
    printf '%s\\n' "$BLOCK" > "$FILE_PATH"
  fi
}

if [ ! -f "$GLOBAL_FILE" ] || [ $(find "$GLOBAL_FILE" -mmin +60 2>/dev/null | wc -l) -gt 0 ]; then
  generate_global
fi
generate_current
generate_context_files
chown -R $USER_NAME:$USER_NAME "$CONTEXT_DIR" 2>/dev/null || true
echo "Context: $GLOBAL_FILE + $CURRENT_FILE + $TARGET_DIR/{CLAUDE,AGENTS,GEMINI}.md"`;
}

/**
 * Context system documentation README.
 */
export function getContextReadme(): string {
  return `# ellul.ai Context System

The context system provides AI coding assistants (OpenCode, Claude, Aider, Codex, Gemini) with information about your server, projects, and preferences. This helps them write better code that follows your conventions.

## How It Works

When you send a message through Vibe Mode, the system automatically prepends context to your message before sending it to the AI. The AI sees:

\\\`\\\`\\\`
<system_context>
[Global context]
[Project context if a project is selected]
</system_context>

User request: [Your message]
\\\`\\\`\\\`

## Context Hierarchy

### 1. Global Context (Server-wide)
**File:** \\\`\${HOME_DIR}/.ellulai/context/global.md\\\`

Applies to ALL projects. Contains:
- Server URLs and deployment info
- Project structure requirements
- App detection rules
- Commands reference
- Secrets management
- Debugging tips

**Edit this to:** Add server-wide rules, conventions, or preferences.

### 2. Custom Context Files
**Location:** \\\`\${HOME_DIR}/.ellulai/context/*.md\\\`

Any \\\`.md\\\` file you add here (except \\\`global.md\\\` and \\\`current.md\\\`) will be included in the context.

**Examples:**
- \\\`coding-style.md\\\` - Your preferred coding conventions
- \\\`tech-stack.md\\\` - Libraries and frameworks you prefer
- \\\`api-guidelines.md\\\` - How APIs should be structured

### 3. Project Context (App-specific)
**Files:** Inside each project folder
- \\\`CLAUDE.md\\\` - Project-specific instructions
- \\\`README.md\\\` - First 2000 chars included automatically
- \\\`package.json\\\` - Scripts and description extracted

**Edit these to:** Add project-specific context like:
- What the project does
- Key files and their purposes
- Specific patterns to follow
- Known issues or constraints

## Editing Context

### Via Dashboard
The Context tab in your ellul.ai dashboard lets you view and edit context files.

### Via Terminal
\\\`\\\`\\\`bash
# Edit global context
nano \${HOME_DIR}/.ellulai/context/global.md

# Add custom context
nano \${HOME_DIR}/.ellulai/context/my-preferences.md

# Edit project context
nano \${HOME_DIR}/projects/myapp/CLAUDE.md
\\\`\\\`\\\`

### Via AI
Ask any AI CLI: "Add to my global context that I prefer TypeScript over JavaScript"

## Context Refresh

Context is cached for 30 seconds for performance. Changes take effect within 30 seconds automatically.

## Example Custom Context

### coding-style.md
\\\`\\\`\\\`markdown
# Coding Preferences

## TypeScript
- Always use strict mode
- Prefer interfaces over types
- Use async/await over .then()

## React
- Use functional components only
- Prefer Tailwind CSS for styling
- Use React Query for data fetching

## Code Style
- Max line length: 100 characters
- Use 2-space indentation
- Always add JSDoc comments to functions
\\\`\\\`\\\`

### api-guidelines.md
\\\`\\\`\\\`markdown
# API Guidelines

## REST Conventions
- Use plural nouns: /users not /user
- Use HTTP methods correctly (GET, POST, PUT, DELETE)
- Return 201 for creation, 204 for deletion

## Error Handling
- Always return { error: string, code: string }
- Use appropriate HTTP status codes
- Log errors with context

## Authentication
- Use Bearer tokens in Authorization header
- Validate tokens on every request
- Return 401 for invalid/missing tokens
\\\`\\\`\\\`

## Tips

1. **Keep context concise** - AI has token limits. Focus on what matters.
2. **Use project CLAUDE.md** - Put project-specific info there, not in global.
3. **Update as you go** - When you establish a pattern, add it to context.
4. **Check what AI sees** - Ask "What context do you have about this project?"
5. **Remove outdated info** - Stale context can confuse the AI.

## Files Reference

| File | Purpose | Scope |
|------|---------|-------|
| \\\`~/.ellulai/context/global.md\\\` | Server rules, URLs, commands | All projects |
| \\\`~/.ellulai/context/*.md\\\` | Custom preferences | All projects |
| \\\`~/projects/CLAUDE.md\\\` | Project structure rules | Projects root |
| \\\`~/projects/{app}/CLAUDE.md\\\` | App-specific context | Single app |
| \\\`~/projects/{app}/README.md\\\` | Auto-included (2000 chars) | Single app |`;
}
