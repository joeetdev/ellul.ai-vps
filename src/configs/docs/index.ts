/**
 * Documentation & Welcome Configs
 *
 * Project documentation, CLAUDE.md files, and welcome content.
 */

/**
 * Welcome project README.
 */
export function getWelcomeReadme(): string {
  return `# ellul.ai

AI: opencode (ready) | claude, codex, gemini, aider (background)
Tools: z, bat, rg, fzf, btop

Quick Start: npx create-next-app my-app && cd my-app && npm run dev`;
}

/**
 * Welcome project ecosystem.config.js.
 */
export function getWelcomeEcosystem(svcHome: string = '/home/dev'): string {
  return `module.exports={apps:[{name:'prod',script:'npm',args:'start',cwd:'${svcHome}/projects/welcome',env:{NODE_ENV:'production',PORT:3001}},{name:'preview-welcome',script:'npm',args:'run dev',cwd:'${svcHome}/projects/welcome',env:{NODE_ENV:'development',PORT:4000}}]};`;
}

/**
 * Welcome project CLAUDE.md.
 *
 * @param domain - The server domain
 * @param tier - Billing tier ("starter" or paid tier name)
 */
export function getWelcomeClaudeMd(domain: string, tier?: string): string {
  if (tier === "starter") {
    const devDomain = domain.replace("-srv.", "-dev.").replace("-dc.", "-ddev.");
    return `# ellul.ai Sandbox

## You are running in a Sandbox
This is an isolated cloud workspace at ${domain} for building and previewing web apps.
Everything you build is instantly previewable — no deploy step needed.

## SECURITY - DO NOT MODIFY (BRICK RISK)
NEVER touch: /etc/ellulai/*, /etc/warden/*, /var/lib/sovereign-shield/*
Tampering with security files = PERMANENT LOCKOUT with no recovery.

## Preview Your Work
Preview URL: https://${devDomain} (preview port from ~/.ellulai/preview-ports.json)
Start your dev server → it's live immediately at the preview URL.

## DO NOT manage the dev server
The preview system starts and restarts the dev server automatically.
**DO NOT** run pm2, npx next dev, npx vite, npm run dev, or any process management commands for the preview.
Just write code, create config files, and run \`npm install\`. The preview auto-detects your framework and starts the server.
After making changes, the preview URL is: https://${devDomain}

## Sandbox Boundaries
- Preview only (assigned port) — no external deployment
- Git: clone and pull only — outbound push is blocked
- No database servers — use SQLite or in-memory stores
- No SSH access — use the web terminal
- No custom domains

Upgrade to Sovereign for full features: https://coemad.com/pricing

## Security (Enforced by Git Hook)
- Never commit .env files
- Never hardcode API keys
- Use process.env for secrets`;
  }

  return `# ellul.ai Server

## IMPORTANT: You are running ON the ellul.ai server
This is a cloud VPS at ${domain}

## SECURITY - DO NOT MODIFY (BRICK RISK)
NEVER touch: /etc/ellulai/*, ~/.ssh/authorized_keys, /var/lib/sovereign-shield/*
Tampering with security files = PERMANENT LOCKOUT with no recovery.

## Recommended Stack (New Apps)
- Framework: Next.js 14 (App Router)
  \`npx create-next-app@latest my-app --typescript --tailwind --app\`
- Database: Drizzle ORM + PostgreSQL (via Supabase)
  \`npm i drizzle-orm postgres\` + \`npm i -D drizzle-kit\`
- Schema: Define in \`src/db/schema.ts\`, config in \`drizzle.config.ts\`
- Migrations: \`npx drizzle-kit push\` (dev) or \`npx drizzle-kit migrate\` (prod)

Unless the user specifies otherwise, always default to Next.js for new web apps
and Drizzle + PostgreSQL for database schemas.

## To Deploy This App
Run: ship

This will build and deploy with auto-SSL.

## DO NOT manage the dev server
The preview system starts and restarts the dev server automatically.
**DO NOT** run pm2, npx next dev, npx vite, npm run dev, or any process management commands for the preview.
Just write code, create config files, and run \`npm install\`. The preview auto-detects your framework and starts the server.
After making changes, the preview is live at the preview URL.

## Deploy
Run: ship (auto-build + deploy with SSL)
Manual: npm run build → sudo ellulai-expose <app-name> 3000

## Key Commands
- ship - Auto-deploy current project
- ellulai-apps - List all deployed apps with URLs
- ellulai-expose NAME PORT - Expose app with SSL

## Security (Enforced by Git Hook)
- Never commit .env files
- Never hardcode API keys
- Use process.env for secrets`;
}

/**
 * Global CLAUDE.md for home directory.
 *
 * @param domain - The server domain
 * @param tier - Billing tier ("starter" or paid tier name)
 */
export function getGlobalClaudeMd(domain: string, tier?: string, svcHome: string = '/home/dev'): string {
  // Convert main domain to dev domain on ellul.app (user content isolation)
  // {shortId}-srv.ellul.ai → {shortId}-dev.ellul.app
  // When domain is a placeholder (__DOMAIN__), use __DEV_DOMAIN__ so boot-config
  // can replace server domain and dev domain independently via sed
  const devDomain = domain === "__DOMAIN__"
    ? "__DEV_DOMAIN__"
    : domain.replace("-srv.", "-dev.").replace("-dc.", "-ddev.").replace(/\.ellul\.ai$/, ".ellul.app");
  const shortId = domain.match(/^([a-f0-9]{8})-/)?.[1] || domain.split('.')[0];

  if (tier === "starter") {
    return `# ellul.ai Sandbox: ${domain}

## You are running in a Sandbox
This is an isolated cloud workspace for building and previewing web apps.
Everything you build is instantly previewable at https://${devDomain}

## Available Tools
AI: opencode (ready) | claude, codex, gemini, aider (install on first use)
CLI: z (smart cd), bat (cat++), rg (ripgrep), fzf (fuzzy finder), btop (system monitor)
Quick Start: npx create-next-app my-app && cd my-app && npm run dev

## SECURITY - DO NOT MODIFY (BRICK RISK)
NEVER touch these files - tampering causes PERMANENT LOCKOUT:
- /etc/ellulai/* (tier, markers, domain, server_id)
- /etc/warden/* (network proxy rules)
- /var/lib/sovereign-shield/*
- systemd services: sovereign-shield, warden

## Dev Server (CRITICAL)
Vite: server: { host: true, port: {PREVIEW_PORT}, allowedHosts: true }
Next.js: "dev": "next dev -H 0.0.0.0 -p {PREVIEW_PORT}"
Preview port is read from ~/.ellulai/preview-ports.json (range 4000-4099).

## DO NOT manage the dev server
The preview system starts and restarts the dev server automatically.
**DO NOT** run pm2, npx next dev, npx vite, npm run dev, or any process management commands for the preview.
Just write code, create config files, and run \`npm install\`. The preview auto-detects your framework and starts the server on the assigned port.
After making changes, the preview URL is: https://${devDomain}

## Sandbox Boundaries
- Preview only (assigned port) — no external deployment
- Git: clone and pull only — outbound push is blocked
- No database servers — use SQLite or in-memory stores
- No SSH access — use the web terminal
- No custom domains

Upgrade to Sovereign for full features: https://coemad.com/pricing

## Commands
npm install — install dependencies (preview auto-restarts after)`;
  }

  return `# ellul.ai Server: ${domain}

## IMPORTANT: You are running ON the ellul.ai server
This is a cloud VPS at ${domain}

Preview: https://${devDomain} (per-project port from ~/.ellulai/preview-ports.json)
Apps: https://${shortId}-<app-name>.ellul.app | Custom domains: ellulai-expose NAME PORT mydomain.com

## Available Tools
AI: opencode (ready) | claude, codex, gemini, aider (install on first use)
CLI: z (smart cd), bat (cat++), rg (ripgrep), fzf (fuzzy finder), btop (system monitor)
Quick Start: npx create-next-app my-app && cd my-app && npm run dev

## SECURITY - DO NOT MODIFY (BRICK RISK)
NEVER touch these files - tampering causes PERMANENT LOCKOUT:
- /etc/ellulai/* (tier, markers, domain, server_id)
- ${svcHome}/.ssh/authorized_keys
- /var/lib/sovereign-shield/*
- systemd services: sovereign-shield, sshd

## Dev Server (CRITICAL)
Vite: server: { host: true, port: {PREVIEW_PORT}, allowedHosts: true }
Next.js: "dev": "next dev -H 0.0.0.0 -p {PREVIEW_PORT}"
Preview port is read from ~/.ellulai/preview-ports.json (range 4000-4099).

## DO NOT manage the dev server
The preview system starts and restarts the dev server automatically.
**DO NOT** run pm2, npx next dev, npx vite, npm run dev, or any process management commands for the preview.
Just write code, create config files, and run \`npm install\`. The preview auto-detects your framework and starts the server on the assigned port.
After making changes, the preview URL is: https://${devDomain}

## Deploy
Run: ship (auto-build + deploy with SSL)
Manual: npm run build → sudo ellulai-expose <app-name> 3000

## Commands
ship | ellulai-expose NAME PORT | ellulai-apps`;
}

/**
 * CLAUDE.md for the projects root directory.
 * Quick reference - detailed docs in global context.
 *
 * @param tier - Billing tier ("starter" or paid tier name)
 * @param domain - Server domain (for deriving dev preview URL)
 */
export function getProjectsClaudeMd(tier?: string, domain?: string): string {
  // Derive dev domain from server domain (same logic as getGlobalClaudeMd)
  let devDomain = "__DEV_DOMAIN__";
  if (domain && domain !== "__DOMAIN__" && domain !== "$SERVER_DOMAIN") {
    devDomain = domain.replace("-srv.", "-dev.").replace("-dc.", "-ddev.").replace(/\.ellul\.ai$/, ".ellul.app");
  }

  if (tier === "starter") {
    return `# Projects Directory (Sandbox)

## RULES (ALWAYS FOLLOW)
1. **WORKSPACE BOUNDARY**: Work ONLY inside your assigned project directory. NEVER create new directories under ~/projects/. NEVER modify files outside your project.
2. **NAME PROTECTION**: The "name" field in ellulai.json and package.json is USER-DEFINED. NEVER change it.
3. **SECURITY**: NEVER touch /etc/ellulai/*, /etc/warden/*, /var/lib/sovereign-shield/*. Tampering = PERMANENT LOCKOUT.

## Project Structure
- Each project in its own folder: ~/projects/<app-name>/
- ALWAYS create a \`ellulai.json\` file in the project root (dashboard won't detect without it)
- \`{ "type": "frontend", "previewable": true, "name": "My App", "summary": "..." }\`
- type: "frontend" | "backend" | "library"
- previewable: true if it has a web UI, false otherwise

## Dev Preview
Preview URL: https://${devDomain}
Apps on the assigned preview port are automatically served at this URL. Always tell the user their preview URL after starting a dev server.

## Within Your Project
1. Create/edit project files
2. **REQUIRED**: Create \`ellulai.json\` in project root with name, type, summary
   If it already exists: NEVER change the "name" field
3. **MANDATORY FIRST**: ALWAYS run \`npm install\` BEFORE any other step — even if you just created the project. Framework CLIs sometimes skip deps.
   - If using Vite/React/Vue: verify binary exists: \`npx vite --version\` or \`npx next --version\`. If it fails, \`npm install\` again.
   - For static HTML without a framework: use \`npx -y serve -l 3000\`
4. **REQUIRED**: Configure dev server to bind 0.0.0.0:{PREVIEW_PORT}

## DO NOT manage the dev server
The preview system starts and restarts the dev server automatically.
**DO NOT** run pm2, npx next dev, npx vite, npm run dev, or any process management commands for the preview.
Just write code, create config files, and run \`npm install\`. The preview auto-detects your framework and starts the server on port {PREVIEW_PORT}.
After making changes, the preview URL is: https://${devDomain}

## Sandbox Boundaries
- Preview only (assigned port) — no external deployment
- Git: clone and pull only — push is blocked
- No database servers — use SQLite or in-memory stores

## Commands
npm install — install dependencies (preview auto-restarts after)`;
  }

  return `# Projects Directory

## RULES (ALWAYS FOLLOW)
1. **WORKSPACE BOUNDARY**: Work ONLY inside your assigned project directory. NEVER create new directories under ~/projects/. NEVER modify files outside your project.
2. **NAME PROTECTION**: The "name" field in ellulai.json and package.json is USER-DEFINED. NEVER change it.
3. **SECURITY**: NEVER touch /etc/ellulai/*, ~/.ssh/authorized_keys, /var/lib/sovereign-shield/*. Tampering = PERMANENT LOCKOUT.

## Project Structure
- Each project in its own folder: ~/projects/<app-name>/
- ALWAYS create a \`ellulai.json\` file in the project root (dashboard won't detect without it)
- \`{ "type": "frontend", "previewable": true, "name": "My App", "summary": "..." }\`
- type: "frontend" | "backend" | "library"
- previewable: true if it has a web UI, false otherwise

## Dev Preview
Preview URL: https://${devDomain}
Apps on the assigned preview port are automatically served at this URL. Always tell the user their preview URL after starting a dev server.

## Within Your Project
1. Create/edit project files
2. **REQUIRED**: Create \`ellulai.json\` in project root with name, type, summary
   If it already exists: NEVER change the "name" field
3. **MANDATORY FIRST**: ALWAYS run \`npm install\` BEFORE any other step — even if you just created the project. Framework CLIs sometimes skip deps.
   - If using Vite/React/Vue: verify binary exists: \`npx vite --version\` or \`npx next --version\`. If it fails, \`npm install\` again.
   - For static HTML without a framework: use \`npx -y serve -l 3000\`
4. **REQUIRED**: Configure dev server to bind 0.0.0.0:{PREVIEW_PORT}

## DO NOT manage the dev server
The preview system starts and restarts the dev server automatically.
**DO NOT** run pm2, npx next dev, npx vite, npm run dev, or any process management commands for the preview.
Just write code, create config files, and run \`npm install\`. The preview auto-detects your framework and starts the server on port {PREVIEW_PORT}.
After making changes, the preview URL is: https://${devDomain}

## Commands
ship | ellulai-apps | ellulai-expose NAME PORT`;
}
