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
  return `module.exports={apps:[{name:'prod',script:'npm',args:'start',cwd:'${svcHome}/projects/welcome',env:{NODE_ENV:'production',PORT:3001}},{name:'preview',script:'npm',args:'run dev',cwd:'${svcHome}/projects/welcome',env:{NODE_ENV:'development',PORT:3000}}]};`;
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
Preview URL: https://${devDomain} (port 3000)
Start your dev server → it's live immediately at the preview URL.

## Key Commands
- pm2 start npm --name preview -- run dev — Start dev server
- pm2 logs NAME — View logs
- pm2 restart NAME — Restart app
- curl localhost:3000 — Verify preview is working

## Sandbox Boundaries
- Preview only (port 3000) — no external deployment
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

## Manual Deploy
1. npm run build
2. pm2 start npm --name APPNAME -- start -- -p 3000
3. sudo ellulai-expose APPNAME 3000

## Key Commands
- ship - Auto-deploy current project
- ellulai-apps - List all deployed apps with URLs
- ellulai-expose NAME PORT - Expose app with SSL
- pm2 logs NAME - View logs
- pm2 restart NAME - Restart app

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
Vite: server: { host: true, port: 3000, allowedHosts: true }
Next.js: "dev": "next dev -H 0.0.0.0 -p 3000"

## After changes: verify preview
npm install → pm2 start npm --name preview -- run dev → curl localhost:3000 → 200

## Sandbox Boundaries
- Preview only (port 3000) — no external deployment
- Git: clone and pull only — outbound push is blocked
- No database servers — use SQLite or in-memory stores
- No SSH access — use the web terminal
- No custom domains

Upgrade to Sovereign for full features: https://coemad.com/pricing

## Commands
pm2 start|logs|restart|delete NAME`;
  }

  return `# ellul.ai Server: ${domain}

## IMPORTANT: You are running ON the ellul.ai server
This is a cloud VPS at ${domain}

Preview: https://${devDomain} (port 3000)
Apps: https://APPNAME-${domain} | Custom domains: ellulai-expose NAME PORT mydomain.com

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
Vite: server: { host: true, port: 3000, allowedHosts: true }
Next.js: "dev": "next dev -H 0.0.0.0 -p 3000"

## After changes: verify preview
npm install → pm2 start npm --name preview -- run dev → curl localhost:3000 → 200

## Deploy
Run: ship (auto-build + deploy with SSL)
Manual: npm run build → pm2 start npm --name APPNAME -- start -- -p 3000 → sudo ellulai-expose APPNAME 3000

## Commands
ship | ellulai-expose NAME PORT | ellulai-apps | pm2 logs|restart NAME`;
}

/**
 * CLAUDE.md for the projects root directory.
 * Quick reference - detailed docs in global context.
 *
 * @param tier - Billing tier ("starter" or paid tier name)
 */
export function getProjectsClaudeMd(tier?: string): string {
  if (tier === "starter") {
    return `# Projects Directory (Sandbox)

## RULES (ALWAYS FOLLOW)
1. **WORKSPACE BOUNDARY**: Work ONLY inside your assigned project directory. NEVER create new directories under ~/projects/. NEVER modify files outside your project.
2. **NAME PROTECTION**: The "name" field in ellulai.json and package.json is USER-DEFINED. NEVER change it.
3. **SECURITY**: NEVER touch /etc/ellulai/*, /etc/warden/*, /var/lib/sovereign-shield/*. Tampering = PERMANENT LOCKOUT.

## Project Structure
- Each project in its own folder: ~/projects/APPNAME/
- ALWAYS create a \`ellulai.json\` file in the project root (dashboard won't detect without it)
- \`{ "type": "frontend", "previewable": true, "name": "My App", "summary": "..." }\`
- type: "frontend" | "backend" | "library"
- previewable: true if it has a web UI, false otherwise

## Within Your Project
1. Create/edit project files
2. **REQUIRED**: Create \`ellulai.json\` in project root with name, type, summary
   If it already exists: NEVER change the "name" field
3. **IF Node.js**: Run \`npm install\` to install dependencies
4. **REQUIRED**: Configure dev server to bind 0.0.0.0:3000 (or use \`npx serve -l 3000\` for static HTML)
5. **REQUIRED**: Start with pm2 (e.g., \`pm2 start npm --name preview -- run dev\` or \`pm2 start "npx serve -l 3000" --name preview\`)
6. **REQUIRED**: Verify with \`curl localhost:3000\` - MUST return 200
7. STOP: Do not report success until step 6 passes!

## Dev Server Config (CRITICAL)
Vite: \`server: { host: true, port: 3000, allowedHosts: true }\`
Next.js: \`"dev": "next dev -H 0.0.0.0 -p 3000"\`

## Verification Required
- \`pm2 list\` → shows your app as "online"
- \`curl localhost:3000\` → returns 200 status

## Sandbox Boundaries
- Preview only (port 3000) — no external deployment
- Git: clone and pull only — push is blocked
- No database servers — use SQLite or in-memory stores

## Commands
pm2 start|logs|restart|delete NAME`;
  }

  return `# Projects Directory

## RULES (ALWAYS FOLLOW)
1. **WORKSPACE BOUNDARY**: Work ONLY inside your assigned project directory. NEVER create new directories under ~/projects/. NEVER modify files outside your project.
2. **NAME PROTECTION**: The "name" field in ellulai.json and package.json is USER-DEFINED. NEVER change it.
3. **SECURITY**: NEVER touch /etc/ellulai/*, ~/.ssh/authorized_keys, /var/lib/sovereign-shield/*. Tampering = PERMANENT LOCKOUT.

## Project Structure
- Each project in its own folder: ~/projects/APPNAME/
- ALWAYS create a \`ellulai.json\` file in the project root (dashboard won't detect without it)
- \`{ "type": "frontend", "previewable": true, "name": "My App", "summary": "..." }\`
- type: "frontend" | "backend" | "library"
- previewable: true if it has a web UI, false otherwise

## Within Your Project
1. Create/edit project files
2. **REQUIRED**: Create \`ellulai.json\` in project root with name, type, summary
   If it already exists: NEVER change the "name" field
3. **IF Node.js**: Run \`npm install\` to install dependencies
4. **REQUIRED**: Configure dev server to bind 0.0.0.0:3000 (or use \`npx serve -l 3000\` for static HTML)
5. **REQUIRED**: Start with pm2 (e.g., \`pm2 start npm --name NAME -- run dev\` or \`pm2 start "npx serve -l 3000" --name NAME\`)
6. **REQUIRED**: Verify with \`curl localhost:3000\` - MUST return 200
7. STOP: Do not report success until step 6 passes!

## Dev Server Config (CRITICAL)
Vite: \`server: { host: true, port: 3000, allowedHosts: true }\`
Next.js: \`"dev": "next dev -H 0.0.0.0 -p 3000"\`

## Verification Required
- \`pm2 list\` → shows your app as "online"
- \`curl localhost:3000\` → returns 200 status

## Commands
ship | ellulai-apps | pm2 logs|restart NAME`;
}
