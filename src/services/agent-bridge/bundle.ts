/**
 * Agent Bridge Bundle Generator
 *
 * Bundles the modular TypeScript source files into a deployable JavaScript
 * script using esbuild. This replaces the monolithic 2,000+ line template.
 *
 * Usage:
 *   import { getAgentBridgeScript, getAgentBridgeService } from './bundle';
 *   const script = getAgentBridgeScript();
 */

import * as esbuild from 'esbuild';
import * as path from 'path';
import * as fs from 'fs';
import { fileURLToPath } from 'url';
import { VERSION } from '../../version';

// Cache for bundled script
let cachedBundle: string | null = null;

/**
 * Get the source directory path.
 * Works whether running from src/ (dev) or dist/ (production).
 */
function getSourceDir(): string {
  const currentFile = fileURLToPath(import.meta.url);
  const currentDir = path.dirname(currentFile);

  // If we're in dist (compiled), go up to package root and into src/
  if (currentDir.includes('/dist/') || currentDir.endsWith('/dist')) {
    const packageRoot = currentDir.replace(/\/dist(\/.*)?$/, '');
    return path.join(packageRoot, 'src', 'services', 'agent-bridge');
  }

  // Already in src/
  return currentDir;
}

/**
 * Bundle the modular TypeScript files into a single JavaScript file.
 */
async function bundleModular(): Promise<string> {
  if (cachedBundle) return cachedBundle;

  const sourceDir = getSourceDir();
  const entryPoint = path.join(sourceDir, 'src', 'main.ts');

  const result = await esbuild.build({
    entryPoints: [entryPoint],
    bundle: true,
    platform: 'node',
    target: 'node18',
    format: 'cjs',
    minify: false,
    write: false,
    external: [
      'fs', 'path', 'crypto', 'http', 'https', 'url', 'events', 'stream', 'util', 'os',
      'child_process', 'ws', 'node-pty', 'better-sqlite3',
    ],
  });

  if (!result.outputFiles?.[0]) {
    throw new Error('esbuild produced no output');
  }

  cachedBundle = result.outputFiles[0].text;
  return cachedBundle;
}

/**
 * Get the agent bridge script for VPS deployment.
 */
export async function getAgentBridgeScript(): Promise<string> {
  const bundledCode = await bundleModular();

  return `// Agent Bridge v${VERSION.components.agentBridge}
// Phone Stack Vibe Mode WebSocket Server
// Generated from modular source

${bundledCode}
`;
}

/**
 * Get the agent bridge script synchronously (for compatibility).
 */
export function getAgentBridgeScriptSync(): string {
  const preBundledPath = path.join(__dirname, 'dist', 'server.js');
  if (fs.existsSync(preBundledPath)) {
    const bundledCode = fs.readFileSync(preBundledPath, 'utf8');
    return `// Agent Bridge v${VERSION.components.agentBridge}
// Phone Stack Vibe Mode WebSocket Server
${bundledCode}
`;
  }

  throw new Error('Pre-bundled agent-bridge not found. Run build first or use async getAgentBridgeScript()');
}

/**
 * Generate the systemd service file for agent-bridge.
 * @param svcUser - Service user name (coder for free tier, dev for paid)
 */
export function getAgentBridgeService(svcUser: string = "dev"): string {
  const svcHome = `/home/${svcUser}`;
  return `[Unit]
Description=Phone Stack Agent Bridge (Vibe Mode)
After=network.target

[Service]
Type=simple
User=${svcUser}
Group=${svcUser}
WorkingDirectory=${svcHome}
Environment=NODE_ENV=production
Environment=PORT=7700
Environment=NODE_PATH=${svcHome}/.nvm/versions/node/v20.20.0/lib/node_modules
Environment=PATH=${svcHome}/.nvm/versions/node/v20.20.0/bin:${svcHome}/.opencode/bin:${svcHome}/.local/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=${svcHome}/.nvm/versions/node/v20.20.0/bin/node /usr/local/bin/phonestack-agent-bridge
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`;
}

/**
 * Get the version of the agent bridge module.
 */
export function getAgentBridgeVersion(): string {
  return VERSION.components.agentBridge;
}
