/**
 * File API Bundle Generator
 *
 * Bundles the modular TypeScript source files into a deployable JavaScript
 * script using esbuild. This replaces the monolithic 2,200+ line template.
 *
 * Usage:
 *   import { getFileApiScript, getFileApiService } from './bundle';
 *   const script = getFileApiScript(serverId);
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
  // Check for /dist/ in path OR path ending with /dist
  if (currentDir.includes('/dist/') || currentDir.endsWith('/dist')) {
    const packageRoot = currentDir.replace(/\/dist(\/.*)?$/, '');
    return path.join(packageRoot, 'src', 'services', 'file-api');
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
      'child_process', 'ws', 'chokidar',
    ],
  });

  if (!result.outputFiles?.[0]) {
    throw new Error('esbuild produced no output');
  }

  cachedBundle = result.outputFiles[0].text;
  return cachedBundle;
}

/**
 * Get the file API script for VPS deployment.
 */
export async function getFileApiScript(serverId: string): Promise<string> {
  const bundledCode = await bundleModular();

  return `// File API v${VERSION.components.fileApi}
// ellul.ai Code Browser Backend
// Generated from modular source

process.env.ELLULAI_SERVER_ID = ${JSON.stringify(serverId)};

${bundledCode}
`;
}

/**
 * Get the file API script synchronously (for compatibility).
 */
export function getFileApiScriptSync(serverId: string): string {
  const preBundledPath = path.join(__dirname, 'dist', 'server.js');
  if (fs.existsSync(preBundledPath)) {
    const bundledCode = fs.readFileSync(preBundledPath, 'utf8');
    return `// File API v${VERSION.components.fileApi}
// ellul.ai Code Browser Backend
process.env.ELLULAI_SERVER_ID = ${JSON.stringify(serverId)};
${bundledCode}
`;
  }

  throw new Error('Pre-bundled file-api not found. Run build first or use async getFileApiScript()');
}

/**
 * Generate the systemd service file for file-api.
 * @param svcUser - Service user name (coder for free tier, dev for paid)
 */
export function getFileApiService(svcUser: string = "dev"): string {
  const svcHome = `/home/${svcUser}`;
  return `[Unit]
Description=ellul.ai File API (Code Browser)
After=network.target

[Service]
Type=simple
User=${svcUser}
Group=${svcUser}
WorkingDirectory=${svcHome}
Environment=NODE_ENV=production
Environment=PORT=3002
Environment=NODE_PATH=${svcHome}/.node/lib/node_modules
Environment=PATH=${svcHome}/.node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=${svcHome}/.node/bin/node /usr/local/bin/ellulai-file-api
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`;
}

/**
 * Get the version of the file API module.
 */
export function getFileApiVersion(): string {
  return VERSION.components.fileApi;
}
