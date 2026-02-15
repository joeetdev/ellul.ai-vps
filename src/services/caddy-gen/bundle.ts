/**
 * Caddy Generator Bundle
 *
 * Bundles the caddy-gen CLI into a deployable JavaScript script using esbuild.
 * Deployed to /usr/local/bin/ellulai-caddy-gen on the VPS.
 *
 * Usage:
 *   import { getCaddyGenScript } from './bundle';
 *   const script = await getCaddyGenScript();
 */

import * as esbuild from "esbuild";
import * as path from "path";
import { fileURLToPath } from "url";

let cachedBundle: string | null = null;

/**
 * Get the source directory path.
 * Works whether running from src/ (dev) or dist/ (production).
 */
function getSourceDir(): string {
  const currentFile = fileURLToPath(import.meta.url);
  const currentDir = path.dirname(currentFile);

  if (currentDir.includes("/dist/") || currentDir.endsWith("/dist")) {
    const packageRoot = currentDir.replace(/\/dist(\/.*)?$/, "");
    return path.join(packageRoot, "src", "services", "caddy-gen");
  }

  return currentDir;
}

/**
 * Bundle the caddy-gen CLI into a single JavaScript file.
 */
async function bundleModular(): Promise<string> {
  if (cachedBundle) return cachedBundle;

  const sourceDir = getSourceDir();
  const entryPoint = path.join(sourceDir, "main.ts");

  const result = await esbuild.build({
    entryPoints: [entryPoint],
    bundle: true,
    platform: "node",
    target: "node18",
    format: "cjs",
    minify: false,
    write: false,
    external: ["fs", "path", "crypto", "os", "url", "util"],
  });

  if (!result.outputFiles?.[0]) {
    throw new Error("esbuild produced no output");
  }

  cachedBundle = result.outputFiles[0].text;
  return cachedBundle;
}

/**
 * Get the caddy-gen CLI script for VPS deployment.
 * Returns JavaScript code that generates Caddyfile content.
 */
export async function getCaddyGenScript(): Promise<string> {
  const bundledCode = await bundleModular();

  return `#!/usr/bin/env node
// ellulai-caddy-gen — Caddyfile Generator
// Single source of truth for Caddy configuration.
// Usage: ellulai-caddy-gen --model <cloudflare|direct|gateway> --main-domain <d> --code-domain <d> --dev-domain <d>

${bundledCode}
`;
}
