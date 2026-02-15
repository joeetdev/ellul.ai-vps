import { defineConfig } from "tsup";
// @ts-expect-error — Node built-in, not in project lib scope
import { readFileSync } from "fs";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    version: "src/version.ts",
    "configs/ai/index": "src/configs/ai/index.ts",
    "configs/index": "src/configs/index.ts",
    "scripts/index": "src/scripts/index.ts",
    "services/index": "src/services/index.ts",
    "services/enforcer/bundle": "src/services/enforcer/bundle.ts",
    "services/file-api/bundle": "src/services/file-api/bundle.ts",
    "services/agent-bridge/bundle": "src/services/agent-bridge/bundle.ts",
    "services/sovereign-shield/bundle": "src/services/sovereign-shield/bundle.ts",
    "services/caddy-gen/bundle": "src/services/caddy-gen/bundle.ts",
    "services/watchdog/index": "src/services/watchdog/index.ts",
  },
  format: ["esm"],
  clean: true,
  sourcemap: true,
  dts: true,
  // Keep esbuild external - used at runtime for bundling service scripts
  external: ["esbuild"],
  // Also keep native modules external
  noExternal: [],
  // Load .html and .js files from static/ directories as text strings at build time
  esbuildPlugins: [{
    name: 'static-text',
    setup(build) {
      build.onLoad({ filter: /[/\\]static[/\\][^/\\]+\.(html|js)$/ }, (args) => {
        const content = readFileSync(args.path, 'utf8');
        return {
          contents: `export default ${JSON.stringify(content)}`,
          loader: 'js',
        };
      });
    },
  }],
});
