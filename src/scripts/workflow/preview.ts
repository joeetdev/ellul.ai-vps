/**
 * Preview server script - serves user-selected app on its dedicated preview port.
 * Auto-detects framework and runs appropriate dev command.
 * Port is read from ~/.ellulai/preview-ports.json (range 4000-4099).
 */
export function getPreviewScript(): string {
  // Node.js code for heredocs uses String.raw to preserve backslash escapes
  // (\n, \s, \{, etc.) that would otherwise be consumed by the template literal.
  const VITE_CONFIG_FIXER = String.raw`const fs = require('fs'), path = require('path');
const dir = process.env.VITE_FIX_DIR;
try { JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')); } catch { process.exit(0); }
const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
const deps = { ...pkg.dependencies, ...pkg.devDependencies };
if (!deps['vite']) process.exit(0);

const PLUGINS = [
  { trigger: 'react',    pkg: '@vitejs/plugin-react',         imp: 'import react from "@vitejs/plugin-react";',              call: 'react()',  detect: ['plugin-react','pluginReact'] },
  { trigger: 'vue',      pkg: '@vitejs/plugin-vue',           imp: 'import vue from "@vitejs/plugin-vue";',                  call: 'vue()',    detect: ['plugin-vue','pluginVue'] },
  { trigger: 'svelte',   pkg: '@sveltejs/vite-plugin-svelte', imp: 'import { svelte } from "@sveltejs/vite-plugin-svelte";', call: 'svelte()', detect: ['vite-plugin-svelte','pluginSvelte'] },
  { trigger: 'solid-js', pkg: 'vite-plugin-solid',            imp: 'import solid from "vite-plugin-solid";',                 call: 'solid()',  detect: ['vite-plugin-solid','pluginSolid'] },
  { trigger: 'preact',   pkg: '@preact/preset-vite',          imp: 'import preact from "@preact/preset-vite";',              call: 'preact()', detect: ['preset-vite','@preact/preset'] },
];
const needed = PLUGINS.filter(p => deps[p.trigger]);
const cfgFiles = ['vite.config.js','vite.config.ts','vite.config.mjs','vite.config.mts'];
const existing = cfgFiles.find(f => fs.existsSync(path.join(dir, f)));

if (!existing) {
  const imports = ['import { defineConfig } from "vite";', ...needed.map(p => p.imp)];
  const calls = needed.map(p => p.call).join(', ');
  const plugins = calls ? '\n  plugins: [' + calls + '],' : '';
  fs.writeFileSync(path.join(dir, 'vite.config.js'),
    imports.join('\n') + '\nexport default defineConfig({' + plugins + '\n  server: {\n    host: true,\n    port: ' + (process.env.FW_FIX_PORT || '4000') + ',\n    allowedHosts: true,\n  },\n});\n');
  console.log('Created vite.config.js');
  process.exit(0);
}

let content = fs.readFileSync(path.join(dir, existing), 'utf8');
let changed = false;

if (!content.includes('allowedHosts')) {
  if (/server\s*:\s*\{/.test(content)) {
    content = content.replace(/(server\s*:\s*\{)/, '$1\n    allowedHosts: true,');
  } else if (content.includes('defineConfig(')) {
    content = content.replace(/(defineConfig\s*\(\s*\{)/, '$1\n  server: { host: true, port: ' + (process.env.FW_FIX_PORT || '4000') + ', allowedHosts: true },');
  }
  changed = true;
}

for (const spec of needed) {
  if (spec.detect.some(d => content.includes(d))) continue;
  if (/import\s+.*from\s+['"]vite['"]/.test(content)) {
    content = content.replace(/(import\s+.*from\s+['"]vite['"].*\n)/, '$1' + spec.imp + '\n');
  } else {
    content = spec.imp + '\n' + content;
  }
  if (content.includes('plugins')) {
    content = content.replace(/(plugins\s*:\s*\[)/, '$1' + spec.call + ', ');
  } else if (content.includes('defineConfig(')) {
    content = content.replace(/(defineConfig\s*\(\s*\{)/, '$1\n  plugins: [' + spec.call + '],');
  }
  changed = true;
  console.log('Patched ' + existing + ': added ' + spec.pkg);
}

if (changed) fs.writeFileSync(path.join(dir, existing), content);`;

  const VITE_PLUGIN_INSTALLER = String.raw`const fs = require('fs'), path = require('path'), { execSync } = require('child_process');
const dir = process.env.VITE_FIX_DIR;
try { JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')); } catch { process.exit(0); }
const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
const deps = { ...pkg.dependencies, ...pkg.devDependencies };
if (!deps['vite']) process.exit(0);
const PLUGINS = {
  react: '@vitejs/plugin-react',
  vue: '@vitejs/plugin-vue',
  svelte: '@sveltejs/vite-plugin-svelte',
  'solid-js': 'vite-plugin-solid',
  preact: '@preact/preset-vite',
};
for (const [trigger, pkgName] of Object.entries(PLUGINS)) {
  if (!deps[trigger]) continue;
  const parts = pkgName.split('/');
  const modDir = path.join(dir, 'node_modules', ...parts);
  if (fs.existsSync(modDir)) continue;
  console.log('Installing ' + pkgName + '...');
  try { execSync('npm install -D ' + pkgName, { cwd: dir, stdio: 'pipe', timeout: 60000 }); }
  catch (e) { console.error('Failed to install ' + pkgName); }
}`;

  const CSS_RESET_INJECTOR = String.raw`const fs = require('fs'), path = require('path');
const dir = process.env.CSS_RESET_DIR;
const MARKER = 'data-ellulai-reset';
const STYLE = '<style ' + MARKER + '>*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}html,body,#root,#__next,#app{width:100%;height:100%;min-height:100vh}</style>';
const locations = [
  path.join(dir, 'index.html'),
  path.join(dir, 'dist', 'index.html'),
  path.join(dir, 'build', 'index.html'),
  path.join(dir, 'out', 'index.html'),
];
for (const htmlPath of locations) {
  if (!fs.existsSync(htmlPath)) continue;
  try {
    let html = fs.readFileSync(htmlPath, 'utf8');
    if (html.includes(MARKER)) continue;
    if (html.includes('<head>')) {
      html = html.replace('<head>', '<head>\n' + STYLE);
    } else if (/<head\s/.test(html)) {
      html = html.replace(/<head\s[^>]*>/, '$&\n' + STYLE);
    } else if (html.includes('<html')) {
      html = html.replace(/<html[^>]*>/, '$&\n<head>' + STYLE + '</head>');
    } else {
      html = STYLE + '\n' + html;
    }
    fs.writeFileSync(htmlPath, html);
    console.log('Injected CSS reset into ' + htmlPath);
  } catch (e) { console.error('CSS reset failed for ' + htmlPath + ': ' + e.message); }
}`;

  const SCAFFOLD_READINESS_CHECKER = String.raw`const fs = require('fs'), path = require('path'), { glob } = { glob: (pattern, dir) => {
  const exts = ['.tsx', '.jsx', '.ts', '.js', '.astro', '.vue', '.svelte'];
  try {
    const files = fs.readdirSync(path.join(dir, path.dirname(pattern)));
    const base = path.basename(pattern).replace('.*', '');
    return files.some(f => { const n = f.replace(/\.[^.]+$/, ''); return n === base && exts.some(e => f.endsWith(e)); });
  } catch { return false; }
}};
const dir = process.env.SCAFFOLD_DIR;
const fw = process.env.SCAFFOLD_FW;
const checks = {
  next: () => ['app/page', 'pages/index', 'src/app/page', 'src/pages/index'].some(p => glob(p + '.*', dir)),
  vite: () => fs.existsSync(path.join(dir, 'index.html')),
  svelte: () => fs.existsSync(path.join(dir, 'index.html')),
  cra: () => fs.existsSync(path.join(dir, 'public/index.html')) && ['src/index', 'src/App'].some(p => glob(p + '.*', dir)),
  astro: () => glob('src/pages/index.*', dir),
  nuxt: () => fs.existsSync(path.join(dir, 'app.vue')) || glob('pages/index.*', dir),
  remix: () => glob('app/root.*', dir),
  gatsby: () => glob('src/pages/index.*', dir),
};
const check = checks[fw];
if (!check) { process.exit(0); }
process.exit(check() ? 0 : 1);`;

  const FRAMEWORK_CONFIG_FIXER = String.raw`const fs = require('fs'), path = require('path');
const dir = process.env.FW_FIX_DIR;
const fw = process.env.FW_FIX_FW;
const port = process.env.FW_FIX_PORT || '4000';
try { JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')); } catch { process.exit(0); }

if (fw === 'next') {
  // Ensure tsconfig.json if TypeScript files exist
  const hasTs = (() => {
    try {
      const check = (d) => {
        for (const f of fs.readdirSync(d, { withFileTypes: true })) {
          if (f.name === 'node_modules' || f.name === '.next') continue;
          const full = path.join(d, f.name);
          if (f.isDirectory()) { if (check(full)) return true; }
          else if (f.name.endsWith('.tsx') || f.name.endsWith('.ts')) return true;
        }
        return false;
      };
      return check(dir);
    } catch { return false; }
  })();
  if (hasTs && !fs.existsSync(path.join(dir, 'tsconfig.json'))) {
    fs.writeFileSync(path.join(dir, 'tsconfig.json'), JSON.stringify({ compilerOptions: { target: "es5", lib: ["dom", "dom.iterable", "esnext"], allowJs: true, skipLibCheck: true, strict: false, noEmit: true, esModuleInterop: true, module: "esnext", moduleResolution: "bundler", resolveJsonModule: true, isolatedModules: true, jsx: "preserve", incremental: true, plugins: [{ name: "next" }], paths: { "@/*": ["./*"] } }, include: ["next-env.d.ts", "**/*.ts", "**/*.tsx", ".next/types/**/*.ts"], exclude: ["node_modules"] }, null, 2));
    console.log('Created tsconfig.json for Next.js TypeScript');
  }
  // Ensure next.config exists
  const cfgFiles = ['next.config.js', 'next.config.mjs', 'next.config.ts'];
  if (!cfgFiles.some(f => fs.existsSync(path.join(dir, f)))) {
    fs.writeFileSync(path.join(dir, 'next.config.mjs'), '/** @type {import("next").NextConfig} */\nconst nextConfig = {};\nexport default nextConfig;\n');
    console.log('Created next.config.mjs');
  }
} else if (fw === 'astro') {
  const cfgFiles = ['astro.config.mjs', 'astro.config.ts', 'astro.config.js'];
  if (!cfgFiles.some(f => fs.existsSync(path.join(dir, f)))) {
    fs.writeFileSync(path.join(dir, 'astro.config.mjs'), 'import { defineConfig } from "astro/config";\nexport default defineConfig({\n  server: { host: "0.0.0.0", port: ' + port + ' },\n});\n');
    console.log('Created astro.config.mjs');
  }
} else if (fw === 'nuxt') {
  const cfgFiles = ['nuxt.config.ts', 'nuxt.config.js'];
  if (!cfgFiles.some(f => fs.existsSync(path.join(dir, f)))) {
    fs.writeFileSync(path.join(dir, 'nuxt.config.ts'), 'export default defineNuxtConfig({\n  devServer: { host: "0.0.0.0", port: ' + port + ' },\n});\n');
    console.log('Created nuxt.config.ts');
  }
}`;

  return `#!/bin/bash
# Preview Server — serves user-selected app on its dedicated preview port.
# Reads ~/.ellulai/preview-app to determine which project to serve.
# Reads port from ~/.ellulai/preview-ports.json (range 4000-4099).
# Handles all frameworks: Vite, Next.js, CRA, Astro, Remix, Nuxt, Svelte, Gatsby, static HTML.
#
# Robustness guarantees:
# - Never starts serve/static for a project that has package.json (waits for readiness)
# - Re-detects framework every cycle (handles LLM scaffolding race)
# - Clears Vite dep cache on every cold start (prevents stale jsxDEV errors)
# - Ensures Vite config has allowedHosts + correct framework plugin
# - Health-checks after startup — restarts if MIME types are wrong
# - Won't npm install while another install is already running

PROJECTS_DIR="\$HOME/projects"
CHECK_INTERVAL=3
APP_FILE="\$HOME/.ellulai/preview-app"
SCRIPT_FILE="\$HOME/.ellulai/preview-script"
PORT_REGISTRY="\$HOME/.ellulai/preview-ports.json"
HEALTH_CHECK_DELAY=8
MAX_READINESS_WAIT=60
DEFAULT_PORT=4000

# Get the preview port for a project from the port registry
get_project_port() {
  local project="$1"
  [ -z "$project" ] && echo "$DEFAULT_PORT" && return
  [ ! -f "$PORT_REGISTRY" ] && echo "$DEFAULT_PORT" && return
  local port
  port=$(node -e "try{const r=JSON.parse(require('fs').readFileSync('$PORT_REGISTRY','utf8'));console.log(r['$project']||$DEFAULT_PORT)}catch{console.log($DEFAULT_PORT)}" 2>/dev/null)
  echo "\${port:-$DEFAULT_PORT}"
}

PORT=$DEFAULT_PORT

log() { echo "[$(date -Iseconds)] $1"; }

# ── Framework detection ──────────────────────────────────────────────────
detect_framework() {
  local dir="$1"
  [ ! -f "$dir/package.json" ] && echo "static" && return
  # Validate JSON — if file is being written, it may be truncated
  local pkg
  pkg=$(cat "$dir/package.json" 2>/dev/null)
  echo "$pkg" | node -e "try{JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'))}catch{process.exit(1)}" 2>/dev/null
  if [ $? -ne 0 ]; then
    echo "pending"
    return
  fi
  if echo "$pkg" | grep -q '"next"'; then echo "next"
  elif echo "$pkg" | grep -q '"nuxt"'; then echo "nuxt"
  elif echo "$pkg" | grep -q '"vite"'; then echo "vite"
  elif echo "$pkg" | grep -q '"vue"'; then echo "vue"
  elif echo "$pkg" | grep -q '"react-scripts"'; then echo "cra"
  elif echo "$pkg" | grep -q '"svelte"'; then echo "svelte"
  elif echo "$pkg" | grep -q '"astro"'; then echo "astro"
  elif echo "$pkg" | grep -q '"gatsby"'; then echo "gatsby"
  elif echo "$pkg" | grep -q '"remix"'; then echo "remix"
  elif echo "$pkg" | grep -q '"scripts"' && echo "$pkg" | grep -q '"dev"'; then echo "npm-dev"
  else echo "static"
  fi
}

# ── Framework → dev command ──────────────────────────────────────────────
# Uses npx to invoke binaries directly, bypassing potentially broken npm scripts.
get_dev_command() {
  local framework="$1"
  case "$framework" in
    next)     echo "npx next dev -H 0.0.0.0 -p $PORT" ;;
    nuxt)     echo "npx nuxi dev --port $PORT" ;;
    vite)     echo "npx vite --port $PORT --host 0.0.0.0" ;;
    vue)      echo "npx vue-cli-service serve --port $PORT" ;;
    cra)      echo "PORT=$PORT npx react-scripts start" ;;
    svelte)   echo "npx vite --port $PORT --host 0.0.0.0" ;;
    astro)    echo "npx astro dev --port $PORT --host 0.0.0.0" ;;
    gatsby)   echo "npx gatsby develop -p $PORT" ;;
    remix)    echo "npx remix vite:dev --port $PORT --host 0.0.0.0" ;;
    npm-dev)  echo "npm run dev" ;;
    *)        echo "" ;;
  esac
}

# ── Process management ───────────────────────────────────────────────────
kill_tree() {
  local pid=$1
  local children=$(pgrep -P $pid 2>/dev/null)
  for child in $children; do
    kill_tree $child
  done
  kill $pid 2>/dev/null
  # Wait up to 1s, then SIGKILL if still alive
  local waited=0
  while [ $waited -lt 10 ] && kill -0 $pid 2>/dev/null; do
    sleep 0.1
    waited=$((waited + 1))
  done
  kill -0 $pid 2>/dev/null && kill -9 $pid 2>/dev/null
}

port_in_use_by_other() {
  local pids
  pids=$(ss -tlnp "sport = :$PORT" 2>/dev/null | grep -oP 'pid=\\K[0-9]+')
  [ -z "$pids" ] && return 1
  for pid in $pids; do
    local check=$pid
    local is_ours=false
    while [ "$check" -gt 1 ] 2>/dev/null; do
      if [ "$check" = "$$" ]; then
        is_ours=true
        break
      fi
      check=$(ps -o ppid= -p "$check" 2>/dev/null | tr -d ' ')
      [ -z "$check" ] && break
    done
    $is_ours && continue
    return 0
  done
  return 1
}

# ── Readiness gate ───────────────────────────────────────────────────────
# For projects with package.json, wait until node_modules has the framework binary.
# Returns 0 (ready) or 1 (not ready / timed out).
wait_for_install() {
  local dir="$1"
  local framework="$2"
  [ ! -f "$dir/package.json" ] && return 0

  # Map framework to expected binary in node_modules
  local expected_bin=""
  case "$framework" in
    vite|svelte|remix) expected_bin="node_modules/.bin/vite" ;;
    next)     expected_bin="node_modules/.bin/next" ;;
    cra)      expected_bin="node_modules/.bin/react-scripts" ;;
    astro)    expected_bin="node_modules/.bin/astro" ;;
    nuxt)     expected_bin="node_modules/.bin/nuxi" ;;
    gatsby)   expected_bin="node_modules/.bin/gatsby" ;;
    vue)      expected_bin="node_modules/.bin/vue-cli-service" ;;
    npm-dev)  expected_bin="node_modules" ;;
    *)        return 0 ;;  # static — no install needed
  esac

  if [ -e "$dir/$expected_bin" ]; then
    return 0
  fi

  log "Waiting for install to complete ($expected_bin)..."
  local waited=0
  while [ $waited -lt $MAX_READINESS_WAIT ]; do
    # Don't run npm install if another process is already doing it
    if ! pgrep -f "npm install" >/dev/null 2>&1 && ! pgrep -f "npm exec" >/dev/null 2>&1; then
      if [ ! -d "$dir/node_modules" ]; then
        log "Running npm install..."
        cd "$dir" && npm install 2>&1 | tail -5
      fi
    fi
    [ -e "$dir/$expected_bin" ] && return 0
    sleep 2
    waited=$((waited + 2))
  done
  log "WARNING: Install did not complete within \${MAX_READINESS_WAIT}s"
  return 1
}

# ── Vite config fixup (inline Node.js via heredoc) ───────────────────────
# Ensures vite.config has allowedHosts and the correct framework plugin.
# Uses heredoc with single-quoted delimiter to avoid ALL bash escaping issues.
ensure_vite_config() {
  local dir="$1"
  [ ! -f "$dir/package.json" ] && return
  VITE_FIX_DIR="$dir" FW_FIX_PORT="$PORT" node << 'VITECFG_EOF'
${VITE_CONFIG_FIXER}
VITECFG_EOF
}

# ── CSS reset injection (eliminates white border) ─────────────────────────
# Injects <style data-ellulai-reset> into index.html <head>.
# Idempotent — skips if already present. Works for all frameworks.
ensure_css_reset() {
  local dir="$1"
  [ ! -f "$dir/index.html" ] && [ ! -f "$dir/dist/index.html" ] && return
  CSS_RESET_DIR="$dir" node << 'CSSRESET_EOF'
${CSS_RESET_INJECTOR}
CSSRESET_EOF
}

# ── Scaffold readiness gate ───────────────────────────────────────────
# Waits for framework-specific route/entry files before starting dev server.
# Prevents starting a framework server before the project is scaffolded.
wait_for_scaffold() {
  local dir="$1"
  local framework="$2"
  [ ! -f "$dir/package.json" ] && return 0
  case "$framework" in
    next|vite|svelte|cra|astro|nuxt|remix|gatsby) ;;
    *) return 0 ;;
  esac

  # Quick check — already ready?
  if SCAFFOLD_DIR="$dir" SCAFFOLD_FW="$framework" node << 'SCAFFOLD_EOF'
${SCAFFOLD_READINESS_CHECKER}
SCAFFOLD_EOF
  then
    return 0
  fi

  log "Waiting for scaffold readiness ($framework)..."
  local waited=0
  while [ $waited -lt 30 ]; do
    if SCAFFOLD_DIR="$dir" SCAFFOLD_FW="$framework" node << 'SCAFFOLD_EOF2'
${SCAFFOLD_READINESS_CHECKER}
SCAFFOLD_EOF2
    then
      log "Scaffold ready ($framework)"
      return 0
    fi
    sleep 2
    waited=$((waited + 2))
  done
  log "WARNING: Scaffold readiness timeout after 30s, starting anyway"
  return 0
}

# ── Framework config fixup ────────────────────────────────────────────
# Ensures framework-specific config files exist (tsconfig, next.config, astro.config, etc.)
ensure_framework_config() {
  local dir="$1"
  local framework="$2"
  [ ! -f "$dir/package.json" ] && return
  case "$framework" in
    next|astro|nuxt) ;;
    *) return ;;
  esac
  FW_FIX_DIR="$dir" FW_FIX_FW="$framework" FW_FIX_PORT="$PORT" node << 'FWCFG_EOF'
${FRAMEWORK_CONFIG_FIXER}
FWCFG_EOF
}

# ── Install missing Vite plugin packages ─────────────────────────────────
ensure_vite_plugins_installed() {
  local dir="$1"
  [ ! -f "$dir/package.json" ] && return
  VITE_FIX_DIR="$dir" node << 'VITEPKG_EOF'
${VITE_PLUGIN_INSTALLER}
VITEPKG_EOF
}

# ── Health check ─────────────────────────────────────────────────────────
# After starting, verify the server is serving content correctly.
# Returns 0 if healthy, 1 if unhealthy.
health_check() {
  local dir="$1"
  local framework="$CURRENT_FRAMEWORK"

  # Check HTTP status code
  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:$PORT/ 2>/dev/null)

  # Framework-specific HTTP status checks
  case "$framework" in
    next|astro|nuxt)
      # 404 = no routes compiled / missing route files
      if [ "$status" = "404" ]; then
        log "HEALTH FAIL: $framework returned 404 (missing route files)"
        return 1
      fi
      ;;
    nuxt)
      # Nuxt may also 500 on startup issues
      if [ "$status" = "500" ]; then
        log "HEALTH FAIL: nuxt returned 500"
        return 1
      fi
      ;;
  esac

  # Check port is responding with HTML
  local ct
  ct=$(curl -sI http://localhost:$PORT/ 2>/dev/null | grep -i "^content-type:" | head -1)
  if ! echo "$ct" | grep -qi "text/html"; then
    return 1
  fi

  # For Vite/JSX projects: verify module entry points are transformed
  local html
  html=$(curl -s http://localhost:$PORT/ 2>/dev/null)
  # Extract <script type="module" src="..."> paths
  local src
  src=$(echo "$html" | grep -oP '<script[^>]+type\\s*=\\s*[\"\\x27]module[\"\\x27][^>]+src\\s*=\\s*[\"\\x27]\\K[^\"\\x27]+')
  for entry in $src; do
    local entry_ct
    entry_ct=$(curl -sI "http://localhost:$PORT$entry" 2>/dev/null | grep -i "^content-type:" | head -1)
    # text/jsx, text/tsx, text/x-vue = broken transform
    if echo "$entry_ct" | grep -qiE "text/(jsx|tsx|x-vue|x-svelte)"; then
      log "HEALTH FAIL: $entry served as $entry_ct"
      return 1
    fi
  done
  return 0
}

# ── State ────────────────────────────────────────────────────────────────
DEV_PID=""
CURRENT_APP=""
CURRENT_SCRIPT=""
CURRENT_FRAMEWORK=""
HEALTH_CHECKED=false
START_TIME=0

cleanup() {
  log "Shutting down preview server..."
  [ -n "$DEV_PID" ] && kill_tree $DEV_PID
  exit 0
}
trap cleanup SIGTERM SIGINT

log "Preview Server starting (waiting for app selection)..."

while true; do
  SELECTED_APP=""
  SELECTED_SCRIPT=""
  [ -f "$APP_FILE" ] && SELECTED_APP=$(cat "$APP_FILE" 2>/dev/null | tr -d '\\n')
  [ -f "$SCRIPT_FILE" ] && SELECTED_SCRIPT=$(cat "$SCRIPT_FILE" 2>/dev/null | tr -d '\\n')

  # ── No app selected → stop everything ──────────────────────────────
  if [ -z "$SELECTED_APP" ]; then
    if [ -n "$DEV_PID" ]; then
      log "No app selected, stopping server"
      kill_tree $DEV_PID
      DEV_PID=""
      CURRENT_APP=""
      CURRENT_FRAMEWORK=""
    fi
    sleep $CHECK_INTERVAL
    continue
  fi

  PROJECT_DIR="$PROJECTS_DIR/$SELECTED_APP"

  if [ ! -d "$PROJECT_DIR" ]; then
    sleep $CHECK_INTERVAL
    continue
  fi

  # ── Port owned by external process → back off ──────────────────────
  if port_in_use_by_other; then
    if [ -n "$DEV_PID" ]; then
      log "External process on port $PORT, stopping auto-server"
      kill_tree $DEV_PID
      DEV_PID=""
    fi
    sleep $CHECK_INTERVAL
    continue
  fi

  # ── App changed → kill old, reset state, update port ────────────────
  if [ "$SELECTED_APP" != "$CURRENT_APP" ] || [ "$SELECTED_SCRIPT" != "$CURRENT_SCRIPT" ]; then
    [ -n "$DEV_PID" ] && kill_tree $DEV_PID && sleep 1
    DEV_PID=""
    CURRENT_APP="$SELECTED_APP"
    CURRENT_SCRIPT="$SELECTED_SCRIPT"
    CURRENT_FRAMEWORK=""
    HEALTH_CHECKED=false
    PORT=$(get_project_port "$SELECTED_APP")
    log "App changed to: $SELECTED_APP (port $PORT)"
  fi

  # ── Re-detect framework every cycle ────────────────────────────────
  # Critical for race condition: project may be created AFTER preview-app is written
  if [ -z "$SELECTED_SCRIPT" ]; then
    NEW_FRAMEWORK=$(detect_framework "$PROJECT_DIR")

    # "pending" = package.json exists but is invalid JSON (still being written)
    if [ "$NEW_FRAMEWORK" = "pending" ]; then
      sleep 1
      continue
    fi

    # Framework upgraded from static/previous → restart with correct command
    if [ -n "$DEV_PID" ] && kill -0 $DEV_PID 2>/dev/null; then
      if [ "$NEW_FRAMEWORK" != "$CURRENT_FRAMEWORK" ] && [ "$NEW_FRAMEWORK" != "static" ]; then
        log "Framework changed: $CURRENT_FRAMEWORK -> $NEW_FRAMEWORK, restarting"
        kill_tree $DEV_PID
        sleep 1
        rm -rf "$PROJECT_DIR/node_modules/.vite" "$PROJECT_DIR/.next" "$PROJECT_DIR/.nuxt" "$PROJECT_DIR/.astro" 2>/dev/null
        DEV_PID=""
        CURRENT_FRAMEWORK=""
        HEALTH_CHECKED=false
      fi
    fi
  fi

  # ── Health check: verify server is serving correctly after startup ──
  if [ -n "$DEV_PID" ] && kill -0 $DEV_PID 2>/dev/null && [ "$HEALTH_CHECKED" = "false" ]; then
    local_now=$(date +%s)
    if [ $((local_now - START_TIME)) -ge $HEALTH_CHECK_DELAY ]; then
      if health_check "$PROJECT_DIR"; then
        log "Health check passed"
        HEALTH_CHECKED=true
      else
        log "Health check FAILED — restarting with cache clear"
        kill_tree $DEV_PID
        sleep 1
        rm -rf "$PROJECT_DIR/node_modules/.vite" "$PROJECT_DIR/.next" "$PROJECT_DIR/.nuxt" "$PROJECT_DIR/.astro" 2>/dev/null
        ensure_vite_config "$PROJECT_DIR"
        ensure_vite_plugins_installed "$PROJECT_DIR"
        ensure_framework_config "$PROJECT_DIR" "$CURRENT_FRAMEWORK"
        DEV_PID=""
        CURRENT_FRAMEWORK=""
        # Don't set HEALTH_CHECKED — will re-check after restart
      fi
    fi
  fi

  # ── Start server if not running ────────────────────────────────────
  if [ -z "$DEV_PID" ] || ! kill -0 $DEV_PID 2>/dev/null; then
    cd "$PROJECT_DIR"

    if [ -n "$SELECTED_SCRIPT" ]; then
      DEV_CMD="npm run $SELECTED_SCRIPT"
      log "Using custom script: $DEV_CMD"
      CURRENT_FRAMEWORK="custom"
    else
      FRAMEWORK=$(detect_framework "$PROJECT_DIR")

      # Don't start serve for projects that have package.json — wait for framework detection
      if [ "$FRAMEWORK" = "pending" ]; then
        sleep 1
        continue
      fi
      if [ "$FRAMEWORK" = "static" ] && [ -f "$PROJECT_DIR/package.json" ]; then
        # package.json exists but no recognized framework — likely still being scaffolded
        # or has a dev script. Check for dev script before falling back.
        if grep -q '"dev"' "$PROJECT_DIR/package.json" 2>/dev/null; then
          FRAMEWORK="npm-dev"
        else
          # No dev script and no recognized framework — nothing to preview, wait
          sleep $CHECK_INTERVAL
          continue
        fi
      fi

      # Static with no framework — nothing to preview (no serve fallback)
      if [ "$FRAMEWORK" = "static" ]; then
        sleep $CHECK_INTERVAL
        continue
      fi

      CURRENT_FRAMEWORK="$FRAMEWORK"

      # Wait for node_modules to be ready (don't start before install completes)
      if [ "$FRAMEWORK" != "static" ]; then
        if ! wait_for_install "$PROJECT_DIR" "$FRAMEWORK"; then
          sleep $CHECK_INTERVAL
          continue
        fi
      fi

      # Universal: wait for scaffold readiness + ensure config
      wait_for_scaffold "$PROJECT_DIR" "$FRAMEWORK"
      ensure_framework_config "$PROJECT_DIR" "$FRAMEWORK"

      # Clear stale caches before starting
      rm -rf "$PROJECT_DIR/.next" "$PROJECT_DIR/.nuxt" "$PROJECT_DIR/.astro" "$PROJECT_DIR/node_modules/.vite" 2>/dev/null

      # Vite-specific: ensure config is correct
      case "$FRAMEWORK" in
        vite|svelte|remix)
          ensure_vite_config "$PROJECT_DIR"
          ensure_vite_plugins_installed "$PROJECT_DIR"
          ;;
      esac

      DEV_CMD=$(get_dev_command "$FRAMEWORK")
      log "Detected: $FRAMEWORK -> $DEV_CMD"
    fi

    # Set environment for framework compatibility
    export NODE_ENV=development
    export DANGEROUSLY_DISABLE_HOST_CHECK=true
    export HOST=0.0.0.0
    export BROWSER=none

    eval "$DEV_CMD &"
    DEV_PID=$!
    START_TIME=$(date +%s)
    HEALTH_CHECKED=false
    log "Dev server started (PID: $DEV_PID)"
  fi

  sleep $CHECK_INTERVAL
done`;
}

/**
 * Preview server systemd service.
 * @param svcUser - Service user name (coder for free tier, dev for paid)
 */
export function getPreviewService(svcUser: string = "dev"): string {
  const svcHome = `/home/${svcUser}`;
  return `[Unit]
Description=ellul.ai Preview Server
After=network.target ellulai-file-api.service

[Service]
Type=simple
User=${svcUser}
ExecStart=/usr/local/bin/ellulai-preview
Restart=always
RestartSec=5
Environment=PATH=${svcHome}/.node/bin:/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=multi-user.target`;
}
