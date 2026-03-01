/**
 * Shared Framework Registry — single source of truth for framework detection,
 * start commands, install commands, and environment variables.
 *
 * Consumed by:
 * - sovereign-shield (workflow.routes.ts) — production deploy via PM2
 * - file-api (preview.service.ts) — dev preview via PM2
 * - preview.ts — bash preview script (generated bash functions)
 * - expose.ts — client-side stack label detection (generated bash)
 */

import fs from 'fs';
import path from 'path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type Runtime =
  | 'node'
  | 'python'
  | 'ruby'
  | 'rust'
  | 'go'
  | 'elixir'
  | 'dart'
  | 'php'
  | 'dotnet'
  | 'static'
  | 'custom';

export interface FrameworkDef {
  id: string;
  runtime: Runtime;
  stackLabel: string;

  // Detection
  marker: string;
  detect?: {
    grep?: string;   // Pattern to grep in marker file
    dep?: string;    // package.json dependency name (Node.js only)
    file?: string;   // Additional file that must exist
  };

  // Commands ($PORT placeholder replaced at runtime)
  devCommand: string;
  prodCommand: string;
  install: string | null;
  prodInstall: string | null;

  // Environment
  env: Record<string, string>;
  devEnv?: Record<string, string>;
  prodEnv?: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Registry — ordered by detection priority (most specific first)
// ---------------------------------------------------------------------------

/** Non-Node frameworks — checked when no package.json, or as fallback */
const NON_NODE_FRAMEWORKS: FrameworkDef[] = [
  {
    id: 'rails', runtime: 'ruby', stackLabel: 'Ruby on Rails',
    marker: 'Gemfile', detect: { grep: 'rails' },
    devCommand: 'bundle exec rails server -b 0.0.0.0 -p $PORT',
    prodCommand: 'bundle exec rails server -b 0.0.0.0 -p $PORT -e production',
    install: 'bundle install', prodInstall: 'bundle install --without development test',
    env: { HOST: '0.0.0.0', BINDING: '0.0.0.0' },
    devEnv: { RAILS_ENV: 'development' },
    prodEnv: { RAILS_ENV: 'production' },
  },
  {
    id: 'sinatra', runtime: 'ruby', stackLabel: 'Sinatra',
    marker: 'Gemfile', detect: { grep: 'sinatra' },
    devCommand: 'bundle exec ruby app.rb -p $PORT -o 0.0.0.0',
    prodCommand: 'bundle exec ruby app.rb -p $PORT -o 0.0.0.0 -e production',
    install: 'bundle install', prodInstall: 'bundle install --without development test',
    env: { HOST: '0.0.0.0' },
    devEnv: {}, prodEnv: {},
  },
  {
    id: 'ruby', runtime: 'ruby', stackLabel: 'Ruby',
    marker: 'Gemfile',
    devCommand: 'bundle exec ruby app.rb',
    prodCommand: 'bundle exec ruby app.rb',
    install: 'bundle install', prodInstall: 'bundle install --without development test',
    env: { HOST: '0.0.0.0' },
  },
  {
    id: 'django', runtime: 'python', stackLabel: 'Django',
    marker: 'requirements.txt', detect: { file: 'manage.py' },
    devCommand: 'python manage.py runserver 0.0.0.0:$PORT',
    prodCommand: 'python manage.py runserver 0.0.0.0:$PORT',
    install: 'pip install -r requirements.txt', prodInstall: 'pip install -r requirements.txt',
    env: { HOST: '0.0.0.0' },
    devEnv: {}, prodEnv: {},
  },
  {
    id: 'fastapi', runtime: 'python', stackLabel: 'FastAPI',
    marker: 'requirements.txt', detect: { grep: 'fastapi|uvicorn' },
    devCommand: 'uvicorn $MODULE:app --host 0.0.0.0 --port $PORT --reload',
    prodCommand: 'uvicorn $MODULE:app --host 0.0.0.0 --port $PORT',
    install: 'pip install -r requirements.txt', prodInstall: 'pip install -r requirements.txt',
    env: { HOST: '0.0.0.0' },
  },
  {
    id: 'flask', runtime: 'python', stackLabel: 'Flask',
    marker: 'requirements.txt', detect: { grep: 'flask' },
    devCommand: 'flask run --host 0.0.0.0 --port $PORT',
    prodCommand: 'flask run --host 0.0.0.0 --port $PORT',
    install: 'pip install -r requirements.txt', prodInstall: 'pip install -r requirements.txt',
    env: { HOST: '0.0.0.0' },
    devEnv: { FLASK_ENV: 'development', FLASK_RUN_HOST: '0.0.0.0' },
    prodEnv: { FLASK_ENV: 'production', FLASK_RUN_HOST: '0.0.0.0' },
  },
  {
    id: 'streamlit', runtime: 'python', stackLabel: 'Streamlit',
    marker: 'requirements.txt', detect: { grep: 'streamlit' },
    devCommand: 'streamlit run app.py --server.port $PORT --server.address 0.0.0.0',
    prodCommand: 'streamlit run app.py --server.port $PORT --server.address 0.0.0.0',
    install: 'pip install -r requirements.txt', prodInstall: 'pip install -r requirements.txt',
    env: {},
  },
  {
    id: 'python', runtime: 'python', stackLabel: 'Python',
    marker: 'requirements.txt',
    devCommand: 'python app.py',
    prodCommand: 'python app.py',
    install: 'pip install -r requirements.txt', prodInstall: 'pip install -r requirements.txt',
    env: { HOST: '0.0.0.0' },
  },
  {
    id: 'python-pyproject', runtime: 'python', stackLabel: 'Python',
    marker: 'pyproject.toml',
    devCommand: 'python app.py',
    prodCommand: 'python app.py',
    install: 'pip install -e .', prodInstall: 'pip install -e .',
    env: { HOST: '0.0.0.0' },
  },
  {
    id: 'golang', runtime: 'go', stackLabel: 'Go',
    marker: 'go.mod',
    devCommand: 'go run .',
    prodCommand: 'go run .',
    install: null, prodInstall: null,
    env: { HOST: '0.0.0.0' },
  },
  {
    id: 'rust', runtime: 'rust', stackLabel: 'Rust',
    marker: 'Cargo.toml',
    devCommand: 'cargo run',
    prodCommand: 'cargo run --release',
    install: null, prodInstall: null,
    env: { HOST: '0.0.0.0' },
  },
  {
    id: 'phoenix', runtime: 'elixir', stackLabel: 'Phoenix',
    marker: 'mix.exs', detect: { grep: 'phoenix' },
    devCommand: 'mix phx.server',
    prodCommand: 'mix phx.server',
    install: 'mix deps.get', prodInstall: 'mix deps.get --only prod',
    env: { PHX_HOST: '0.0.0.0' },
    devEnv: { MIX_ENV: 'dev' },
    prodEnv: { MIX_ENV: 'prod' },
  },
  {
    id: 'elixir', runtime: 'elixir', stackLabel: 'Elixir',
    marker: 'mix.exs',
    devCommand: 'mix run --no-halt',
    prodCommand: 'mix run --no-halt',
    install: 'mix deps.get', prodInstall: 'mix deps.get --only prod',
    env: {},
    devEnv: { MIX_ENV: 'dev' },
    prodEnv: { MIX_ENV: 'prod' },
  },
  {
    id: 'flutter', runtime: 'dart', stackLabel: 'Flutter',
    marker: 'pubspec.yaml', detect: { grep: 'flutter' },
    devCommand: 'flutter run -d web-server --web-port $PORT --web-hostname 0.0.0.0',
    prodCommand: 'flutter run -d web-server --web-port $PORT --web-hostname 0.0.0.0',
    install: 'flutter pub get', prodInstall: 'flutter pub get',
    env: {},
  },
  {
    id: 'dart', runtime: 'dart', stackLabel: 'Dart',
    marker: 'pubspec.yaml',
    devCommand: 'dart run',
    prodCommand: 'dart run',
    install: 'dart pub get', prodInstall: 'dart pub get',
    env: {},
  },
  {
    id: 'laravel', runtime: 'php', stackLabel: 'Laravel',
    marker: 'composer.json', detect: { grep: 'laravel' },
    devCommand: 'php artisan serve --host 0.0.0.0 --port $PORT',
    prodCommand: 'php artisan serve --host 0.0.0.0 --port $PORT',
    install: 'composer install', prodInstall: 'composer install --no-dev',
    env: { PHP_CLI_SERVER_WORKERS: '4' },
  },
  {
    id: 'php', runtime: 'php', stackLabel: 'PHP',
    marker: 'composer.json',
    devCommand: 'php -S 0.0.0.0:$PORT',
    prodCommand: 'php -S 0.0.0.0:$PORT',
    install: 'composer install', prodInstall: 'composer install --no-dev',
    env: { PHP_CLI_SERVER_WORKERS: '4' },
  },
];

/** Node.js frameworks — checked when package.json exists, ordered by priority */
const NODE_FRAMEWORKS: FrameworkDef[] = [
  {
    id: 'next', runtime: 'node', stackLabel: 'Next.js',
    marker: 'package.json', detect: { dep: 'next' },
    devCommand: 'npx next dev -H 0.0.0.0 -p $PORT',
    prodCommand: 'npm start',
    install: 'npm install', prodInstall: 'npm install --omit=dev',
    env: { HOST: '0.0.0.0' },
    devEnv: { NODE_ENV: 'development' },
    prodEnv: { NODE_ENV: 'production' },
  },
  {
    id: 'nuxt', runtime: 'node', stackLabel: 'Nuxt',
    marker: 'package.json', detect: { dep: 'nuxt' },
    devCommand: 'npx nuxi dev --port $PORT',
    prodCommand: 'npm start',
    install: 'npm install', prodInstall: 'npm install --omit=dev',
    env: { HOST: '0.0.0.0' },
    devEnv: { NODE_ENV: 'development' },
    prodEnv: { NODE_ENV: 'production' },
  },
  {
    id: 'vite', runtime: 'node', stackLabel: 'Vite',
    marker: 'package.json', detect: { dep: 'vite' },
    devCommand: 'npx vite --port $PORT --host 0.0.0.0',
    prodCommand: 'npx serve -s dist -l $PORT',
    install: 'npm install', prodInstall: 'npm install --omit=dev',
    env: { HOST: '0.0.0.0' },
    devEnv: { NODE_ENV: 'development' },
    prodEnv: { NODE_ENV: 'production' },
  },
  {
    id: 'cra', runtime: 'node', stackLabel: 'Create React App',
    marker: 'package.json', detect: { dep: 'react-scripts' },
    devCommand: 'npx react-scripts start',
    prodCommand: 'npx serve -s build -l $PORT',
    install: 'npm install', prodInstall: 'npm install --omit=dev',
    env: { HOST: '0.0.0.0', DANGEROUSLY_DISABLE_HOST_CHECK: 'true', BROWSER: 'none' },
    devEnv: { NODE_ENV: 'development' },
    prodEnv: { NODE_ENV: 'production' },
  },
  {
    id: 'svelte', runtime: 'node', stackLabel: 'SvelteKit',
    marker: 'package.json', detect: { dep: '@sveltejs/kit' },
    devCommand: 'npx vite dev --host 0.0.0.0 --port $PORT',
    prodCommand: 'npm start',
    install: 'npm install', prodInstall: 'npm install --omit=dev',
    env: { HOST: '0.0.0.0' },
    devEnv: { NODE_ENV: 'development' },
    prodEnv: { NODE_ENV: 'production' },
  },
  {
    id: 'astro', runtime: 'node', stackLabel: 'Astro',
    marker: 'package.json', detect: { dep: 'astro' },
    devCommand: 'npx astro dev --host 0.0.0.0 --port $PORT',
    prodCommand: 'npm start',
    install: 'npm install', prodInstall: 'npm install --omit=dev',
    env: { HOST: '0.0.0.0' },
    devEnv: { NODE_ENV: 'development' },
    prodEnv: { NODE_ENV: 'production' },
  },
  {
    id: 'gatsby', runtime: 'node', stackLabel: 'Gatsby',
    marker: 'package.json', detect: { dep: 'gatsby' },
    devCommand: 'npx gatsby develop -p $PORT',
    prodCommand: 'npx serve -s public -l $PORT',
    install: 'npm install', prodInstall: 'npm install --omit=dev',
    env: { HOST: '0.0.0.0' },
    devEnv: { NODE_ENV: 'development' },
    prodEnv: { NODE_ENV: 'production' },
  },
  {
    id: 'remix', runtime: 'node', stackLabel: 'Remix',
    marker: 'package.json', detect: { dep: '@remix-run/dev' },
    devCommand: 'npx remix vite:dev --host 0.0.0.0 --port $PORT',
    prodCommand: 'npm start',
    install: 'npm install', prodInstall: 'npm install --omit=dev',
    env: { HOST: '0.0.0.0' },
    devEnv: { NODE_ENV: 'development' },
    prodEnv: { NODE_ENV: 'production' },
  },
  {
    id: 'vue-cli', runtime: 'node', stackLabel: 'Vue CLI',
    marker: 'package.json', detect: { dep: '@vue/cli-service' },
    devCommand: 'npx vue-cli-service serve --port $PORT',
    prodCommand: 'npx serve -s dist -l $PORT',
    install: 'npm install', prodInstall: 'npm install --omit=dev',
    env: { HOST: '0.0.0.0' },
    devEnv: { NODE_ENV: 'development' },
    prodEnv: { NODE_ENV: 'production' },
  },
];

/** All frameworks combined for export */
export const FRAMEWORKS: FrameworkDef[] = [...NON_NODE_FRAMEWORKS, ...NODE_FRAMEWORKS];

// Directories to skip when scanning for app root
const SKIP_DIRS = new Set(['.git', 'node_modules', '.openclaw', 'vendor', '__pycache__', '.bundle', '.next', '.nuxt', '.astro', 'dist', 'build', 'out']);

// All marker files we look for
const ALL_MARKERS = [...new Set(FRAMEWORKS.map(f => f.marker))];

// ---------------------------------------------------------------------------
// findAppRoot — locate the actual app directory
// ---------------------------------------------------------------------------

/**
 * Find the app root by looking for framework marker files.
 * 1. Check projectPath directly
 * 2. Scan immediate subdirectories (one level deep)
 * 3. Fallback: return projectPath
 */
export function findAppRoot(projectPath: string): string {
  // Check projectPath itself
  if (hasAnyMarker(projectPath)) return projectPath;

  // Scan one level of subdirectories
  try {
    const entries = fs.readdirSync(projectPath, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory() || SKIP_DIRS.has(entry.name)) continue;
      const subdir = path.join(projectPath, entry.name);
      if (hasAnyMarker(subdir)) return subdir;
    }
  } catch {}

  return projectPath;
}

function hasAnyMarker(dir: string): boolean {
  for (const marker of ALL_MARKERS) {
    if (marker === 'package.json' || marker === '*.csproj') continue; // check these more carefully
    if (fs.existsSync(path.join(dir, marker))) return true;
  }
  // package.json
  if (fs.existsSync(path.join(dir, 'package.json'))) return true;
  // *.csproj glob
  try {
    const files = fs.readdirSync(dir);
    if (files.some(f => f.endsWith('.csproj'))) return true;
  } catch {}
  return false;
}

// ---------------------------------------------------------------------------
// detectFramework — identify the stack
// ---------------------------------------------------------------------------

/**
 * Detect the framework used in the given directory.
 * Priority:
 * 1. ellulai.json explicit startCommand
 * 2. Procfile web: line
 * 3. Non-Node markers (Gemfile, requirements.txt, etc.)
 * 4. Node.js package.json dependencies
 * 5. Node.js scripts fallback (start/dev)
 * 6. Static HTML (index.html)
 * 7. Build output directories
 */
export function detectFramework(appRoot: string): FrameworkDef | null {
  // 1. ellulai.json explicit override
  const ellulaiJson = safeReadJson(path.join(appRoot, 'ellulai.json'));
  if (ellulaiJson) {
    const startCmd = ellulaiJson.startCommand || ellulaiJson.deploy?.command;
    if (startCmd) {
      return {
        id: 'custom', runtime: 'custom', stackLabel: 'Custom (ellulai.json)',
        marker: 'ellulai.json',
        devCommand: ellulaiJson.startCommand || startCmd,
        prodCommand: ellulaiJson.deploy?.command || startCmd,
        install: ellulaiJson.install || null,
        prodInstall: ellulaiJson.deploy?.install || ellulaiJson.install || null,
        env: { HOST: '0.0.0.0', ...(ellulaiJson.env || {}) },
      };
    }
  }

  // 2. Procfile
  const procfile = safeReadFile(path.join(appRoot, 'Procfile'));
  if (procfile) {
    const webLine = procfile.split('\n').find(l => /^web\s*:/.test(l));
    if (webLine) {
      const cmd = webLine.replace(/^web\s*:\s*/, '').trim();
      return {
        id: 'procfile', runtime: 'custom', stackLabel: 'Procfile',
        marker: 'Procfile',
        devCommand: cmd,
        prodCommand: cmd,
        install: null, prodInstall: null,
        env: { HOST: '0.0.0.0' },
      };
    }
  }

  // 3. Non-Node markers (fast — no JSON parsing)
  const nonNodeResult = detectNonNode(appRoot);
  if (nonNodeResult) return nonNodeResult;

  // 4–5. Node.js (package.json)
  const nodeResult = detectNode(appRoot);
  if (nodeResult) return nodeResult;

  // 6. Static HTML
  if (fs.existsSync(path.join(appRoot, 'index.html'))) {
    return {
      id: 'static', runtime: 'static', stackLabel: 'Static HTML',
      marker: 'index.html',
      devCommand: 'npx serve -l $PORT',
      prodCommand: 'npx serve -s . -l $PORT',
      install: null, prodInstall: null,
      env: {},
    };
  }

  // 7. Build output directories
  for (const outDir of ['dist', 'build', 'out', '.output/public']) {
    if (fs.existsSync(path.join(appRoot, outDir, 'index.html'))) {
      return {
        id: 'static', runtime: 'static', stackLabel: 'Static (build output)',
        marker: `${outDir}/index.html`,
        devCommand: `npx serve -s ${outDir} -l $PORT`,
        prodCommand: `npx serve -s ${outDir} -l $PORT`,
        install: null, prodInstall: null,
        env: {},
      };
    }
  }

  return null;
}

function detectNonNode(appRoot: string): FrameworkDef | null {
  for (const fw of NON_NODE_FRAMEWORKS) {
    const markerPath = path.join(appRoot, fw.marker);
    if (!fs.existsSync(markerPath)) continue;

    // If framework requires a grep pattern, check it
    if (fw.detect?.grep) {
      const content = safeReadFile(markerPath);
      if (!content) continue;
      const pattern = new RegExp(fw.detect.grep, 'i');
      if (!pattern.test(content)) continue;
    }

    // If framework requires an additional file, check it
    if (fw.detect?.file) {
      if (!fs.existsSync(path.join(appRoot, fw.detect.file))) continue;
    }

    return fw;
  }
  return null;
}

function detectNode(appRoot: string): FrameworkDef | null {
  const pkgPath = path.join(appRoot, 'package.json');
  if (!fs.existsSync(pkgPath)) return null;

  const pkg = safeReadJson(pkgPath);
  if (!pkg) return null; // Invalid JSON — still being written

  const allDeps: Record<string, string> = { ...pkg.dependencies, ...pkg.devDependencies };

  // Check known Node.js frameworks by dependency
  for (const fw of NODE_FRAMEWORKS) {
    if (fw.detect?.dep && allDeps[fw.detect.dep]) {
      return fw;
    }
  }

  // Fallback: check for non-Node markers alongside package.json (mixed projects)
  const nonNodeResult = detectNonNode(appRoot);
  if (nonNodeResult) return nonNodeResult;

  // Node.js scripts fallback
  if (pkg.scripts?.start) {
    return {
      id: 'node-start', runtime: 'node', stackLabel: 'Node.js (npm start)',
      marker: 'package.json',
      devCommand: 'npm start',
      prodCommand: 'npm start',
      install: 'npm install', prodInstall: 'npm install --omit=dev',
      env: { HOST: '0.0.0.0' },
      devEnv: { NODE_ENV: 'development' },
      prodEnv: { NODE_ENV: 'production' },
    };
  }
  if (pkg.scripts?.dev) {
    return {
      id: 'node-dev', runtime: 'node', stackLabel: 'Node.js (npm run dev)',
      marker: 'package.json',
      devCommand: 'npm run dev',
      prodCommand: pkg.scripts.start ? 'npm start' : 'npm run dev',
      install: 'npm install', prodInstall: 'npm install --omit=dev',
      env: { HOST: '0.0.0.0' },
      devEnv: { NODE_ENV: 'development' },
      prodEnv: { NODE_ENV: 'production' },
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// getStartCommand / getInstallCommand
// ---------------------------------------------------------------------------

/**
 * Build the start command and environment for a detected framework.
 */
export function getStartCommand(
  fw: FrameworkDef,
  port: number,
  mode: 'dev' | 'production',
): { command: string; env: Record<string, string> } {
  const raw = mode === 'dev' ? fw.devCommand : fw.prodCommand;
  let command = raw.replace(/\$PORT/g, String(port));

  // FastAPI: resolve $MODULE
  if (command.includes('$MODULE')) {
    const candidates = ['main.py', 'app.py', 'server.py', 'api.py'];
    // Note: appRoot not available here — caller should resolve if needed,
    // but for FastAPI the module is typically in CWD
    command = command.replace(/\$MODULE/g, 'main');
  }

  const env: Record<string, string> = {
    PORT: String(port),
    ...fw.env,
    ...(mode === 'dev' ? fw.devEnv : fw.prodEnv),
  };

  return { command, env };
}

/**
 * Resolve FastAPI $MODULE placeholder using actual files in appRoot.
 */
export function resolveModule(appRoot: string): string {
  const candidates = ['main.py', 'app.py', 'server.py', 'api.py'];
  const found = candidates.find(f => fs.existsSync(path.join(appRoot, f)));
  return found ? found.replace('.py', '') : 'main';
}

/**
 * Get the install command for a detected framework.
 */
export function getInstallCommand(fw: FrameworkDef, mode: 'dev' | 'production'): string | null {
  return mode === 'dev' ? fw.install : fw.prodInstall;
}

// ---------------------------------------------------------------------------
// Bash generators — produce bash code from the registry
// ---------------------------------------------------------------------------

/**
 * Generate the bash detect_framework() function body.
 * Produces the same detection logic as detectFramework() but in bash.
 */
export function generateBashDetectFramework(): string {
  const lines: string[] = [];
  lines.push('detect_framework() {');
  lines.push('  local dir="$1"');
  lines.push('');

  // Non-Node detection (before package.json check)
  lines.push('  # Non-Node detection (before package.json check)');
  lines.push('  if [ ! -f "$dir/package.json" ]; then');

  // Group non-node frameworks by marker
  const markerGroups = new Map<string, FrameworkDef[]>();
  for (const fw of NON_NODE_FRAMEWORKS) {
    const list = markerGroups.get(fw.marker) || [];
    list.push(fw);
    markerGroups.set(fw.marker, list);
  }

  let firstMarker = true;
  for (const [marker, fws] of markerGroups) {
    const indent = '    ';
    lines.push(`${indent}if [ -f "$dir/${marker}" ]; then`);

    // Special case: django needs manage.py check before general requirements.txt
    const djangoFw = fws.find(f => f.id === 'django');
    const otherFws = fws.filter(f => f.id !== 'django');

    if (djangoFw && marker === 'requirements.txt') {
      // Django must be before the general requirements.txt check
      // But django is detect: { file: 'manage.py' } — it's handled separately
    }

    let first = true;
    for (const fw of fws) {
      if (fw.detect?.file) {
        // Additional file check (django)
        lines.push(`${indent}  if [ -f "$dir/${fw.detect.file}" ]; then echo "${fw.id}" && return; fi`);
      } else if (fw.detect?.grep) {
        const grepPattern = fw.detect.grep.replace(/\|/g, '\\|');
        lines.push(`${indent}  ${first ? 'if' : 'elif'} grep -qi '${grepPattern}' "$dir/${marker}" 2>/dev/null; then echo "${fw.id}"`);
        first = false;
      } else {
        // Fallback for this marker (no detect criteria)
        if (!first) {
          lines.push(`${indent}  else echo "${fw.id}"`);
        } else {
          lines.push(`${indent}  echo "${fw.id}"`);
        }
      }
    }

    if (!first) {
      lines.push(`${indent}  fi`);
    }
    lines.push(`${indent}  return`);
    lines.push(`${indent}fi`);
    firstMarker = false;
  }

  // Static HTML fallback (no package manager files)
  lines.push('    if ls "$dir"/*.html >/dev/null 2>&1; then echo "static" && return; fi');
  lines.push('    echo "static" && return');
  lines.push('  fi');
  lines.push('');

  // Node.js: validate package.json
  lines.push('  # Node.js: validate package.json');
  lines.push('  local pkg');
  lines.push('  pkg=$(cat "$dir/package.json" 2>/dev/null)');
  lines.push('  echo "$pkg" | node -e "try{JSON.parse(require(\'fs\').readFileSync(\'/dev/stdin\',\'utf8\'))}catch{process.exit(1)}" 2>/dev/null');
  lines.push('  if [ $? -ne 0 ]; then');
  lines.push('    echo "pending"');
  lines.push('    return');
  lines.push('  fi');

  // Node.js framework detection by dependency
  let firstNode = true;
  for (const fw of NODE_FRAMEWORKS) {
    if (!fw.detect?.dep) continue;
    const keyword = `"${fw.detect.dep}"`;
    lines.push(`  ${firstNode ? 'if' : 'elif'} echo "$pkg" | grep -q '${keyword}'; then echo "${fw.id}"`);
    firstNode = false;
  }

  // Node.js scripts fallback
  lines.push(`  elif echo "$pkg" | grep -q '"scripts"' && echo "$pkg" | grep -q '"dev"'; then echo "npm-dev"`);

  // Fallback: check for non-Node markers alongside package.json
  lines.push('  # Fallback: check for non-Node markers alongside package.json');
  lines.push('  elif [ -f "$dir/Gemfile" ]; then');
  lines.push('    if grep -q \'rails\' "$dir/Gemfile" 2>/dev/null; then echo "rails"');
  lines.push('    elif grep -q \'sinatra\' "$dir/Gemfile" 2>/dev/null; then echo "sinatra"');
  lines.push('    else echo "ruby"');
  lines.push('    fi');
  lines.push('  else echo "static"');
  lines.push('  fi');
  lines.push('}');

  return lines.join('\n');
}

/**
 * Generate bash get_dev_command() / get_prod_command() function.
 */
export function generateBashGetCommand(mode: 'dev' | 'production'): string {
  const fnName = mode === 'dev' ? 'get_dev_command' : 'get_prod_command';
  const lines: string[] = [];
  lines.push(`${fnName}() {`);
  lines.push('  local framework="$1"');
  lines.push('  case "$framework" in');

  const allFws = [...NON_NODE_FRAMEWORKS, ...NODE_FRAMEWORKS];
  const seen = new Set<string>();
  for (const fw of allFws) {
    if (seen.has(fw.id)) continue;
    seen.add(fw.id);
    const cmd = mode === 'dev' ? fw.devCommand : fw.prodCommand;
    lines.push(`    ${fw.id})${' '.repeat(Math.max(1, 12 - fw.id.length))}echo "${cmd}" ;;`);
  }

  // npm-dev alias (maps to node-dev in TypeScript but "npm-dev" in bash)
  if (!seen.has('npm-dev')) {
    lines.push('    npm-dev)    echo "npm run dev" ;;');
  }

  lines.push('    *)          echo "" ;;');
  lines.push('  esac');
  lines.push('}');

  return lines.join('\n');
}

/**
 * Generate bash wait_for_install() function from registry.
 */
export function generateBashWaitForInstall(): string {
  const lines: string[] = [];
  lines.push('wait_for_install() {');
  lines.push('  local dir="$1"');
  lines.push('  local framework="$2"');
  lines.push('');
  lines.push('  # Non-Node frameworks: handle their own package managers');
  lines.push('  case "$framework" in');

  // Group by install command pattern
  // Ruby
  lines.push('    rails|sinatra|ruby)');
  lines.push('      [ ! -f "$dir/Gemfile" ] && return 0');
  lines.push('      if [ ! -f "$dir/Gemfile.lock" ] || [ ! -d "$dir/vendor/bundle" ]; then');
  lines.push('        log "Running bundle install..."');
  lines.push('        cd "$dir" && bundle install 2>&1 | tail -5');
  lines.push('      fi');
  lines.push('      return 0');
  lines.push('      ;;');

  // Python
  lines.push('    django|flask|fastapi|streamlit|python|python-pyproject)');
  lines.push('      if [ -f "$dir/requirements.txt" ]; then');
  lines.push('        log "Running pip install..."');
  lines.push('        cd "$dir" && pip install -r requirements.txt 2>&1 | tail -5');
  lines.push('      elif [ -f "$dir/pyproject.toml" ]; then');
  lines.push('        log "Running pip install -e ."');
  lines.push('        cd "$dir" && pip install -e . 2>&1 | tail -5');
  lines.push('      fi');
  lines.push('      return 0');
  lines.push('      ;;');

  // Rust/Go
  lines.push('    rust|golang)');
  lines.push('      return 0  # cargo run / go run handle deps automatically');
  lines.push('      ;;');

  // Elixir
  lines.push('    phoenix|elixir)');
  lines.push('      [ ! -f "$dir/mix.exs" ] && return 0');
  lines.push('      if [ ! -f "$dir/mix.lock" ] || [ ! -d "$dir/deps" ]; then');
  lines.push('        log "Running mix deps.get..."');
  lines.push('        cd "$dir" && mix deps.get 2>&1 | tail -5');
  lines.push('      fi');
  lines.push('      return 0');
  lines.push('      ;;');

  // Flutter
  lines.push('    flutter)');
  lines.push('      [ ! -f "$dir/pubspec.yaml" ] && return 0');
  lines.push('      if [ ! -d "$dir/.dart_tool" ]; then');
  lines.push('        log "Running flutter pub get..."');
  lines.push('        cd "$dir" && flutter pub get 2>&1 | tail -5');
  lines.push('      fi');
  lines.push('      return 0');
  lines.push('      ;;');

  // Dart
  lines.push('    dart)');
  lines.push('      [ ! -f "$dir/pubspec.yaml" ] && return 0');
  lines.push('      if [ ! -d "$dir/.dart_tool" ]; then');
  lines.push('        log "Running dart pub get..."');
  lines.push('        cd "$dir" && dart pub get 2>&1 | tail -5');
  lines.push('      fi');
  lines.push('      return 0');
  lines.push('      ;;');

  // PHP
  lines.push('    laravel|php)');
  lines.push('      [ ! -f "$dir/composer.json" ] && return 0');
  lines.push('      if [ ! -d "$dir/vendor" ]; then');
  lines.push('        log "Running composer install..."');
  lines.push('        cd "$dir" && composer install 2>&1 | tail -5');
  lines.push('      fi');
  lines.push('      return 0');
  lines.push('      ;;');

  lines.push('  esac');
  lines.push('');

  // Node.js frameworks: wait for node_modules
  lines.push('  # Node.js frameworks: wait for node_modules');
  lines.push('  [ ! -f "$dir/package.json" ] && return 0');
  lines.push('');
  lines.push('  local expected_bin=""');
  lines.push('  case "$framework" in');
  lines.push('    vite|svelte|remix) expected_bin="node_modules/.bin/vite" ;;');
  lines.push('    next)     expected_bin="node_modules/.bin/next" ;;');
  lines.push('    cra)      expected_bin="node_modules/.bin/react-scripts" ;;');
  lines.push('    astro)    expected_bin="node_modules/.bin/astro" ;;');
  lines.push('    nuxt)     expected_bin="node_modules/.bin/nuxi" ;;');
  lines.push('    gatsby)   expected_bin="node_modules/.bin/gatsby" ;;');
  lines.push('    vue-cli)  expected_bin="node_modules/.bin/vue-cli-service" ;;');
  lines.push('    npm-dev|node-start|node-dev) expected_bin="node_modules" ;;');
  lines.push('    *)        return 0 ;;');
  lines.push('  esac');
  lines.push('');
  lines.push('  if [ -e "$dir/$expected_bin" ]; then');
  lines.push('    return 0');
  lines.push('  fi');
  lines.push('');
  lines.push('  log "Waiting for install to complete ($expected_bin)..."');
  lines.push('  local waited=0');
  lines.push('  while [ $waited -lt $MAX_READINESS_WAIT ]; do');
  lines.push('    # Don\'t run npm install if another process is already doing it');
  lines.push('    if ! pgrep -f "npm install" >/dev/null 2>&1 && ! pgrep -f "npm exec" >/dev/null 2>&1; then');
  lines.push('      if [ ! -d "$dir/node_modules" ]; then');
  lines.push('        log "Running npm install..."');
  lines.push('        cd "$dir" && npm install 2>&1 | tail -5');
  lines.push('      fi');
  lines.push('    fi');
  lines.push('    [ -e "$dir/$expected_bin" ] && return 0');
  lines.push('    sleep 2');
  lines.push('    waited=$((waited + 2))');
  lines.push('  done');
  lines.push('  log "WARNING: Install did not complete within ${MAX_READINESS_WAIT}s"');
  lines.push('  return 1');
  lines.push('}');

  return lines.join('\n');
}

/**
 * Generate bash stack detection for expose.ts (just sets STACK variable).
 */
export function generateBashStackDetect(): string {
  const lines: string[] = [];
  lines.push('# ── Detect stack (harmless, runs in user space) ───────────────────');
  lines.push('PROJECT_PATH="$(pwd)"');
  lines.push('STACK="Unknown"');
  lines.push('');

  // findAppRoot equivalent in bash
  lines.push('# Find app root (check subdirs if no marker in PROJECT_PATH)');
  lines.push('APP_ROOT="$PROJECT_PATH"');
  lines.push(`MARKERS="package.json Gemfile requirements.txt pyproject.toml go.mod Cargo.toml mix.exs pubspec.yaml composer.json"`);
  lines.push('found_marker=false');
  lines.push('for m in $MARKERS; do');
  lines.push('  if [ -f "$PROJECT_PATH/$m" ]; then found_marker=true; break; fi');
  lines.push('done');
  lines.push('if [ "$found_marker" = "false" ]; then');
  lines.push('  for d in "$PROJECT_PATH"/*/; do');
  lines.push('    [ ! -d "$d" ] && continue');
  lines.push('    dname=$(basename "$d")');
  lines.push('    case "$dname" in .git|node_modules|.openclaw|vendor|__pycache__|.bundle) continue ;; esac');
  lines.push('    for m in $MARKERS; do');
  lines.push('      if [ -f "$d$m" ]; then APP_ROOT="$d"; found_marker=true; break 2; fi');
  lines.push('    done');
  lines.push('  done');
  lines.push('fi');
  lines.push('');

  // Node.js detection
  lines.push('if [ -f "$APP_ROOT/package.json" ]; then');
  for (const fw of NODE_FRAMEWORKS) {
    if (!fw.detect?.dep) continue;
    lines.push(`  if grep -q '"${fw.detect.dep}"' "$APP_ROOT/package.json" 2>/dev/null; then`);
    lines.push(`    STACK="${fw.stackLabel}"`);
    // For express/hono/fastify — check common non-framework deps
    lines.push(`  el`);
  }
  // Also check for common server frameworks not in NODE_FRAMEWORKS
  const serverFrameworks = [
    { dep: 'express', label: 'Express' },
    { dep: 'hono', label: 'Hono' },
    { dep: 'fastify', label: 'Fastify' },
  ];
  for (const sf of serverFrameworks) {
    lines.push(`  if grep -q '"${sf.dep}"' "$APP_ROOT/package.json" 2>/dev/null; then`);
    lines.push(`    STACK="${sf.label}"`);
    lines.push(`  el`);
  }

  // Hmm, this approach is getting messy. Let me restructure it as a simpler if/elif chain.
  // Let me rewrite this function properly.

  const lines2: string[] = [];
  lines2.push('# ── Detect stack (harmless, runs in user space) ───────────────────');
  lines2.push('PROJECT_PATH="$(pwd)"');
  lines2.push('STACK="Unknown"');
  lines2.push('');

  // findAppRoot equivalent in bash
  lines2.push('# Find app root (check subdirs if no marker in PROJECT_PATH)');
  lines2.push('APP_ROOT="$PROJECT_PATH"');
  lines2.push('MARKERS="package.json Gemfile requirements.txt pyproject.toml go.mod Cargo.toml mix.exs pubspec.yaml composer.json"');
  lines2.push('found_marker=false');
  lines2.push('for m in $MARKERS; do');
  lines2.push('  if [ -f "$PROJECT_PATH/$m" ]; then found_marker=true; break; fi');
  lines2.push('done');
  lines2.push('if [ "$found_marker" = "false" ]; then');
  lines2.push('  for d in "$PROJECT_PATH"/*/; do');
  lines2.push('    [ ! -d "$d" ] && continue');
  lines2.push('    dname=$(basename "$d")');
  lines2.push('    case "$dname" in .git|node_modules|.openclaw|vendor|__pycache__|.bundle) continue ;; esac');
  lines2.push('    for m in $MARKERS; do');
  lines2.push('      if [ -f "$d$m" ]; then APP_ROOT="${d%/}"; found_marker=true; break 2; fi');
  lines2.push('    done');
  lines2.push('  done');
  lines2.push('fi');
  lines2.push('');

  // Node.js
  lines2.push('if [ -f "$APP_ROOT/package.json" ]; then');

  const allNodeDeps = [
    ...NODE_FRAMEWORKS.filter(f => f.detect?.dep).map(f => ({ dep: f.detect!.dep!, label: f.stackLabel })),
    { dep: 'react', label: 'React' },
    { dep: 'express', label: 'Express' },
    { dep: 'hono', label: 'Hono' },
    { dep: 'fastify', label: 'Fastify' },
  ];

  let isFirst = true;
  for (const { dep, label } of allNodeDeps) {
    lines2.push(`  ${isFirst ? 'if' : 'elif'} grep -q '"${dep}"' "$APP_ROOT/package.json" 2>/dev/null; then`);
    lines2.push(`    STACK="${label}"`);
    isFirst = false;
  }
  lines2.push('  else');
  lines2.push('    STACK="Node.js"');
  lines2.push('  fi');
  lines2.push('  if [ -f "$APP_ROOT/tsconfig.json" ]; then');
  lines2.push('    STACK="$STACK/TS"');
  lines2.push('  fi');

  // Non-Node markers
  const nonNodeStacks: Array<{ marker: string; checks?: Array<{ grep: string; label: string }>; fallback: string }> = [
    {
      marker: 'Gemfile',
      checks: [{ grep: 'rails', label: 'Ruby on Rails' }, { grep: 'sinatra', label: 'Sinatra' }],
      fallback: 'Ruby',
    },
    {
      marker: 'requirements.txt',
      checks: [{ grep: 'fastapi', label: 'FastAPI' }, { grep: 'flask', label: 'Flask' }, { grep: 'django', label: 'Django' }, { grep: 'streamlit', label: 'Streamlit' }],
      fallback: 'Python',
    },
    { marker: 'pyproject.toml', fallback: 'Python' },
    { marker: 'go.mod', fallback: 'Go' },
    { marker: 'Cargo.toml', fallback: 'Rust' },
    {
      marker: 'mix.exs',
      checks: [{ grep: 'phoenix', label: 'Phoenix' }],
      fallback: 'Elixir',
    },
    {
      marker: 'pubspec.yaml',
      checks: [{ grep: 'flutter', label: 'Flutter' }],
      fallback: 'Dart',
    },
    {
      marker: 'composer.json',
      checks: [{ grep: 'laravel', label: 'Laravel' }],
      fallback: 'PHP',
    },
  ];

  for (const { marker, checks, fallback } of nonNodeStacks) {
    lines2.push(`elif [ -f "$APP_ROOT/${marker}" ]; then`);
    if (checks && checks.length > 0) {
      let first = true;
      for (const { grep, label } of checks) {
        lines2.push(`  ${first ? 'if' : 'elif'} grep -qi "${grep}" "$APP_ROOT/${marker}" 2>/dev/null; then`);
        lines2.push(`    STACK="${label}"`);
        first = false;
      }
      lines2.push('  else');
      lines2.push(`    STACK="${fallback}"`);
      lines2.push('  fi');
    } else {
      lines2.push(`  STACK="${fallback}"`);
    }
  }

  lines2.push('fi');

  return lines2.join('\n');
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function safeReadFile(filePath: string): string | null {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
}

function safeReadJson(filePath: string): any {
  const content = safeReadFile(filePath);
  if (!content) return null;
  try {
    return JSON.parse(content);
  } catch {
    return null;
  }
}
