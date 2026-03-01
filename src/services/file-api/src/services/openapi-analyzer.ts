/**
 * OpenAPI Static Analyzer
 *
 * Extracts route definitions from source code for any language/framework
 * using regex patterns. Universal fallback when no running server is available.
 */

import * as fs from 'fs';
import * as path from 'path';

export interface AnalyzedRoute {
  method: string; // GET, POST, PUT, DELETE, PATCH
  path: string;   // /api/users/{id} (OpenAPI format)
}

// Directories to skip when scanning source files
const SKIP_DIRS = new Set([
  'node_modules', 'vendor', '.git', 'dist', 'build', '__pycache__',
  'bin', 'obj', 'target', 'deps', '_build', '.next', '.nuxt',
  'coverage', 'test', 'tests', 'spec', '__tests__', '.turbo', '.cache',
]);

const SKIP_FILE_PATTERNS = [/\.test\./, /\.spec\./, /_test\./, /_spec\./];

const MAX_DEPTH = 5;
const MAX_FILES = 200;
const MAX_FILE_SIZE = 100 * 1024; // 100KB
const SCAN_TIMEOUT_MS = 3000;

// ---------------------------------------------------------------------------
// Language Detection
// ---------------------------------------------------------------------------

type Lang = 'js' | 'python' | 'go' | 'rust' | 'csharp' | 'ruby' | 'php' | 'elixir';

const LANG_EXTENSIONS: Record<Lang, string[]> = {
  js: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
  python: ['.py'],
  go: ['.go'],
  rust: ['.rs'],
  csharp: ['.cs'],
  ruby: ['.rb'],
  php: ['.php'],
  elixir: ['.ex', '.exs'],
};

const FRAMEWORK_LANG: Record<string, Lang> = {
  express: 'js', fastify: 'js', hono: 'js', koa: 'js', nestjs: 'js',
  nextjs: 'js', vite: 'js', cra: 'js',
  fastapi: 'python', flask: 'python', django: 'python', python: 'python',
  go: 'go',
  rust: 'rust',
  dotnet: 'csharp',
  rails: 'ruby', sinatra: 'ruby', ruby: 'ruby',
  laravel: 'php', php: 'php',
  phoenix: 'elixir', elixir: 'elixir',
};

function detectLang(appPath: string, framework: string): Lang | null {
  if (FRAMEWORK_LANG[framework]) return FRAMEWORK_LANG[framework];
  // Infer from file markers
  if (fs.existsSync(path.join(appPath, 'package.json'))) return 'js';
  if (fs.existsSync(path.join(appPath, 'go.mod'))) return 'go';
  if (fs.existsSync(path.join(appPath, 'Cargo.toml'))) return 'rust';
  if (fs.existsSync(path.join(appPath, 'requirements.txt')) || fs.existsSync(path.join(appPath, 'pyproject.toml'))) return 'python';
  if (fs.existsSync(path.join(appPath, 'Gemfile'))) return 'ruby';
  if (fs.existsSync(path.join(appPath, 'composer.json'))) return 'php';
  if (fs.existsSync(path.join(appPath, 'mix.exs'))) return 'elixir';
  try {
    const files = fs.readdirSync(appPath);
    if (files.some(f => f.endsWith('.csproj') || f.endsWith('.sln'))) return 'csharp';
  } catch {}
  return null;
}

// ---------------------------------------------------------------------------
// File Scanner
// ---------------------------------------------------------------------------

function scanSourceFiles(appPath: string, extensions: string[], deadline: number): string[] {
  const files: string[] = [];

  function walk(dir: string, depth: number): void {
    if (depth > MAX_DEPTH || files.length >= MAX_FILES || Date.now() > deadline) return;
    let entries: string[];
    try { entries = fs.readdirSync(dir); } catch { return; }
    for (const entry of entries) {
      if (files.length >= MAX_FILES || Date.now() > deadline) return;
      if (SKIP_DIRS.has(entry) || entry.startsWith('.')) continue;
      const fullPath = path.join(dir, entry);
      try {
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
          walk(fullPath, depth + 1);
        } else if (stat.isFile() && stat.size <= MAX_FILE_SIZE) {
          const ext = path.extname(entry).toLowerCase();
          if (extensions.includes(ext) && !SKIP_FILE_PATTERNS.some(p => p.test(entry))) {
            files.push(fullPath);
          }
        }
      } catch {}
    }
  }

  walk(appPath, 0);
  return files;
}

// ---------------------------------------------------------------------------
// Comment Strippers
// ---------------------------------------------------------------------------

function stripCFamilyComments(code: string): string {
  // Remove // line comments and /* block comments */
  return code
    .replace(/\/\/.*$/gm, '')
    .replace(/\/\*[\s\S]*?\*\//g, '');
}

function stripPythonComments(code: string): string {
  return code
    .replace(/#.*$/gm, '')
    .replace(/"""[\s\S]*?"""/g, '')
    .replace(/'''[\s\S]*?'''/g, '');
}

function stripHashComments(code: string): string {
  return code
    .replace(/#.*$/gm, '')
    .replace(/=begin[\s\S]*?=end/g, '');
}

function stripComments(code: string, lang: Lang): string {
  switch (lang) {
    case 'js': case 'go': case 'rust': case 'csharp': case 'php':
      return stripCFamilyComments(code);
    case 'python':
      return stripPythonComments(code);
    case 'ruby': case 'elixir':
      return stripHashComments(code);
    default:
      return code;
  }
}

// ---------------------------------------------------------------------------
// Route Extractors
// ---------------------------------------------------------------------------

function extractJsTsRoutes(code: string): AnalyzedRoute[] {
  const routes: AnalyzedRoute[] = [];

  // Pattern 1: app.get('/path', ...), router.post('/api/users', ...)
  const p1 = /\b\w+\.(get|post|put|delete|patch|options|head|all)\s*\(\s*['"`/]([^'"`]+)['"`]/gi;
  let m;
  while ((m = p1.exec(code)) !== null) {
    const method = m[1].toUpperCase();
    if (method === 'ALL') continue; // skip .all()
    routes.push({ method, path: m[2] });
  }

  // Pattern 2: @Get('/users'), @Post(), @Delete(':id') — NestJS decorators
  const p2 = /@(Get|Post|Put|Delete|Patch|Options|Head)\s*\(\s*['"`]?([^'"`\)]*?)['"`]?\s*\)/gi;
  while ((m = p2.exec(code)) !== null) {
    routes.push({ method: m[1].toUpperCase(), path: m[2] || '/' });
  }

  // Pattern 3: @Controller('prefix') — NestJS controller prefix
  const p3 = /@Controller\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/gi;
  const prefixes: string[] = [];
  while ((m = p3.exec(code)) !== null) {
    prefixes.push(m[1]);
  }

  // Apply controller prefix to decorator routes
  if (prefixes.length > 0) {
    const prefix = prefixes[0];
    for (const route of routes) {
      if (!route.path.startsWith('/')) {
        route.path = `${prefix.replace(/\/$/, '')}/${route.path}`;
      }
    }
  }

  // Pattern 4: .route('/users').get(...).post(...)
  const p4 = /\.route\s*\(\s*['"`]([^'"`]+)['"`]\s*\)\s*\.(get|post|put|delete|patch)/gi;
  while ((m = p4.exec(code)) !== null) {
    routes.push({ method: m[2].toUpperCase(), path: m[1] });
  }

  return routes;
}

function extractPythonRoutes(code: string): AnalyzedRoute[] {
  const routes: AnalyzedRoute[] = [];
  let m;

  // Pattern 1: @app.get("/users"), @router.post("/items")
  const p1 = /@\w+\.(get|post|put|delete|patch|options|head)\s*\(\s*['"`]([^'"`]+)['"`]/gi;
  while ((m = p1.exec(code)) !== null) {
    routes.push({ method: m[1].toUpperCase(), path: m[2] });
  }

  // Pattern 2: @app.route('/path', methods=['GET', 'POST'])
  const p2 = /@\w+\.route\s*\(\s*['"`]([^'"`]+)['"`](?:\s*,\s*methods\s*=\s*\[([^\]]+)\])?/gi;
  while ((m = p2.exec(code)) !== null) {
    const routePath = m[1];
    if (m[2]) {
      const methods = m[2].replace(/['"]/g, '').split(',').map(s => s.trim().toUpperCase());
      for (const method of methods) {
        if (method) routes.push({ method, path: routePath });
      }
    } else {
      routes.push({ method: 'GET', path: routePath });
    }
  }

  // Pattern 3: @app.api_route("/path")
  const p3 = /@\w+\.api_route\s*\(\s*['"`]([^'"`]+)['"`]/gi;
  while ((m = p3.exec(code)) !== null) {
    routes.push({ method: 'GET', path: m[1] });
  }

  // Pattern 4: path('users/', views.list) — Django
  const p4 = /(?:path|re_path|url)\s*\(\s*r?['"`]([^'"`]+)['"`]/gi;
  while ((m = p4.exec(code)) !== null) {
    routes.push({ method: 'GET', path: '/' + m[1].replace(/^\^/, '').replace(/\$$/, '') });
  }

  // Pattern 5: APIRouter(prefix="/api/v1") — FastAPI prefix
  const p5 = /APIRouter\s*\(\s*prefix\s*=\s*['"`]([^'"`]+)['"`]/gi;
  const prefixes: string[] = [];
  while ((m = p5.exec(code)) !== null) {
    prefixes.push(m[1]);
  }
  if (prefixes.length > 0) {
    const prefix = prefixes[0];
    for (const route of routes) {
      if (!route.path.startsWith(prefix)) {
        route.path = prefix.replace(/\/$/, '') + '/' + route.path.replace(/^\//, '');
      }
    }
  }

  return routes;
}

function extractGoRoutes(code: string): AnalyzedRoute[] {
  const routes: AnalyzedRoute[] = [];
  let m;

  // Pattern 1: r.GET("/users", handler) — Gin (uppercase)
  const p1 = /\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*"([^"]+)"/g;
  while ((m = p1.exec(code)) !== null) {
    routes.push({ method: m[1], path: m[2] });
  }

  // Pattern 2: r.Get("/users", handler) — Chi, Echo (capitalized)
  const p2 = /\.(Get|Post|Put|Delete|Patch|Head|Options)\s*\(\s*"([^"]+)"/g;
  while ((m = p2.exec(code)) !== null) {
    routes.push({ method: m[1].toUpperCase(), path: m[2] });
  }

  // Pattern 3: http.HandleFunc("/path", handler) — stdlib
  const p3 = /HandleFunc\s*\(\s*"([^"]+)"/g;
  while ((m = p3.exec(code)) !== null) {
    routes.push({ method: 'GET', path: m[1] });
  }

  // Pattern 4: mux.Handle("/path", handler)
  const p4 = /Handle\s*\(\s*"([^"]+)"/g;
  while ((m = p4.exec(code)) !== null) {
    routes.push({ method: 'GET', path: m[1] });
  }

  return routes;
}

function extractRustRoutes(code: string): AnalyzedRoute[] {
  const routes: AnalyzedRoute[] = [];
  let m;

  // Pattern 1: #[get("/users/{id}")] — Actix, Rocket
  const p1 = /#\[(get|post|put|delete|patch|head|options)\s*\(\s*"([^"]+)"/gi;
  while ((m = p1.exec(code)) !== null) {
    routes.push({ method: m[1].toUpperCase(), path: m[2] });
  }

  // Pattern 2: .route("/path", web::get().to(handler)) — Actix
  const p2 = /\.route\s*\(\s*"([^"]+)"\s*,\s*web::(get|post|put|delete|patch)/gi;
  while ((m = p2.exec(code)) !== null) {
    routes.push({ method: m[2].toUpperCase(), path: m[1] });
  }

  // Pattern 3: .route("/path", get(handler)) — Axum
  const p3 = /\.route\s*\(\s*"([^"]+)"\s*,\s*(get|post|put|delete|patch)\s*\(/gi;
  while ((m = p3.exec(code)) !== null) {
    routes.push({ method: m[2].toUpperCase(), path: m[1] });
  }

  return routes;
}

function extractCsharpRoutes(code: string): AnalyzedRoute[] {
  const routes: AnalyzedRoute[] = [];
  let m;

  // Pattern 1: [HttpGet("users/{id}")], [HttpPost]
  const p1 = /\[Http(Get|Post|Put|Delete|Patch)\s*\(\s*"?([^"\]]*?)"?\s*\)\]/gi;
  while ((m = p1.exec(code)) !== null) {
    routes.push({ method: m[1].toUpperCase(), path: m[2] || '/' });
  }

  // Pattern 2: app.MapGet("/hello", handler) — Minimal API
  const p2 = /\.Map(Get|Post|Put|Delete|Patch)\s*\(\s*"([^"]+)"/gi;
  while ((m = p2.exec(code)) !== null) {
    routes.push({ method: m[1].toUpperCase(), path: m[2] });
  }

  // Pattern 3: [Route("api/[controller]")] — controller prefix
  const p3 = /\[Route\s*\(\s*"([^"]+)"\s*\)\]/gi;
  const prefixes: string[] = [];
  while ((m = p3.exec(code)) !== null) {
    const rp = m[1].replace(/\[controller\]/gi, '').replace(/\[action\]/gi, '');
    if (rp) prefixes.push(rp);
  }

  // Pattern 4: app.MapGroup("/api") — minimal API prefix
  const p4 = /\.MapGroup\s*\(\s*"([^"]+)"/gi;
  while ((m = p4.exec(code)) !== null) {
    prefixes.push(m[1]);
  }

  if (prefixes.length > 0) {
    const prefix = '/' + prefixes[0].replace(/^\//, '').replace(/\/$/, '');
    for (const route of routes) {
      if (!route.path.startsWith('/')) {
        route.path = prefix + '/' + route.path;
      }
    }
  }

  return routes;
}

function extractRubyRoutes(code: string): AnalyzedRoute[] {
  const routes: AnalyzedRoute[] = [];
  let m;

  // Pattern 1: get '/hello', post "/users"
  const p1 = /\b(get|post|put|patch|delete)\s+['"`]([^'"`]+)['"`]/gi;
  while ((m = p1.exec(code)) !== null) {
    routes.push({ method: m[1].toUpperCase(), path: m[2] });
  }

  // Pattern 2: resources :users → standard CRUD
  const p2 = /\bresources\s+:(\w+)/gi;
  while ((m = p2.exec(code)) !== null) {
    const name = m[1];
    routes.push({ method: 'GET', path: `/${name}` });
    routes.push({ method: 'GET', path: `/${name}/:id` });
    routes.push({ method: 'POST', path: `/${name}` });
    routes.push({ method: 'PUT', path: `/${name}/:id` });
    routes.push({ method: 'DELETE', path: `/${name}/:id` });
  }

  // Pattern 3: resource :profile → singular CRUD
  const p3 = /\bresource\s+:(\w+)/gi;
  while ((m = p3.exec(code)) !== null) {
    const name = m[1];
    routes.push({ method: 'GET', path: `/${name}` });
    routes.push({ method: 'POST', path: `/${name}` });
    routes.push({ method: 'PUT', path: `/${name}` });
    routes.push({ method: 'DELETE', path: `/${name}` });
  }

  return routes;
}

function extractPhpRoutes(code: string): AnalyzedRoute[] {
  const routes: AnalyzedRoute[] = [];
  let m;

  // Pattern 1: Route::get('/users', ...)
  const p1 = /Route::(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/gi;
  while ((m = p1.exec(code)) !== null) {
    routes.push({ method: m[1].toUpperCase(), path: m[2] });
  }

  // Pattern 2: Route::resource('photos', ...) → CRUD
  const p2 = /Route::resource\s*\(\s*['"`]([^'"`]+)['"`]/gi;
  while ((m = p2.exec(code)) !== null) {
    const name = m[1];
    routes.push({ method: 'GET', path: `/${name}` });
    routes.push({ method: 'GET', path: `/${name}/{id}` });
    routes.push({ method: 'POST', path: `/${name}` });
    routes.push({ method: 'PUT', path: `/${name}/{id}` });
    routes.push({ method: 'DELETE', path: `/${name}/{id}` });
  }

  // Pattern 3: $router->get('/users', handler) — Lumen/Slim
  const p3 = /\$\w+->(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/gi;
  while ((m = p3.exec(code)) !== null) {
    routes.push({ method: m[1].toUpperCase(), path: m[2] });
  }

  return routes;
}

function extractElixirRoutes(code: string): AnalyzedRoute[] {
  const routes: AnalyzedRoute[] = [];
  let m;

  // Pattern 1: get "/hello", PageController, :index
  const p1 = /\b(get|post|put|patch|delete)\s+["']([^"']+)["']/gi;
  while ((m = p1.exec(code)) !== null) {
    routes.push({ method: m[1].toUpperCase(), path: m[2] });
  }

  // Pattern 2: resources "/users", UserController → CRUD
  const p2 = /\bresources?\s+["']([^"']+)["']/gi;
  while ((m = p2.exec(code)) !== null) {
    const rpath = m[1];
    routes.push({ method: 'GET', path: rpath });
    routes.push({ method: 'GET', path: `${rpath}/:id` });
    routes.push({ method: 'POST', path: rpath });
    routes.push({ method: 'PUT', path: `${rpath}/:id` });
    routes.push({ method: 'DELETE', path: `${rpath}/:id` });
  }

  return routes;
}

// ---------------------------------------------------------------------------
// Param Normalization — convert framework params to OpenAPI {param} format
// ---------------------------------------------------------------------------

function normalizeParams(routePath: string): string {
  return routePath
    .replace(/:([a-zA-Z_]\w*)/g, '{$1}')    // Express/Rails/Go :id → {id}
    .replace(/<\w+:(\w+)>/g, '{$1}')          // Django <int:id> → {id}
    .replace(/<(\w+)>/g, '{$1}');              // Django <id> → {id}
}

// ---------------------------------------------------------------------------
// Spec Generator
// ---------------------------------------------------------------------------

function routesToSpec(routes: AnalyzedRoute[]): object | null {
  if (routes.length === 0) return null;

  // Deduplicate by method+path
  const seen = new Set<string>();
  const unique: AnalyzedRoute[] = [];
  for (const r of routes) {
    let p = normalizeParams(r.path);
    if (!p.startsWith('/')) p = '/' + p;
    p = p.replace(/\/+/g, '/'); // collapse double slashes
    const key = `${r.method}:${p}`;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push({ method: r.method, path: p });
    }
  }

  const paths: Record<string, Record<string, unknown>> = {};
  for (const r of unique) {
    if (!paths[r.path]) paths[r.path] = {};
    const method = r.method.toLowerCase();
    const op: Record<string, unknown> = {
      responses: { '200': { description: 'OK' } },
    };

    // Extract path parameters
    const params: Array<{ name: string; in: string; required: boolean; schema: { type: string } }> = [];
    const paramRe = /\{([^}]+)\}/g;
    let pm;
    while ((pm = paramRe.exec(r.path)) !== null) {
      params.push({ name: pm[1], in: 'path', required: true, schema: { type: 'string' } });
    }
    if (params.length) op.parameters = params;

    if (method === 'post' || method === 'put' || method === 'patch') {
      op.requestBody = { content: { 'application/json': { schema: { type: 'object' } } } };
    }

    paths[r.path][method] = op;
  }

  // Sort paths alphabetically
  const sortedPaths: Record<string, unknown> = {};
  for (const key of Object.keys(paths).sort()) {
    sortedPaths[key] = paths[key];
  }

  return {
    openapi: '3.0.3',
    info: { title: 'API (auto-discovered)', version: '1.0.0' },
    paths: sortedPaths,
  };
}

// ---------------------------------------------------------------------------
// Main Entry Point
// ---------------------------------------------------------------------------

export function analyzeRoutesFromSource(
  appPath: string,
  framework: string,
): { routes: AnalyzedRoute[]; spec: object } | null {
  try {
    const deadline = Date.now() + SCAN_TIMEOUT_MS;

    const lang = detectLang(appPath, framework);
    if (!lang) return null;

    const extensions = LANG_EXTENSIONS[lang];
    if (!extensions) return null;

    const files = scanSourceFiles(appPath, extensions, deadline);
    if (files.length === 0) return null;

    const allRoutes: AnalyzedRoute[] = [];
    const extractor = getExtractor(lang);

    for (const filePath of files) {
      if (Date.now() > deadline) break;
      try {
        const raw = fs.readFileSync(filePath, 'utf8');
        const code = stripComments(raw, lang);
        const routes = extractor(code);
        allRoutes.push(...routes);
      } catch {}
    }

    if (allRoutes.length === 0) return null;

    const spec = routesToSpec(allRoutes);
    if (!spec) return null;

    return { routes: allRoutes, spec };
  } catch {
    return null;
  }
}

function getExtractor(lang: Lang): (code: string) => AnalyzedRoute[] {
  switch (lang) {
    case 'js': return extractJsTsRoutes;
    case 'python': return extractPythonRoutes;
    case 'go': return extractGoRoutes;
    case 'rust': return extractRustRoutes;
    case 'csharp': return extractCsharpRoutes;
    case 'ruby': return extractRubyRoutes;
    case 'php': return extractPhpRoutes;
    case 'elixir': return extractElixirRoutes;
  }
}
