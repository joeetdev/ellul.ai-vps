/**
 * Caddy Handler Generators
 *
 * Single source of truth for all Caddy route handlers (CORS, auth gates,
 * reverse proxies). Used by both provisioning (caddy.ts) and runtime
 * (ellulai-caddy-gen CLI) to ensure the Caddyfile is always consistent.
 *
 * Handlers use placeholder domains: MAIN_DOMAIN, CODE_DOMAIN_PLACEHOLDER,
 * DEV_DOMAIN_PLACEHOLDER — callers replace these with actual domains.
 */

// ── Constants ──

const CONSOLE_ORIGIN = "https://console.ellul.ai";
const SHIELD_PORT = 3005;
const TERM_PROXY_PORT = 7701;
const FILE_API_PORT = 3002;
const AGENT_BRIDGE_PORT = 7700;
const PREVIEW_PORT = 3000;

interface CorsConfig {
  methods: string;
  headers: string;
}

const SHIELD_CORS: CorsConfig = {
  methods: "GET, POST, DELETE, OPTIONS",
  headers: "Content-Type, Authorization, Cookie, X-Code-Token, X-PoP-Signature, X-PoP-Timestamp, X-PoP-Nonce",
};

const CODE_CORS: CorsConfig = {
  methods: "GET, POST, DELETE, OPTIONS",
  headers: "Content-Type, Authorization, Cookie, X-Code-Token",
};

const STRIP_CORS_DOWNSTREAM = [
  "Access-Control-Allow-Origin",
  "Access-Control-Allow-Methods",
  "Access-Control-Allow-Headers",
  "Access-Control-Allow-Credentials",
  "Access-Control-Max-Age",
  "Access-Control-Expose-Headers",
];

// Shield auth paths — each gets full CORS + OPTIONS preflight + reverse_proxy to shield.
// Order matters: specific paths before catch-all.
const SHIELD_AUTH_PATHS = [
  "/_auth/terminal/*",
  "/_auth/agent/*",
  "/_auth/code/*",
  "/_auth/bridge*",
  "/_auth/*",
];

// Routes behind forward_auth gate to sovereign-shield
interface AuthedRoute {
  path: string;
  backend: number;
  cors?: { methods: string; headers: string };
}

const AUTHED_ROUTES: AuthedRoute[] = [
  { path: "/terminal/sessions", backend: TERM_PROXY_PORT, cors: { methods: "GET, OPTIONS", headers: "Content-Type" } },
  { path: "/terminal/session/*", backend: TERM_PROXY_PORT },
  { path: "/term/*", backend: TERM_PROXY_PORT },
  { path: "/ttyd/*", backend: TERM_PROXY_PORT },
  { path: "/vibe", backend: AGENT_BRIDGE_PORT },
];

// ── Line builder helpers ──

type Lines = string[];

function indent(lines: Lines, depth: number): Lines {
  const pad = "    ".repeat(depth);
  return lines.map(l => (l === "" ? "" : pad + l));
}

function corsHeaders(cors: CorsConfig, depth: number): Lines {
  return indent([
    `header Access-Control-Allow-Origin "${CONSOLE_ORIGIN}"`,
    `header Access-Control-Allow-Methods "${cors.methods}"`,
    `header Access-Control-Allow-Headers "${cors.headers}"`,
    `header Access-Control-Allow-Credentials "true"`,
  ], depth);
}

function corsPreflightBlock(matcherName: string, cors: CorsConfig, depth: number): Lines {
  return [
    ...indent([`@${matcherName} method OPTIONS`], depth),
    ...indent([`handle @${matcherName} {`], depth),
    ...corsHeaders(cors, depth + 1),
    ...indent([`respond "" 204`], depth + 1),
    ...indent([`}`], depth),
  ];
}

function forwardAuthBlock(depth: number, extraHeaders?: string[]): Lines {
  return indent([
    `forward_auth localhost:${SHIELD_PORT} {`,
    `    uri /api/auth/session`,
    `    header_up Cookie {http.request.header.Cookie}`,
    `    header_up Accept {http.request.header.Accept}`,
    `    header_up X-PoP-Signature {http.request.header.X-PoP-Signature}`,
    `    header_up X-PoP-Timestamp {http.request.header.X-PoP-Timestamp}`,
    `    header_up X-PoP-Nonce {http.request.header.X-PoP-Nonce}`,
    `    header_up User-Agent {http.request.header.User-Agent}`,
    `    header_up Sec-Ch-Ua {http.request.header.Sec-Ch-Ua}`,
    `    header_up Sec-Ch-Ua-Mobile {http.request.header.Sec-Ch-Ua-Mobile}`,
    `    header_up Sec-Ch-Ua-Platform {http.request.header.Sec-Ch-Ua-Platform}`,
    `    header_up Sec-Fetch-Dest {http.request.header.Sec-Fetch-Dest}`,
    `    header_up Sec-Fetch-Mode {http.request.header.Sec-Fetch-Mode}`,
    ...(extraHeaders ?? []).map(h => `    header_up ${h}`),
    `    header_up X-Forwarded-Uri {uri}`,
    `    header_up X-Forwarded-Host {host}`,
    `    copy_headers X-Auth-User X-Auth-Tier X-Auth-Session`,
    `}`,
  ], depth);
}

function stripCorsDownstream(depth: number): Lines {
  return indent(STRIP_CORS_DOWNSTREAM.map(h => `header_down -${h}`), depth);
}

// ── Route builders ──

/**
 * Shield auth proxy — CORS + OPTIONS preflight + reverse_proxy to shield.
 * Used for all /_auth/* paths on the main domain.
 */
function shieldAuthRoute(path: string): Lines {
  return [
    `        handle ${path} {`,
    ...corsPreflightBlock("options", SHIELD_CORS, 3),
    "",
    ...corsHeaders(SHIELD_CORS, 3),
    ...indent([`reverse_proxy localhost:${SHIELD_PORT} {`], 3),
    ...stripCorsDownstream(4),
    ...indent([`}`], 3),
    `        }`,
  ];
}

/**
 * Auth-gated reverse proxy — forward_auth to shield, then proxy to backend.
 */
function authedRoute(route: AuthedRoute): Lines {
  const lines: Lines = [`        handle ${route.path} {`];

  if (route.cors) {
    lines.push(...corsPreflightBlock("cors", route.cors, 3));
  }

  lines.push(...forwardAuthBlock(3));

  if (route.cors) {
    lines.push(
      ...indent([`header Access-Control-Allow-Origin "${CONSOLE_ORIGIN}"`], 3),
      ...indent([`header Access-Control-Allow-Credentials "true"`], 3),
    );
  }

  lines.push(...indent([`reverse_proxy localhost:${route.backend}`], 3));
  lines.push(`        }`);
  return lines;
}

// ── Public API ──

/**
 * Generate Caddy route handlers for the given scope.
 * - "ai": code + main handlers (for *.ellul.ai site block)
 * - "app": dev handler only (for *.ellul.app site block)
 * - "all": all handlers in one block (for direct connect / Let's Encrypt)
 */
export function generateCaddyHandlers(scope: "ai" | "app" | "all"): string {
  const lines: Lines = [];

  if (scope === "ai" || scope === "all") {
    lines.push(...codeHandler());
    lines.push(...mainHandler());
  }

  if (scope === "app" || scope === "all") {
    lines.push(...devHandler());
  }

  lines.push(...indent([
    `log {`,
    `    output file /var/log/caddy/access.log`,
    `    format json`,
    `}`,
  ], 1));

  return lines.join("\n");
}

/**
 * Code domain handler — file-api proxy with CORS and auth gate.
 */
function codeHandler(): Lines {
  return [
    "",
    `    @code host CODE_DOMAIN_PLACEHOLDER`,
    `    handle @code {`,
    ...indent([`header Content-Security-Policy "frame-ancestors 'self' ${CONSOLE_ORIGIN}"`], 2),
    "",
    `        # Handle OPTIONS preflight BEFORE auth (no cookies on preflight)`,
    ...corsPreflightBlock("options", CODE_CORS, 2),
    "",
    `        # Non-OPTIONS requests go through auth gate`,
    ...indent([`@notOptions not method OPTIONS`], 2),
    ...indent([`handle @notOptions {`], 2),
    `            # CORS headers on ALL responses (including 502 when backends aren't ready)`,
    ...corsHeaders(CODE_CORS, 3),
    "",
    `            # Auth gate - sovereign-shield checks session/tier before allowing access`,
    ...forwardAuthBlock(3, [
      `X-Requested-With {http.request.header.X-Requested-With}`,
      `X-Code-Token {http.request.header.X-Code-Token}`,
    ]),
    "",
    ...indent([`reverse_proxy localhost:${FILE_API_PORT}`], 3),
    ...indent([`}`], 2),
    `    }`,
  ];
}

/**
 * Dev domain handler — user app preview proxy with auth gate.
 */
function devHandler(): Lines {
  return [
    "",
    `    @dev host DEV_DOMAIN_PLACEHOLDER`,
    `    handle @dev {`,
    ...indent([`@notAuth not path /_auth/*`], 2),
    ...indent([`header @notAuth Content-Security-Policy "frame-ancestors 'self' ${CONSOLE_ORIGIN}"`], 2),
    "",
    `        # CRITICAL: Use route to enforce written order.`,
    `        # Without route, Caddy's standard directive order runs 'uri' BEFORE 'forward_auth',`,
    `        # which would strip _preview_token from the URI before sovereign-shield can read it.`,
    ...indent([`route {`], 2),
    ...forwardAuthBlock(3),
    `            # Strip auth params before forwarding to user's app - prevents 404s from naive routers`,
    ...indent([`uri query -_shield_session`], 3),
    ...indent([`uri query -_preview_token`], 3),
    ...indent([
      `reverse_proxy localhost:${PREVIEW_PORT} {`,
      `    header_up Host localhost`,
      `    header_up X-Real-IP {remote_host}`,
      `}`,
    ], 3),
    ...indent([`}`], 2),
    `    }`,
  ];
}

/**
 * Main (srv) domain handler — sovereign shield, terminals, vibe, static fallback.
 */
function mainHandler(): Lines {
  const lines: Lines = [
    "",
    `    @main host MAIN_DOMAIN`,
    `    handle @main {`,
    ...indent([`@notAuth not path /_auth/*`], 2),
    ...indent([`header @notAuth Content-Security-Policy "frame-ancestors 'self' ${CONSOLE_ORIGIN}"`], 2),
    "",
    `        # Sovereign Shield auth endpoints (port ${SHIELD_PORT})`,
    `        # Includes: terminal, agent, code token authorization, passkey auth, bridge`,
  ];

  for (const path of SHIELD_AUTH_PATHS) {
    if (path === "/_auth/*") {
      lines.push("");
      lines.push(`        # Sovereign Shield - all remaining _auth routes (unified auth)`);
    }
    lines.push(...shieldAuthRoute(path));
    lines.push("");
  }

  for (const route of AUTHED_ROUTES) {
    lines.push(...authedRoute(route));
  }

  // Per-agent OpenClaw gateway routes (dynamically written by agent wrapper)
  lines.push(...indent([`import /etc/caddy/agents.d/*.caddy`], 2));
  lines.push("");

  // Catch-all: auth gate + static landing page.
  // web_locked: sovereign-shield redirects to passkey login
  // standard: sovereign-shield allows navigation through (landing page is public)
  lines.push(
    ...indent([`handle {`], 2),
    ...forwardAuthBlock(3),
    ...indent([`root * /var/www/ellulai`], 3),
    ...indent([`rewrite * /index.html`], 3),
    ...indent([`file_server`], 3),
    ...indent([`}`], 2),
    `    }`,
  );

  return lines;
}
