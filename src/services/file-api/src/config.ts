/**
 * File API Configuration
 *
 * Constants and paths for the code browser backend service.
 */

import * as os from 'os';

// Derive all user paths from the runtime user's home directory
export const HOME = os.homedir();

// Server configuration
export const PORT = 3002;
export const ROOT_DIR = `${HOME}/projects`;

// File paths
export const PATHS = {
  TIER: '/etc/ellulai/security-tier',
  SERVER_ID: '/etc/ellulai/server-id',
  API_URL: '/etc/ellulai/api-url',
  AI_PROXY_TOKEN: '/etc/ellulai/ai-proxy-token',
  DOMAIN: '/etc/ellulai/domain',
  JWT_SECRET: '/etc/ellulai/jwt-secret',
  SSH_AUTH_KEYS: `${HOME}/.ssh/authorized_keys`,
} as const;

// Ignored patterns for file tree
export const IGNORED_PATTERNS = [
  'node_modules',
  '.git',
  '.next',
  'dist',
  'build',
  '.turbo',
  '.cache',
  '__pycache__',
  '.pytest_cache',
  'coverage',
  '.nyc_output',
  'vendor',
  '.idea',
  '.vscode',
  '*.log',
  '.DS_Store',
  'Thumbs.db',
] as const;

// Binary file extensions (don't read content)
export const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp', '.svg',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.zip', '.tar', '.gz', '.rar', '.7z',
  '.exe', '.dll', '.so', '.dylib',
  '.mp3', '.mp4', '.wav', '.avi', '.mov', '.mkv',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.pyc', '.pyo', '.class',
]);

// Max file size for reading (5MB)
export const MAX_FILE_SIZE = 5 * 1024 * 1024;

// WebSocket debounce time for file changes (ms)
export const DEBOUNCE_MS = 500;

// Security tiers
export type SecurityTier = 'standard' | 'web_locked';

export const TIERS = {
  STANDARD: 'standard' as SecurityTier,
  WEB_LOCKED: 'web_locked' as SecurityTier,
} as const;

// App framework detection patterns
export const FRAMEWORK_PATTERNS = {
  nextjs: {
    files: ['next.config.js', 'next.config.mjs', 'next.config.ts'],
    packageJson: ['next'],
  },
  remix: {
    files: ['remix.config.js'],
    packageJson: ['@remix-run/react'],
  },
  astro: {
    files: ['astro.config.mjs', 'astro.config.ts'],
    packageJson: ['astro'],
  },
  vite: {
    files: ['vite.config.js', 'vite.config.ts'],
    packageJson: ['vite'],
  },
  cra: {
    files: [],
    packageJson: ['react-scripts'],
  },
  express: {
    files: [],
    packageJson: ['express'],
  },
  fastify: {
    files: [],
    packageJson: ['fastify'],
  },
  hono: {
    files: [],
    packageJson: ['hono'],
  },
  nestjs: {
    files: ['nest-cli.json'],
    packageJson: ['@nestjs/core'],
  },
  koa: {
    files: [],
    packageJson: ['koa'],
  },
  html: {
    files: ['index.html'],
    packageJson: [],
  },
} as const;

// Default ports by framework
export const DEFAULT_PORTS: Record<string, number> = {
  nextjs: 3000,
  remix: 3000,
  astro: 4321,
  vite: 5173,
  cra: 3000,
  express: 3000,
  fastify: 3000,
  hono: 3000,
  nestjs: 3000,
  koa: 3000,
  html: 3000,
  unknown: 3000,
};

// CORS allowed origins
export const ALLOWED_ORIGINS = [
  'https://ellul.ai',
  'https://www.ellul.ai',
  'http://localhost:3000',
  'http://localhost:5173',
];

// Unauthorized HTML response
export const UNAUTHORIZED_HTML = `<!DOCTYPE html>
<html>
<head><title>Unauthorized</title></head>
<body style="font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;">
<div style="text-align: center;">
<h1 style="color: #dc2626;">401 Unauthorized</h1>
<p>Authentication required. Please sign in to access the file browser.</p>
</div>
</body>
</html>`;
