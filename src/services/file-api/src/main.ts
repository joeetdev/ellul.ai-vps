/**
 * File API Main Entry Point
 *
 * Code browser backend service running on port 3002.
 * Provides file tree, content, git status, project management,
 * app detection, preview control, context management, and real-time WebSocket updates.
 */

import * as http from 'http';
import * as url from 'url';
import * as path from 'path';
import * as fs from 'fs';
import * as crypto from 'crypto';

import { PORT, ROOT_DIR, HOME, PATHS } from './config';
import { getCurrentTier } from './auth';
import {
  getTree,
  getFileContent,
  listProjects,
  getActiveProject,
  setActiveProject,
  parseMultipart,
  uploadFile,
  type UploadedFile,
} from './services/files.service';
import { detectApps } from './services/apps.service';
import { analyzeRoutesFromSource } from './services/openapi-analyzer';
import { getPreviewStatus, getPreviewHealth, setPreviewApp, startPreview, stopPreview, getProjectPort, releaseProjectPort, reconcilePortRegistry, cleanupOrphanedPreviews, getPreviewMetrics, ensureCaddyRoute } from './services/preview.service';
import {
  listContextFiles,
  getContextFile,
  saveContextFile,
  deleteContextFile,
} from './services/context.service';
import { getCurrentTier as getTierFromService } from './services/tier.service';
import { killProcessesOnPorts, restartServices } from './services/processes.service';
import {
  setupWebSocket,
  broadcast,
  initWatchers,
  initServerStatusWatcher,
  initPreviewStatusWatcher,
  startPollingFallback,
} from './services/websocket.service';
import {
  listOpenclawWorkspaceFiles,
  getOpenclawWorkspaceFile,
  saveOpenclawWorkspaceFile,
  getOpenclawChannels,
  saveOpenclawChannel,
  startWhatsAppLogin,
  stopWhatsAppLogin,
  handleWhatsAppQrStream,
  getWhatsAppQrPageHtml,
  getOpenclawLlmKey,
  saveOpenclawLlmKey,
  removeOpenclawLlmKey,
} from './services/openclaw.service';
import codeBrowserHtml from '@ellul.ai/vps-ui/code-browser';

// Auth is handled by sovereign-shield via Caddy forward_auth.
// file-api trusts X-Auth-User headers set by the forward_auth layer.

// Global error handlers
process.on('uncaughtException', (err) => {
  console.error('[file-api] Uncaught exception:', err.message);
  console.error(err.stack);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[file-api] Unhandled rejection at:', promise);
  console.error('[file-api] Reason:', reason);
});

process.on('SIGTERM', () => {
  console.log('[file-api] Received SIGTERM, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('[file-api] Received SIGINT, shutting down gracefully');
  process.exit(0);
});

/**
 * Parse JSON body from request.
 */
function parseBody(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (chunk: Buffer) => (body += chunk.toString()));
    req.on('end', () => {
      try {
        resolve(JSON.parse(body));
      } catch {
        resolve({});
      }
    });
    req.on('error', () => resolve({}));
  });
}

/**
 * Read config file.
 */
function readConfig(): {
  apps: Array<Record<string, unknown>>;
  hidden: string[];
  overrides: Record<string, Record<string, unknown>>;
} {
  const configPath = path.join(ROOT_DIR, '.ellulai.json');
  try {
    if (fs.existsSync(configPath)) {
      return JSON.parse(fs.readFileSync(configPath, 'utf8'));
    }
  } catch {}
  return { apps: [], hidden: [], overrides: {} };
}

/**
 * Write config file.
 */
function writeConfig(config: Record<string, unknown>): void {
  const configPath = path.join(ROOT_DIR, '.ellulai.json');
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
}

// ============================================
// Daemon API authentication (platform-to-VPS RPC)
// JWT signed by the platform API using the server's JWT secret
// ============================================

const DAEMON_PATHS = [
  '/api/mount-volume',
  '/api/flush-volume',
  '/api/migrate/',
  '/api/update-identity',
  '/api/luks-init',
  '/api/luks-unlock',
  '/api/luks-close',
  '/api/backup-identity',
  '/api/restore-identity',
];

function isDaemonPath(pathname: string): boolean {
  return DAEMON_PATHS.some(p => pathname === p || pathname.startsWith(p));
}

function verifyDaemonJwt(authHeader: string | undefined): boolean {
  if (!authHeader?.startsWith('Bearer ')) return false;

  const token = authHeader.slice(7);
  const parts = token.split('.');
  if (parts.length !== 3) return false;

  let jwtSecret: string;
  try {
    jwtSecret = fs.readFileSync(PATHS.JWT_SECRET, 'utf8').trim();
  } catch {
    return false;
  }

  // Verify HMAC-SHA256 signature
  const signInput = `${parts[0]}.${parts[1]}`;
  const expectedSig = crypto
    .createHmac('sha256', jwtSecret)
    .update(signInput)
    .digest('base64url');

  const sigBuf = Buffer.from(parts[2]!, 'base64url');
  const expectedBuf = Buffer.from(expectedSig, 'base64url');
  if (sigBuf.length !== expectedBuf.length) return false;
  if (!crypto.timingSafeEqual(sigBuf, expectedBuf)) return false;

  // Verify payload
  try {
    const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString());
    if (payload.purpose !== 'daemon-call') return false;
    if (payload.exp && payload.exp < Date.now() / 1000) return false;
    return true;
  } catch {
    return false;
  }
}

// In-memory cache for OpenAPI spec detection (path + spec, 30s TTL)
const openApiSpecCache = new Map<string, { path: string; spec: unknown; timestamp: number }>();

// Create HTTP server
const server = http.createServer(async (req, res) => {
  // CORS is handled by Caddy (edge proxy) - file-api only runs on localhost
  // Caddy adds CORS headers and strips any duplicate backend headers via header_down
  res.setHeader('Content-Type', 'application/json');

  // Caddy handles OPTIONS preflight, but handle here as safety fallback
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const parsedUrl = url.parse(req.url || '', true);
  const pathname = parsedUrl.pathname || '/';

  // Get headers as record
  const headers: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(req.headers)) {
    headers[key] = Array.isArray(value) ? value[0] : value;
  }

  // Daemon API authentication — platform-to-VPS calls via port 3006
  // These endpoints require a valid JWT signed with the server's secret
  const isDaemon = isDaemonPath(pathname);
  if (isDaemon) {
    if (!verifyDaemonJwt(headers['authorization'])) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }
    // JWT valid — skip tier-based auth below, proceed directly to endpoint handler
  }

  // Security tier enforcement (skipped for daemon-authenticated requests)
  if (!isDaemon) {
    const currentTier = getCurrentTier();

    // Web Locked mode - sovereign-shield is the sole auth gate via Caddy forward_auth
    // All requests go through forward_auth which validates code_session and sets X-Auth-User
    if (currentTier === 'web_locked') {
      const forwardAuthUser = headers['x-auth-user'];

      if (!forwardAuthUser) {
        // No X-Auth-User means forward_auth didn't approve this request
        // This should only happen if something bypassed Caddy (shouldn't be possible)
        console.log('[file-api] SECURITY: Request without X-Auth-User in web_locked mode');
        res.writeHead(401);
        res.end(
          JSON.stringify({
            error: 'Authentication required',
            message: 'Request must be authenticated via sovereign-shield',
            tier: 'web_locked',
          })
        );
        return;
      }

      console.log('[file-api] Authenticated via sovereign-shield:', forwardAuthUser);
    }
  }

  // Resolve app identifier to directory name
  // Primary: directory (the unique identifier used throughout the system)
  // Fallback: display name lookup (for backward compatibility)
  function resolveProjectDir(identifier: string): string | null {
    // Direct directory match (primary - this is what the frontend sends)
    if (fs.existsSync(path.join(ROOT_DIR, identifier))) return identifier;
    // Fallback: look up by display name for backward compatibility
    const apps = detectApps();
    const match = apps.find(a => a.name === identifier);
    return match?.directory || null;
  }

  // Project path resolution
  const requestedProject = parsedUrl.query.project as string | undefined;
  const showRoot = !requestedProject;
  const resolvedProject = requestedProject ? resolveProjectDir(requestedProject) : null;
  const activeProject = resolvedProject || getActiveProject();
  const projectPath = showRoot ? ROOT_DIR : path.join(ROOT_DIR, activeProject);

  try {
    // ============================================
    // Code Browser SPA (VPS-served iframe)
    // ============================================

    if (pathname === '/browser') {
      // NOTE: Nonce-based CSP is NOT compatible with pre-built SPA bundles because
      // bundled JS contains string literals like innerHTML="<script>" which regex
      // nonce injection corrupts. Use 'unsafe-inline' — real protection is
      // frame-ancestors + auth cookies + sovereign-shield.
      const csp = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self' data:",
        "connect-src 'self' wss:",
        "frame-ancestors 'self' https://console.ellul.ai",
        "base-uri 'self'",
        "form-action 'none'",
        "object-src 'none'",
      ].join('; ');

      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': csp,
        'Cache-Control': 'no-store',
      });
      res.end(codeBrowserHtml);
      return;
    }

    // ============================================
    // File API endpoints
    // Auth: sovereign-shield via Caddy forward_auth (port 3005)
    // ============================================

    // GET /api/tree
    if (pathname === '/api/tree') {
      const tree = getTree(projectPath);
      res.writeHead(200);
      res.end(JSON.stringify({ project: showRoot ? 'projects' : (requestedProject || activeProject), tree }));
      return;
    }

    // GET /api/file
    if (pathname === '/api/file') {
      let relativePath = parsedUrl.query.path as string;
      if (!relativePath) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Missing path parameter' }));
        return;
      }

      // Resolve display name prefix in path (e.g., "Hello World/index.html" → "hello-world/index.html")
      const slashIdx = relativePath.indexOf('/');
      if (slashIdx > 0) {
        const prefix = relativePath.substring(0, slashIdx);
        const resolved = resolveProjectDir(prefix);
        if (resolved && resolved !== prefix) {
          relativePath = resolved + relativePath.substring(slashIdx);
        }
      }

      const result = getFileContent(relativePath, projectPath);
      if (result.error) {
        res.writeHead(result.statusCode);
        res.end(JSON.stringify({ error: result.error }));
        return;
      }

      res.setHeader('Content-Type', 'text/plain');
      res.writeHead(200);
      res.end(result.content);
      return;
    }

    // POST /api/fs/upload
    if (req.method === 'POST' && pathname === '/api/fs/upload') {
      try {
        const chunks: Buffer[] = [];
        for await (const chunk of req) {
          chunks.push(chunk);
        }
        const buffer = Buffer.concat(chunks);
        const contentType = headers['content-type'] || '';
        const parts = parseMultipart(buffer, contentType);

        const file = parts.file as UploadedFile | undefined;
        if (!file || !file.data) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'No file provided' }));
          return;
        }

        const destPath = (parts.path as string) || undefined;
        const targetProject = (parts.project as string) || activeProject;

        const result = uploadFile(file, destPath, targetProject);
        res.writeHead(result.success ? 200 : 400);
        res.end(JSON.stringify(result));
      } catch (e) {
        const error = e as Error;
        res.writeHead(500);
        res.end(JSON.stringify({ error: 'Upload failed: ' + error.message }));
      }
      return;
    }

    // GET /api/tier
    if (pathname === '/api/tier') {
      const tier = getTierFromService();
      res.writeHead(200);
      res.end(JSON.stringify({ tier }));
      return;
    }

    // POST /api/restart-services
    if (req.method === 'POST' && pathname === '/api/restart-services') {
      const tier = getTierFromService();
      const result = restartServices(tier);
      res.writeHead(result.success ? 200 : 500);
      res.end(JSON.stringify(result));
      return;
    }

    // GET /api/status
    if (pathname === '/api/status') {
      const { exec } = await import('child_process');
      const runCmd = (cmd: string): Promise<string> =>
        new Promise((resolve) => {
          exec(cmd, { cwd: projectPath, timeout: 5000 }, (err, stdout) => {
            resolve(err ? '' : stdout.trim());
          });
        });

      const statusOutput = await runCmd('git status --porcelain');
      const diffOutput = await runCmd('git diff --stat');

      const modified: Array<{ status: string; file: string }> = [];
      if (statusOutput) {
        for (const line of statusOutput.split('\n')) {
          if (line.trim()) {
            const statusCode = line.substring(0, 2);
            const file = line.substring(3);
            modified.push({ status: statusCode.trim() || 'M', file });
          }
        }
      }

      res.writeHead(200);
      res.end(
        JSON.stringify({
          project: activeProject,
          modified,
          stats: diffOutput || '',
        })
      );
      return;
    }

    // GET /api/projects
    if (pathname === '/api/projects') {
      const result = listProjects();
      res.writeHead(200);
      res.end(JSON.stringify(result));
      return;
    }

    // GET /api/apps
    if (pathname === '/api/apps') {
      const detectedApps = detectApps();
      const config = readConfig();
      const configPath = path.join(ROOT_DIR, '.ellulai.json');
      const hasConfig = fs.existsSync(configPath);

      // Filter out hidden apps (check both directory and name for backward compat)
      const hidden = new Set(config.hidden || []);
      const visibleApps = detectedApps.filter((a) => !hidden.has(a.directory) && !hidden.has(a.name));

      // Apply any user overrides from config (check directory first, then name for backward compat)
      const apps = visibleApps.map((app) => {
        const overrides = config.overrides || {};
        const override = overrides[app.directory] || overrides[app.name];
        if (!override) return app;
        return {
          ...app,
          type: (override.type as typeof app.type) || app.type,
          previewable: override.previewable !== undefined ? override.previewable as boolean : app.previewable,
          framework: (override.framework as string) || app.framework,
        };
      });

      res.writeHead(200);
      res.end(JSON.stringify({ apps, hasConfig }));
      return;
    }

    // GET/POST /api/apps/config
    if (pathname === '/api/apps/config') {
      if (req.method === 'GET') {
        const config = readConfig();
        res.writeHead(200);
        res.end(JSON.stringify(config));
        return;
      }

      if (req.method === 'POST') {
        const body = await parseBody(req);
        const config = readConfig();

        const action = body.action as string;
        const appName = body.app as string;

        if (action === 'hide') {
          config.hidden = config.hidden || [];
          if (!config.hidden.includes(appName)) {
            config.hidden.push(appName);
          }
        } else if (action === 'unhide') {
          config.hidden = (config.hidden || []).filter((h) => h !== appName);
        } else if (action === 'override') {
          config.overrides = config.overrides || {};
          config.overrides[appName] = {
            ...(config.overrides[appName] || {}),
            ...(body.properties as Record<string, unknown>),
          };
        } else if (action === 'removeOverride') {
          if (config.overrides) {
            delete config.overrides[appName];
          }
        } else if (action === 'addApp') {
          config.apps = config.apps || [];
          const newApp = body.app as Record<string, unknown>;
          if (!config.apps.find((a) => a.name === newApp.name)) {
            config.apps.push(newApp);
          }
        } else if (action === 'removeApp') {
          config.apps = (config.apps || []).filter((a) => a.name !== appName);
        } else if (action === 'setConfig') {
          writeConfig(body.config as Record<string, unknown>);
          res.writeHead(200);
          res.end(JSON.stringify({ success: true }));
          return;
        }

        writeConfig(config);
        res.writeHead(200);
        res.end(JSON.stringify({ success: true, config }));
        return;
      }
    }

    // POST /api/apps/create - Create a new app (blank or from git)
    if (req.method === 'POST' && pathname === '/api/apps/create') {
      const body = await parseBody(req);
      const { name, type } = body as { name: string; type: 'blank' | 'git' };

      if (!name || !type) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'Missing name or type' }));
        return;
      }

      // Sanitize name for directory (lowercase, alphanumeric + dashes)
      const dirName = name.toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
      const appPath = path.join(ROOT_DIR, dirName);

      if (fs.existsSync(appPath)) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'App directory already exists' }));
        return;
      }

      if (type === 'blank') {
        // Create blank app - just directory + ellulai.json with unknown type
        try {
          fs.mkdirSync(appPath, { recursive: true });

          // Create ellulai.json with minimal config
          const ellulaiConfig = {
            name: name,
            type: 'unknown',
            previewable: false,
          };
          fs.writeFileSync(
            path.join(appPath, 'ellulai.json'),
            JSON.stringify(ellulaiConfig, null, 2)
          );

          // Initialize OpenClaw workspace files + create agent (fire-and-forget)
          try {
            const { exec: execCmd } = await import('child_process');
            // Write minimal OpenClaw workspace files into .openclaw/ subdirectory.
            // Keeps them separate from CLI context files (CLAUDE.md, AGENTS.md) in root.
            const ocDir = path.join(appPath, '.openclaw');
            if (!fs.existsSync(ocDir)) fs.mkdirSync(ocDir, { recursive: true });
            const soulPath = path.join(ocDir, 'SOUL.md');
            if (!fs.existsSync(soulPath)) {
              fs.writeFileSync(soulPath, `# SOUL.md — Dev Assistant\n\nYou are a focused development assistant for the **${dirName}** project.\n\n## Core Principles\n- **Ship code, not conversation.** Help the user build, debug, and deploy.\n- **Be concise and action-oriented.** Suggest what to do next, don't philosophize.\n- **Read before asking.** Check project files, README, package.json before asking the user what the project is.\n- **Stay in scope.** All work happens inside this project directory.\n\n## CLI Setup\nIf a CLI tool isn't authenticated, help the user set it up.\nOutput [SETUP_CLI:toolname] and the system handles the rest — don't try to run login commands yourself.\n`, 'utf8');
            }
            const heartbeatPath = path.join(ocDir, 'HEARTBEAT.md');
            if (!fs.existsSync(heartbeatPath)) {
              fs.writeFileSync(heartbeatPath, '# Keep empty to skip heartbeat checks for dev agents.\n', 'utf8');
            }

            const ocWorkspace = path.join(appPath, '.openclaw');
            execCmd(`openclaw agents add "dev-${dirName}" --workspace "${ocWorkspace}" --non-interactive`, { timeout: 15000 }, (err) => {
              if (err) console.warn(`[file-api] OpenClaw agent creation failed for ${dirName}:`, err.message);
              else console.log(`[file-api] OpenClaw agent "dev-${dirName}" created`);
            });
          } catch {}

          // Return app info
          const app = {
            name: name,
            directory: dirName,
            path: appPath,
            framework: 'unknown',
            scripts: [],
            type: 'unknown' as const,
            previewable: false,
          };

          res.writeHead(200);
          res.end(JSON.stringify({ success: true, app }));
          return;
        } catch (e) {
          const error = e as Error;
          res.writeHead(500);
          res.end(JSON.stringify({ success: false, error: error.message }));
          return;
        }
      }

      if (type === 'git') {
        const { provider, repoFullName } = body as { provider: string; repoFullName: string };

        if (!provider || !repoFullName) {
          res.writeHead(400);
          res.end(JSON.stringify({ success: false, error: 'Missing provider or repoFullName' }));
          return;
        }

        // SECURITY: Validate repoFullName to prevent command injection
        if (!/^[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+$/.test(repoFullName)) {
          res.writeHead(400);
          res.end(JSON.stringify({ success: false, error: 'Invalid repository name format (expected owner/repo)' }));
          return;
        }

        // Read git credentials from config
        const gitCredsPath = path.join(ROOT_DIR, '.ellulai', 'git-credentials.json');
        let gitCreds: Record<string, { token?: string }> = {};
        try {
          if (fs.existsSync(gitCredsPath)) {
            gitCreds = JSON.parse(fs.readFileSync(gitCredsPath, 'utf8'));
          }
        } catch {}

        const providerCreds = gitCreds[provider];
        if (!providerCreds?.token) {
          res.writeHead(400);
          res.end(JSON.stringify({ success: false, error: `No credentials found for ${provider}. Please connect your ${provider} account first.` }));
          return;
        }

        // Build clone URL with token
        let cloneUrl: string;
        if (provider === 'github') {
          cloneUrl = `https://${providerCreds.token}@github.com/${repoFullName}.git`;
        } else if (provider === 'gitlab') {
          cloneUrl = `https://oauth2:${providerCreds.token}@gitlab.com/${repoFullName}.git`;
        } else if (provider === 'bitbucket') {
          cloneUrl = `https://x-token-auth:${providerCreds.token}@bitbucket.org/${repoFullName}.git`;
        } else {
          res.writeHead(400);
          res.end(JSON.stringify({ success: false, error: `Unsupported provider: ${provider}` }));
          return;
        }

        // Clone the repo — use spawn (no shell) to prevent command injection
        const { exec, spawn } = await import('child_process');
        const cloneResult = await new Promise<{ success: boolean; error?: string }>((resolve) => {
          const proc = spawn('git', ['clone', cloneUrl, appPath], { timeout: 120000, stdio: 'pipe' });
          let stderr = '';
          proc.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });
          proc.on('close', (code) => {
            if (code !== 0) resolve({ success: false, error: stderr || `git clone exited with code ${code}` });
            else resolve({ success: true });
          });
          proc.on('error', (err) => resolve({ success: false, error: err.message }));
        });

        if (!cloneResult.success) {
          res.writeHead(500);
          res.end(JSON.stringify({ success: false, error: `Clone failed: ${cloneResult.error}` }));
          return;
        }

        // Detect framework from cloned repo
        const detected = detectApps().find(a => a.directory === dirName);
        const inferredType = detected?.type || 'unknown';
        const inferredFramework = detected?.framework || 'unknown';
        const inferredPreviewable = detected?.previewable ?? false;

        // Create ellulai.json if not exists
        const ellulaiPath = path.join(appPath, 'ellulai.json');
        if (!fs.existsSync(ellulaiPath)) {
          const ellulaiConfig = {
            name: name,
            type: inferredType,
            framework: inferredFramework,
            previewable: inferredPreviewable,
          };
          fs.writeFileSync(ellulaiPath, JSON.stringify(ellulaiConfig, null, 2));
        }

        // Run npm install in background (don't block response)
        const packageJsonPath = path.join(appPath, 'package.json');
        if (fs.existsSync(packageJsonPath)) {
          const npmInstall = spawn('npm', ['install'], {
            cwd: appPath,
            detached: true,
            stdio: 'ignore',
          });
          npmInstall.unref();
        }

        // Create OpenClaw agent for the new project (fire-and-forget)
        try {
          const ocWorkspace = path.join(appPath, '.openclaw');
          exec(`mkdir -p "${ocWorkspace}" && openclaw agents add "dev-${dirName}" --workspace "${ocWorkspace}" --non-interactive`, { timeout: 15000 }, (err) => {
            if (err) console.warn(`[file-api] OpenClaw agent creation failed for ${dirName}:`, err.message);
            else console.log(`[file-api] OpenClaw agent "dev-${dirName}" created`);
          });
        } catch {}

        // Return app info
        const app = {
          name: name,
          directory: dirName,
          path: appPath,
          framework: inferredFramework,
          scripts: detected?.scripts || [],
          type: inferredType,
          previewable: inferredPreviewable,
        };

        res.writeHead(200);
        res.end(JSON.stringify({ success: true, app }));
        return;
      }

      res.writeHead(400);
      res.end(JSON.stringify({ success: false, error: `Invalid type: ${type}` }));
      return;
    }

    // POST /api/active-project - Set the active project (for sidebar clicks)
    if (req.method === 'POST' && pathname === '/api/active-project') {
      const body = await parseBody(req);
      const project = body.project as string;
      if (!project) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'Missing project' }));
        return;
      }
      const success = setActiveProject(project);
      res.writeHead(success ? 200 : 404);
      res.end(JSON.stringify({ success, project }));
      return;
    }

    // DELETE /api/apps/:directory - Delete an app with full cleanup
    if (req.method === 'DELETE' && pathname.startsWith('/api/apps/')) {
      const appIdentifier = decodeURIComponent(pathname.replace('/api/apps/', ''));

      if (!appIdentifier) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'Missing app identifier' }));
        return;
      }

      // Find the app by directory (primary) or name (backward compat)
      const apps = detectApps();
      const app = apps.find(a => a.directory === appIdentifier || a.name === appIdentifier);

      if (!app) {
        res.writeHead(404);
        res.end(JSON.stringify({ success: false, error: 'App not found' }));
        return;
      }

      const appPath = path.join(ROOT_DIR, app.directory);

      // Safety checks - don't delete if path is outside ROOT_DIR
      const resolvedPath = path.resolve(appPath);
      if (!resolvedPath.startsWith(ROOT_DIR) || resolvedPath === ROOT_DIR) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'Invalid app path' }));
        return;
      }

      const { exec } = await import('child_process');
      const runCmd = (cmd: string): Promise<{ success: boolean; output: string; error?: string }> =>
        new Promise((resolve) => {
          exec(cmd, { timeout: 30000 }, (err, stdout, stderr) => {
            resolve({
              success: !err,
              output: stdout.trim(),
              error: err ? stderr.trim() || err.message : undefined,
            });
          });
        });

      const cleanup: string[] = [];

      // Find this app's deployment metadata by matching projectPath
      // This ensures we only clean up resources that belong to THIS specific app
      const appsMetaDir = `${HOME}/.ellulai/apps`;
      let deployedAppName: string | null = null;
      let deployedMetaFile: string | null = null;

      if (fs.existsSync(appsMetaDir)) {
        try {
          const metaFiles = fs.readdirSync(appsMetaDir).filter(f => f.endsWith('.json'));
          for (const metaFile of metaFiles) {
            const metaPath = path.join(appsMetaDir, metaFile);
            try {
              const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
              // Match by projectPath to ensure we have the exact app
              if (meta.projectPath === appPath) {
                deployedAppName = meta.name;
                deployedMetaFile = metaPath;
                break;
              }
            } catch {
              // Skip invalid JSON files
            }
          }
        } catch {
          // Can't read apps dir, skip deployment cleanup
        }
      }

      try {
        // 1. Stop PM2 process - ONLY if we found a matching deployment
        if (deployedAppName) {
          // Use exact name from deployment metadata
          const pm2Result = await runCmd(`pm2 delete "${deployedAppName}" 2>/dev/null || true`);
          if (pm2Result.success) cleanup.push('pm2');
        }

        // 1.5 Stop preview PM2 process and release port
        try {
          await runCmd(`pm2 delete "preview-${app.directory}" 2>/dev/null || true`);
          cleanup.push('preview-pm2');
        } catch {}
        try {
          releaseProjectPort(app.directory);
          cleanup.push('preview-port');
        } catch {}

        // 2. Remove Caddy config - ONLY the file that matches our deployment
        if (deployedAppName) {
          const caddyConfigPath = `/etc/caddy/sites-enabled/${deployedAppName}.caddy`;
          if (fs.existsSync(caddyConfigPath)) {
            fs.unlinkSync(caddyConfigPath);
            cleanup.push('caddy-config');
          }
        }

        // 3. Remove app metadata JSON - the specific file we found
        if (deployedMetaFile && fs.existsSync(deployedMetaFile)) {
          fs.unlinkSync(deployedMetaFile);
          cleanup.push('app-metadata');
        }

        // 4. Clean up app-specific secrets from ~/.ellulai-env
        // Use exact matching with the deployed app name (not pattern matching)
        if (deployedAppName) {
          const envFilePath = `${HOME}/.ellulai-env`;
          if (fs.existsSync(envFilePath)) {
            try {
              const envContent = fs.readFileSync(envFilePath, 'utf8');
              const lines = envContent.split('\n');
              // Exact suffix match: __SECRETNAME__exactappname=
              const suffix = `__${deployedAppName}=`;
              const filteredLines = lines.filter(line => {
                // Keep line unless it's an export with our exact app suffix
                if (!line.startsWith('export __')) return true;
                // Check if this line ends with __appname= (exact match)
                const eqIndex = line.indexOf('=');
                if (eqIndex === -1) return true;
                const varName = line.substring(7, eqIndex); // After "export "
                return !varName.endsWith(`__${deployedAppName}`);
              });
              const cleanedContent = filteredLines.join('\n');
              if (cleanedContent !== envContent) {
                fs.writeFileSync(envFilePath, cleanedContent);
                cleanup.push('env-secrets');
              }
            } catch (e) {
              console.warn(`[file-api] Could not clean env secrets: ${(e as Error).message}`);
            }
          }
        }

        // 5. Clean up app-specific git credentials - exact key match only
        if (deployedAppName) {
          const gitCredsPath = `${HOME}/.ellulai/git-credentials.json`;
          if (fs.existsSync(gitCredsPath)) {
            try {
              const gitCreds = JSON.parse(fs.readFileSync(gitCredsPath, 'utf8'));
              // Only delete the exact key matching our deployed app name
              if (Object.prototype.hasOwnProperty.call(gitCreds, deployedAppName)) {
                delete gitCreds[deployedAppName];
                fs.writeFileSync(gitCredsPath, JSON.stringify(gitCreds, null, 2));
                cleanup.push('git-credentials');
              }
            } catch (e) {
              console.warn(`[file-api] Could not clean git credentials: ${(e as Error).message}`);
            }
          }
        }

        // 6. Reload Caddy to apply config changes (only if we removed a config)
        if (cleanup.includes('caddy-config')) {
          await runCmd('systemctl reload caddy 2>/dev/null || systemctl restart caddy 2>/dev/null || true');
          cleanup.push('caddy-reload');
        }

        // 7. Delete OpenClaw agent for this project
        try {
          await runCmd(`openclaw agents delete "dev-${app.directory}" 2>/dev/null || true`);
          cleanup.push('openclaw-agent');
        } catch {}

        // 7.5. Clean up chat threads for this project
        try {
          const cleanupReq = http.request(
            { hostname: '127.0.0.1', port: 7700, path: '/api/cleanup-project', method: 'POST',
              headers: { 'Content-Type': 'application/json' } },
            (cleanupRes) => {
              if (cleanupRes.statusCode === 200) cleanup.push('threads');
            }
          );
          cleanupReq.write(JSON.stringify({ project: app.directory }));
          cleanupReq.end();
          // Fire-and-forget — don't block delete on thread cleanup
        } catch {}

        // 7.6. Remove deployment snapshot if it exists
        try {
          const deploymentPath = `${HOME}/.ellulai/deployments/${app.directory}`;
          if (fs.existsSync(deploymentPath)) {
            fs.rmSync(deploymentPath, { recursive: true, force: true });
            cleanup.push('deployment-snapshot');
          }
        } catch {}

        // 8. Remove the app directory recursively
        fs.rmSync(appPath, { recursive: true, force: true });
        cleanup.push('directory');

        // 9. If deleted app was the active project, clear persistence so it falls back
        try {
          const activeFile = `${HOME}/.ellulai/active-project`;
          if (fs.existsSync(activeFile) && fs.readFileSync(activeFile, 'utf8').trim() === app.directory) {
            fs.unlinkSync(activeFile);
          }
        } catch {}

        console.log(`[file-api] Deleted app "${app.name}" with cleanup: ${cleanup.join(', ')}`);

        res.writeHead(200);
        res.end(JSON.stringify({ success: true, deleted: app.name, cleanup }));
        return;
      } catch (e) {
        const error = e as Error;
        console.error(`[file-api] Error deleting app "${app.name}":`, error.message);
        res.writeHead(500);
        res.end(JSON.stringify({ success: false, error: error.message, partialCleanup: cleanup }));
        return;
      }
    }

    // GET /api/deployment/:name/versions - List available deployment versions
    if (req.method === 'GET' && pathname.match(/^\/api\/deployment\/[^/]+\/versions$/)) {
      const parts = pathname.split('/');
      const deployName = decodeURIComponent(parts[3] || '');

      if (!deployName || !/^[a-z0-9][a-z0-9-]*$/.test(deployName)) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Invalid deployment name' }));
        return;
      }

      const deployPath = path.join(HOME, '.ellulai', 'deployments', deployName);
      if (!fs.existsSync(deployPath)) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'Deployment not found', name: deployName }));
        return;
      }

      // Read timestamp directories, resolve current symlink
      const entries = fs.readdirSync(deployPath).filter(e => /^\d+$/.test(e)).sort((a, b) => Number(a) - Number(b));
      let currentTs: string | null = null;
      try {
        const target = fs.readlinkSync(path.join(deployPath, 'current'));
        currentTs = path.basename(target);
      } catch { /* no current symlink */ }

      const versions = entries.map((ts, i) => ({
        id: ts,
        label: `Version ${i + 1}`,
        timestamp: Number(ts),
        isCurrent: ts === currentTs,
      }));

      res.writeHead(200);
      res.end(JSON.stringify({ versions }));
      return;
    }

    // GET /api/deployment/:name/tree - Get file tree for a deployment snapshot
    if (req.method === 'GET' && pathname.match(/^\/api\/deployment\/[^/]+\/tree$/)) {
      const parts = pathname.split('/');
      const deployName = decodeURIComponent(parts[3] || '');

      if (!deployName || !/^[a-z0-9][a-z0-9-]*$/.test(deployName)) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Invalid deployment name' }));
        return;
      }

      const deployPath = path.join(HOME, '.ellulai', 'deployments', deployName);
      if (!fs.existsSync(deployPath)) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'Deployment snapshot not found', name: deployName }));
        return;
      }

      // Resolve version: ?version=<timestamp> or default to current symlink
      const versionParam = parsedUrl.query.version as string | undefined;
      let snapshotPath: string;
      if (versionParam && /^\d+$/.test(versionParam)) {
        snapshotPath = path.join(deployPath, versionParam);
      } else {
        snapshotPath = path.join(deployPath, 'current');
      }

      if (!fs.existsSync(snapshotPath)) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'Version not found', name: deployName }));
        return;
      }

      const tree = getTree(snapshotPath);
      res.writeHead(200);
      res.end(JSON.stringify({ root: deployName, tree }));
      return;
    }

    // GET /api/deployment/:name/file?path=... - Get file content from a deployment snapshot
    if (req.method === 'GET' && pathname.match(/^\/api\/deployment\/[^/]+\/file$/)) {
      const parts = pathname.split('/');
      const deployName = decodeURIComponent(parts[3] || '');

      if (!deployName || !/^[a-z0-9][a-z0-9-]*$/.test(deployName)) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Invalid deployment name' }));
        return;
      }

      const filePath = parsedUrl.query.path as string;
      if (!filePath) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Missing path parameter' }));
        return;
      }

      const deployPath = path.join(HOME, '.ellulai', 'deployments', deployName);
      if (!fs.existsSync(deployPath)) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'Deployment snapshot not found', name: deployName }));
        return;
      }

      // Resolve version: ?version=<timestamp> or default to current symlink
      const versionParam = parsedUrl.query.version as string | undefined;
      let snapshotPath: string;
      if (versionParam && /^\d+$/.test(versionParam)) {
        snapshotPath = path.join(deployPath, versionParam);
      } else {
        snapshotPath = path.join(deployPath, 'current');
      }

      if (!fs.existsSync(snapshotPath)) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'Version not found', name: deployName }));
        return;
      }

      const result = getFileContent(filePath, snapshotPath);
      if (result.error) {
        res.writeHead(result.statusCode);
        res.end(JSON.stringify({ error: result.error }));
        return;
      }

      res.setHeader('Content-Type', 'text/plain');
      res.writeHead(200);
      res.end(result.content);
      return;
    }

    // GET /api/deployment/:name/logs - Get PM2 logs for a deployment
    if (req.method === 'GET' && pathname.match(/^\/api\/deployment\/[^/]+\/logs$/)) {
      const parts = pathname.split('/');
      const deployName = decodeURIComponent(parts[3] || '');

      if (!deployName || !/^[a-z0-9][a-z0-9-]*$/.test(deployName)) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Invalid deployment name' }));
        return;
      }

      const linesParam = parseInt(parsedUrl.query.lines as string || '100', 10);
      const lines = Math.min(Math.max(linesParam, 1), 500);
      const logType = (parsedUrl.query.type as string) || 'all';

      if (!['out', 'err', 'all'].includes(logType)) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Invalid type parameter (out, err, all)' }));
        return;
      }

      const pm2LogDir = path.join(HOME, '.pm2', 'logs');
      const result: Array<{ line: string; type: 'out' | 'err' }> = [];

      const readLogTail = (filePath: string, type: 'out' | 'err'): Array<{ line: string; type: 'out' | 'err' }> => {
        try {
          if (!fs.existsSync(filePath)) return [];
          const content = fs.readFileSync(filePath, 'utf8');
          const allLines = content.split('\n').filter(l => l.trim());
          return allLines.slice(-lines).map(line => ({ line, type }));
        } catch {
          return [];
        }
      };

      if (logType === 'out' || logType === 'all') {
        result.push(...readLogTail(path.join(pm2LogDir, `${deployName}-out.log`), 'out'));
      }
      if (logType === 'err' || logType === 'all') {
        result.push(...readLogTail(path.join(pm2LogDir, `${deployName}-error.log`), 'err'));
      }

      // For 'all', keep order as stdout first then stderr (no timestamps to interleave)
      // Limit total to requested lines
      const limited = result.slice(-lines);

      res.writeHead(200);
      res.end(JSON.stringify({ logs: limited, name: deployName }));
      return;
    }

    // POST /api/deployment/:name/redeploy - Trigger redeployment via sovereign-shield
    if (req.method === 'POST' && pathname.match(/^\/api\/deployment\/[^/]+\/redeploy$/)) {
      const parts = pathname.split('/');
      const deployName = decodeURIComponent(parts[3] || '');

      if (!deployName || !/^[a-z0-9][a-z0-9-]*$/.test(deployName)) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Invalid deployment name' }));
        return;
      }

      // Read app metadata to get deploy params
      const metaFile = path.join(HOME, '.ellulai', 'apps', `${deployName}.json`);
      if (!fs.existsSync(metaFile)) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'Deployment not found' }));
        return;
      }

      let meta: Record<string, unknown>;
      try {
        meta = JSON.parse(fs.readFileSync(metaFile, 'utf8'));
      } catch {
        res.writeHead(500);
        res.end(JSON.stringify({ error: 'Failed to read deployment metadata' }));
        return;
      }

      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 120000);

        const shieldRes = await fetch('http://127.0.0.1:3005/api/workflow/expose', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: meta.name,
            port: meta.port,
            projectPath: meta.projectPath,
            stack: meta.stack,
          }),
          signal: controller.signal,
        });
        clearTimeout(timeout);

        const shieldData = await shieldRes.json();

        if (!shieldRes.ok) {
          res.writeHead(shieldRes.status);
          res.end(JSON.stringify(shieldData));
          return;
        }

        res.writeHead(200);
        res.end(JSON.stringify(shieldData));
      } catch (e) {
        res.writeHead(500);
        res.end(JSON.stringify({ error: `Redeploy failed: ${(e as Error).message}` }));
      }
      return;
    }

    // DELETE /api/deployment/:name - Remove a deployment via sovereign-shield
    if (req.method === 'DELETE' && pathname.match(/^\/api\/deployment\/[^/]+$/) && !pathname.includes('/tree') && !pathname.includes('/file') && !pathname.includes('/logs') && !pathname.includes('/redeploy')) {
      const parts = pathname.split('/');
      const deployName = decodeURIComponent(parts[3] || '');

      if (!deployName || !/^[a-z0-9][a-z0-9-]*$/.test(deployName)) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Invalid deployment name' }));
        return;
      }

      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 30000);

        const shieldRes = await fetch('http://127.0.0.1:3005/api/workflow/remove', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: deployName }),
          signal: controller.signal,
        });
        clearTimeout(timeout);

        const shieldData = await shieldRes.json();

        if (!shieldRes.ok) {
          res.writeHead(shieldRes.status);
          res.end(JSON.stringify(shieldData));
          return;
        }

        res.writeHead(200);
        res.end(JSON.stringify(shieldData));
      } catch (e) {
        res.writeHead(500);
        res.end(JSON.stringify({ error: `Remove failed: ${(e as Error).message}` }));
      }
      return;
    }

    // GET /api/app/:directory - Get single app details + auto-activate preview
    // This is the main backend-driven endpoint for app pages
    if (req.method === 'GET' && pathname.startsWith('/api/app/') && !pathname.includes('/tree') && !pathname.includes('/context') && !pathname.includes('/status')) {
      const appIdentifier = decodeURIComponent(pathname.replace('/api/app/', ''));

      if (!appIdentifier) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Missing app identifier' }));
        return;
      }

      // Find the app by directory (primary) or name (backward compat)
      const apps = detectApps();
      const config = readConfig();
      const hidden = new Set(config.hidden || []);

      // Find app and apply overrides
      let app = apps.find(a => a.directory === appIdentifier || a.name === appIdentifier);

      if (!app || hidden.has(app.directory) || hidden.has(app.name)) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'App not found', directory: appIdentifier }));
        return;
      }

      // Apply overrides from config
      const overrides = config.overrides || {};
      const override = overrides[app.directory] || overrides[app.name];
      if (override) {
        app = {
          ...app,
          type: (override.type as typeof app.type) || app.type,
          previewable: override.previewable !== undefined ? override.previewable as boolean : app.previewable,
          framework: (override.framework as string) || app.framework,
        };
      }

      // Handle preview based on app type
      let previewRunning = false;
      let previewActivated = false;

      if (app.previewable) {
        // Use port-level health check to see if preview is actually serving
        const health = getPreviewHealth();
        // Defense-in-depth: verify Caddy route points to correct port
        ensureCaddyRoute(getProjectPort(app.directory));
        if (health.app === app.directory && health.active) {
          // Already running and healthy — reuse
          previewRunning = true;
        } else {
          // Start/switch — non-blocking (returns immediately)
          // Fire-and-forget — don't block the app page response on preview startup
          setPreviewApp(app.directory).catch(() => {});
          previewActivated = true;
        }
      } else {
        // Stop preview for non-previewable apps
        stopPreview();
      }

      // Persist as active project (survives browser refresh)
      setActiveProject(app.directory);

      // Check for context files
      const contextDir = `${HOME}/.ellulai/context`;
      const projectContextPath = path.join(contextDir, `${app.directory}.md`);
      const globalContextPath = path.join(contextDir, 'global.md');
      const hasProjectContext = fs.existsSync(projectContextPath);
      const hasGlobalContext = fs.existsSync(globalContextPath);

      // Include phase/error info from health check
      const healthInfo = previewRunning ? getPreviewHealth() : null;

      res.writeHead(200);
      res.end(JSON.stringify({
        app,
        preview: {
          active: previewRunning,
          app: app.previewable ? app.directory : null,
          activated: previewActivated,
          port: getProjectPort(app.directory),
          phase: healthInfo?.phase ?? (previewActivated ? 'starting' : 'idle'),
          error: healthInfo?.error ?? null,
          logTail: healthInfo?.logTail ?? null,
          healAttempts: healthInfo?.healAttempts ?? 0,
          healStatus: healthInfo?.healStatus ?? null,
        },
        context: {
          hasProjectContext,
          hasGlobalContext,
        },
      }));
      return;
    }

    // GET /api/app/:directory/tree - Get file tree for specific app
    if (req.method === 'GET' && pathname.match(/^\/api\/app\/[^/]+\/tree$/)) {
      const parts = pathname.split('/');
      const appIdentifier = decodeURIComponent(parts[3] || '');

      if (!appIdentifier) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Missing app identifier' }));
        return;
      }

      // Resolve app directory
      const resolvedDir = resolveProjectDir(appIdentifier);
      if (!resolvedDir) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'App not found', directory: appIdentifier }));
        return;
      }

      const appPath = path.join(ROOT_DIR, resolvedDir);
      const tree = getTree(appPath);

      // Get git status for the app
      const { exec } = await import('child_process');
      const runCmd = (cmd: string): Promise<string> =>
        new Promise((resolve) => {
          exec(cmd, { cwd: appPath, timeout: 5000 }, (err, stdout) => {
            resolve(err ? '' : stdout.trim());
          });
        });

      const statusOutput = await runCmd('git status --porcelain');
      const modified: Array<{ status: string; file: string }> = [];
      if (statusOutput) {
        for (const line of statusOutput.split('\n')) {
          if (line.trim()) {
            const statusCode = line.substring(0, 2);
            const file = line.substring(3);
            modified.push({ status: statusCode.trim() || 'M', file });
          }
        }
      }

      res.writeHead(200);
      res.end(JSON.stringify({
        root: resolvedDir,
        tree,
        gitStatus: { modified },
      }));
      return;
    }

    // GET /api/app/:directory/context - Get context files for specific app
    if (req.method === 'GET' && pathname.match(/^\/api\/app\/[^/]+\/context$/)) {
      const parts = pathname.split('/');
      const appIdentifier = decodeURIComponent(parts[3] || '');

      if (!appIdentifier) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Missing app identifier' }));
        return;
      }

      // Resolve app directory
      const resolvedDir = resolveProjectDir(appIdentifier);
      if (!resolvedDir) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'App not found', directory: appIdentifier }));
        return;
      }

      // Get all context files and filter for this app
      const allFiles = listContextFiles();
      const appContextFiles = allFiles.filter(f =>
        f.type === 'global' || f.project === resolvedDir
      );

      res.writeHead(200);
      res.end(JSON.stringify({ files: appContextFiles }));
      return;
    }

    // GET /api/app/:directory/status - Get preview/build status for specific app
    if (req.method === 'GET' && pathname.match(/^\/api\/app\/[^/]+\/status$/)) {
      const parts = pathname.split('/');
      const appIdentifier = decodeURIComponent(parts[3] || '');

      if (!appIdentifier) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Missing app identifier' }));
        return;
      }

      // Resolve app directory
      const resolvedDir = resolveProjectDir(appIdentifier);
      if (!resolvedDir) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'App not found', directory: appIdentifier }));
        return;
      }

      const health = getPreviewHealth();
      const isActivePreview = health.app === resolvedDir;

      res.writeHead(200);
      res.end(JSON.stringify({
        directory: resolvedDir,
        preview: {
          active: isActivePreview && health.active,
          isCurrentApp: isActivePreview,
          phase: isActivePreview ? health.phase : 'idle',
          port: health.port,
          error: isActivePreview ? (health.error ?? null) : null,
          logTail: isActivePreview ? (health.logTail ?? null) : null,
          healAttempts: isActivePreview ? (health.healAttempts ?? 0) : 0,
          healStatus: isActivePreview ? (health.healStatus ?? null) : null,
        },
      }));
      return;
    }

    // GET /api/openapi-spec?app=<directory> - Probe running dev server for OpenAPI spec
    // Three-layer discovery: 1) Probe running app  2) Node.js preload  3) Static analysis
    if (req.method === 'GET' && pathname === '/api/openapi-spec') {
      const appDir = parsedUrl.query.app as string;
      if (!appDir) {
        res.writeHead(400);
        res.end(JSON.stringify({ found: false, reason: 'Missing app parameter' }));
        return;
      }

      // Resolve and find the app
      const resolvedDir = resolveProjectDir(appDir);
      if (!resolvedDir) {
        res.writeHead(404);
        res.end(JSON.stringify({ found: false, reason: 'App not found' }));
        return;
      }

      const appPath = path.join(ROOT_DIR, resolvedDir);

      // Check preview is running
      const previewHealth = getPreviewHealth();
      const canProbe = previewHealth.active && previewHealth.app === resolvedDir;

      // Get the app's configured port and info
      const allApps = detectApps();
      const appInfo = allApps.find(a => a.directory === resolvedDir);
      const port = appInfo?.port ?? getProjectPort(resolvedDir);

      // Check in-memory cache (path → spec, 30s TTL) — covers both probe and static
      const cacheKey = `${resolvedDir}:${port}`;
      const cached = openApiSpecCache.get(cacheKey);
      if (cached && Date.now() - cached.timestamp < 30000) {
        res.writeHead(200);
        res.end(JSON.stringify({ found: true, path: cached.path, spec: cached.spec, source: cached.path === 'static-analysis' ? 'static' : 'probe' }));
        return;
      }

      // Check static analysis cache
      const staticCacheKey = `static:${resolvedDir}`;
      const staticCached = openApiSpecCache.get(staticCacheKey);

      // Layer 1: Probe running app for OpenAPI spec
      if (canProbe) {
        const specPaths = [
          '/openapi.json',
          '/swagger.json',
          '/api-docs',
          '/api-docs/swagger.json',
          '/api-docs/openapi.json',
          '/documentation/json',
          '/docs/json',
          '/api-json',
          '/swagger-json',
          '/doc',
          '/v3/api-docs',
          '/v2/api-docs',
          '/api/openapi.json',
          '/api/schema/',
          '/schema/',
          '/swagger/v1/swagger.json',
          '/swagger/v2/swagger.json',
          '/apispec.json',
        ];

        const timeout = setTimeout(() => {}, 5000);

        try {
          const results = await Promise.allSettled(
            specPaths.map(async (specPath) => {
              const ac = new AbortController();
              const t = setTimeout(() => ac.abort(), 2000);
              try {
                const response = await fetch(`http://localhost:${port}${specPath}`, {
                  signal: ac.signal,
                  headers: { 'Accept': 'application/json' },
                });
                if (!response.ok) return null;
                const text = await response.text();
                const json = JSON.parse(text);
                if (json.openapi || json.swagger) {
                  return { path: specPath, spec: json };
                }
                return null;
              } finally {
                clearTimeout(t);
              }
            })
          );

          clearTimeout(timeout);

          for (const result of results) {
            if (result.status === 'fulfilled' && result.value) {
              const { path: specPath, spec } = result.value;
              openApiSpecCache.set(cacheKey, { path: specPath, spec, timestamp: Date.now() });
              res.writeHead(200);
              res.end(JSON.stringify({ found: true, path: specPath, spec, source: 'probe' }));
              return;
            }
          }
        } catch {
          clearTimeout(timeout);
          // Probing failed — fall through to static analysis
        }
      }

      // Layer 3: Static source analysis (works for ALL languages, even before preview starts)
      // Return cached static result if fresh
      if (staticCached && Date.now() - staticCached.timestamp < 30000) {
        res.writeHead(200);
        res.end(JSON.stringify({ found: true, path: staticCached.path, spec: staticCached.spec, source: 'static' }));
        return;
      }

      try {
        const framework = appInfo?.framework || 'unknown';
        const result = analyzeRoutesFromSource(appPath, framework);
        if (result && result.routes.length > 0) {
          openApiSpecCache.set(staticCacheKey, { path: 'static-analysis', spec: result.spec, timestamp: Date.now() });
          res.writeHead(200);
          res.end(JSON.stringify({ found: true, path: 'static-analysis', spec: result.spec, source: 'static' }));
          return;
        }
      } catch {}

      res.writeHead(200);
      res.end(JSON.stringify({ found: false, reason: 'No routes discovered' }));
      return;
    }

    // POST /api/app/:directory/git-pull - Pull code from remote using VPS-local credentials
    // Reads git token from ~/.ellulai-env (synced by daemon). No secrets from frontend.
    if (req.method === 'POST' && pathname.match(/^\/api\/app\/[^/]+\/git-pull$/)) {
      const parts = pathname.split('/');
      const appIdentifier = decodeURIComponent(parts[3] || '');

      if (!appIdentifier) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'Missing app identifier' }));
        return;
      }

      // Resolve app directory
      const dirName = resolveProjectDir(appIdentifier) || appIdentifier;
      const appPath = path.join(ROOT_DIR, dirName);

      if (!fs.existsSync(appPath)) {
        fs.mkdirSync(appPath, { recursive: true });
      }

      // Read per-app git credentials from daemon-synced env file
      // Secrets are stored as __GIT_TOKEN__MY_APP (suffix = uppercase, alnum + underscore)
      const envPath = `${HOME}/.ellulai-env`;
      const appSuffix = '__' + dirName.toUpperCase().replace(/[^A-Z0-9]/g, '_').replace(/_+/g, '_').replace(/^_|_$/, '');

      const readGitEnv = () => {
        const vars: Record<string, string> = {};
        try {
          if (fs.existsSync(envPath)) {
            const content = fs.readFileSync(envPath, 'utf8');
            for (const line of content.split('\n')) {
              const m = line.match(/^export\s+(\w+)="(.*)"/);
              if (m?.[1]) vars[m[1]] = m[2] ?? '';
            }
          }
        } catch {}
        return {
          token: vars[`__GIT_TOKEN${appSuffix}`] || vars['__GIT_TOKEN'] || '',
          provider: vars[`__GIT_PROVIDER${appSuffix}`] || vars['__GIT_PROVIDER'] || '',
          repoUrl: vars[`__GIT_REPO_URL${appSuffix}`] || vars['__GIT_REPO_URL'] || '',
          defaultBranch: vars[`__GIT_DEFAULT_BRANCH${appSuffix}`] || vars['__GIT_DEFAULT_BRANCH'] || 'main',
        };
      };

      let { token, provider, repoUrl, defaultBranch } = readGitEnv();

      // Fallback: if secrets aren't on disk, ask sovereign-shield to sync from API
      if (!token || !repoUrl) {
        try {
          const setupRes = await fetch('http://127.0.0.1:3005/_internal/git-setup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ appName: dirName }),
          });
          if (setupRes.ok) {
            ({ token, provider, repoUrl, defaultBranch } = readGitEnv());
          }
        } catch {}
      }

      if (!token || !repoUrl) {
        res.writeHead(409);
        res.end(JSON.stringify({
          success: false,
          error: 'Git credentials not synced yet. The daemon may still be processing — try again in a few seconds.',
        }));
        return;
      }

      // Extract repo path from URL (e.g. "https://github.com/owner/repo" → "owner/repo")
      let repoFullName = repoUrl
        .replace(/^https?:\/\/(github\.com|gitlab\.com|bitbucket\.org)\//, '')
        .replace(/\.git$/, '');

      // Build authenticated clone URL
      let cloneUrl: string;
      if (provider === 'github') {
        cloneUrl = `https://x-access-token:${token}@github.com/${repoFullName}.git`;
      } else if (provider === 'gitlab') {
        cloneUrl = `https://oauth2:${token}@gitlab.com/${repoFullName}.git`;
      } else if (provider === 'bitbucket') {
        cloneUrl = `https://x-token-auth:${token}@bitbucket.org/${repoFullName}.git`;
      } else {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: `Unsupported provider: ${provider}` }));
        return;
      }

      const { exec } = await import('child_process');

      console.log(`[file-api] Git pull: ${provider}/${repoFullName} → ${appPath} (branch: ${defaultBranch})`);

      try {
        const runCmd = (cmd: string): Promise<{ success: boolean; output: string; error?: string }> =>
          new Promise((resolve) => {
            exec(cmd, { cwd: appPath, timeout: 120000 }, (err, stdout, stderr) => {
              resolve({
                success: !err,
                output: stdout.trim(),
                error: err ? stderr.trim() || err.message : undefined,
              });
            });
          });

        const hasGit = fs.existsSync(path.join(appPath, '.git'));

        if (!hasGit) {
          // Check if directory has existing files to protect
          const existingFiles = fs.readdirSync(appPath).filter(f => !f.startsWith('.'));
          if (existingFiles.length > 0) {
            // Snapshot existing work so it's recoverable
            await runCmd('git init');
            await runCmd('git add -A');
            await runCmd('git commit -m "pre-import backup" --allow-empty');
            await runCmd('git branch pre-import-backup');
          } else {
            await runCmd('git init');
          }
          await runCmd(`git remote add origin "${cloneUrl}"`);
          const fetchResult = await runCmd(`git fetch origin ${defaultBranch}`);
          if (!fetchResult.success) {
            res.writeHead(500);
            res.end(JSON.stringify({ success: false, error: `Fetch failed: ${fetchResult.error}` }));
            return;
          }
          await runCmd(`git checkout -B ${defaultBranch} origin/${defaultBranch}`);
        } else {
          // Existing git repo — update remote and pull
          const hasOrigin = (await runCmd('git remote')).output.split('\n').includes('origin');
          if (hasOrigin) {
            await runCmd(`git remote set-url origin "${cloneUrl}"`);
          } else {
            await runCmd(`git remote add origin "${cloneUrl}"`);
          }

          // Stash uncommitted changes before pulling
          const statusResult = await runCmd('git status --porcelain');
          const hasChanges = statusResult.success && statusResult.output.length > 0;
          if (hasChanges) {
            await runCmd('git stash --include-untracked');
          }

          const pullResult = await runCmd(`git pull origin ${defaultBranch} --no-edit`);
          if (!pullResult.success) {
            // Save current work on a backup branch before destructive checkout
            await runCmd('git branch -f pre-import-backup HEAD');
            await runCmd(`git fetch origin ${defaultBranch}`);
            await runCmd(`git checkout -B ${defaultBranch} origin/${defaultBranch}`);
          }

          // Restore stashed changes
          if (hasChanges) {
            await runCmd('git stash pop');
          }
        }

        // Detect app framework after pull
        const detected = detectApps().find(a => a.directory === dirName);

        // Install dependencies before responding — preview starts immediately
        // after the console receives this response, so node_modules must be ready.
        const packageJsonPath = path.join(appPath, 'package.json');
        if (fs.existsSync(packageJsonPath) && !fs.existsSync(path.join(appPath, 'node_modules'))) {
          const lockFile = fs.existsSync(path.join(appPath, 'pnpm-lock.yaml'))
            ? 'pnpm' : fs.existsSync(path.join(appPath, 'yarn.lock'))
            ? 'yarn' : 'npm';
          try {
            await runCmd(`${lockFile} install`);
          } catch {}
        }

        res.writeHead(200);
        res.end(JSON.stringify({
          success: true,
          directory: dirName,
          framework: detected?.framework || 'unknown',
          type: detected?.type || 'unknown',
        }));
      } catch (e) {
        const error = e as Error;
        console.error(`[file-api] Git pull failed for ${dirName}:`, error.message);
        res.writeHead(500);
        res.end(JSON.stringify({ success: false, error: error.message }));
      }
      return;
    }

    // GET/POST /api/preview
    if (pathname === '/api/preview') {
      if (req.method === 'GET') {
        const health = getPreviewHealth();
        let autoStarted = false;

        if (health.app) {
          // Defense-in-depth: verify Caddy route on every poll.
          // Primary write happens in setPreviewApp(), this catches edge cases.
          ensureCaddyRoute(health.port);

          if (!health.active) {
            // Auto-start if port-level check shows nothing running
            // (avoids killing preview started by the ellulai-preview bash script)
            const result = await startPreview(health.app);
            if (result.success) {
              autoStarted = true;
            }
          }
        }

        res.writeHead(200);
        res.end(JSON.stringify({ app: health.app, running: health.active || autoStarted, autoStarted }));
        return;
      }

      if (req.method === 'POST') {
        const body = await parseBody(req);
        const { app, script } = body as { app?: string; script?: string };
        const result = await setPreviewApp(app || null, script);
        res.writeHead(200);
        res.end(JSON.stringify(result));
        return;
      }
    }

    // GET /api/preview/health — structured health for agent-bridge polling
    if (req.method === 'GET' && pathname === '/api/preview/health') {
      const queryProject = parsedUrl.query.project as string | undefined;
      const health = getPreviewHealth();
      // If a specific project was requested and it doesn't match the active preview, return idle
      if (queryProject && health.app && queryProject !== health.app) {
        res.writeHead(200);
        res.end(JSON.stringify({ phase: 'idle', active: false, app: health.app, requestedProject: queryProject }));
        return;
      }
      res.writeHead(200);
      res.end(JSON.stringify(health));
      return;
    }

    // GET /api/preview/metrics — operational counters for observability
    if (req.method === 'GET' && pathname === '/api/preview/metrics') {
      res.writeHead(200);
      res.end(JSON.stringify(getPreviewMetrics()));
      return;
    }

    // GET/POST/DELETE /api/context
    if (pathname === '/api/context') {
      const fileName = parsedUrl.query.file as string | undefined;

      if (req.method === 'GET' && !fileName) {
        const files = listContextFiles();
        res.writeHead(200);
        res.end(JSON.stringify({ files }));
        return;
      }

      if (req.method === 'GET' && fileName) {
        const result = getContextFile(fileName);
        if (!result) {
          res.writeHead(404);
          res.end(JSON.stringify({ error: 'File not found' }));
          return;
        }
        res.writeHead(200);
        res.end(JSON.stringify(result));
        return;
      }

      if (req.method === 'POST') {
        const body = await parseBody(req);
        const { file, content } = body as { file?: string; content?: string };
        if (!file || content === undefined) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'Missing file or content' }));
          return;
        }
        const result = saveContextFile(file, content);
        res.writeHead(200);
        res.end(JSON.stringify(result));
        return;
      }

      if (req.method === 'DELETE' && fileName) {
        const result = deleteContextFile(fileName);
        res.writeHead(result.success ? 200 : result.error === 'File not found' ? 404 : 403);
        res.end(JSON.stringify(result));
        return;
      }
    }

    // GET/POST /api/openclaw/workspace
    if (pathname === '/api/openclaw/workspace') {
      const wsFile = parsedUrl.query.file as string | undefined;

      if (req.method === 'GET' && !wsFile) {
        const files = listOpenclawWorkspaceFiles();
        res.writeHead(200);
        res.end(JSON.stringify({ files }));
        return;
      }

      if (req.method === 'GET' && wsFile) {
        const result = getOpenclawWorkspaceFile(wsFile);
        if (!result) {
          res.writeHead(404);
          res.end(JSON.stringify({ error: 'File not found' }));
          return;
        }
        res.writeHead(200);
        res.end(JSON.stringify(result));
        return;
      }

      if (req.method === 'POST') {
        const body = await parseBody(req);
        const { file, content } = body as { file?: string; content?: string };
        if (!file || content === undefined) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'Missing file or content' }));
          return;
        }
        const result = saveOpenclawWorkspaceFile(file, content);
        res.writeHead(result.success ? 200 : 400);
        res.end(JSON.stringify(result));
        return;
      }
    }

    // GET /api/openclaw/channels
    if (req.method === 'GET' && pathname === '/api/openclaw/channels') {
      const project = parsedUrl.query.project as string | undefined;
      const channels = getOpenclawChannels(project);
      res.writeHead(200);
      res.end(JSON.stringify({ channels }));
      return;
    }

    // PUT /api/openclaw/channels/:channel
    if (req.method === 'PUT' && pathname.startsWith('/api/openclaw/channels/')) {
      const channel = pathname.split('/').pop();
      if (!channel) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Missing channel' }));
        return;
      }
      const project = parsedUrl.query.project as string | undefined;
      const body = await parseBody(req);
      const result = saveOpenclawChannel(channel, body as Record<string, unknown>, project);
      res.writeHead(result.success ? 200 : 400);
      res.end(JSON.stringify(result));
      return;
    }

    // GET /api/openclaw/channels/whatsapp/qr — self-contained QR pairing page (for iframe)
    if (req.method === 'GET' && pathname === '/api/openclaw/channels/whatsapp/qr') {
      const project = parsedUrl.query.project as string | undefined;
      const html = getWhatsAppQrPageHtml(project);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
      return;
    }

    // GET /api/openclaw/channels/whatsapp/qr-stream — SSE stream of QR data
    if (req.method === 'GET' && pathname === '/api/openclaw/channels/whatsapp/qr-stream') {
      const project = parsedUrl.query.project as string | undefined;
      handleWhatsAppQrStream(res, project);
      return;
    }

    // POST /api/openclaw/channels/whatsapp/login — start WhatsApp QR pairing
    if (req.method === 'POST' && pathname === '/api/openclaw/channels/whatsapp/login') {
      const project = parsedUrl.query.project as string | undefined;
      const result = startWhatsAppLogin(project, broadcast);
      res.writeHead(result.success ? 200 : 500);
      res.end(JSON.stringify(result));
      return;
    }

    // DELETE /api/openclaw/channels/whatsapp/login — stop WhatsApp QR pairing
    if (req.method === 'DELETE' && pathname === '/api/openclaw/channels/whatsapp/login') {
      stopWhatsAppLogin();
      res.writeHead(200);
      res.end(JSON.stringify({ success: true }));
      return;
    }

    // GET /api/openclaw/llm-key — check BYOK key status
    if (req.method === 'GET' && pathname === '/api/openclaw/llm-key') {
      const result = getOpenclawLlmKey();
      res.writeHead(200);
      res.end(JSON.stringify(result));
      return;
    }

    // PUT /api/openclaw/llm-key — save BYOK key
    if (req.method === 'PUT' && pathname === '/api/openclaw/llm-key') {
      const body = await parseBody(req);
      const provider = body.provider as string | undefined;
      const apiKey = body.apiKey as string | undefined;
      if (!provider || !apiKey) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Missing provider or apiKey' }));
        return;
      }
      const modelId = body.modelId as string | undefined;
      const result = saveOpenclawLlmKey(provider, apiKey, modelId);
      res.writeHead(result.success ? 200 : 400);
      res.end(JSON.stringify(result));
      return;
    }

    // DELETE /api/openclaw/llm-key — remove BYOK key
    if (req.method === 'DELETE' && pathname === '/api/openclaw/llm-key') {
      const result = removeOpenclawLlmKey();
      res.writeHead(200);
      res.end(JSON.stringify(result));
      return;
    }

    // GET /api/assets/:app/icon
    if (req.method === 'GET' && pathname.startsWith('/api/assets/') && pathname.endsWith('/icon')) {
      const pathParts = pathname.split('/');
      const appIdentifier = pathParts[3];

      if (!appIdentifier) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Missing app identifier' }));
        return;
      }

      // Resolve identifier to directory (supports both directory and name)
      const directory = resolveProjectDir(appIdentifier);
      if (!directory) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'App not found' }));
        return;
      }

      const appPath = path.join(ROOT_DIR, directory);

      const searchPaths = [
        '.ellulai/icon.png',
        'public/favicon.ico',
        'public/logo.png',
        'public/icon.png',
        'static/favicon.ico',
        'static/logo.png',
        'assets/logo.png',
        'logo.png',
      ];

      for (const p of searchPaths) {
        const fullPath = path.join(appPath, p);
        if (fs.existsSync(fullPath)) {
          const ext = path.extname(fullPath).toLowerCase();
          const mimeTypes: Record<string, string> = {
            '.png': 'image/png',
            '.ico': 'image/x-icon',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.svg': 'image/svg+xml',
          };
          const contentType = mimeTypes[ext] || 'application/octet-stream';

          res.setHeader('Content-Type', contentType);
          res.setHeader('Cache-Control', 'public, max-age=3600');
          res.writeHead(200);
          res.end(fs.readFileSync(fullPath));
          return;
        }
      }

      res.writeHead(404);
      res.end(JSON.stringify({ error: 'No icon found' }));
      return;
    }

    // POST /api/processes/kill-ports
    if (req.method === 'POST' && pathname === '/api/processes/kill-ports') {
      const body = await parseBody(req);
      const { ports } = body as { ports?: number[] };

      if (!Array.isArray(ports)) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Invalid ports: expected array' }));
        return;
      }

      const result = killProcessesOnPorts(ports);
      res.writeHead(result.success ? 200 : 400);
      res.end(JSON.stringify(result));
      return;
    }

    // Hydrate workspace from Neon snapshot (called by platform during wake)
    if (req.method === 'POST' && pathname === '/api/hydrate') {
      const body = await parseBody(req);
      const { snapshotId } = body as { snapshotId?: string };

      if (!snapshotId) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Missing snapshotId' }));
        return;
      }

      // Read server config from filesystem
      const { execSync } = await import('child_process');
      const serverId = fs.readFileSync(PATHS.SERVER_ID, 'utf8').trim();
      const apiUrl = fs.readFileSync(PATHS.API_URL, 'utf8').trim();
      const aiProxyToken = fs.readFileSync(PATHS.AI_PROXY_TOKEN, 'utf8').trim();

      console.log(`[file-api] Hydrating workspace from snapshot ${snapshotId.slice(0, 8)}...`);

      try {
        // Run hydrate.sh script (packaged at /opt/ellulai/startup-agent/hydrate.sh)
        const hydratePath = '/opt/ellulai/startup-agent/hydrate.sh';
        if (!fs.existsSync(hydratePath)) {
          res.writeHead(500);
          res.end(JSON.stringify({ error: 'hydrate.sh not found' }));
          return;
        }

        execSync(`bash ${hydratePath} "${serverId}" "${apiUrl}" "${aiProxyToken}"`, {
          timeout: 300_000, // 5 min max
          stdio: 'inherit',
        });

        console.log('[file-api] Hydration complete');
        res.writeHead(200);
        res.end(JSON.stringify({ success: true }));
      } catch (hydrateErr) {
        const errMsg = hydrateErr instanceof Error ? hydrateErr.message : 'Unknown error';
        console.error('[file-api] Hydration failed:', errMsg);
        res.writeHead(500);
        res.end(JSON.stringify({ error: 'Hydration failed', details: errMsg }));
      }
      return;
    }

    // ============================================
    // Migration endpoints (daemon API - JWT authenticated)
    // ============================================

    // POST /api/migrate/pack — Create tar.gz of home directory for data transfer
    // Auth: daemon JWT (verified above at DAEMON_PATHS gate)
    if (req.method === 'POST' && pathname === '/api/migrate/pack') {
      try {
        const { execSync } = await import('child_process');
        const archivePath = `/tmp/migration-${Date.now()}.tar.gz`;

        // Clean up old migration archives from failed attempts (prevent /tmp from filling up)
        try {
          const tmpFiles = fs.readdirSync('/tmp');
          for (const f of tmpFiles) {
            if (/^migration-\d+\.tar\.gz$/.test(f)) {
              fs.unlinkSync(`/tmp/${f}`);
            }
          }
        } catch { /* non-fatal */ }

        // Backup passkey DB so it's included in the migration tar
        // .ellulai-identity/ is under $HOME and NOT in the tar exclude list
        try {
          const BACKUP_DIR = path.join(HOME, '.ellulai-identity');
          fs.mkdirSync(BACKUP_DIR, { recursive: true, mode: 0o700 });
          if (fs.existsSync('/etc/ellulai/shield-data/local-auth.db')) {
            fs.copyFileSync('/etc/ellulai/shield-data/local-auth.db', path.join(BACKUP_DIR, 'local-auth.db'));
            if (fs.existsSync('/etc/ellulai/shield-data/local-auth.db-wal')) {
              fs.copyFileSync('/etc/ellulai/shield-data/local-auth.db-wal', path.join(BACKUP_DIR, 'local-auth.db-wal'));
            }
            if (fs.existsSync('/etc/ellulai/shield-data/local-auth.db-shm')) {
              fs.copyFileSync('/etc/ellulai/shield-data/local-auth.db-shm', path.join(BACKUP_DIR, 'local-auth.db-shm'));
            }
          }
        } catch { /* non-fatal */ }

        console.log(`[file-api] Packing ${HOME} for migration...`);
        execSync(
          `tar czf ${archivePath} --exclude=node_modules --exclude=.cache --exclude='.git/objects' --exclude='*.log' --exclude=.nvm --exclude=.node --exclude=.opencode --exclude='.bashrc' --exclude='.profile' --exclude='.bash_logout' --exclude='.ssh' --exclude='.local/bin' -C ${HOME} .`,
          { timeout: 120_000, encoding: 'utf8' }
        );

        const stats = fs.statSync(archivePath);
        console.log(`[file-api] Migration pack created: ${archivePath} (${stats.size} bytes)`);

        res.writeHead(200);
        res.end(JSON.stringify({ success: true, archivePath, sizeBytes: stats.size }));
      } catch (e) {
        const error = e as Error;
        console.error('[file-api] Migration pack failed:', error.message);
        res.writeHead(500);
        res.end(JSON.stringify({ success: false, error: error.message }));
      }
      return;
    }

    // GET /api/migrate/download — Stream tar.gz archive for target server to pull
    if (req.method === 'GET' && pathname === '/api/migrate/download') {
      const archivePath = parsedUrl.query.path as string;

      if (!archivePath || !/^\/tmp\/migration-\d+\.tar\.gz$/.test(archivePath)) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Invalid archive path' }));
        return;
      }

      if (!fs.existsSync(archivePath)) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'Archive not found' }));
        return;
      }

      const stats = fs.statSync(archivePath);
      res.setHeader('Content-Type', 'application/gzip');
      res.setHeader('Content-Length', stats.size.toString());
      res.writeHead(200);

      const stream = fs.createReadStream(archivePath);
      stream.pipe(res);
      stream.on('end', () => {
        try { fs.unlinkSync(archivePath); } catch {}
      });
      return;
    }

    // POST /api/migrate/pull — Pull data from source server via its daemon port
    // Auth: daemon JWT (verified above at DAEMON_PATHS gate)
    if (req.method === 'POST' && pathname === '/api/migrate/pull') {
      const body = await parseBody(req);
      const { sourceUrl, sourceIp, sourceToken, archivePath } = body as {
        sourceUrl?: string;
        sourceIp?: string;
        sourceToken?: string;
        archivePath?: string;
      };

      if (!sourceUrl || !sourceToken || !archivePath) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'Missing sourceUrl, sourceToken, or archivePath' }));
        return;
      }

      // Validate inputs to prevent command injection
      // Accept both IP-based URLs and daemon.ellul.ai hostname (origin cert)
      if (!/^https:\/\/(\d+\.\d+\.\d+\.\d+|daemon\.ellul\.ai):3006\//.test(sourceUrl)) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'Invalid source URL format' }));
        return;
      }
      if (!/^[A-Za-z0-9_\-.]+$/.test(sourceToken)) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'Invalid token format' }));
        return;
      }
      if (!/^\/tmp\/migration-\d+\.tar\.gz$/.test(archivePath)) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'Invalid archive path format' }));
        return;
      }
      if (sourceIp && !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(sourceIp)) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'Invalid source IP format' }));
        return;
      }

      // Migration lock: prevent enforcer from restarting file-api during transfer.
      // The enforcer health-checks file-api every ~30s and restarts it if unresponsive.
      // On older VPS images using execFileSync, the event loop blocks during download,
      // causing the enforcer to kill file-api mid-transfer. This lock file tells the
      // enforcer to skip the health check entirely during migration.
      const MIGRATION_LOCK = '/tmp/ellulai-migration.lock';
      try {
        fs.writeFileSync(MIGRATION_LOCK, `${Date.now()}`);
      } catch {}

      try {
        const { execFile } = await import('child_process');
        const downloadUrl = `${sourceUrl}?path=${encodeURIComponent(archivePath)}`;

        console.log(`[file-api] Migration pull from ${sourceUrl}`);

        // Run as root via sudo to bypass Warden's iptables redirect.
        // On paid dev tiers, Warden Tunnel Guard redirects all outbound TCP from
        // the dev user through its MITM proxy — breaking TLS verification against
        // the Cloudflare Origin CA. Running as root avoids the iptables rule
        // (which matches --uid-owner dev) and preserves proper TLS verification.
        // Token is passed via stdin (execFile input) to avoid exposure in ps output.
        // IMPORTANT: Use async execFile (not execFileSync) to keep the event loop
        // unblocked — belt-and-suspenders with the migration lock above.
        const result = await new Promise<{ stdout: string; stderr: string }>((resolve, reject) => {
          const child = execFile('sudo', [
            '/usr/local/bin/ellulai-migrate-pull',
            downloadUrl,
            sourceIp || '',
            HOME,
          ], { timeout: 600_000, encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
            if (error) {
              const err = error as Error & { stderr?: string; stdout?: string; signal?: string; status?: number | null; killed?: boolean };
              err.stderr = stderr;
              err.stdout = stdout;
              reject(err);
            } else {
              resolve({ stdout: stdout as string, stderr: stderr as string });
            }
          });
          // Pass token via stdin — must not fail silently
          if (!child.stdin) {
            child.kill();
            throw new Error('execFile child has no stdin pipe');
          }
          child.stdin.write(sourceToken + '\n');
          child.stdin.end();
        });

        console.log('[file-api] Migration pull complete');
        res.writeHead(200);
        res.end(JSON.stringify({ success: true }));
      } catch (e) {
        const error = e as Error & { stderr?: string | Buffer; stdout?: string | Buffer; signal?: string; status?: number | null; killed?: boolean; code?: number | string };
        const stderr = error.stderr ? String(error.stderr).trim() : '';
        const stdout = error.stdout ? String(error.stdout).trim() : '';
        // Build detailed diagnostic — error.code is exit code for async execFile, error.status for sync
        const exitCode = error.code ?? error.status ?? 'null';
        const diag = [
          `exit=${exitCode}`,
          `signal=${error.signal || 'none'}`,
          `killed=${error.killed ?? false}`,
        ].join(' | ');
        // Log stderr separately (full) so it's not truncated in the JSON response
        console.error(`[file-api] Migration pull failed: ${diag}`);
        if (stderr) console.error(`[file-api] migrate-pull stderr: ${stderr}`);
        if (stdout) console.error(`[file-api] migrate-pull stdout: ${stdout.slice(0, 500)}`);
        res.writeHead(500);
        res.end(JSON.stringify({ success: false, error: `${diag} | stderr=${stderr.slice(0, 800)}` }));
      } finally {
        try { fs.unlinkSync(MIGRATION_LOCK); } catch {}
      }
      return;
    }

    // ============================================
    // Daemon infrastructure endpoints (JWT authenticated)
    // ============================================

    // POST /api/mount-volume — Mount a block volume at the user's home directory (hibernate wake)
    if (req.method === 'POST' && pathname === '/api/mount-volume') {
      const body = await parseBody(req);
      const { volumeDevice } = body as { volumeDevice?: string };

      if (!volumeDevice) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'Missing volumeDevice' }));
        return;
      }

      try {
        const { execSync } = await import('child_process');
        const result = execSync(
          `sudo /usr/local/bin/ellulai-mount-volume mount "${volumeDevice}"`,
          { timeout: 120_000, encoding: 'utf8' }
        );
        const parsed = JSON.parse(result.trim());
        console.log(`[file-api] Volume mount result:`, parsed);
        res.writeHead(parsed.success ? 200 : 500);
        res.end(result.trim());
      } catch (e) {
        const error = e as Error;
        console.error('[file-api] Volume mount failed:', error.message);
        res.writeHead(500);
        res.end(JSON.stringify({ success: false, error: error.message }));
      }
      return;
    }

    // POST /api/flush-volume — Flush filesystem buffers before volume detach (hibernate)
    if (req.method === 'POST' && pathname === '/api/flush-volume') {
      try {
        const { execSync } = await import('child_process');
        const result = execSync(
          'sudo /usr/local/bin/ellulai-mount-volume flush',
          { timeout: 15_000, encoding: 'utf8' }
        );
        const parsed = JSON.parse(result.trim());
        res.writeHead(parsed.success ? 200 : 500);
        res.end(result.trim());
      } catch (e) {
        const error = e as Error;
        console.error('[file-api] Volume flush failed:', error.message);
        res.writeHead(500);
        res.end(JSON.stringify({ success: false, error: error.message }));
      }
      return;
    }

    // POST /api/update-identity — Update server identity after migration
    // Called by API after DB swap to sync VPS files with new server record.
    // Updates: server-id, domain, owner.lock, billing-tier, regenerates Ed25519 heartbeat keypair.
    // Delegates to privileged helper script via sudo (file-api runs as dev/coder, not root).
    if (req.method === 'POST' && pathname === '/api/update-identity') {
      const body = await parseBody(req);
      const { serverId, domain, userId, billingTier, deploymentModel } = body as {
        serverId?: string; domain?: string; userId?: string; billingTier?: string; deploymentModel?: string;
      };

      if (!serverId) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'Missing serverId' }));
        return;
      }

      // Validate inputs to prevent command injection
      const safePattern = /^[a-zA-Z0-9._:-]+$/;
      if (!safePattern.test(serverId)) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'Invalid serverId format' }));
        return;
      }
      if (domain && !safePattern.test(domain)) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'Invalid domain format' }));
        return;
      }
      if (userId && !safePattern.test(userId)) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'Invalid userId format' }));
        return;
      }
      if (billingTier && !safePattern.test(billingTier)) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'Invalid billingTier format' }));
        return;
      }
      if (deploymentModel && !safePattern.test(deploymentModel)) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'Invalid deploymentModel format' }));
        return;
      }

      try {
        const { execSync } = await import('child_process');

        // Build command args for the privileged helper
        let cmd = `sudo /usr/local/bin/ellulai-update-identity --server-id=${serverId}`;
        if (domain) cmd += ` --domain=${domain}`;
        if (userId) cmd += ` --user-id=${userId}`;
        if (billingTier) cmd += ` --billing-tier=${billingTier}`;
        if (deploymentModel) cmd += ` --deployment-model=${deploymentModel}`;

        // The identity script uses `caddy reload` (not restart) to apply the new
        // Caddyfile without dropping connections. The daemon port 3006 TLS session
        // stays alive, so this response reaches callDaemon reliably.
        const result = execSync(cmd, { timeout: 120_000, encoding: 'utf8' });
        const trimmed = result.trim();
        // Extract last JSON line — helper script may emit non-JSON logs before final output
        const lastLine = trimmed.split('\n').pop() || '{}';
        const parsed = JSON.parse(lastLine);

        console.log(`[file-api] Identity updated: serverId=${serverId}, domain=${domain || 'unchanged'}`);
        res.writeHead(parsed.success ? 200 : 500);
        res.end(lastLine);
      } catch (e) {
        const error = e as Error;
        console.error('[file-api] Identity update failed:', error.message.slice(0, 500));
        res.writeHead(500);
        res.end(JSON.stringify({ success: false, error: error.message.slice(0, 500) }));
      }
      return;
    }

    // ============================================
    // LUKS Volume Encryption endpoints (daemon API - JWT authenticated)
    // ============================================

    // POST /api/luks-init — First-time LUKS2 format with PRF key + optional recovery key
    if (req.method === 'POST' && pathname === '/api/luks-init') {
      const body = await parseBody(req);
      const { prfKey, recoveryKey, volumeDevice } = body as { prfKey?: string; recoveryKey?: string; volumeDevice?: string };

      if (!prfKey) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'Missing prfKey' }));
        return;
      }

      try {
        const { execSync } = await import('child_process');

        // Decode PRF key from base64
        const keyBuffer = Buffer.from(prfKey as string, 'base64');
        if (keyBuffer.length !== 32) {
          res.writeHead(400);
          res.end(JSON.stringify({ success: false, error: 'Invalid PRF key length' }));
          return;
        }

        // Read volume device — accept from request body or from disk file
        const deviceFilePath = '/etc/ellulai/volume-device';
        let device = '';
        if (volumeDevice) {
          device = volumeDevice;
          fs.mkdirSync('/etc/ellulai', { recursive: true });
          fs.writeFileSync(deviceFilePath, device);
          fs.chmodSync(deviceFilePath, 0o644);
        } else if (fs.existsSync(deviceFilePath)) {
          device = fs.readFileSync(deviceFilePath, 'utf8').trim();
        }
        if (!device) {
          res.writeHead(400);
          res.end(JSON.stringify({ success: false, error: 'No volume device configured' }));
          return;
        }

        // Backup skeleton
        const skelTmp = `/tmp/skel-backup-${process.pid}`;
        execSync(`cp -a ${HOME}/. ${skelTmp}/`, { timeout: 30_000 });

        // Unmount if currently mounted
        try {
          execSync(`mountpoint -q ${HOME} && umount ${HOME}`, { timeout: 10_000 });
        } catch { /* not mounted, fine */ }

        // LUKS format — key via stdin, cap Argon2id memory at 512MB (small VPS safe)
        console.log(`[file-api] LUKS formatting ${device}`);
        execSync(
          `cryptsetup luksFormat --type luks2 --pbkdf-memory 524288 --batch-mode --key-file=- ${device}`,
          { input: keyBuffer, timeout: 120_000 }
        );

        // Add recovery key as slot 1 if provided
        if (recoveryKey) {
          const recoveryBuffer = Buffer.from(recoveryKey as string, 'base64');
          // Add key: existing key on stdin, new key on fd 3
          // cryptsetup luksAddKey expects: existing key via --key-file=-, new key on stdin
          // Approach: pipe existing key via --key-file=/dev/fd/3, new key via stdin
          const tmpKeyFile = `/tmp/luks-key-${process.pid}`;
          fs.writeFileSync(tmpKeyFile, keyBuffer, { mode: 0o600 });
          try {
            execSync(
              `cryptsetup luksAddKey --key-file=${tmpKeyFile} ${device} -`,
              { input: recoveryBuffer, timeout: 120_000 }
            );
          } finally {
            // Securely wipe temp key file
            fs.writeFileSync(tmpKeyFile, Buffer.alloc(32));
            fs.unlinkSync(tmpKeyFile);
          }
          console.log('[file-api] Recovery key added as LUKS key slot 1');
        }

        // Open LUKS container
        execSync(
          `cryptsetup luksOpen --key-file=- ${device} luks-home`,
          { input: keyBuffer, timeout: 30_000 }
        );

        // Format and mount
        execSync(`mkfs.ext4 -L ellulai-home /dev/mapper/luks-home`, { timeout: 30_000 });
        execSync(`mount -o nosuid,nodev /dev/mapper/luks-home ${HOME}`, { timeout: 10_000 });

        // Restore skeleton and fix ownership
        execSync(`cp -a ${skelTmp}/. ${HOME}/`, { timeout: 30_000 });
        execSync(`rm -rf ${skelTmp}`, { timeout: 10_000 });

        // Read SVC_USER from config
        let svcUser = 'dev';
        try {
          if (fs.existsSync('/etc/default/ellulai')) {
            const envContent = fs.readFileSync('/etc/default/ellulai', 'utf8');
            const match = envContent.match(/PS_USER=(\w+)/);
            if (match?.[1]) svcUser = match[1];
          }
        } catch {}
        execSync(`chown -R ${svcUser}:${svcUser} ${HOME}`, { timeout: 30_000 });

        console.log('[file-api] LUKS init complete');
        res.writeHead(200);
        res.end(JSON.stringify({ success: true }));
      } catch (e) {
        const error = e as Error;
        console.error('[file-api] LUKS init failed:', error.message);
        res.writeHead(500);
        res.end(JSON.stringify({ success: false, error: error.message }));
      }
      return;
    }

    // POST /api/luks-unlock — Wake unlock: open LUKS + mount
    if (req.method === 'POST' && pathname === '/api/luks-unlock') {
      const body = await parseBody(req);
      const { prfKey, volumeDevice } = body as { prfKey?: string; volumeDevice?: string };

      if (!prfKey) {
        res.writeHead(400);
        res.end(JSON.stringify({ success: false, error: 'Missing prfKey' }));
        return;
      }

      try {
        const { execSync } = await import('child_process');

        const keyBuffer = Buffer.from(prfKey as string, 'base64');
        if (keyBuffer.length !== 32) {
          res.writeHead(400);
          res.end(JSON.stringify({ success: false, error: 'Invalid PRF key length' }));
          return;
        }

        // Check if already mounted
        try {
          execSync(`mountpoint -q ${HOME}`, { timeout: 5_000 });
          // Already mounted
          res.writeHead(200);
          res.end(JSON.stringify({ success: true, alreadyMounted: true }));
          return;
        } catch { /* not mounted, proceed */ }

        // Read volume device — accept from request body (pool wake) or from disk file
        const deviceFilePath = '/etc/ellulai/volume-device';
        let device = '';
        if (volumeDevice) {
          // Pool wake: API passes device path; persist for future use
          device = volumeDevice;
          fs.mkdirSync('/etc/ellulai', { recursive: true });
          fs.writeFileSync(deviceFilePath, device);
          fs.chmodSync(deviceFilePath, 0o644);
        } else if (fs.existsSync(deviceFilePath)) {
          device = fs.readFileSync(deviceFilePath, 'utf8').trim();
        }
        if (!device) {
          res.writeHead(400);
          res.end(JSON.stringify({ success: false, error: 'No volume device configured' }));
          return;
        }

        // Wait for device to appear (cloud attach can be slow)
        let waited = 0;
        while (!fs.existsSync(device) && waited < 60) {
          await new Promise(r => setTimeout(r, 1000));
          waited++;
        }
        if (!fs.existsSync(device)) {
          res.writeHead(500);
          res.end(JSON.stringify({ success: false, error: `Device ${device} not found after 60s` }));
          return;
        }

        // Open LUKS — key via stdin
        console.log(`[file-api] LUKS unlocking ${device}`);
        execSync(
          `cryptsetup luksOpen --key-file=- ${device} luks-home`,
          { input: keyBuffer, timeout: 30_000 }
        );

        // Mount
        execSync(`mount -o nosuid,nodev /dev/mapper/luks-home ${HOME}`, { timeout: 10_000 });

        // Fix ownership if needed
        let svcUser = 'dev';
        try {
          if (fs.existsSync('/etc/default/ellulai')) {
            const envContent = fs.readFileSync('/etc/default/ellulai', 'utf8');
            const match = envContent.match(/PS_USER=(\w+)/);
            if (match?.[1]) svcUser = match[1];
          }
        } catch {}
        execSync(`chown -R ${svcUser}:${svcUser} ${HOME}`, { timeout: 30_000 });

        console.log('[file-api] LUKS unlock + mount complete');
        res.writeHead(200);
        res.end(JSON.stringify({ success: true }));
      } catch (e) {
        const error = e as Error;
        console.error('[file-api] LUKS unlock failed:', error.message);
        res.writeHead(500);
        res.end(JSON.stringify({ success: false, error: error.message }));
      }
      return;
    }

    // POST /api/luks-close — Pre-hibernate: unmount + close LUKS (wipes key from kernel RAM)
    if (req.method === 'POST' && pathname === '/api/luks-close') {
      try {
        const { execSync } = await import('child_process');

        // Sync filesystem
        execSync('sync', { timeout: 10_000 });

        // Kill processes using the mount point
        try {
          execSync(`fuser -kvm ${HOME} 2>/dev/null || true`, { timeout: 15_000 });
        } catch { /* no processes, fine */ }

        // Give processes time to exit
        await new Promise(r => setTimeout(r, 1000));

        // Unmount
        try {
          execSync(`umount ${HOME}`, { timeout: 10_000 });
        } catch {
          // Lazy unmount as fallback
          try {
            execSync(`umount -l ${HOME}`, { timeout: 10_000 });
          } catch { /* best effort */ }
        }

        // Close LUKS container (wipes decryption key from kernel memory)
        try {
          execSync('cryptsetup luksClose luks-home', { timeout: 10_000 });
        } catch { /* may not be open */ }

        console.log('[file-api] LUKS close complete');
        res.writeHead(200);
        res.end(JSON.stringify({ success: true }));
      } catch (e) {
        const error = e as Error;
        console.error('[file-api] LUKS close failed:', error.message);
        res.writeHead(500);
        res.end(JSON.stringify({ success: false, error: error.message }));
      }
      return;
    }

    // POST /api/backup-identity — Backup passkey DB to volume before hibernate
    if (req.method === 'POST' && pathname === '/api/backup-identity') {
      try {
        const BACKUP_DIR = path.join(HOME, '.ellulai-identity');
        fs.mkdirSync(BACKUP_DIR, { recursive: true, mode: 0o700 });

        const AUTH_DB = '/etc/ellulai/shield-data/local-auth.db';
        let backedUp = false;

        if (fs.existsSync(AUTH_DB)) {
          fs.copyFileSync(AUTH_DB, path.join(BACKUP_DIR, 'local-auth.db'));
          // Copy WAL/SHM if they exist (SQLite journal files)
          if (fs.existsSync(AUTH_DB + '-wal')) {
            fs.copyFileSync(AUTH_DB + '-wal', path.join(BACKUP_DIR, 'local-auth.db-wal'));
          }
          if (fs.existsSync(AUTH_DB + '-shm')) {
            fs.copyFileSync(AUTH_DB + '-shm', path.join(BACKUP_DIR, 'local-auth.db-shm'));
          }
          backedUp = true;
        }

        // Save security tier marker so restore can detect web_locked
        const tierFile = '/etc/ellulai/security-tier';
        if (fs.existsSync(tierFile)) {
          const tier = fs.readFileSync(tierFile, 'utf8').trim();
          if (tier === 'web_locked') {
            fs.writeFileSync(path.join(BACKUP_DIR, '.web_locked_activated'), '1');
          } else {
            // Remove stale marker if tier is no longer web_locked
            try { fs.unlinkSync(path.join(BACKUP_DIR, '.web_locked_activated')); } catch {}
          }
        }

        console.log(`[file-api] Identity backup: ${backedUp ? 'backed up' : 'no auth DB found'}`);
        res.writeHead(200);
        res.end(JSON.stringify({ success: true, backed_up: backedUp }));
      } catch (e) {
        const error = e as Error;
        console.error('[file-api] Identity backup failed:', error.message);
        res.writeHead(500);
        res.end(JSON.stringify({ success: false, error: error.message }));
      }
      return;
    }

    // POST /api/restore-identity — Restore passkey DB from volume backup after wake
    if (req.method === 'POST' && pathname === '/api/restore-identity') {
      try {
        const { execSync } = await import('child_process');
        const result = execSync(
          'sudo /usr/local/bin/ellulai-restore-identity',
          { timeout: 30_000, encoding: 'utf8' }
        );
        const trimmed = result.trim();
        const lastLine = trimmed.split('\n').pop() || '{}';
        const parsed = JSON.parse(lastLine);

        console.log(`[file-api] Identity restore result:`, parsed);
        res.writeHead(parsed.success ? 200 : 500);
        res.end(lastLine);
      } catch (e) {
        const error = e as Error;
        console.error('[file-api] Identity restore failed:', error.message);
        res.writeHead(500);
        res.end(JSON.stringify({ success: false, error: error.message }));
      }
      return;
    }

    // 404
    res.writeHead(404);
    res.end(JSON.stringify({ error: 'Not found' }));
  } catch (e) {
    const error = e as Error;
    res.writeHead(500);
    res.end(JSON.stringify({ error: error.message }));
  }
});

// Handle server errors
server.on('error', (err: NodeJS.ErrnoException) => {
  console.error('[file-api] Server error:', err.message);
  if (err.code === 'EADDRINUSE') {
    console.error('[file-api] Port ' + PORT + ' is already in use. Retrying in 5 seconds...');
    setTimeout(() => {
      server.close();
      server.listen(PORT, '127.0.0.1');
    }, 5000);
  }
});

server.on('clientError', (err, socket) => {
  console.error('[file-api] Client error:', err.message);
  if (socket.writable) {
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  }
});

// Start server
server.listen(PORT, '127.0.0.1', () => {
  console.log(`ellul.ai File API running on port ${PORT}`);

  // Preview GC on startup (after 5s delay for PM2 to settle)
  setTimeout(() => { reconcilePortRegistry(); cleanupOrphanedPreviews(); }, 5000);
  // Preview GC hourly
  setInterval(() => { reconcilePortRegistry(); cleanupOrphanedPreviews(); }, 3600000);
});

// Set up WebSocket
setupWebSocket(server);

// Initialize file watchers
setTimeout(initWatchers, 1000);
setInterval(initWatchers, 60000); // Re-scan periodically

// Polling fallback — fs.watch is unreliable on Linux VPS
startPollingFallback();

// Initialize server status watcher
setTimeout(initServerStatusWatcher, 2000);

// Initialize preview status watcher (broadcasts when AI starts/stops preview)
initPreviewStatusWatcher();

console.log('[WS] WebSocket server ready on /ws');
