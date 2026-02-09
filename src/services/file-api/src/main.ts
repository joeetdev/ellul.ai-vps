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

import { PORT, ROOT_DIR, HOME, PATHS } from './config';
import { getCurrentTier } from './auth';
import {
  getTree,
  getFileContent,
  listProjects,
  getActiveProject,
  parseMultipart,
  uploadFile,
  type UploadedFile,
} from './services/files.service';
import { detectApps } from './services/apps.service';
import { getPreviewStatus, setPreviewApp, startPreview, stopPreview } from './services/preview.service';
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
  initWatchers,
  initServerStatusWatcher,
} from './services/websocket.service';

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

  // Security tier enforcement
  const currentTier = getCurrentTier();

  // SSH Only mode enforcement
  if (currentTier === 'ssh_only') {
    const allowedPaths = ['/_auth/', '/api/tier'];
    const isAllowedPath = allowedPaths.some((p) => pathname.startsWith(p));

    if (!isAllowedPath) {
      res.writeHead(403);
      res.end(
        JSON.stringify({
          error: 'SSH Only mode active',
          message: 'File access is disabled. Use SSH/SFTP instead.',
          tier: 'ssh_only',
        })
      );
      return;
    }
  }

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

        // Clone the repo
        const { exec, spawn } = await import('child_process');
        const cloneResult = await new Promise<{ success: boolean; error?: string }>((resolve) => {
          exec(`git clone ${cloneUrl} ${appPath}`, { timeout: 120000 }, (err) => {
            if (err) resolve({ success: false, error: err.message });
            else resolve({ success: true });
          });
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

        // 7. Remove the app directory recursively
        fs.rmSync(appPath, { recursive: true, force: true });
        cleanup.push('directory');

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
      let previewStatus: { app: string | null; running: boolean } = { app: null, running: false };
      let previewActivated = false;

      if (app.previewable) {
        // Always activate preview for previewable apps
        // This ensures switching works reliably
        const result = setPreviewApp(app.directory);
        previewActivated = true;
        previewStatus = {
          app: app.directory,
          running: result.preview?.success ?? false,
        };
      } else {
        // Stop preview for non-previewable apps
        stopPreview();
        previewStatus = { app: null, running: false };
      }

      // Check for context files
      const contextDir = `${HOME}/.ellulai/context`;
      const projectContextPath = path.join(contextDir, `${app.directory}.md`);
      const globalContextPath = path.join(contextDir, 'global.md');
      const hasProjectContext = fs.existsSync(projectContextPath);
      const hasGlobalContext = fs.existsSync(globalContextPath);

      res.writeHead(200);
      res.end(JSON.stringify({
        app,
        preview: {
          active: previewStatus.running,
          app: previewStatus.app,
          activated: previewActivated,
          port: 3000, // Default preview port
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

      const previewStatus = getPreviewStatus();
      const isActivePreview = previewStatus.app === resolvedDir;

      res.writeHead(200);
      res.end(JSON.stringify({
        directory: resolvedDir,
        preview: {
          active: isActivePreview && previewStatus.running,
          isCurrentApp: isActivePreview,
          port: 3000,
        },
      }));
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
      const envVars: Record<string, string> = {};
      try {
        if (fs.existsSync(envPath)) {
          const envContent = fs.readFileSync(envPath, 'utf8');
          for (const line of envContent.split('\n')) {
            const match = line.match(/^export\s+(\w+)="(.*)"/);
            if (match?.[1]) envVars[match[1]] = match[2] ?? '';
          }
        }
      } catch {}

      // Resolve per-app suffix: "my-app" → "__MY_APP"
      const appSuffix = '__' + dirName.toUpperCase().replace(/[^A-Z0-9]/g, '_').replace(/_+/g, '_').replace(/^_|_$/, '');
      const token = envVars[`__GIT_TOKEN${appSuffix}`] || envVars['__GIT_TOKEN'] || '';
      const provider = envVars[`__GIT_PROVIDER${appSuffix}`] || envVars['__GIT_PROVIDER'] || '';
      const repoUrl = envVars[`__GIT_REPO_URL${appSuffix}`] || envVars['__GIT_REPO_URL'] || '';
      const defaultBranch = envVars[`__GIT_DEFAULT_BRANCH${appSuffix}`] || envVars['__GIT_DEFAULT_BRANCH'] || 'main';

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
          // Fresh directory — init, add remote, fetch, and checkout
          await runCmd('git init');
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
          const pullResult = await runCmd(`git pull origin ${defaultBranch} --no-edit`);
          if (!pullResult.success) {
            // Try fetch + checkout if pull fails (e.g. unrelated histories)
            await runCmd(`git fetch origin ${defaultBranch}`);
            await runCmd(`git checkout -B ${defaultBranch} origin/${defaultBranch}`);
          }
        }

        // Detect app framework after pull
        const detected = detectApps().find(a => a.directory === dirName);

        // Run npm install in background if package.json exists
        const packageJsonPath = path.join(appPath, 'package.json');
        if (fs.existsSync(packageJsonPath)) {
          const { spawn } = await import('child_process');
          const npmInstall = spawn('npm', ['install'], {
            cwd: appPath,
            detached: true,
            stdio: 'ignore',
          });
          npmInstall.unref();
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
        const status = getPreviewStatus();
        let autoStarted = false;

        if (status.app && !status.running) {
          const result = startPreview(status.app);
          if (result.success) {
            status.running = true;
            autoStarted = true;
          }
        }

        res.writeHead(200);
        res.end(JSON.stringify({ ...status, autoStarted }));
        return;
      }

      if (req.method === 'POST') {
        const body = await parseBody(req);
        const { app, script } = body as { app?: string; script?: string };
        const result = setPreviewApp(app || null, script);
        res.writeHead(200);
        res.end(JSON.stringify(result));
        return;
      }
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
          { timeout: 60_000, encoding: 'utf8' }
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

    // POST /api/trigger-sync — Wake enforcer daemon via SIGUSR1 (push-based command dispatch)
    if (req.method === 'POST' && pathname === '/api/trigger-sync') {
      try {
        const pidStr = fs.readFileSync('/run/ellulai-enforcer.pid', 'utf8').trim();
        const pid = parseInt(pidStr, 10);
        if (isNaN(pid) || pid <= 0) throw new Error(`Invalid PID: ${pidStr}`);
        process.kill(pid, 'SIGUSR1');
        console.log('[file-api] Sent SIGUSR1 to enforcer (pid ' + pid + ')');
        res.writeHead(200);
        res.end(JSON.stringify({ success: true, pid }));
      } catch (e) {
        const error = e as Error;
        // Non-fatal: enforcer's 30s poll will pick up the command
        console.warn('[file-api] trigger-sync failed:', error.message);
        res.writeHead(200); // Still 200 — push is best-effort optimization
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
});

// Set up WebSocket
setupWebSocket(server);

// Initialize file watchers
setTimeout(initWatchers, 1000);
setInterval(initWatchers, 60000); // Re-scan periodically

// Initialize server status watcher
setTimeout(initServerStatusWatcher, 2000);

console.log('[WS] WebSocket server ready on /ws');
