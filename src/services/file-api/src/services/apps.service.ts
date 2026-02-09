/**
 * Apps Service
 *
 * Handles app/project detection, framework identification, and preview management.
 */

import * as fs from 'fs';
import * as path from 'path';
import { ROOT_DIR, FRAMEWORK_PATTERNS, DEFAULT_PORTS } from '../config';
import { safeReadFile, safeReadDir, safeStat, safeJsonParse, safeExec } from '../utils';

// Frameworks that are typically frontend vs backend
const FRONTEND_FRAMEWORKS = new Set(['nextjs', 'remix', 'astro', 'vite', 'cra', 'nuxt', 'vue', 'svelte', 'gatsby', 'static', 'html']);
const BACKEND_FRAMEWORKS = new Set(['express', 'fastify', 'hono', 'koa', 'nestjs']);

/**
 * Determine app type from framework name.
 */
function getTypeFromFramework(framework: string): 'frontend' | 'backend' | 'library' {
  if (FRONTEND_FRAMEWORKS.has(framework)) return 'frontend';
  if (BACKEND_FRAMEWORKS.has(framework)) return 'backend';
  return 'frontend';
}

/**
 * Detected app/project info.
 */
export interface AppInfo {
  name: string;
  directory: string;  // Actual filesystem directory name (for path operations)
  path: string;
  framework: string;
  port: number;
  hasPackageJson: boolean;
  type: 'frontend' | 'backend' | 'library' | 'monorepo';
  previewable: boolean;
  scripts?: Record<string, string>;
  dependencies?: string[];
  isRunning?: boolean;
  isMonorepo?: boolean;
  packages?: string[];
}

/**
 * Detect framework from package.json dependencies.
 */
function detectFramework(packageJson: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> }): string {
  const allDeps = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies,
  };

  for (const [framework, patterns] of Object.entries(FRAMEWORK_PATTERNS)) {
    for (const dep of patterns.packageJson) {
      if (allDeps[dep]) {
        return framework;
      }
    }
  }

  return 'unknown';
}

/**
 * Detect framework from config files.
 */
function detectFrameworkFromFiles(projectPath: string): string | null {
  for (const [framework, patterns] of Object.entries(FRAMEWORK_PATTERNS)) {
    for (const file of patterns.files) {
      if (fs.existsSync(path.join(projectPath, file))) {
        return framework;
      }
    }
  }
  return null;
}

/**
 * Get default port for a framework.
 */
function getDefaultPort(framework: string): number {
  return DEFAULT_PORTS[framework] ?? DEFAULT_PORTS.unknown ?? 3000;
}

/**
 * Detect all apps/projects in the projects directory.
 */
export function detectApps(): AppInfo[] {
  const apps: AppInfo[] = [];
  const entries = safeReadDir(ROOT_DIR);

  for (const entry of entries) {
    const projectPath = path.join(ROOT_DIR, entry);
    const stats = safeStat(projectPath);

    if (!stats?.isDirectory()) continue;

    // Check for package.json
    const packageJsonPath = path.join(projectPath, 'package.json');
    const packageJsonContent = safeReadFile(packageJsonPath);
    const packageJson = safeJsonParse<{
      name?: string;
      scripts?: Record<string, string>;
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    }>(packageJsonContent, {});

    const hasPackageJson = !!packageJsonContent;

    // Detect framework
    let framework = detectFrameworkFromFiles(projectPath);
    if (!framework && hasPackageJson) {
      framework = detectFramework(packageJson);
    }
    framework = framework || 'unknown';

    // Get port from scripts or use default
    let port = getDefaultPort(framework);

    // Try to detect port from package.json scripts
    if (packageJson.scripts) {
      const devScript = packageJson.scripts.dev || packageJson.scripts.start;
      if (devScript) {
        const portMatch = devScript.match(/--port[=\s]+(\d+)|-p[=\s]+(\d+)/);
        if (portMatch) {
          const portStr = portMatch[1] ?? portMatch[2] ?? '';
          if (portStr) {
            port = parseInt(portStr, 10);
          }
        }
      }
    }

    // Read app-level config: ellulai.json in app root, or ellulai field in package.json
    const appConfigContent = safeReadFile(path.join(projectPath, 'ellulai.json'));
    const appConfig = safeJsonParse<{ type?: string; previewable?: boolean; name?: string; port?: number }>(appConfigContent, {});
    const pkgEllulai = (packageJson as Record<string, unknown>).ellulai as
      { type?: string; previewable?: boolean; summary?: string } | undefined;

    // Priority: app-level ellulai.json > package.json ellulai field > framework inference
    const explicitType = appConfig.type || pkgEllulai?.type;
    let type: AppInfo['type'] = explicitType
      ? explicitType as AppInfo['type']
      : getTypeFromFramework(framework);

    let isMonorepo = false;
    let packages: string[] | undefined;

    if (hasPackageJson && (packageJson as Record<string, unknown>).workspaces) {
      type = 'monorepo';
      isMonorepo = true;
      packages = [];
      for (const dir of ['packages', 'apps']) {
        const subDir = path.join(projectPath, dir);
        const subEntries = safeReadDir(subDir);
        for (const sub of subEntries) {
          const subPath = path.join(subDir, sub);
          const subStats = safeStat(subPath);
          if (subStats?.isDirectory() && fs.existsSync(path.join(subPath, 'package.json'))) {
            packages.push(sub);
          }
        }
      }
    }

    // Explicit previewable from config, otherwise true for frontend apps
    const explicitPreviewable = appConfig.previewable ?? pkgEllulai?.previewable;
    const previewable = explicitPreviewable !== undefined ? explicitPreviewable : type === 'frontend';

    if (appConfig.port) port = appConfig.port;

    apps.push({
      name: appConfig.name || packageJson.name || entry,
      directory: entry,
      path: projectPath,
      framework,
      port,
      hasPackageJson,
      type,
      previewable,
      scripts: packageJson.scripts,
      dependencies: packageJson.dependencies ? Object.keys(packageJson.dependencies) : undefined,
      ...(isMonorepo ? { isMonorepo: true, packages } : {}),
    });
  }

  return apps;
}

/**
 * Check if an app is running by checking if its port is in use.
 */
export function isAppRunning(port: number): boolean {
  const result = safeExec(`lsof -i :${port} -t`);
  return result.success && result.output.length > 0;
}

/**
 * Get running processes on common dev ports.
 */
export function getRunningProcesses(): { port: number; pid: number; command: string }[] {
  const processes: { port: number; pid: number; command: string }[] = [];
  const devPorts = [3000, 3001, 4000, 5000, 5173, 8000, 8080, 8888, 9000];

  for (const port of devPorts) {
    const result = safeExec(`lsof -i :${port} -t`);
    if (result.success && result.output) {
      const pids = result.output.split('\n').filter(Boolean);
      for (const pidStr of pids) {
        const pid = parseInt(pidStr, 10);
        if (isNaN(pid)) continue;

        // Get command for this PID
        const cmdResult = safeExec(`ps -p ${pid} -o comm=`);
        const command = cmdResult.success ? cmdResult.output : 'unknown';

        processes.push({ port, pid, command });
      }
    }
  }

  return processes;
}

/**
 * Start an app (run npm/pnpm dev).
 */
export function startApp(
  appPath: string,
  script: string = 'dev'
): { success: boolean; error?: string } {
  // Determine package manager
  const hasYarnLock = fs.existsSync(path.join(appPath, 'yarn.lock'));
  const hasPnpmLock = fs.existsSync(path.join(appPath, 'pnpm-lock.yaml'));

  let pm = 'npm';
  if (hasPnpmLock) pm = 'pnpm';
  else if (hasYarnLock) pm = 'yarn';

  // Start in background
  const result = safeExec(`cd "${appPath}" && nohup ${pm} run ${script} > /dev/null 2>&1 &`);

  return {
    success: result.success,
    error: result.error,
  };
}

/**
 * Get app icon path if it exists.
 */
export function getAppIconPath(appPath: string): string | null {
  const iconPaths = [
    'public/favicon.ico',
    'public/favicon.png',
    'public/icon.png',
    'public/logo.png',
    'app/favicon.ico',
    'src/favicon.ico',
  ];

  for (const iconPath of iconPaths) {
    const fullPath = path.join(appPath, iconPath);
    if (fs.existsSync(fullPath)) {
      return fullPath;
    }
  }

  return null;
}
