/**
 * Git Service
 *
 * Execute git operations (push, pull, setup, teardown) on the VPS.
 * Ported from enforcer handle_git_action() in enforcement.sh.
 *
 * Per-app secrets resolution: secrets are stored with app-specific suffixes
 * (e.g. __GIT_TOKEN__MY_APP) and resolved to non-suffixed names for scripts.
 *
 * Called via bridge endpoint (passkey-authenticated).
 */

import { execSync } from 'child_process';
import fs from 'fs';
import { SVC_HOME, SVC_USER, API_URL_FILE } from '../config';
import { readEnvFile, writeEnvFile, setSecretsBulk, type EncryptedEnvelope } from './secrets.service';

export type GitAction = 'push' | 'pull' | 'force-push' | 'setup' | 'teardown';

const ENV_FILE = `${SVC_HOME}/.ellulai-env`;
const ACTIVE_GIT_APP_FILE = '/etc/ellulai/shield-data/.active-git-app';
const PROJECTS_DIR = `${SVC_HOME}/projects`;

const GIT_SECRET_VARS = [
  '__GIT_TOKEN',
  '__GIT_PROVIDER',
  '__GIT_REPO_URL',
  '__GIT_USER_NAME',
  '__GIT_USER_EMAIL',
  '__GIT_DEFAULT_BRANCH',
];

/**
 * Resolve the project directory for the given app.
 * Falls back to $SVC_HOME/projects/welcome, then $SVC_HOME/projects.
 */
function resolveProjectDir(appName: string | undefined): string {
  if (appName && appName !== 'null' && appName !== 'default') {
    const appDir = `${PROJECTS_DIR}/${appName}`;
    if (fs.existsSync(appDir)) return appDir;
  }
  const welcomeDir = `${PROJECTS_DIR}/welcome`;
  if (fs.existsSync(welcomeDir)) return welcomeDir;
  return PROJECTS_DIR;
}

/**
 * Build an app-name suffix for secret resolution.
 * e.g. "my-app" → "__MY_APP"
 */
function buildAppSuffix(appName: string): string {
  const cleaned = appName
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_/, '')
    .replace(/_$/, '');
  return `__${cleaned}`;
}

/**
 * Build the shell export command that maps per-app secrets to non-suffixed names.
 * e.g. export __GIT_TOKEN='value_from___GIT_TOKEN__MY_APP' &&
 *
 * We source the env file first, then read the suffixed vars from it.
 */
function buildGitEnvCmd(appName: string | undefined): string {
  if (!appName || appName === 'null' || appName === 'default') return '';

  const suffix = buildAppSuffix(appName);

  // Read env file to find suffixed vars
  let envContent = '';
  try {
    envContent = fs.readFileSync(ENV_FILE, 'utf8');
  } catch {
    return '';
  }

  const exports: string[] = [];
  for (const varName of GIT_SECRET_VARS) {
    const suffixedVar = `${varName}${suffix}`;
    // Parse: export __GIT_TOKEN__MY_APP="value" or __GIT_TOKEN__MY_APP='value'
    const regex = new RegExp(`(?:export\\s+)?${suffixedVar}=['"](.*?)['"]`);
    const match = envContent.match(regex);
    if (match?.[1]) {
      // Escape single quotes in value for shell
      const val = match[1].replace(/'/g, "'\\''");
      exports.push(`${varName}='${val}'`);
    }
  }

  if (exports.length === 0) return '';
  return `export ${exports.join(' ')} &&`;
}

/**
 * Pull all encrypted secrets from the API and decrypt them into ~/.ellulai-env.
 * This ensures the env file exists before git-setup runs, even if the frontend
 * only stored secrets in the API database (not directly on the VPS).
 */
function syncSecretsFromApi(): void {
  let apiUrl: string;
  let bearerToken: string;

  try {
    apiUrl = fs.readFileSync(API_URL_FILE, 'utf8').trim();
  } catch {
    return; // No API URL configured
  }

  try {
    bearerToken = fs.readFileSync('/etc/ellulai/ai-proxy-token', 'utf8').trim();
  } catch {
    return; // No token
  }

  try {
    const url = `${apiUrl}/api/servers/secrets/sync`;
    const result = execSync(
      `curl -s -f -m 15 -H 'Authorization: Bearer ${bearerToken}' '${url}'`,
      { timeout: 20_000, encoding: 'utf8' },
    );

    const data = JSON.parse(result);
    if (data.secrets && Array.isArray(data.secrets) && data.secrets.length > 0) {
      const items = data.secrets
        .filter((s: any) => s.encryptedKey && s.iv && s.encryptedData)
        .map((s: any) => ({
          name: s.name,
          envelope: {
            encryptedKey: s.encryptedKey,
            iv: s.iv,
            encryptedData: s.encryptedData,
          } as EncryptedEnvelope,
        }));
      if (items.length > 0) {
        setSecretsBulk(items);
        console.log(`[shield] Synced ${items.length} secrets from API`);
      }
    }
  } catch (err: any) {
    console.warn('[shield] Secrets sync from API failed:', err.message);
  }
}

/**
 * Execute a git action on the VPS.
 * Runs as the service user via sudo -u $SVC_USER.
 */
export function executeGitAction(action: GitAction, appName?: string): { success: boolean; output?: string } {
  // Resolve active app from file if not provided
  let activeApp = appName;
  if (!activeApp) {
    try {
      activeApp = fs.readFileSync(ACTIVE_GIT_APP_FILE, 'utf8').trim();
    } catch {
      activeApp = undefined;
    }
  }

  const projectDir = resolveProjectDir(activeApp);
  const gitEnvCmd = buildGitEnvCmd(activeApp);

  // Persist active git app for credential helper
  if (activeApp && activeApp !== 'null') {
    fs.writeFileSync(ACTIVE_GIT_APP_FILE, activeApp);
    try { fs.chmodSync(ACTIVE_GIT_APP_FILE, 0o644); } catch {}
  }

  const execOpts = { timeout: 120_000 };

  // NOTE: sovereign-shield already runs as SVC_USER (systemd User=dev).
  // Do NOT use sudo — the systemd unit has NoNewPrivileges=true which blocks it.
  switch (action) {
    case 'setup': {
      if (!fs.existsSync('/usr/local/bin/ellulai-git-setup')) {
        return { success: false, output: 'ellulai-git-setup not found' };
      }
      // Sync secrets from API → ~/.ellulai-env (in case frontend only stored in DB)
      syncSecretsFromApi();
      // Re-resolve gitEnvCmd now that env file may have been populated
      const freshGitEnvCmd = buildGitEnvCmd(activeApp);
      const output = execSync(
        `bash -c "[ -f ${ENV_FILE} ] && source ${ENV_FILE}; export ELLULAI_PROJECT_DIR='${projectDir}' && ${freshGitEnvCmd} /usr/local/bin/ellulai-git-setup"`,
        { ...execOpts, timeout: 60_000 }
      ).toString();
      return { success: true, output };
    }

    case 'push': {
      const output = execSync(
        `bash -c "[ -f ${ENV_FILE} ] && source ${ENV_FILE}; ${gitEnvCmd} cd '${projectDir}' && /usr/local/bin/ellulai-git-flow backup"`,
        execOpts
      ).toString();
      return { success: true, output };
    }

    case 'force-push': {
      const output = execSync(
        `bash -c "[ -f ${ENV_FILE} ] && source ${ENV_FILE}; ${gitEnvCmd} cd '${projectDir}' && /usr/local/bin/ellulai-git-flow force-backup"`,
        execOpts
      ).toString();
      return { success: true, output };
    }

    case 'pull': {
      const output = execSync(
        `bash -c "[ -f ${ENV_FILE} ] && source ${ENV_FILE}; ${gitEnvCmd} cd '${projectDir}' && /usr/local/bin/ellulai-git-flow pull"`,
        execOpts
      ).toString();
      return { success: true, output };
    }

    case 'teardown': {
      try {
        execSync(
          `bash -c "cd '${projectDir}' && git remote remove origin 2>/dev/null; git config --global --unset credential.helper 2>/dev/null" || true`,
          { timeout: 10_000 }
        );
      } catch {}
      try { fs.unlinkSync(ACTIVE_GIT_APP_FILE); } catch {}
      // Remove git secrets from env file
      try {
        const secrets = readEnvFile();
        let changed = false;
        for (const key of [...secrets.keys()]) {
          if (key.startsWith('__GIT_')) {
            secrets.delete(key);
            changed = true;
          }
        }
        if (changed) writeEnvFile(secrets);
      } catch {}
      return { success: true };
    }

    default:
      return { success: false, output: `Unknown git action: ${action}` };
  }
}
