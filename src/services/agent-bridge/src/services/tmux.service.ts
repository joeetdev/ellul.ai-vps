/**
 * Tmux Service
 *
 * Manages tmux sessions for the main shell.
 */

import { execSync, spawn } from 'child_process';

/**
 * Ensure a tmux session exists.
 */
export function ensureTmuxSession(name: string): boolean {
  try {
    execSync(`tmux has-session -t ${name} 2>/dev/null`, {
      env: { ...process.env, TMUX: '' },
    });
    return true;
  } catch {
    try {
      execSync(`tmux new-session -d -s ${name}`, {
        env: { ...process.env, TMUX: '' },
      });
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Capture tmux pane content.
 */
export function captureTmuxPane(name: string): string | null {
  try {
    return execSync(`tmux capture-pane -t ${name} -p -S -100`, {
      encoding: 'utf8',
      env: { ...process.env, TMUX: '' },
    });
  } catch {
    return null;
  }
}

/**
 * Send command to a tmux session.
 */
export function sendToTmux(session: string, command: string): Promise<string> {
  if (!ensureTmuxSession(session)) {
    return Promise.reject(new Error(`No ${session} session`));
  }

  return new Promise((resolve, reject) => {
    const proc = spawn('env', ['-u', 'TMUX', 'tmux', 'send-keys', '-t', session, command, 'Enter']);
    proc.on('close', (code) => (code === 0 ? resolve('Command sent') : reject(new Error('Failed'))));
    proc.on('error', reject);
  });
}

/**
 * Send command to main tmux session.
 */
export function sendToMain(command: string): Promise<string> {
  return sendToTmux('main', command);
}
