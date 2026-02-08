/**
 * Credential utilities for VPS services.
 * Reads server identity and configuration from the filesystem.
 */

import fs from 'fs';
import { execSync } from 'child_process';
import {
  SERVER_ID_FILE,
  API_URL_FILE,
  DOMAIN_FILE,
  OWNER_LOCK_FILE,
  JWT_SECRET_FILE,
} from './constants';

export interface ServerCredentials {
  serverId: string | null;
  apiUrl: string | null;
  domain: string;
  ownerId: string | null;
  jwtSecret: string | null;
}

/**
 * Get the server ID.
 */
export function getServerId(): string | null {
  try {
    return fs.readFileSync(SERVER_ID_FILE, 'utf8').trim();
  } catch {
    return null;
  }
}

/**
 * Get the API URL.
 */
export function getApiUrl(): string | null {
  try {
    return fs.readFileSync(API_URL_FILE, 'utf8').trim();
  } catch {
    return null;
  }
}

/**
 * Get the server domain.
 */
export function getDomain(fallback = 'localhost'): string {
  try {
    const domain = fs.readFileSync(DOMAIN_FILE, 'utf8').trim();
    return domain || fallback;
  } catch {
    return fallback;
  }
}

/**
 * Get the owner ID (immutable, set during first setup).
 */
export function getOwnerId(): string | null {
  try {
    return fs.readFileSync(OWNER_LOCK_FILE, 'utf8').trim();
  } catch {
    return null;
  }
}

/**
 * Set the owner ID (one-time operation).
 * File is made immutable via chattr +i after writing.
 */
export function setOwnerId(ownerId: string): void {
  // Check if already set (immutable)
  if (getOwnerId()) {
    throw new Error('Owner already set and cannot be changed');
  }

  fs.writeFileSync(OWNER_LOCK_FILE, ownerId, 'utf8');

  // Make immutable (requires root)
  try {
    execSync(`chattr +i ${OWNER_LOCK_FILE}`, { stdio: 'ignore' });
  } catch {
    console.warn('[credentials] Could not make owner file immutable');
  }
}

/**
 * Get the JWT secret for terminal tokens.
 */
export function getJwtSecret(): string | null {
  try {
    return fs.readFileSync(JWT_SECRET_FILE, 'utf8').trim();
  } catch {
    return null;
  }
}

/**
 * Get all server credentials as an object.
 */
export function getServerCredentials(domainFallback?: string): ServerCredentials {
  return {
    serverId: getServerId(),
    apiUrl: getApiUrl(),
    domain: getDomain(domainFallback),
    ownerId: getOwnerId(),
    jwtSecret: getJwtSecret(),
  };
}
