/**
 * JWT Authentication
 *
 * JWT verification for standard tier authentication.
 */

import crypto from 'crypto';
import fs from 'fs';
import type { HonoRequest } from 'hono';
import { JWT_SECRET_FILE, SERVER_ID_FILE } from '../config';
import { parseCookies } from '../utils/cookie';

export interface JwtPayload {
  sub?: string;
  sid?: string;
  jti?: string;
  iat?: number;
  exp?: number;
  nbf?: number;
  [key: string]: unknown;
}

// Load JWT secret for standard tier authentication
let JWT_SECRET: string | null = null;
try {
  JWT_SECRET = fs.readFileSync(JWT_SECRET_FILE, 'utf8').trim();
} catch {
  console.log('[shield] No JWT secret found - standard tier auth disabled');
}

// Load server ID for JWT validation
let SERVER_ID: string | null = null;
try {
  SERVER_ID = fs.readFileSync(SERVER_ID_FILE, 'utf8').trim();
} catch {
  console.log('[shield] No server ID found');
}

/**
 * Verify JWT token (for standard tier)
 * Returns payload if valid, null otherwise
 */
export function verifyJwtToken(req: HonoRequest): JwtPayload | null {
  if (!JWT_SECRET) return null;

  const cookies = parseCookies(req.header('cookie'));
  const token = cookies['term_session'] || cookies['terminal_token'] ||
    (req.header('authorization') || '').replace('Bearer ', '');

  if (!token) return null;

  try {
    const parts = token.split('.');
    if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) return null;

    const payload: JwtPayload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    const signInput = parts[0] + '.' + parts[1];
    const expectedSig = crypto.createHmac('sha256', JWT_SECRET).update(signInput).digest('base64url');

    // SECURITY: Use timing-safe comparison to prevent timing attacks
    const expectedBuf = Buffer.from(expectedSig, 'utf8');
    const actualBuf = Buffer.from(parts[2], 'utf8');
    if (expectedBuf.length !== actualBuf.length || !crypto.timingSafeEqual(expectedBuf, actualBuf)) return null;

    // Check expiration
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;

    // Check server ID binding
    if (SERVER_ID && payload.sid && payload.sid !== SERVER_ID) return null;

    return payload;
  } catch {
    return null;
  }
}

/**
 * Create a JWT token
 */
export function createJwtToken(payload: Omit<JwtPayload, 'iat' | 'exp' | 'sid'>, expiresIn = 3600): string {
  if (!JWT_SECRET) throw new Error('JWT secret not available');

  const now = Math.floor(Date.now() / 1000);
  const fullPayload: JwtPayload = {
    ...payload,
    iat: now,
    exp: now + expiresIn,
    sid: SERVER_ID || undefined,
  };

  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(fullPayload)).toString('base64url');
  const signInput = header + '.' + body;
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(signInput).digest('base64url');

  return signInput + '.' + signature;
}

export { JWT_SECRET, SERVER_ID };
