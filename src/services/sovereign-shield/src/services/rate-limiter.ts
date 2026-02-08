/**
 * Rate Limiter Service
 *
 * Authentication and API rate limiting to prevent abuse.
 */

import type Database from 'better-sqlite3';
import {
  RATE_LIMIT_WINDOW_MS,
  RATE_LIMIT_MAX_ATTEMPTS,
  LOCKOUT_DURATION_MS,
} from '../config';

// Database will be injected to avoid circular dependencies
let db: Database;

export function setDatabase(database: Database): void {
  db = database;
}

// General API rate limiter (for bridge endpoints)
const apiRateLimiter = new Map<string, { count: number; resetTime: number }>();
const API_RATE_LIMIT = 100; // requests per minute
const API_RATE_WINDOW = 60 * 1000; // 1 minute

export interface RateLimitResult {
  blocked: boolean;
  until?: number;
  remaining?: number;
}

export interface RecoveryRateLimitResult {
  blocked: boolean;
  attempts: number;
  remaining: number;
}

/**
 * Check authentication rate limit (persistent, db-backed)
 */
export function checkRateLimit(ip: string): RateLimitResult {
  const windowStart = Date.now() - RATE_LIMIT_WINDOW_MS;
  const recentFailures = db.prepare(
    'SELECT COUNT(*) as count FROM auth_attempts WHERE ip = ? AND timestamp > ? AND success = 0'
  ).get(ip, windowStart) as { count: number };

  if (recentFailures.count >= RATE_LIMIT_MAX_ATTEMPTS) {
    const lastAttempt = db.prepare(
      'SELECT timestamp FROM auth_attempts WHERE ip = ? AND success = 0 ORDER BY timestamp DESC LIMIT 1'
    ).get(ip) as { timestamp: number };
    const lockoutEnd = lastAttempt.timestamp + LOCKOUT_DURATION_MS;
    if (Date.now() < lockoutEnd) {
      return { blocked: true, until: lockoutEnd, remaining: lockoutEnd - Date.now() };
    }
  }

  return { blocked: false };
}

/**
 * Record an authentication attempt
 */
export function recordAuthAttempt(ip: string, success: boolean): void {
  db.prepare('INSERT INTO auth_attempts (ip, timestamp, success) VALUES (?, ?, ?)').run(ip, Date.now(), success ? 1 : 0);
  // Clean up old attempts (older than 24 hours)
  db.prepare('DELETE FROM auth_attempts WHERE timestamp < ?').run(Date.now() - 86400000);
}

/**
 * Check API rate limit (in-memory, per-minute)
 */
export function checkApiRateLimit(ip: string): RateLimitResult {
  const now = Date.now();
  const record = apiRateLimiter.get(ip);

  if (!record || now > record.resetTime) {
    apiRateLimiter.set(ip, { count: 1, resetTime: now + API_RATE_WINDOW });
    return { blocked: false };
  }

  record.count++;
  if (record.count > API_RATE_LIMIT) {
    return { blocked: true, remaining: record.resetTime - now };
  }

  return { blocked: false };
}

/**
 * Check recovery code rate limit (max 3 attempts per hour per IP)
 */
export function checkRecoveryRateLimit(ip: string): RecoveryRateLimitResult {
  const hourAgo = Date.now() - 3600000;
  const attempts = db.prepare(
    'SELECT COUNT(*) as count FROM recovery_attempts WHERE ip = ? AND timestamp > ?'
  ).get(ip, hourAgo) as { count: number };

  return {
    blocked: attempts.count >= 3,
    attempts: attempts.count,
    remaining: 3 - attempts.count
  };
}

/**
 * Record a recovery attempt
 */
export function recordRecoveryAttempt(ip: string, success: boolean): void {
  db.prepare(
    'INSERT INTO recovery_attempts (ip, timestamp, success) VALUES (?, ?, ?)'
  ).run(ip, Date.now(), success ? 1 : 0);
}

// Clean up old rate limit records periodically
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of apiRateLimiter) {
    if (now > record.resetTime) {
      apiRateLimiter.delete(ip);
    }
  }
}, 60 * 1000);
