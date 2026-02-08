/**
 * Device Fingerprinting
 *
 * Enhanced device fingerprinting using only stable, low-entropy headers.
 */

import crypto from 'crypto';
import type { Context } from 'hono';
import { STABLE_FINGERPRINT_HEADERS } from '../config';

export interface FingerprintData {
  hash: string;
  components: Record<string, string>;
  isNavigation: boolean;
  countryCode: string | null;
  clientIp: string | null;
}

export interface FingerprintComparison {
  match: boolean;
  mismatches: string[];
}

/**
 * Detect if this is a navigation request vs fetch/XHR
 */
export function isNavigationRequest(c: Context): boolean {
  const fetchMode = c.req.header('sec-fetch-mode');
  const fetchDest = c.req.header('sec-fetch-dest');

  // Navigation requests have mode=navigate and dest=document
  if (fetchMode === 'navigate' && fetchDest === 'document') {
    return true;
  }

  // Fallback: check Accept header (browsers send text/html for navigation)
  const accept = c.req.header('accept') || '';
  if (accept.includes('text/html') && !accept.startsWith('application/json')) {
    return true;
  }

  // fetch/XHR often set this header
  if (c.req.header('x-requested-with')) {
    return false;
  }

  return false;
}

/**
 * Get device fingerprint using only stable low-entropy headers
 */
export function getDeviceFingerprint(c: Context): FingerprintData {
  const components: Record<string, string> = {};
  const isNav = isNavigationRequest(c);

  // Collect only stable headers that are sent on ALL request types
  for (const header of STABLE_FINGERPRINT_HEADERS) {
    components[header] = c.req.header(header) || '';
  }

  // Get Cloudflare geographic info
  const countryCode = c.req.header('cf-ipcountry') || null;
  const clientIp = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for')?.split(',')[0]?.trim() || null;

  // Build fingerprint string from sorted components for consistency
  const sortedKeys = Object.keys(components).sort();
  const fingerprintString = sortedKeys
    .map(key => key + ':' + components[key])
    .join('|');

  const hash = crypto.createHash('sha256')
    .update(fingerprintString)
    .digest('hex');

  return {
    hash,
    components,
    isNavigation: isNav,
    countryCode,
    clientIp,
  };
}

/**
 * Compare two fingerprints with detailed mismatch info
 */
export function compareFingerprints(
  stored: Record<string, string>,
  current: Record<string, string>
): FingerprintComparison {
  const mismatches: string[] = [];

  // Check all stored components against current
  for (const key of Object.keys(stored)) {
    const storedValue = stored[key] ?? '';
    const currentValue = current[key] ?? '';
    if (storedValue !== currentValue) {
      mismatches.push(key + ': "' + storedValue.substring(0, 50) + '" -> "' + currentValue.substring(0, 50) + '"');
    }
  }

  return {
    match: mismatches.length === 0,
    mismatches,
  };
}

/**
 * Get client IP address from request
 */
export function getClientIp(c: Context): string {
  // Prefer CF-Connecting-IP when behind Cloudflare (consistent client IP)
  const cfIp = c.req.header('cf-connecting-ip');
  if (cfIp) return cfIp.trim();

  // Fall back to X-Forwarded-For
  const forwarded = c.req.header('x-forwarded-for');
  if (forwarded) return (forwarded.split(',')[0] ?? '').trim();

  return c.req.header('x-real-ip') || 'unknown';
}
