/**
 * Content Security Policy helpers
 *
 * Nonce-based CSP for auth pages to prevent XSS.
 */

import crypto from 'crypto';

/**
 * Generate a cryptographically random nonce for CSP script-src.
 */
export function generateCspNonce(): string {
  return crypto.randomBytes(16).toString('base64');
}

/**
 * Build a CSP header value for auth pages.
 * Uses nonce-based script-src so only inline scripts with the matching
 * nonce attribute are allowed to execute.
 */
export function getCspHeader(nonce: string): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    `style-src 'self' 'unsafe-inline'`,
    "img-src 'self' data:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "frame-ancestors 'self' https://console.ellul.ai",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; ');
}
