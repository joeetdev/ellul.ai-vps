/**
 * CORS Middleware
 *
 * Cross-Origin Resource Sharing for dashboard communication.
 */

import type { Context } from 'hono';

export const ALLOWED_ORIGINS = ['https://console.phone-stack.app', 'https://phone-stack.app'];

/**
 * Secure origin validation - prevents spoofing via similar domain names
 */
export function isValidPhoneStackOrigin(origin: string | undefined): boolean {
  if (!origin) return false;
  if (ALLOWED_ORIGINS.includes(origin)) return true;
  // Only allow proper subdomains: https://<subdomain>.phone-stack.app
  // This rejects evil-phone-stack.app and phone-stack.app.attacker.com
  return /^https:\/\/[a-zA-Z0-9-]+\.phone-stack\.app$/.test(origin);
}

/**
 * Set CORS headers on response
 */
export function setCorsHeaders(c: Context): void {
  const origin = c.req.header('origin');
  const isAllowed = isValidPhoneStackOrigin(origin);
  if (isAllowed && origin) {
    c.header('Access-Control-Allow-Origin', origin);
    c.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    c.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cookie, X-Pop-Signature, X-Pop-Timestamp, X-Pop-Nonce');
    c.header('Access-Control-Allow-Credentials', 'true');
    c.header('Access-Control-Max-Age', '86400');
  }
}

/**
 * CORS preflight handler
 */
export function handleCorsOptions(c: Context): Response {
  setCorsHeaders(c);
  return c.body(null, 204);
}
