/**
 * Deterministic Body Hashing
 *
 * Produces identical SHA-256 digests for semantically identical JSON objects
 * regardless of key ordering. Used by both PoP signatures and HMAC confirmation
 * tokens to cryptographically bind request bodies to their authorization proofs.
 *
 * The browser-side equivalent (inlined in SESSION_POP_JS) uses the Web Crypto API
 * but follows the same canonicalization algorithm.
 */

import crypto from 'crypto';

/**
 * Recursively sort object keys alphabetically.
 * Arrays preserve element order; only object keys are sorted.
 */
function sortKeys(obj: unknown): unknown {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(sortKeys);
  return Object.keys(obj as Record<string, unknown>)
    .sort()
    .reduce((sorted: Record<string, unknown>, key) => {
      sorted[key] = sortKeys((obj as Record<string, unknown>)[key]);
      return sorted;
    }, {});
}

/**
 * Produce a canonical JSON string from any body value.
 * - null/undefined/empty string → empty string
 * - string → try to parse as JSON and re-serialize sorted; fallback to raw string
 * - object → JSON.stringify with sorted keys
 */
export function canonicalize(body: unknown): string {
  if (body === undefined || body === null || body === '') return '';
  if (typeof body === 'string') {
    try {
      const parsed = JSON.parse(body);
      return JSON.stringify(sortKeys(parsed));
    } catch {
      return body;
    }
  }
  return JSON.stringify(sortKeys(body));
}

/**
 * Compute a deterministic SHA-256 hash of a request body.
 * Returns a base64url-encoded digest (URL-safe, no padding).
 *
 * Both this function and the browser-side hashBody() produce
 * identical output for the same input.
 */
export function getDeterministicBodyHash(body: unknown): string {
  const canonical = canonicalize(body);
  return crypto.createHash('sha256').update(canonical).digest('base64url');
}
