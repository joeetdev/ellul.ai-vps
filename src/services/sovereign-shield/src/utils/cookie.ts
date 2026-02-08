/**
 * Cookie Utilities
 *
 * Cookie parsing and manipulation.
 */

export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'Strict' | 'Lax' | 'None';
  path?: string;
  maxAge?: number;
  expires?: Date;
  domain?: string;
}

/**
 * Parse cookies from cookie header string
 */
export function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieHeader) return cookies;

  cookieHeader.split(';').forEach(cookie => {
    const [name, ...rest] = cookie.split('=');
    if (name && rest.length > 0) {
      const trimmedName = name.trim();
      cookies[trimmedName] = rest.join('=').trim();
      // Alias __Host- prefixed cookies so callers can use unprefixed names
      // e.g. __Host-shield_session → also accessible as shield_session
      if (trimmedName.startsWith('__Host-')) {
        cookies[trimmedName.slice(7)] = cookies[trimmedName];
      }
    }
  });

  return cookies;
}

/**
 * Create a Set-Cookie header value
 */
export function createCookieHeader(name: string, value: string, options: CookieOptions = {}): string {
  const {
    httpOnly = true,
    secure = true,
    sameSite = 'Strict',
    path = '/',
    maxAge,
    expires,
    domain,
  } = options;

  let cookie = `${name}=${value}; Path=${path}`;

  if (httpOnly) cookie += '; HttpOnly';
  if (secure) cookie += '; Secure';
  if (sameSite) cookie += `; SameSite=${sameSite}`;
  if (maxAge !== undefined) cookie += `; Max-Age=${maxAge}`;
  if (expires) cookie += `; Expires=${expires.toUTCString()}`;
  if (domain) cookie += `; Domain=${domain}`;

  return cookie;
}

/**
 * Create a cookie deletion header (sets Max-Age=0)
 */
export function deleteCookieHeader(name: string, path = '/'): string {
  return `${name}=; Path=${path}; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}
