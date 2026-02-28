/**
 * Chat Routes
 *
 * Serves the VPS-side chat SPA from /_auth/chat.
 * The SPA runs same-origin — authenticates via shield_session cookie (web_locked)
 * or JWT cookie (standard). The platform never sees agent tokens.
 *
 * Security:
 * - CSP with frame-ancestors prevents framing from unauthorized origins
 * - no-store prevents caching of authenticated content
 * - session-pop.js injected for WebSocket PoP challenge-response
 */

import type { Hono } from 'hono';
import chatHtml from '@ellul.ai/vps-ui/chat';

export function registerChatRoutes(app: Hono): void {
  app.get('/_auth/chat', (c) => {
    // Inject session-pop.js before the first <script> in the SPA
    // This makes SESSION_POP available for WebSocket PoP challenge-response
    let html = chatHtml;
    const popScript = `<script src="/_auth/static/session-pop.js"></script>`;
    html = html.replace('<script', popScript + '<script');

    // NOTE: Nonce-based CSP is NOT compatible with pre-built SPA bundles because
    // bundled JS contains string literals like innerHTML="<script>" which regex
    // nonce injection corrupts. Use 'unsafe-inline' for script/style — the real
    // protection is frame-ancestors + auth cookies + PoP challenge-response.
    const csp = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "font-src 'self' data:",
      "connect-src 'self' wss:",
      "frame-ancestors 'self' https://console.ellul.ai",
      "base-uri 'self'",
      "form-action 'none'",
      "object-src 'none'",
    ].join('; ');

    c.header('Content-Type', 'text/html; charset=utf-8');
    c.header('Content-Security-Policy', csp);
    c.header('Cache-Control', 'no-store');
    return c.body(html);
  });
}
