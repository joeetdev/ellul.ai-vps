/**
 * Chat Routes
 *
 * Serves the VPS-side chat SPA from /_auth/chat.
 * The SPA runs same-origin — authenticates via shield_session cookie (web_locked)
 * or JWT cookie (standard). The platform never sees agent tokens.
 *
 * Security:
 * - frame-ancestors CSP prevents framing from unauthorized origins
 * - no-store prevents caching of authenticated content
 */

import type { Hono } from 'hono';
import chatHtml from '@ellul.ai/vps-ui/chat';

export function registerChatRoutes(app: Hono): void {
  app.get('/_auth/chat', (c) => {
    c.header('Content-Type', 'text/html; charset=utf-8');
    c.header('Content-Security-Policy', "frame-ancestors 'self' https://console.ellul.ai");
    c.header('Cache-Control', 'no-store');
    return c.body(chatHtml);
  });
}
