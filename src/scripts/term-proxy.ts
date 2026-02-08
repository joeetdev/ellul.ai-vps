/**
 * Terminal Auth Proxy - Routes terminal connections to the correct ttyd instance.
 *
 * UNIFIED AUTH ARCHITECTURE:
 * - HTTP requests: No auth required - only serves ttyd web UI (HTML/CSS/JS)
 * - WebSocket: Requires terminal token from /_auth/terminal/authorize
 *   Token validated via sovereign-shield (handles all tiers internally)
 *
 * Security model: The ttyd web UI is harmless on its own. Actual terminal
 * access requires WebSocket connection with valid terminal token.
 * Sovereign-shield issues tokens based on tier-specific authentication.
 *
 * DYNAMIC SESSION SUPPORT:
 * - All sessions are dynamic: claude-1704567890123 → port from agent-bridge
 * - Sessions created on-demand via agent-bridge API
 *
 * Port: 7701
 * Routes: /term/<session-instance-id>/* → localhost:<session-port>
 */
export function getTermProxyScript(): string {
  return `#!/usr/bin/env node
const http = require('http');
const { WebSocket, WebSocketServer } = require('ws');

const PORT = 7701;
const SHIELD_URL = 'http://127.0.0.1:3005';
const BRIDGE_URL = 'http://127.0.0.1:7700';

// Cache for dynamic session ports (TTL: 60 seconds)
const dynamicPortCache = new Map();
const PORT_CACHE_TTL = 60000;

// No local session storage — sovereign-shield owns all session state.
// Terminal sessions persist indefinitely until explicitly closed.
// Security is enforced per-request (WebSocket auth via sovereign-shield).

function parseCookies(req) {
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return {};
  return cookieHeader.split(';').reduce((acc, c) => {
    const [k, ...v] = c.trim().split('=');
    if (k) acc[k] = v.join('=');
    return acc;
  }, {});
}

function getShieldSession(req) {
  const cookies = parseCookies(req);
  return cookies['__Host-shield_session'] || cookies['shield_session'] || null;
}

function getTermSession(req) {
  return parseCookies(req)['_term_auth'] || null;
}

function getClientIp(req) {
  return req.headers['cf-connecting-ip']
    || req.headers['x-real-ip']
    || (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket.remoteAddress
    || '';
}

// Validate terminal token via sovereign-shield (returns binding data)
async function validateTerminalToken(token, sessionId) {
  try {
    const res = await fetch(SHIELD_URL + '/_auth/terminal/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, sessionId })
    });
    const data = await res.json();
    if (data.valid === true) {
      return { valid: true, ip: data.ip || '', tier: data.tier || '', sessionId: data.sessionId || '' };
    }
    return { valid: false };
  } catch (e) {
    console.error('[TermProxy] Token validation error:', e.message);
    return { valid: false };
  }
}

// Create a term session in sovereign-shield (survives term-proxy restarts)
async function createTermSession(ip, shieldSessionId, tier) {
  try {
    const res = await fetch(SHIELD_URL + '/_auth/terminal/session/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, shieldSessionId, tier })
    });
    const data = await res.json();
    return data.sessionId || null;
  } catch (e) {
    console.error('[TermProxy] Session create error:', e.message);
    return null;
  }
}

// Validate a term session in sovereign-shield (checks IP, shield_session, expiry)
async function validateTermSession(termSessionId, ip, shieldSessionId) {
  try {
    const res = await fetch(SHIELD_URL + '/_auth/terminal/session/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ termSessionId, ip, shieldSessionId })
    });
    const data = await res.json();
    return data.valid === true;
  } catch (e) {
    console.error('[TermProxy] Session validate error:', e.message);
    return false;
  }
}

/**
 * Get port for a dynamic session from agent-bridge.
 * Returns cached value if available and not expired.
 */
async function getDynamicSessionPort(sessionId) {
  // Check cache first
  const cached = dynamicPortCache.get(sessionId);
  if (cached && Date.now() - cached.timestamp < PORT_CACHE_TTL) {
    return cached.port;
  }

  try {
    const res = await fetch(BRIDGE_URL + '/terminal/session/' + sessionId + '/port');
    if (res.ok) {
      const data = await res.json();
      if (data.port) {
        dynamicPortCache.set(sessionId, { port: data.port, timestamp: Date.now() });
        return data.port;
      }
    }
  } catch (e) {
    console.error('[TermProxy] Failed to get port for session ' + sessionId + ':', e.message);
  }
  return null;
}

/**
 * Create a dynamic session via agent-bridge.
 * Returns the port if successful.
 * @param sessionId - Unique session identifier
 * @param type - Session type (main, opencode, claude, codex, gemini)
 * @param project - Optional project/app scope
 */
async function createDynamicSession(sessionId, type, project) {
  try {
    const body = { type, instanceId: sessionId };
    if (project) body.project = project;
    const res = await fetch(BRIDGE_URL + '/terminal/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (res.ok) {
      const data = await res.json();
      if (data.port) {
        dynamicPortCache.set(sessionId, { port: data.port, timestamp: Date.now() });
        console.log('[TermProxy] Created dynamic session ' + sessionId + ' on port ' + data.port + (project ? ' (project: ' + project + ')' : ''));
        return data.port;
      }
    }
  } catch (e) {
    console.error('[TermProxy] Failed to create session ' + sessionId + ':', e.message);
  }
  return null;
}

/**
 * Parse session ID to extract base type.
 * e.g., "claude-1704567890123" → "claude"
 */
function parseSessionType(sessionId) {
  const match = sessionId.match(/^(main|opencode|claude|codex|gemini)(-\\d+)?$/);
  return match ? match[1] : null;
}

/**
 * Resolve upstream port and path from the incoming request URL.
 * All sessions are dynamic - port retrieved from agent-bridge.
 * Strips _term_token, _embedded, and _project params before forwarding.
 */
async function resolveUpstream(reqUrl) {
  const url = new URL(reqUrl, 'http://localhost');
  const pathname = url.pathname;

  let result = null;
  if (pathname.startsWith('/term/')) {
    const parts = pathname.split('/');
    const sessionId = parts[2];

    if (!sessionId) {
      return null;
    }

    // Extract project for session scoping (used when creating new sessions)
    const project = url.searchParams.get('_project') || null;

    // Get port from agent-bridge (creates session if needed)
    let port = await getDynamicSessionPort(sessionId);

    // If session doesn't exist, try to create it
    if (!port) {
      const type = parseSessionType(sessionId);
      if (type) {
        port = await createDynamicSession(sessionId, type, project);
      }
    }

    if (port) {
      result = { port, basePath: pathname, sessionId };
    }
  }

  if (result) {
    // Extract terminal token before stripping params
    result.termToken = url.searchParams.get('_term_token');

    // Strip auth/session params for upstream
    url.searchParams.delete('_term_token');
    url.searchParams.delete('_embedded');
    url.searchParams.delete('_project');

    const qs = url.searchParams.toString();
    result.path = result.basePath + (qs ? '?' + qs : '');
  }

  return result;
}

// HTTP server handles health checks and proxies HTTP requests
const httpServer = http.createServer(async (req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', service: 'term-proxy' }));
    return;
  }

  // Clear cache endpoint (for when sessions are closed)
  if (req.url && req.url.startsWith('/cache/clear/') && req.method === 'DELETE') {
    const sessionId = req.url.split('/')[3];
    dynamicPortCache.delete(sessionId);
    res.writeHead(200);
    res.end();
    return;
  }

  // List active terminal sessions (proxy to agent-bridge)
  // Parse URL to handle query parameters (e.g., ?project=test-app)
  const sessionsUrl = req.url && new URL(req.url, 'http://localhost');
  if (sessionsUrl?.pathname === '/terminal/sessions' && req.method === 'GET') {
    try {
      // Forward query params to agent-bridge
      const bridgeUrl = new URL(BRIDGE_URL + '/terminal/sessions');
      sessionsUrl.searchParams.forEach((value, key) => bridgeUrl.searchParams.set(key, value));
      const bridgeRes = await fetch(bridgeUrl.toString());
      const data = await bridgeRes.json();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(data));
    } catch (e) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to fetch sessions' }));
    }
    return;
  }

  // Close terminal session (proxy to agent-bridge)
  const closeMatch = req.url && req.url.match(/^\\/terminal\\/session\\/([^/]+)$/);
  if (closeMatch && req.method === 'DELETE') {
    const instanceId = closeMatch[1];
    try {
      const bridgeRes = await fetch(BRIDGE_URL + '/terminal/session/' + instanceId, {
        method: 'DELETE'
      });
      const data = await bridgeRes.json();
      // Also clear the port cache
      dynamicPortCache.delete(instanceId);
      res.writeHead(bridgeRes.ok ? 200 : 404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(data));
    } catch (e) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to close session' }));
    }
    return;
  }

  // CORS preflight for capture endpoint
  if (req.method === 'OPTIONS' && req.url && req.url.match(/^\\/term\\/[^/]+\\/capture/)) {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': req.headers.origin || '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Max-Age': '86400'
    });
    res.end();
    return;
  }

  // Capture terminal pane content (for mobile select/copy mode)
  const captureMatch = req.url && req.url.match(/^\\/term\\/([^/]+)\\/capture/);
  if (captureMatch && req.method === 'GET') {
    const captureSessionId = captureMatch[1];
    const captureUrl = new URL(req.url, 'http://localhost');
    const captureTermToken = captureUrl.searchParams.get('_term_token');

    // Validate auth: token from query param or session cookie
    let captureAuthorized = false;
    if (captureTermToken) {
      const captureShieldSession = getShieldSession(req);
      const captureResult = await validateTerminalToken(captureTermToken, captureShieldSession);
      captureAuthorized = captureResult.valid;
    }
    if (!captureAuthorized) {
      const captureTermSessionId = getTermSession(req);
      if (captureTermSessionId) {
        const captureIp = getClientIp(req);
        const captureShield = getShieldSession(req);
        captureAuthorized = await validateTermSession(captureTermSessionId, captureIp, captureShield);
      }
    }

    const corsHeaders = {
      'Access-Control-Allow-Origin': req.headers.origin || '*',
      'Access-Control-Allow-Credentials': 'true'
    };

    if (!captureAuthorized) {
      res.writeHead(401, { 'Content-Type': 'application/json', ...corsHeaders });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }

    // Fetch from agent-bridge
    try {
      const bridgeCaptureRes = await fetch(BRIDGE_URL + '/terminal/session/' + captureSessionId + '/capture');
      const captureData = await bridgeCaptureRes.text();
      res.writeHead(bridgeCaptureRes.ok ? 200 : bridgeCaptureRes.status, { 'Content-Type': 'application/json', ...corsHeaders });
      res.end(captureData);
    } catch (e) {
      res.writeHead(502, { 'Content-Type': 'application/json', ...corsHeaders });
      res.end(JSON.stringify({ error: 'Failed to capture terminal content' }));
    }
    return;
  }

  const upstream = await resolveUpstream(req.url);
  if (!upstream) {
    res.writeHead(404);
    res.end();
    return;
  }

  // If request has _term_token, validate and create an identity-bound session cookie.
  // Session is stored in sovereign-shield (survives term-proxy restarts).
  // Auth chain: passkey → PoP → terminal token → bound cookie → WebSocket
  let setCookieHeader = null;
  if (upstream.termToken) {
    const shieldSessionId = getShieldSession(req);
    const result = await validateTerminalToken(upstream.termToken, shieldSessionId);
    if (result.valid) {
      const clientIp = getClientIp(req);
      const termSessionId = await createTermSession(clientIp, shieldSessionId || '', result.tier);
      if (termSessionId) {
        setCookieHeader = '_term_auth=' + termSessionId + '; Path=/term/; HttpOnly; Secure; SameSite=None; Max-Age=1800';
        console.log('[TermProxy] Token validated, session created in shield (IP: ' + clientIp.substring(0, 10) + '...)');
      } else {
        console.log('[TermProxy] Failed to create session in shield');
      }
    } else {
      console.log('[TermProxy] HTTP token validation failed');
    }
  }

  // Proxy HTTP to upstream ttyd (serves web UI)
  const proxyReq = http.request({
    hostname: '127.0.0.1',
    port: upstream.port,
    path: upstream.path,
    method: req.method,
    headers: { ...req.headers, host: '127.0.0.1:' + upstream.port },
  }, (proxyRes) => {
    const headers = { ...proxyRes.headers };
    if (setCookieHeader) {
      const existing = headers['set-cookie'];
      if (existing) {
        headers['set-cookie'] = Array.isArray(existing)
          ? [...existing, setCookieHeader]
          : [existing, setCookieHeader];
      } else {
        headers['set-cookie'] = setCookieHeader;
      }
    }
    res.writeHead(proxyRes.statusCode, headers);
    proxyRes.pipe(res);
  });

  req.pipe(proxyReq);
  proxyReq.on('error', () => {
    if (!res.headersSent) {
      res.writeHead(502);
      res.end('Bad Gateway');
    }
  });
});

// Handle WebSocket upgrades - two auth methods:
// 1. _term_token in URL (initial load)
// 2. _term_auth session cookie (reconnects - persisted in SQLite via sovereign-shield)
httpServer.on('upgrade', async (req, socket, head) => {
  const upstream = await resolveUpstream(req.url);
  if (!upstream) {
    socket.write('HTTP/1.1 404 Not Found\\r\\nContent-Length: 9\\r\\n\\r\\nNot Found');
    socket.destroy();
    return;
  }

  const { termToken } = upstream;
  let authorized = false;

  // Method 1: Direct token in WebSocket URL (rare - if client controls WS URL)
  if (termToken) {
    const shieldSessionId = getShieldSession(req);
    const result = await validateTerminalToken(termToken, shieldSessionId);
    if (result.valid) {
      authorized = true;
      console.log('[TermProxy] WebSocket authorized via direct token');
    } else {
      console.log('[TermProxy] WebSocket direct token validation failed');
    }
  }

  // Method 2: Session cookie (set during initial HTTP page load by term-proxy)
  // Session is validated by sovereign-shield (checks IP, shield_session, expiry, revocation)
  if (!authorized) {
    const termSessionId = getTermSession(req);
    if (termSessionId) {
      const wsClientIp = getClientIp(req);
      const wsShieldSession = getShieldSession(req);
      const valid = await validateTermSession(termSessionId, wsClientIp, wsShieldSession);
      if (valid) {
        authorized = true;
        console.log('[TermProxy] WebSocket authorized via session cookie (shield-validated)');
      } else {
        console.log('[TermProxy] WebSocket session validation failed (shield rejected)');
      }
    }
  }

  if (!authorized) {
    console.log('[TermProxy] WebSocket auth failed - no valid token or session');
    socket.write('HTTP/1.1 401 Unauthorized\\r\\nContent-Length: 22\\r\\n\\r\\nTerminal auth required');
    socket.destroy();
    return;
  }

  // Connect WebSocket to upstream ttyd
  const upstreamUrl = 'ws://127.0.0.1:' + upstream.port + upstream.path;
  const protocols = req.headers['sec-websocket-protocol'] ?
    req.headers['sec-websocket-protocol'].split(',').map(p => p.trim()) : [];
  const upstreamWs = new WebSocket(upstreamUrl, protocols);

  upstreamWs.on('open', () => {
    const wss = new WebSocketServer({ noServer: true, handleProtocols: (set) => set.values().next().value || false });
    wss.handleUpgrade(req, socket, head, (clientWs) => {
      clientWs.on('message', (data, isBinary) => {
        if (upstreamWs.readyState === WebSocket.OPEN) {
          upstreamWs.send(data, { binary: isBinary });
        }
      });

      upstreamWs.on('message', (data, isBinary) => {
        if (clientWs.readyState === WebSocket.OPEN) {
          clientWs.send(data, { binary: isBinary });
        }
      });

      clientWs.on('close', () => upstreamWs.close());
      upstreamWs.on('close', () => clientWs.close());
      clientWs.on('error', () => upstreamWs.close());
      upstreamWs.on('error', () => clientWs.close());
    });
  });

  upstreamWs.on('error', () => {
    socket.write('HTTP/1.1 502 Bad Gateway\\r\\nContent-Length: 11\\r\\n\\r\\nBad Gateway');
    socket.destroy();
  });
});

httpServer.listen(PORT, '127.0.0.1', () => {
  console.log('[TermProxy] Auth proxy listening on port ' + PORT);
});
`;
}

/**
 * Systemd service for the terminal auth proxy.
 */
export function getTermProxyService(): string {
  return `[Unit]
Description=Phone Stack Terminal Auth Proxy
After=network.target

[Service]
Type=simple
User=root
Environment=NODE_PATH=/opt/phonestack/auth/node_modules:/home/dev/.nvm/versions/node/v20.20.0/lib/node_modules
ExecStart=/home/dev/.nvm/versions/node/v20.20.0/bin/node /usr/local/bin/phonestack-term-proxy
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target`;
}
