#!/usr/bin/env node
/**
 * Agent Wrapper — Lightweight manager for OpenClaw gateway + CLI auth.
 *
 * Runs on 127.0.0.1:7710, proxied via Caddy at /api/watchdog/*.
 * Caddy strips the /api/watchdog prefix.
 *
 * Architecture: One OpenClaw gateway auto-started via PM2 on provision.
 * Agent Bridge opens per-thread WebSocket connections to the gateway.
 * This wrapper handles:
 *   - CLI auth status/setup (claude, gh, npm credentials)
 *   - OpenClaw gateway health monitoring
 */

const http = require("http");
const { exec } = require("child_process");
const { promisify } = require("util");
const fs = require("fs");
const path = require("path");

const execAsync = promisify(exec);

const HOST = "127.0.0.1";
const PORT = 7710;
const SVC_HOME = process.env.SVC_HOME || "/home/dev";
const SVC_USER = process.env.SVC_USER || "dev";
const AGENTS_DIR = path.join(SVC_HOME, ".agents");

// ─── Helpers ────────────────────────────────────────────

function log(msg) {
  console.log(`[${new Date().toISOString()}] ${msg}`);
}

function sendJson(res, status, data) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString()));
      } catch {
        resolve({});
      }
    });
  });
}

// ─── PM2 Helpers ────────────────────────────────────────

async function pm2List() {
  try {
    const { stdout } = await execAsync("pm2 jlist", { timeout: 10000 });
    return JSON.parse(stdout);
  } catch {
    return [];
  }
}

// ─── OpenClaw Gateway Status ────────────────────────────

async function getOpenClawStatus() {
  const all = await pm2List();
  const gateway = all.find((p) => p.name === "openclaw-gateway");
  if (!gateway) {
    return { running: false, status: "not_found" };
  }
  return {
    running: gateway.pm2_env?.status === "online",
    status: gateway.pm2_env?.status || "unknown",
    pid: gateway.pid,
    cpu_usage: gateway.monit?.cpu || 0,
    ram_usage_mb: Math.round((gateway.monit?.memory || 0) / 1024 / 1024),
    uptime: gateway.pm2_env?.pm_uptime || null,
    restarts: gateway.pm2_env?.restart_time || 0,
  };
}

// ─── Auth Status (CLI tool credentials) ─────────────────

function getAuthStatus() {
  const authDir = path.join(AGENTS_DIR, ".auth");
  const tools = { claude: "claude", gh: "gh", npm: "npm" };
  const result = {};
  for (const [tool, dir] of Object.entries(tools)) {
    const toolPath = path.join(authDir, dir);
    let configured = false;
    if (fs.existsSync(toolPath)) {
      try { configured = fs.readdirSync(toolPath).length > 0; } catch {}
    }
    result[tool] = { configured, path: toolPath };
  }
  return result;
}

// ─── HTTP Server ────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  const urlPath = req.url.split("?")[0].replace(/\/+$/, "") || "/";
  const method = req.method;

  try {
    // GET /health
    if (method === "GET" && urlPath === "/health") {
      const status = await getOpenClawStatus();
      return sendJson(res, 200, { status: "ok", openclaw: status });
    }

    // GET /openclaw/status
    if (method === "GET" && urlPath === "/openclaw/status") {
      return sendJson(res, 200, await getOpenClawStatus());
    }

    // POST /agents/auth-status
    if (method === "POST" && urlPath === "/agents/auth-status") {
      return sendJson(res, 200, getAuthStatus());
    }

    // POST /agents/interactive-setup (server-level, no agentId)
    if (method === "POST" && urlPath === "/agents/interactive-setup") {
      const body = await readBody(req);
      const tool = body.tool;
      const cmds = { claude: "claude login", gh: "gh auth login --web", npm: "npm login" };
      if (!cmds[tool]) return sendJson(res, 400, { error: `Unknown tool: ${tool}` });
      try {
        const { stdout, stderr } = await execAsync(cmds[tool], { timeout: 30000 });
        return sendJson(res, 200, { success: true, output: stdout + (stderr || ""), exitCode: 0 });
      } catch (e) {
        return sendJson(res, 200, { success: false, output: e.message, exitCode: 1 });
      }
    }

    sendJson(res, 404, { error: "Not found" });
  } catch (e) {
    log(`ERROR: ${e.message}`);
    sendJson(res, 500, { error: e.message });
  }
});

server.listen(PORT, HOST, () => {
  log(`Agent wrapper listening on ${HOST}:${PORT}`);
});

process.on("SIGTERM", () => {
  log("Shutting down...");
  server.close();
  process.exit(0);
});

process.on("SIGINT", () => {
  log("Shutting down...");
  server.close();
  process.exit(0);
});
