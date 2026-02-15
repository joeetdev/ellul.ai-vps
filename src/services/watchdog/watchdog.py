#!/usr/bin/env python3
"""
ellul.ai Fishbowl Watchdog — Main daemon for OpenClaw agent lifecycle management.

Runs as ellulai-watchdog.service on the VPS. Provides:
- HTTP API on 127.0.0.1:7710 for agent CRUD (called via Caddy reverse proxy)
- Container lifecycle: create, start, stop, terminate
- Boot-time reconciliation for crash recovery
- Health monitoring every 30s
- Status reporting to /etc/ellulai/agent-status.json (read by enforcer heartbeat)
- Mount verification every 60s (security)
"""

import os
import sys
import json
import time
import uuid
import signal
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

from agent_registry import get_agent_config, get_valid_agent_types
from container_manager import ContainerManager
from caddy_manager import (
    write_agent_caddy,
    delete_agent_caddy,
    cleanup_stale_configs,
    reload_caddy,
    ensure_agents_dir,
)
from security import (
    verify_all_mounts,
    check_enforcer_heartbeat,
    terminate_all_agents,
    check_container_health,
)

# ─── Configuration ────────────────────────────────────────

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 7710
STATUS_FILE = "/etc/ellulai/agent-status.json"
EXPECTED_STATE_FILE = "/etc/ellulai/agent-expected-state.json"
SVC_HOME = os.environ.get("SVC_HOME", "/home/dev")
PROJECTS_DIR = os.path.join(SVC_HOME, "projects")
FISHBOWL_DIR = os.path.join(SVC_HOME, ".fishbowl")
WORKSPACES_DIR = os.path.join(FISHBOWL_DIR, "workspaces")
CONFIG_BASE_DIR = os.path.join(FISHBOWL_DIR, "config")
AUTH_DIR = os.path.join(FISHBOWL_DIR, ".auth")

# Health check intervals
HEALTH_CHECK_INTERVAL_S = 30
MOUNT_CHECK_INTERVAL_S = 60
STALE_CONTAINER_TIMEOUT_S = 300  # 5 min unresponsive -> kill

# ─── Logging ──────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/var/log/ellulai-watchdog.log"),
    ],
)
logger = logging.getLogger("watchdog")

# ─── Global State ─────────────────────────────────────────

container_mgr = ContainerManager()
agents_lock = threading.Lock()
agents = {}  # agent_id -> agent state dict
shutdown_event = threading.Event()


# ─── State Persistence ────────────────────────────────────

def load_expected_state():
    """Load expected agent states from disk (survives reboots)."""
    global agents
    try:
        if os.path.exists(EXPECTED_STATE_FILE):
            with open(EXPECTED_STATE_FILE, "r") as f:
                agents = json.load(f)
            logger.info(f"Loaded expected state: {len(agents)} agents")
    except Exception as e:
        logger.error(f"Failed to load expected state: {e}")
        agents = {}


def save_expected_state():
    """Persist expected agent states to disk."""
    try:
        os.makedirs(os.path.dirname(EXPECTED_STATE_FILE), exist_ok=True)
        with open(EXPECTED_STATE_FILE, "w") as f:
            json.dump(agents, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save expected state: {e}")


def write_status_file():
    """Write agent status to JSON for enforcer heartbeat to read."""
    try:
        status_list = []
        with agents_lock:
            for agent_id, agent in agents.items():
                status_list.append({
                    "agentId": agent_id,
                    "status": agent.get("status", "unknown"),
                    "cpuUsage": agent.get("cpu_usage", 0),
                    "ramUsageMb": agent.get("ram_usage_mb", 0),
                    "containerId": agent.get("container_id", ""),
                    "gatewayPort": agent.get("gateway_port", 0),
                    "agentType": agent.get("agent_type", ""),
                })
        os.makedirs(os.path.dirname(STATUS_FILE), exist_ok=True)
        with open(STATUS_FILE, "w") as f:
            json.dump(status_list, f)
    except Exception as e:
        logger.error(f"Failed to write status file: {e}")


# ─── Agent Lifecycle ──────────────────────────────────────

def get_svc_uid_gid():
    """Get the UID/GID of the service user for file ownership."""
    import pwd
    svc_user = os.environ.get("SVC_USER", "dev")
    try:
        pw = pwd.getpwnam(svc_user)
        return pw.pw_uid, pw.pw_gid
    except KeyError:
        logger.warning(f"User {svc_user} not found, using 1000:1000")
        return 1000, 1000


def get_auth_status():
    """Check which CLI tools have auth tokens present."""
    tools = {
        "claude": os.path.join(AUTH_DIR, "claude"),
        "gh": os.path.join(AUTH_DIR, "gh"),
        "npm": os.path.join(AUTH_DIR, "npm"),
    }
    result = {}
    for tool, path in tools.items():
        has_files = False
        if os.path.isdir(path):
            try:
                has_files = len(os.listdir(path)) > 0
            except Exception:
                pass
        result[tool] = {"configured": has_files, "path": path}
    return result


SETUP_COMMANDS = {
    "claude": ["claude", "login"],
    "gh": ["gh", "auth", "login", "--web"],
    "npm": ["npm", "login"],
}


def hire_agent(agent_type, name, agent_id=None, config=None):
    """
    Hire (create + start) an agent.
    Returns agent state dict or raises on error.
    """
    if agent_type not in get_valid_agent_types():
        raise ValueError(f"Unknown agent type: {agent_type}")

    agent_config = get_agent_config(agent_type)
    if not agent_id:
        agent_id = str(uuid.uuid4())

    workspace_dir = os.path.join(WORKSPACES_DIR, agent_id)
    config_dir = os.path.join(CONFIG_BASE_DIR, agent_id)
    svc_uid, svc_gid = get_svc_uid_gid()

    # Allocate port
    port = container_mgr.allocate_port()

    # Pull image if needed (non-blocking check)
    image = agent_config.get("image", "ghcr.io/ellulai/openclaw-agent:latest")

    # Build extra environment from config
    extra_env = {}
    if config and isinstance(config, dict):
        if config.get("model"):
            extra_env["OPENCLAW_MODEL"] = config["model"]
        if config.get("systemPrompt"):
            extra_env["OPENCLAW_SYSTEM_PROMPT"] = config["systemPrompt"]
        # Inject OpenRouter API key (single key for all models)
        if config.get("apiKeys") and isinstance(config["apiKeys"], dict):
            or_key = config["apiKeys"].get("OPENROUTER_API_KEY")
            if or_key:
                extra_env["OPENROUTER_API_KEY"] = or_key

    # Create and start container
    container = container_mgr.create_agent_container(
        agent_id=agent_id,
        agent_type=agent_type,
        agent_config=agent_config,
        projects_dir=PROJECTS_DIR,
        workspace_dir=workspace_dir,
        config_dir=config_dir,
        allocated_port=port,
        svc_uid=svc_uid,
        svc_gid=svc_gid,
        environment=extra_env,
        auth_dir=AUTH_DIR,
    )

    # Write Caddy config and reload
    write_agent_caddy(agent_id, port)
    reload_caddy()

    # Update state
    agent_state = {
        "agent_id": agent_id,
        "agent_type": agent_type,
        "name": name,
        "status": "running",
        "container_id": container.id,
        "gateway_port": port,
        "workspace_dir": workspace_dir,
        "config_dir": config_dir,
        "image": image,
        "cpu_usage": 0,
        "ram_usage_mb": 0,
        "hired_at": time.time(),
    }

    with agents_lock:
        agents[agent_id] = agent_state
    save_expected_state()
    write_status_file()

    logger.info(f"Hired agent {agent_id[:8]} ({agent_type}) '{name}' on port {port}")
    return agent_state


def stop_agent(agent_id):
    """Stop an agent's container (can be restarted)."""
    with agents_lock:
        agent = agents.get(agent_id)
    if not agent:
        raise KeyError(f"Agent {agent_id} not found")

    container_id = agent.get("container_id")
    if container_id:
        container_mgr.stop_container(container_id)

    with agents_lock:
        agents[agent_id]["status"] = "stopped"
    save_expected_state()
    write_status_file()
    logger.info(f"Stopped agent {agent_id[:8]}")


def start_agent(agent_id):
    """Restart a stopped agent."""
    with agents_lock:
        agent = agents.get(agent_id)
    if not agent:
        raise KeyError(f"Agent {agent_id} not found")

    container_id = agent.get("container_id")
    if container_id:
        container_mgr.start_container(container_id)

    with agents_lock:
        agents[agent_id]["status"] = "running"
    save_expected_state()
    write_status_file()
    logger.info(f"Started agent {agent_id[:8]}")


def terminate_agent(agent_id):
    """Terminate an agent — remove container, cleanup workspace, delete Caddy config."""
    with agents_lock:
        agent = agents.get(agent_id)
    if not agent:
        raise KeyError(f"Agent {agent_id} not found")

    container_id = agent.get("container_id")
    if container_id:
        container_mgr.remove_container(container_id, force=True)

    # Delete Caddy config and reload
    delete_agent_caddy(agent_id)
    reload_caddy()

    with agents_lock:
        agents[agent_id]["status"] = "terminated"
        agents[agent_id]["terminated_at"] = time.time()
        # Remove from active agents after marking terminated
        del agents[agent_id]
    save_expected_state()
    write_status_file()
    logger.info(f"Terminated agent {agent_id[:8]}")


# ─── Boot Reconciliation ─────────────────────────────────

def reconcile_on_startup():
    """
    On VPS hard reboot, Docker may leave stale containers.
    Reconcile expected state with actual Docker state.
    """
    logger.info("Running boot-time reconciliation...")
    load_expected_state()

    expected_ids = set(agents.keys())
    actual_containers = container_mgr.list_fishbowl_containers()
    actual_names = {c.name: c for c in actual_containers}

    # Kill orphans: fishbowl-* containers not in expected state
    for container in actual_containers:
        # Extract agent ID from container name: fishbowl-<id[:8]>
        name_suffix = container.name.replace("fishbowl-", "")
        matching_ids = [
            aid for aid in expected_ids if aid.startswith(name_suffix)
        ]
        if not matching_ids:
            logger.warning(f"Killing orphan container: {container.name}")
            container_mgr.remove_container(container.id, force=True)

    # Restart expected running agents whose containers are stopped
    with agents_lock:
        for agent_id, agent in list(agents.items()):
            if agent.get("status") != "running":
                continue
            container_name = f"fishbowl-{agent_id[:8]}"
            actual = actual_names.get(container_name)
            if actual and actual.status == "running":
                continue  # Already running, fine
            elif actual and actual.status != "running":
                logger.info(f"Restarting stopped container for agent {agent_id[:8]}")
                container_mgr.start_container(actual.id)
            else:
                # Container gone — need to recreate
                logger.warning(
                    f"Container missing for agent {agent_id[:8]}, "
                    f"marking as error"
                )
                agents[agent_id]["status"] = "error"
                agents[agent_id]["error_message"] = "Container missing after reboot"

    # Cleanup stale Caddy configs
    cleanup_stale_configs(set(agents.keys()))
    reload_caddy()

    save_expected_state()
    write_status_file()
    logger.info(f"Reconciliation complete: {len(agents)} agents tracked")


# ─── Background Health Monitor ────────────────────────────

def health_monitor():
    """Background thread: check container health and update stats."""
    last_mount_check = 0

    while not shutdown_event.is_set():
        try:
            now = time.time()

            # Update stats for all running agents
            with agents_lock:
                for agent_id, agent in agents.items():
                    if agent.get("status") != "running":
                        continue
                    container_id = agent.get("container_id")
                    if not container_id:
                        continue

                    # Check container status
                    status = container_mgr.get_container_status(container_id)
                    if status == "running":
                        stats = container_mgr.get_container_stats(container_id)
                        if stats:
                            agent["cpu_usage"] = stats["cpu_percent"]
                            agent["ram_usage_mb"] = stats["memory_mb"]
                    elif status in ("exited", "dead", "not_found"):
                        agent["status"] = "stopped"
                        logger.warning(
                            f"Agent {agent_id[:8]} container {status}"
                        )

            # Mount verification (every 60s)
            if now - last_mount_check >= MOUNT_CHECK_INTERVAL_S:
                last_mount_check = now
                killed = verify_all_mounts(container_mgr)
                if killed:
                    # Update agent states for killed containers
                    with agents_lock:
                        for agent_id, agent in agents.items():
                            if agent.get("container_id") in killed:
                                agent["status"] = "error"
                                agent["error_message"] = "Container killed: RO mount compromised"

                # Enforcer stale-check
                if not check_enforcer_heartbeat():
                    logger.critical(
                        "Enforcer stale — terminating all agents for safety"
                    )
                    terminate_all_agents(container_mgr, reason="enforcer_stale")
                    with agents_lock:
                        for agent_id in agents:
                            agents[agent_id]["status"] = "terminated"
                    save_expected_state()

            write_status_file()

        except Exception as e:
            logger.error(f"Health monitor error: {e}")

        shutdown_event.wait(HEALTH_CHECK_INTERVAL_S)


# ─── HTTP API Handler ─────────────────────────────────────

class WatchdogHandler(BaseHTTPRequestHandler):
    """HTTP API on 127.0.0.1:7710 for agent lifecycle management."""

    def log_message(self, format, *args):
        logger.debug(f"HTTP: {format % args}")

    def _send_json(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def _get_agent_id(self):
        """Extract agent ID from path like /agents/<id>"""
        parts = self.path.strip("/").split("/")
        if len(parts) >= 2:
            return parts[1].split("?")[0]
        return None

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")

        if path == "/health":
            self._send_json(200, {
                "status": "ok",
                "agents": len(agents),
                "uptime": time.time(),
            })

        elif path == "/agents":
            with agents_lock:
                agent_list = list(agents.values())
            self._send_json(200, {"agents": agent_list})

        elif path.startswith("/agents/"):
            agent_id = self._get_agent_id()
            with agents_lock:
                agent = agents.get(agent_id)
            if agent:
                # Include workspace file listing
                workspace = agent.get("workspace_dir", "")
                files = []
                if workspace and os.path.isdir(workspace):
                    try:
                        files = os.listdir(workspace)[:100]
                    except Exception:
                        pass
                result = {**agent, "workspace_files": files}
                self._send_json(200, result)
            else:
                self._send_json(404, {"error": "Agent not found"})

        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        path = self.path.split("?")[0].rstrip("/")

        if path == "/agents/auth-status":
            # callDaemon always sends POST
            self._send_json(200, get_auth_status())

        elif path == "/agents":
            # Hire a new agent
            try:
                body = self._read_body()
                agent_type = body.get("agentType")
                name = body.get("name", f"Agent-{agent_type}")
                agent_id = body.get("agentId")
                config = body.get("config")

                if not agent_type:
                    self._send_json(400, {"error": "agentType is required"})
                    return

                result = hire_agent(agent_type, name, agent_id=agent_id, config=config)
                self._send_json(201, result)
            except ValueError as e:
                self._send_json(400, {"error": str(e)})
            except Exception as e:
                logger.error(f"Hire agent error: {e}")
                self._send_json(500, {"error": str(e)})

        elif path.endswith("/stop"):
            agent_id = self._get_agent_id()
            try:
                stop_agent(agent_id)
                self._send_json(200, {"status": "stopped"})
            except KeyError:
                self._send_json(404, {"error": "Agent not found"})
            except Exception as e:
                self._send_json(500, {"error": str(e)})

        elif path.endswith("/start"):
            agent_id = self._get_agent_id()
            try:
                start_agent(agent_id)
                self._send_json(200, {"status": "running"})
            except KeyError:
                self._send_json(404, {"error": "Agent not found"})
            except Exception as e:
                self._send_json(500, {"error": str(e)})

        elif path.endswith("/terminate"):
            # callDaemon always sends POST, so terminate is POST not DELETE
            agent_id = self._get_agent_id()
            try:
                terminate_agent(agent_id)
                self._send_json(200, {"status": "terminated"})
            except KeyError:
                self._send_json(404, {"error": "Agent not found"})
            except Exception as e:
                self._send_json(500, {"error": str(e)})

        elif path.endswith("/interactive-setup"):
            agent_id = self._get_agent_id()
            with agents_lock:
                agent = agents.get(agent_id)
            if not agent:
                self._send_json(404, {"error": "Agent not found"})
                return

            container_id = agent.get("container_id")
            if not container_id or agent.get("status") != "running":
                self._send_json(400, {"error": "Agent is not running"})
                return

            try:
                body = self._read_body()
                tool = body.get("tool")
                cmd = SETUP_COMMANDS.get(tool)
                if not cmd:
                    self._send_json(400, {"error": f"Unknown tool: {tool}"})
                    return

                svc_uid, svc_gid = get_svc_uid_gid()
                container = container_mgr.client.containers.get(container_id)
                exec_result = container.exec_run(
                    cmd, user=f"{svc_uid}:{svc_gid}"
                )
                output = exec_result.output.decode("utf-8", errors="replace") if exec_result.output else ""
                success = exec_result.exit_code == 0
                self._send_json(200, {
                    "success": success,
                    "output": output,
                    "exitCode": exec_result.exit_code,
                })
            except Exception as e:
                logger.error(f"Interactive setup error for agent {agent_id[:8]}: {e}")
                self._send_json(500, {"error": str(e)})

        else:
            self._send_json(404, {"error": "Not found"})

    def do_DELETE(self):
        path = self.path.split("?")[0].rstrip("/")

        if path.startswith("/agents/"):
            agent_id = self._get_agent_id()
            try:
                terminate_agent(agent_id)
                self._send_json(200, {"status": "terminated"})
            except KeyError:
                self._send_json(404, {"error": "Agent not found"})
            except Exception as e:
                self._send_json(500, {"error": str(e)})
        else:
            self._send_json(404, {"error": "Not found"})


# ─── Main ─────────────────────────────────────────────────

def main():
    logger.info("ellulai-watchdog starting...")

    # Ensure directories
    os.makedirs(WORKSPACES_DIR, mode=0o755, exist_ok=True)
    os.makedirs(CONFIG_BASE_DIR, mode=0o755, exist_ok=True)
    os.makedirs(AUTH_DIR, mode=0o755, exist_ok=True)
    ensure_agents_dir()

    # Boot-time reconciliation
    reconcile_on_startup()

    # Start health monitor thread
    monitor_thread = threading.Thread(target=health_monitor, daemon=True)
    monitor_thread.start()

    # Signal handlers
    def handle_shutdown(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        shutdown_event.set()
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    # Start HTTP server
    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), WatchdogHandler)
    logger.info(f"Watchdog API listening on {LISTEN_HOST}:{LISTEN_PORT}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        shutdown_event.set()
        server.server_close()
        logger.info("Watchdog shut down")


if __name__ == "__main__":
    main()
