"""
Caddy Manager — write/delete per-agent .caddy files and trigger reload.

Each agent gets a reverse proxy config in /etc/caddy/agents.d/:
  handle_path /api/agents/<agent_id>/gateway/* {
      reverse_proxy 127.0.0.1:<allocated_port>
  }

The main Caddyfile imports /etc/caddy/agents.d/*.caddy (static line set during provisioning).
Watchdog only touches files inside agents.d/ — never the main Caddyfile.
"""

import os
import subprocess
import logging

logger = logging.getLogger("watchdog.caddy")

AGENTS_DIR = "/etc/caddy/agents.d"


def ensure_agents_dir():
    """Create the agents.d directory if it doesn't exist."""
    os.makedirs(AGENTS_DIR, mode=0o755, exist_ok=True)


def write_agent_caddy(agent_id, port):
    """
    Write a Caddy config file for an agent's gateway proxy.
    Returns the file path on success, None on error.
    """
    ensure_agents_dir()
    filepath = os.path.join(AGENTS_DIR, f"agent_{agent_id}.caddy")
    content = (
        f"handle_path /api/agents/{agent_id}/gateway/* {{\n"
        f"    reverse_proxy 127.0.0.1:{port}\n"
        f"}}\n"
    )
    try:
        with open(filepath, "w") as f:
            f.write(content)
        logger.info(f"Wrote Caddy config for agent {agent_id[:8]} -> port {port}")
        return filepath
    except Exception as e:
        logger.error(f"Failed to write Caddy config for agent {agent_id[:8]}: {e}")
        return None


def delete_agent_caddy(agent_id):
    """Delete the Caddy config file for an agent."""
    filepath = os.path.join(AGENTS_DIR, f"agent_{agent_id}.caddy")
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
            logger.info(f"Deleted Caddy config for agent {agent_id[:8]}")
            return True
        return True  # Already gone
    except Exception as e:
        logger.error(f"Failed to delete Caddy config for agent {agent_id[:8]}: {e}")
        return False


def cleanup_stale_configs(valid_agent_ids):
    """
    Remove Caddy config files for agents that no longer exist.
    Used during boot-time reconciliation.
    """
    ensure_agents_dir()
    removed = []
    try:
        for filename in os.listdir(AGENTS_DIR):
            if not filename.endswith(".caddy"):
                continue
            # Extract agent ID from filename: agent_<id>.caddy
            agent_id = filename.replace("agent_", "").replace(".caddy", "")
            if agent_id not in valid_agent_ids:
                filepath = os.path.join(AGENTS_DIR, filename)
                os.remove(filepath)
                removed.append(agent_id)
                logger.info(f"Cleaned up stale Caddy config: {filename}")
    except Exception as e:
        logger.error(f"Failed to cleanup stale Caddy configs: {e}")
    return removed


def reload_caddy():
    """
    Trigger a Caddy reload. If the config has invalid syntax,
    Caddy refuses the reload and keeps the old config running.
    Returns True on success.
    """
    try:
        result = subprocess.run(
            ["caddy", "reload", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            logger.info("Caddy reloaded successfully")
            return True
        else:
            logger.error(f"Caddy reload failed: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        logger.error("Caddy reload timed out")
        return False
    except Exception as e:
        logger.error(f"Failed to reload Caddy: {e}")
        return False
