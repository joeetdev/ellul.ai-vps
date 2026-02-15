"""
Container Manager — Docker lifecycle operations for Fishbowl agents.

Handles create/start/stop/remove with security hardening.
All ports bound to 127.0.0.1 only (Caddy is the sole external gateway).
"""

import os
import logging
import docker

logger = logging.getLogger("watchdog.container")

# Port range for OpenClaw gateway allocation
PORT_RANGE_START = 18790
PORT_RANGE_END = 18890


class ContainerManager:
    def __init__(self):
        self.client = docker.from_env()
        self._allocated_ports = set()
        self._refresh_allocated_ports()

    def _refresh_allocated_ports(self):
        """Scan running fishbowl containers to find allocated ports."""
        self._allocated_ports.clear()
        try:
            containers = self.client.containers.list(
                all=True, filters={"name": "fishbowl-"}
            )
            for c in containers:
                ports = c.attrs.get("NetworkSettings", {}).get("Ports", {})
                for bindings in (ports or {}).values():
                    if bindings:
                        for b in bindings:
                            if b.get("HostPort"):
                                self._allocated_ports.add(int(b["HostPort"]))
        except Exception as e:
            logger.warning(f"Failed to refresh allocated ports: {e}")

    def allocate_port(self):
        """Allocate the next available host port for an agent gateway."""
        self._refresh_allocated_ports()
        for port in range(PORT_RANGE_START, PORT_RANGE_END):
            if port not in self._allocated_ports:
                self._allocated_ports.add(port)
                return port
        raise RuntimeError("No available ports in fishbowl range")

    def create_agent_container(
        self,
        agent_id,
        agent_type,
        agent_config,
        projects_dir,
        workspace_dir,
        config_dir,
        allocated_port,
        svc_uid,
        svc_gid,
        environment=None,
        auth_dir=None,
    ):
        """
        Create and start an OpenClaw agent container with security hardening.

        Returns the Docker container object.
        """
        container_name = f"fishbowl-{agent_id[:8]}"

        # Ensure workspace and config dirs exist
        os.makedirs(workspace_dir, mode=0o755, exist_ok=True)
        os.makedirs(config_dir, mode=0o755, exist_ok=True)

        # Base environment
        env = {
            "OPENCLAW_GATEWAY_PORT": "18789",
            "OPENCLAW_WORKSPACE": "/workspace",
            "OPENCLAW_PROJECT_CONTEXT": "/project",
            "AGENT_TYPE": agent_type,
            "AGENT_ID": agent_id,
        }
        if environment:
            env.update(environment)

        # Volume mounts — THE FISHBOWL
        volumes = {
            projects_dir: {"bind": "/project", "mode": "ro"},       # Look but don't touch
            workspace_dir: {"bind": "/workspace", "mode": "rw"},    # Do your job
            config_dir: {"bind": "/home/node/.openclaw", "mode": "rw"},
        }

        # CLI auth persistence — shared across all agents
        if auth_dir and os.path.isdir(auth_dir):
            auth_mounts = {
                "claude": "/home/node/.claude",
                "anthropic": "/home/node/.anthropic",
                "gh": "/home/node/.config/gh",
                "npm": "/home/node/.npm-config",
            }
            for tool, container_path in auth_mounts.items():
                tool_dir = os.path.join(auth_dir, tool)
                if os.path.isdir(tool_dir):
                    volumes[tool_dir] = {"bind": container_path, "mode": "rw"}

            # npm uses .npmrc file — point NPM_CONFIG_USERCONFIG to mounted dir
            npm_dir = os.path.join(auth_dir, "npm")
            if os.path.isdir(npm_dir):
                env["NPM_CONFIG_USERCONFIG"] = "/home/node/.npm-config/.npmrc"

        # Port binding — localhost only
        port_bindings = {}
        if agent_config.get("network") != "none":
            port_bindings = {"18789/tcp": ("127.0.0.1", allocated_port)}
        else:
            # Even network=none agents need port forwarding via host network workaround
            # We use a bridge network and bind to localhost
            port_bindings = {"18789/tcp": ("127.0.0.1", allocated_port)}

        # Determine network mode
        network_mode = agent_config.get("network", "none")
        use_network_mode = None
        if network_mode == "none":
            # For agents with no network, we still need port binding,
            # so we use a bridge but will rely on iptables/seccomp for isolation
            use_network_mode = None  # default bridge
        elif network_mode == "fishbowl-restricted":
            use_network_mode = None  # default bridge, ICC disabled at network level

        try:
            container = self.client.containers.run(
                image=agent_config.get("image", "ghcr.io/ellulai/openclaw-agent:latest"),
                name=container_name,
                detach=True,
                read_only=True,
                volumes=volumes,
                tmpfs={"/tmp": "size=100m,noexec"},
                ports=port_bindings,

                # Security hardening
                security_opt=["no-new-privileges"],
                cap_drop=["ALL"],
                pids_limit=100,
                mem_limit=agent_config.get("memory_limit", "512m"),
                cpu_period=100000,
                cpu_quota=int(float(agent_config.get("cpu_limit", "0.5")) * 100000),
                user=f"{svc_uid}:{svc_gid}",

                # No auto-restart — Watchdog handles reconciliation
                restart_policy={"Name": "no"},

                environment=env,
            )

            logger.info(
                f"Created container {container_name} (port {allocated_port}) "
                f"for agent {agent_id} type={agent_type}"
            )
            return container

        except docker.errors.ImageNotFound:
            logger.error(f"Image not found: {agent_config.get('image')}")
            raise
        except docker.errors.APIError as e:
            logger.error(f"Docker API error creating container: {e}")
            raise

    def stop_container(self, container_id, timeout=10):
        """Stop a running container gracefully."""
        try:
            container = self.client.containers.get(container_id)
            container.stop(timeout=timeout)
            logger.info(f"Stopped container {container_id[:12]}")
            return True
        except docker.errors.NotFound:
            logger.warning(f"Container {container_id[:12]} not found")
            return False
        except Exception as e:
            logger.error(f"Error stopping container {container_id[:12]}: {e}")
            return False

    def start_container(self, container_id):
        """Start a stopped container."""
        try:
            container = self.client.containers.get(container_id)
            container.start()
            logger.info(f"Started container {container_id[:12]}")
            return True
        except docker.errors.NotFound:
            logger.warning(f"Container {container_id[:12]} not found")
            return False
        except Exception as e:
            logger.error(f"Error starting container {container_id[:12]}: {e}")
            return False

    def remove_container(self, container_id, force=True):
        """Remove a container (stop first if running)."""
        try:
            container = self.client.containers.get(container_id)
            container.remove(force=force)
            logger.info(f"Removed container {container_id[:12]}")
            return True
        except docker.errors.NotFound:
            logger.warning(f"Container {container_id[:12]} not found for removal")
            return True  # Already gone
        except Exception as e:
            logger.error(f"Error removing container {container_id[:12]}: {e}")
            return False

    def get_container_stats(self, container_id):
        """Get CPU and memory stats for a container."""
        try:
            container = self.client.containers.get(container_id)
            stats = container.stats(stream=False)

            # Calculate CPU percentage
            cpu_delta = (
                stats["cpu_stats"]["cpu_usage"]["total_usage"]
                - stats["precpu_stats"]["cpu_usage"]["total_usage"]
            )
            system_delta = (
                stats["cpu_stats"]["system_cpu_usage"]
                - stats["precpu_stats"]["system_cpu_usage"]
            )
            num_cpus = stats["cpu_stats"].get("online_cpus", 1)
            cpu_percent = 0
            if system_delta > 0:
                cpu_percent = round((cpu_delta / system_delta) * num_cpus * 100, 1)

            # Calculate memory usage in MB
            mem_usage_mb = round(
                stats["memory_stats"].get("usage", 0) / (1024 * 1024), 1
            )

            return {"cpu_percent": cpu_percent, "memory_mb": mem_usage_mb}
        except Exception as e:
            logger.warning(f"Failed to get stats for {container_id[:12]}: {e}")
            return None

    def get_container_status(self, container_id):
        """Get the current status of a container."""
        try:
            container = self.client.containers.get(container_id)
            return container.status  # running, exited, paused, etc.
        except docker.errors.NotFound:
            return "not_found"
        except Exception:
            return "unknown"

    def list_fishbowl_containers(self):
        """List all fishbowl-* containers."""
        try:
            return self.client.containers.list(
                all=True, filters={"name": "fishbowl-"}
            )
        except Exception as e:
            logger.error(f"Failed to list fishbowl containers: {e}")
            return []

    def pull_image(self, image):
        """Pull a Docker image. Returns True on success."""
        try:
            logger.info(f"Pulling image {image}...")
            self.client.images.pull(image)
            logger.info(f"Image {image} pulled successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to pull image {image}: {e}")
            return False
