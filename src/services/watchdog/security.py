"""
Security Module — mount validation, escape detection, stale-check.

Runs periodic checks to ensure container integrity:
- Verify RO mounts haven't been remounted as RW
- Check enforcer heartbeat file for stale-check
- Kill containers that fail security checks
"""

import os
import time
import logging
import subprocess

logger = logging.getLogger("watchdog.security")

# Enforcer heartbeat file — enforcer writes timestamp every heartbeat cycle
ENFORCER_HEARTBEAT_FILE = "/etc/ellulai/enforcer-heartbeat"
ENFORCER_STALE_THRESHOLD_S = 300  # 5 minutes

# Interval for mount verification loop
MOUNT_CHECK_INTERVAL_S = 60


def verify_mount_readonly(container_id, mount_path="/project"):
    """
    Verify that a container's bind mount is still read-only.
    Returns True if the mount is RO, False if compromised.
    """
    try:
        result = subprocess.run(
            [
                "docker", "inspect",
                "--format", '{{range .Mounts}}{{if eq .Destination "' + mount_path + '"}}{{.Mode}}{{end}}{{end}}',
                container_id,
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        mode = result.stdout.strip()
        if mode and mode != "ro":
            logger.critical(
                f"SECURITY: Container {container_id[:12]} mount {mount_path} "
                f"is {mode} instead of ro!"
            )
            return False
        return True
    except Exception as e:
        logger.error(f"Failed to verify mount for {container_id[:12]}: {e}")
        return False


def check_enforcer_heartbeat():
    """
    Check if the enforcer service is still alive by reading its heartbeat file.
    Returns True if alive, False if stale (>5 min since last update).
    """
    try:
        if not os.path.exists(ENFORCER_HEARTBEAT_FILE):
            # No heartbeat file yet — enforcer may not have started
            logger.warning("Enforcer heartbeat file not found")
            return True  # Don't kill containers on first boot

        mtime = os.path.getmtime(ENFORCER_HEARTBEAT_FILE)
        age = time.time() - mtime
        if age > ENFORCER_STALE_THRESHOLD_S:
            logger.critical(
                f"SECURITY: Enforcer heartbeat stale ({age:.0f}s old, "
                f"threshold={ENFORCER_STALE_THRESHOLD_S}s)"
            )
            return False
        return True
    except Exception as e:
        logger.error(f"Failed to check enforcer heartbeat: {e}")
        return True  # Fail open — don't kill containers on error


def verify_all_mounts(container_manager):
    """
    Verify all fishbowl container mounts are still RO.
    Kill any containers with compromised mounts.
    Returns list of killed container IDs.
    """
    killed = []
    containers = container_manager.list_fishbowl_containers()
    for container in containers:
        if container.status != "running":
            continue
        if not verify_mount_readonly(container.id):
            logger.critical(
                f"SECURITY: Killing container {container.name} — "
                f"RO mount compromised"
            )
            container_manager.remove_container(container.id, force=True)
            killed.append(container.id)
    return killed


def terminate_all_agents(container_manager, reason="security"):
    """
    Emergency: terminate all fishbowl containers.
    Used when enforcer heartbeat is stale (possible system compromise).
    """
    containers = container_manager.list_fishbowl_containers()
    count = 0
    for container in containers:
        try:
            container_manager.remove_container(container.id, force=True)
            count += 1
        except Exception as e:
            logger.error(f"Failed to terminate {container.name}: {e}")
    logger.critical(
        f"SECURITY: Terminated {count} fishbowl containers (reason: {reason})"
    )
    return count


def check_container_health(container_manager, container_id, max_unresponsive_s=300):
    """
    Check if a container is healthy (responding to health checks).
    Returns True if healthy, False if unresponsive.
    """
    try:
        status = container_manager.get_container_status(container_id)
        if status == "running":
            return True
        if status in ("exited", "dead"):
            return False
        return True  # paused, restarting, etc.
    except Exception:
        return False
