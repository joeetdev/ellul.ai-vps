"""
Agent Type Registry — maps agent types to OpenClaw container configuration.

Each agent type defines:
- Docker image, resource limits (CPU, memory)
- Network mode (none for dev, restricted bridge for marketing/researcher)
- OpenClaw tools and sandbox rules
"""

AGENT_CONFIGS = {
    "dev": {
        "description": "Code generation, refactoring, file operations",
        "memory_limit": "1g",
        "cpu_limit": "1.0",
        "network": "none",  # No network — pure code agent
        "openclaw_tools": ["file_read", "file_write", "shell"],
        "sandbox_rules": {
            "shell_allowed": True,
            "shell_cwd": "/workspace",
            "shell_readonly_paths": ["/project"],
            "browser_enabled": False,
            "web_search_enabled": False,
        },
    },
    "marketing": {
        "description": "Content creation, social media, web research",
        "memory_limit": "512m",
        "cpu_limit": "0.5",
        "network": "fishbowl-restricted",  # Bridge with no ICC
        "openclaw_tools": ["file_write", "browser", "web_search"],
        "sandbox_rules": {
            "shell_allowed": False,
            "browser_enabled": True,
            "web_search_enabled": True,
        },
    },
    "researcher": {
        "description": "Analysis, documentation, web research",
        "memory_limit": "512m",
        "cpu_limit": "0.5",
        "network": "fishbowl-restricted",  # Bridge with no ICC
        "openclaw_tools": ["file_write", "browser", "web_search"],
        "sandbox_rules": {
            "shell_allowed": False,
            "browser_enabled": True,
            "web_search_enabled": True,
        },
    },
    "designer": {
        "description": "UI/UX design, asset generation",
        "memory_limit": "512m",
        "cpu_limit": "0.5",
        "network": "none",
        "openclaw_tools": ["file_read", "file_write"],
        "sandbox_rules": {
            "shell_allowed": False,
            "browser_enabled": False,
            "web_search_enabled": False,
        },
    },
    "qa": {
        "description": "Testing, quality assurance, bug detection",
        "memory_limit": "1g",
        "cpu_limit": "1.0",
        "network": "none",
        "openclaw_tools": ["file_read", "file_write", "shell"],
        "sandbox_rules": {
            "shell_allowed": True,
            "shell_cwd": "/workspace",
            "shell_readonly_paths": ["/project"],
            "browser_enabled": False,
            "web_search_enabled": False,
        },
    },
    "devops": {
        "description": "Infrastructure, deployment, monitoring",
        "memory_limit": "512m",
        "cpu_limit": "0.5",
        "network": "fishbowl-restricted",
        "openclaw_tools": ["file_read", "file_write", "shell", "web_search"],
        "sandbox_rules": {
            "shell_allowed": True,
            "shell_cwd": "/workspace",
            "shell_readonly_paths": ["/project"],
            "browser_enabled": False,
            "web_search_enabled": True,
        },
    },
}


def get_agent_config(agent_type):
    """Get the configuration for an agent type. Returns None if unknown."""
    return AGENT_CONFIGS.get(agent_type)


def get_valid_agent_types():
    """Return list of valid agent type names."""
    return list(AGENT_CONFIGS.keys())
