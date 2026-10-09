"""Tool modules, each registering a slice of the Wazuh surface onto the server."""

from __future__ import annotations

from mcp.server import MCPServer

from ..config import Config
from . import active_response, agents, alerts, manager, policy, rules, vulnerabilities


def register_all(mcp: MCPServer, config: Config) -> None:
    agents.register(mcp)
    alerts.register(mcp)
    vulnerabilities.register(mcp)
    policy.register(mcp)
    rules.register(mcp)
    manager.register(mcp)
    # Registers nothing unless Active Response is explicitly enabled.
    active_response.register(mcp, config)
