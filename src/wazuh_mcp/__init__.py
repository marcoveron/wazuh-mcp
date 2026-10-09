"""Wazuh MCP server — expose a Wazuh deployment to an MCP client."""

from __future__ import annotations

import os
import sys
from typing import Any

from .config import Config, ConfigError
from .server import build_server

__all__ = ["Config", "ConfigError", "build_server", "main"]

_TRANSPORTS = {"stdio", "sse", "streamable-http"}


def main() -> None:
    """Console entry point. Transport is chosen with WAZUH_MCP_TRANSPORT."""
    transport = os.environ.get("WAZUH_MCP_TRANSPORT", "stdio").strip().lower()
    if transport not in _TRANSPORTS:
        print(
            f"WAZUH_MCP_TRANSPORT={transport!r} is not supported; "
            "use stdio, sse or streamable-http.",
            file=sys.stderr,
        )
        raise SystemExit(2)

    try:
        options = _transport_options(transport)
        server = build_server()
    except ConfigError as exc:
        # stdout is the MCP channel on stdio; configuration errors go to stderr.
        print(f"wazuh-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    server.run(transport=transport, **options)  # type: ignore[arg-type]


def _transport_options(transport: str) -> dict[str, Any]:
    """Where an HTTP transport binds. Irrelevant to stdio, which has no socket.

    The default stays loopback on purpose: this server has no authentication of
    its own, so binding it to 0.0.0.0 hands the whole SIEM to anyone who can
    reach the port. Overriding WAZUH_MCP_HOST is a deliberate act, and belongs
    behind a reverse proxy that does the authenticating.
    """
    if transport == "stdio":
        return {}

    options: dict[str, Any] = {
        "host": os.environ.get("WAZUH_MCP_HOST", "127.0.0.1").strip(),
        "port": _port(),
    }
    path = os.environ.get("WAZUH_MCP_PATH", "").strip()
    if path:
        options["streamable_http_path" if transport == "streamable-http" else "sse_path"] = path
    return options


def _port() -> int:
    raw = os.environ.get("WAZUH_MCP_PORT", "").strip()
    if not raw:
        return 8000
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"WAZUH_MCP_PORT must be a port number, got {raw!r}") from exc
