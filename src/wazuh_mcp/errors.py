"""Error types surfaced to the MCP client.

Tools raise `WazuhError` with a message written for a model to act on: it says
what failed, against which component, and what would make the call succeed.

Inheriting from the SDK's `ToolError`/`ResourceError` is what makes that message
actually travel. The SDK treats any other exception as a crash and replaces its
text with a generic "Error executing tool", so a plain RuntimeError would strand
every diagnostic here on the server.
"""

from __future__ import annotations

from mcp.server.mcpserver.exceptions import ResourceError, ToolError


class WazuhError(ToolError, ResourceError):
    """A recoverable failure the calling model should read and react to."""


class WazuhAuthError(WazuhError):
    """Credentials were rejected by Wazuh."""


class WazuhNotConfigured(WazuhError):
    """A tool needs a component that this deployment did not configure."""
