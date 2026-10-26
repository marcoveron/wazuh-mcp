"""Active Response: the tools that change production hosts.

The write tools are registered only when WAZUH_ALLOW_ACTIVE_RESPONSE is on, so
a read-only deployment does not even advertise them. Listing the configured
commands is read-only and always available, so a triage agent without write
access can still propose a real command for a human or a workflow to run.

Every write call reaches a real endpoint and can lock an administrator out of a
machine, so the guardrails are deliberate:

  - an optional command allowlist (WAZUH_ACTIVE_RESPONSE_COMMANDS),
  - a refusal to fan out to every agent without an explicit confirmation flag,
  - destructive_hint on the annotations so hosts can prompt before running them.
"""

from __future__ import annotations

from typing import Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from ..config import Config
from ..envelope import API, envelope
from ..errors import WazuhError
from ..query import pad_agent_id
from ..runtime import get_runtime

DESTRUCTIVE = ToolAnnotations(
    read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=True
)
READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=True)

_ALL_AGENTS = {"*", "all"}


def register(mcp: MCPServer, config: Config) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_active_response_commands() -> dict[str, Any]:
        """List the Active Response commands declared on the manager.

        Call this before running or proposing an Active Response — it tells you
        what is actually configured (in ossec.conf's <command> blocks) instead of
        guessing a name. Each entry also carries `allowed`, reflecting whether
        WAZUH_ACTIVE_RESPONSE_COMMANDS currently permits it. Read-only: it is
        available even when this server cannot run Active Response itself.
        """
        runtime = get_runtime()
        result = await runtime.api.get_items("/manager/configuration", section="command")
        items = [
            {
                "name": entry.get("name"),
                "executable": entry.get("executable"),
                "timeout_allowed": entry.get("timeout_allowed"),
                "allowed": _is_allowed(runtime.config, str(entry.get("name") or "")),
            }
            for entry in _extract_commands(result["items"])
        ]
        return envelope(
            items,
            source=API,
            allowlist=sorted(runtime.config.active_response_allowlist) or "any",
            active_response_enabled=runtime.config.allow_active_response,
        )

    if not config.allow_active_response:
        return

    @mcp.tool(annotations=DESTRUCTIVE)
    async def wazuh_active_response(
        command: str,
        agent_ids: list[str],
        arguments: list[str] | None = None,
        confirm_all_agents: bool = False,
    ) -> dict[str, Any]:
        """Run an Active Response command on agents. THIS CHANGES PRODUCTION HOSTS.

        Call wazuh_active_response_commands first to see what is actually
        configured. Typical commands are firewall-drop (block a source IP),
        host-deny, disable-account and restart-wazuh. The command must already be
        declared in the manager's ossec.conf; prefix it with "!" to invoke the
        script directly (e.g. "!firewall-drop"). Confirm the target and the blast
        radius before calling — a firewall-drop on the wrong address can cut off
        remote access. Agent "000" is the manager itself, not an endpoint — do
        not target it.

        Args:
            command: Active Response command name as configured on the manager,
                e.g. "firewall-drop" or "!firewall-drop".
            agent_ids: Agents to run it on, e.g. ["001", "004"]. Pass ["*"] to
                target every agent, which also requires confirm_all_agents.
            arguments: Arguments passed to the script. For firewall-drop this is
                the IP to block, e.g. ["203.0.113.10"].
            confirm_all_agents: Must be true to run against every agent at once.
                Guards against fleet-wide self-inflicted outages.
        """
        runtime = get_runtime()
        targets = _resolve_targets(agent_ids, confirm_all_agents, command)
        _check_allowlist(runtime.config, command)

        payload: dict[str, Any] = {"command": command}
        if arguments:
            payload["arguments"] = [str(arg) for arg in arguments]

        body = await runtime.api.request(
            "PUT",
            "/active-response",
            params={"agents_list": targets},
            json_body=payload,
        )
        data = body.get("data", {})
        # `items` are the agents the command actually reached; anything that
        # failed is in context.failed_items, where it cannot be mistaken for a
        # success by something counting `returned`.
        return envelope(
            [{"agent_id": agent} for agent in data.get("affected_items", [])],
            source=API,
            command=command,
            arguments=arguments or [],
            requested_agents=targets,
            failed_items=data.get("failed_items") or None,
            message=data.get("message"),
        )

    @mcp.tool(annotations=DESTRUCTIVE)
    async def wazuh_restart_agents(
        agent_ids: list[str],
        confirm_all_agents: bool = False,
    ) -> dict[str, Any]:
        """Restart the Wazuh agent process on the given hosts.

        Restarts the agent, not the host. Use it to apply a configuration change
        or to recover an agent stuck in a bad state — it briefly stops collection
        on those hosts.

        Args:
            agent_ids: Agents to restart, e.g. ["001"]. Pass ["*"] for all agents,
                which also requires confirm_all_agents.
            confirm_all_agents: Must be true to restart every agent at once.
        """
        runtime = get_runtime()
        targets = _resolve_targets(agent_ids, confirm_all_agents, "restart")

        body = await runtime.api.request(
            "PUT", "/agents/restart", params={"agents_list": targets}
        )
        data = body.get("data", {})
        return envelope(
            [{"agent_id": agent} for agent in data.get("affected_items", [])],
            source=API,
            requested_agents=targets,
            failed_items=data.get("failed_items") or None,
            message=data.get("message"),
        )


def _resolve_targets(agent_ids: list[str], confirm_all: bool, action: str) -> str:
    if not agent_ids:
        raise WazuhError("agent_ids is empty; name the agents to act on.")

    wants_all = any(str(a).strip().lower() in _ALL_AGENTS for a in agent_ids)
    if wants_all:
        if not confirm_all:
            raise WazuhError(
                f"Refusing to run {action!r} against every agent. If that is really "
                "intended, call again with confirm_all_agents=true; otherwise list "
                "the specific agent IDs."
            )
        return "*"

    return ",".join(pad_agent_id(a) for a in agent_ids)


def _is_allowed(config: Config, command: str) -> bool:
    allowlist = config.active_response_allowlist
    if not allowlist:
        return True
    # The "!" prefix only changes how the manager resolves the script, not which
    # action it is, so match on the bare name.
    bare = command.lstrip("!")
    return bare in allowlist or command in allowlist


def _check_allowlist(config: Config, command: str) -> None:
    if _is_allowed(config, command):
        return
    allowlist = config.active_response_allowlist
    raise WazuhError(
        f"Active Response command {command!r} is not in the allowlist "
        f"({', '.join(sorted(allowlist))}). Add it to "
        "WAZUH_ACTIVE_RESPONSE_COMMANDS to permit it."
    )


def _extract_commands(raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten `/manager/configuration?section=command` into one row per <command>.

    Each affected_item is either the command block itself or wraps a list of
    them under a "command" key — ossec.conf allows several <command> stanzas.
    """
    commands: list[dict[str, Any]] = []
    for entry in raw_items:
        section = entry.get("command", entry) if isinstance(entry, dict) else entry
        if isinstance(section, dict):
            section = [section]
        if isinstance(section, list):
            commands.extend(item for item in section if isinstance(item, dict))
    return commands
