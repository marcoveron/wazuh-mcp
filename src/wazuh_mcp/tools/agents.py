"""Agent inventory: who is reporting, who went dark, what they are running."""

from __future__ import annotations

from typing import Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from ..envelope import API, envelope, from_api
from ..query import pad_agent_id
from ..runtime import get_runtime

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=True)

# Enough to triage an agent without dragging its whole configuration along.
_LIST_SELECT = (
    "id,name,ip,status,os.name,os.platform,os.version,version,group,"
    "lastKeepAlive,dateAdd,node_name"
)


def register(mcp: MCPServer) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_list_agents(
        status: list[str] | None = None,
        group: str | None = None,
        os_platform: str | None = None,
        name: str | None = None,
        ip: str | None = None,
        version: str | None = None,
        search: str | None = None,
        query: str | None = None,
        sort: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """List Wazuh agents with their connection status and platform.

        Returns the standard envelope; `items` are agent records.

        Args:
            status: Connection states to include: active, pending, disconnected,
                never_connected. Omit for all.
            group: Only agents belonging to this agent group.
            os_platform: Filter by platform, e.g. "ubuntu", "windows", "centos".
            name: Filter by agent name (exact match).
            ip: Filter by the agent's registered IP.
            version: Filter by agent version, e.g. "4.8.0".
            search: Substring search across the agent's fields.
            query: Wazuh query syntax for precise filters, e.g.
                "status=active;os.platform=windows" (";" is AND, "," is OR).
            sort: Field to sort by; prefix with "-" for descending, e.g. "-lastKeepAlive".
            limit: Maximum agents to return (server caps this).
            offset: Number of agents to skip, for paging.
        """
        runtime = get_runtime()
        result = await runtime.api.get_items(
            "/agents",
            status=",".join(status) if status else None,
            group=group,
            **{"os.platform": os_platform},
            name=name,
            ip=ip,
            version=version,
            search=search,
            q=query,
            sort=sort,
            select=_LIST_SELECT,
            limit=runtime.clamp(limit),
            offset=offset,
        )
        return from_api(result)

    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_get_agent(agent_id: str) -> dict[str, Any]:
        """Get the full record for one agent, including OS details and group membership.

        `items` holds the agent, or is empty when no such agent exists — check
        `returned`, not a truthy record.

        Args:
            agent_id: Agent ID as Wazuh stores it, zero-padded to three digits
                (e.g. "001"). Plain integers are padded automatically.
        """
        runtime = get_runtime()
        padded = pad_agent_id(agent_id)
        result = await runtime.api.get_items("/agents", agents_list=padded)
        return from_api(result, agent_id=padded)

    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_agent_summary() -> dict[str, Any]:
        """Fleet health at a glance: agent counts by connection state, OS and group.

        Start here when asked "how is the environment doing" — it is one round
        trip instead of paging the whole inventory. Each row in `items` carries
        a `dimension` saying which breakdown it belongs to.
        """
        runtime = get_runtime()
        status = await runtime.api.get("/agents/summary/status")
        os_summary = await runtime.api.get_items("/agents/summary/os")
        groups = await runtime.api.get_items("/groups", limit=runtime.clamp(100))

        data = status.get("data", {}) or {}
        # Wazuh 4.x nests the counts under "connection"; older builds are flat.
        connection = data.get("connection", data)
        total_agents = connection.get("total")

        rows: list[dict[str, Any]] = [
            {"dimension": "status", "key": key, "count": value}
            for key, value in connection.items()
            if key != "total" and isinstance(value, int)
        ]
        rows.extend(_os_rows(os_summary["items"]))
        rows.extend(
            {"dimension": "group", "key": g.get("name"), "count": g.get("count")}
            for g in groups["items"]
        )
        return envelope(rows, source=API, total_agents=total_agents)

    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_agent_processes(
        agent_id: str, search: str | None = None, limit: int = 50
    ) -> dict[str, Any]:
        """List processes inventoried on an agent (requires the syscollector module).

        Args:
            agent_id: Target agent ID, e.g. "001".
            search: Substring to match against process name or command line.
            limit: Maximum processes to return.
        """
        runtime = get_runtime()
        padded = pad_agent_id(agent_id)
        result = await runtime.api.get_items(
            f"/syscollector/{padded}/processes",
            search=search,
            limit=runtime.clamp(limit),
            select="pid,ppid,name,cmd,state,euser,start_time",
        )
        return from_api(result, agent_id=padded)

    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_agent_ports(
        agent_id: str, state: str | None = None, limit: int = 50
    ) -> dict[str, Any]:
        """List network ports open on an agent (requires the syscollector module).

        Args:
            agent_id: Target agent ID, e.g. "001".
            state: Socket state to filter by, e.g. "listening", "established".
            limit: Maximum ports to return.
        """
        runtime = get_runtime()
        padded = pad_agent_id(agent_id)
        result = await runtime.api.get_items(
            f"/syscollector/{padded}/ports",
            state=state,
            limit=runtime.clamp(limit),
            select="local.ip,local.port,remote.ip,remote.port,protocol,state,process,pid",
        )
        return from_api(result, agent_id=padded)

    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_agent_packages(
        agent_id: str, search: str | None = None, limit: int = 50
    ) -> dict[str, Any]:
        """List software packages installed on an agent (requires the syscollector module).

        Useful for confirming whether a CVE's vulnerable package is actually present.

        Args:
            agent_id: Target agent ID, e.g. "001".
            search: Substring to match against the package name.
            limit: Maximum packages to return.
        """
        runtime = get_runtime()
        padded = pad_agent_id(agent_id)
        result = await runtime.api.get_items(
            f"/syscollector/{padded}/packages",
            search=search,
            limit=runtime.clamp(limit),
            select="name,version,architecture,vendor,format,install_time",
        )
        return from_api(result, agent_id=padded)


def _os_rows(items: list[Any]) -> list[dict[str, Any]]:
    """`/agents/summary/os` returns bare platform names on some versions and
    counted objects on others; emit a count only where Wazuh supplied one."""
    rows: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            key = item.get("os", {}).get("platform") if isinstance(item.get("os"), dict) else None
            row: dict[str, Any] = {"dimension": "os_platform", "key": key or item.get("platform")}
            if isinstance(item.get("count"), int):
                row["count"] = item["count"]
        else:
            row = {"dimension": "os_platform", "key": item}
        rows.append(row)
    return rows
