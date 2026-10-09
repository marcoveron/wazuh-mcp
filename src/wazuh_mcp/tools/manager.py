"""Manager, cluster and indexer health — is the SOC's own telemetry trustworthy?

Worth checking before concluding "no alerts, all quiet": a stopped analysisd or a
red indexer produces exactly the same silence as a calm network.
"""

from __future__ import annotations

from typing import Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from ..envelope import API, MIXED, envelope, from_api
from ..errors import WazuhError
from ..runtime import get_runtime

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=True)


def register(mcp: MCPServer) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_health() -> dict[str, Any]:
        """Check the health of the whole Wazuh stack: manager daemons, cluster and indexer.

        Run this first in any autonomous cycle. A gap in alerts means nothing
        until you know the pipeline was actually running.

        `items` is one row per component, each carrying `component` and
        `healthy`. `healthy` is null where the answer is genuinely unknown — an
        indexer that was never configured, a cluster that would not answer — and
        `context.healthy` is false only if some component is known to be broken.
        """
        runtime = get_runtime()
        components: list[dict[str, Any]] = []

        status = await runtime.api.get_items("/manager/status")
        daemons = status["items"][0] if status["items"] else {}
        stopped = [name for name, state in daemons.items() if state != "running"]
        manager: dict[str, Any] = {
            "component": "manager",
            "healthy": not stopped,
            "daemons": daemons,
            "stopped_daemons": stopped,
        }

        info = await runtime.api.get_items("/manager/info")
        if info["items"]:
            detail = info["items"][0]
            manager["version"] = detail.get("version")
            manager["node_name"] = detail.get("node_name")
            manager["type"] = detail.get("type")
        components.append(manager)

        components.append(await _cluster_health(runtime))
        components.append(await _indexer_health(runtime))

        return envelope(
            components,
            source=MIXED,
            healthy=not any(c["healthy"] is False for c in components),
        )

    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_manager_logs(
        level: str | None = None,
        tag: str | None = None,
        search: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Read the Wazuh manager's own log (ossec.log) — for diagnosing the stack itself.

        Args:
            level: Log level to filter by: "info", "warning", "error", "critical",
                "debug". Start with "error" when something looks broken.
            tag: Daemon that emitted the line, e.g. "wazuh-analysisd",
                "wazuh-remoted", "wazuh-modulesd".
            search: Substring to match in the log message.
            limit: Lines to return, newest first.
        """
        runtime = get_runtime()
        result = await runtime.api.get_items(
            "/manager/logs",
            level=level,
            tag=tag,
            search=search,
            limit=runtime.clamp(limit),
            sort="-timestamp",
        )
        return from_api(result)

    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_manager_stats(date: str | None = None) -> dict[str, Any]:
        """Get manager throughput statistics: events received, dropped and alerts written.

        A rising "dropped" count means the manager is shedding events, so absence
        of alerts is not evidence of absence of attacks.

        `items` holds the hourly rows; the live analysisd and remoted counters
        are in `context`.

        Args:
            date: Day to report on, as YYYY-MM-DD. Defaults to today.
        """
        runtime = get_runtime()
        result = await runtime.api.get_items("/manager/stats", date=date)
        analysisd = await runtime.api.get_items("/manager/stats/analysisd")
        remoted = await runtime.api.get_items("/manager/stats/remoted")
        return envelope(
            result["items"],
            source=API,
            total=result["total"],
            analysisd=analysisd["items"][0] if analysisd["items"] else {},
            remoted=remoted["items"][0] if remoted["items"] else {},
        )


async def _cluster_health(runtime) -> dict[str, Any]:
    """Cluster endpoints 400 on a standalone manager, which is not a failure."""
    try:
        status = await runtime.api.get("/cluster/status")
    except WazuhError as exc:
        return {"component": "cluster", "healthy": None, "enabled": "unknown", "error": str(exc)}

    data = status.get("data", {})
    if data.get("enabled") != "yes":
        return {"component": "cluster", "healthy": True, "enabled": False, "mode": "standalone"}

    try:
        check = await runtime.api.get_items("/cluster/healthcheck")
    except WazuhError as exc:
        return {
            "component": "cluster",
            "healthy": False,
            "enabled": True,
            "running": data.get("running"),
            "error": str(exc),
        }
    return {
        "component": "cluster",
        "healthy": data.get("running") == "yes",
        "enabled": True,
        "running": data.get("running"),
        "nodes": check["items"],
    }


async def _indexer_health(runtime) -> dict[str, Any]:
    if runtime.indexer is None:
        return {"component": "indexer", "healthy": None, "configured": False}
    try:
        cluster = await runtime.indexer.cluster_health()
        indices = await runtime.indexer.indices(runtime.indexer.config.alerts_index)
    except WazuhError as exc:
        return {"component": "indexer", "healthy": False, "reachable": False, "error": str(exc)}

    status = cluster.get("status")
    return {
        "component": "indexer",
        # Yellow is normal on a single node: replicas are unassigned by design.
        "healthy": status in {"green", "yellow"},
        "reachable": True,
        "status": status,
        "nodes": cluster.get("number_of_nodes"),
        "unassigned_shards": cluster.get("unassigned_shards"),
        "alert_indices": indices[-5:],
    }
