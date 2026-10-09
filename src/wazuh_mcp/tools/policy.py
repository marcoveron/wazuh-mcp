"""File integrity monitoring, configuration assessment and rootcheck.

These read per-agent state held by the manager, so they go through the Server
API rather than the indexer. They answer "what changed on this host" and "how far
from the benchmark is this host" — the two questions that usually follow an alert.
"""

from __future__ import annotations

from typing import Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from ..envelope import from_api
from ..query import pad_agent_id
from ..runtime import get_runtime

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=True)


def register(mcp: MCPServer) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_fim_findings(
        agent_id: str,
        file: str | None = None,
        entry_type: str | None = None,
        search: str | None = None,
        query: str | None = None,
        hash_value: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Read file-integrity-monitoring state for an agent: what FIM is tracking and its hashes.

        This is the current FIM database, not the change events. For "what changed
        and when", search alerts with rule_groups=["syscheck"] instead.

        Args:
            agent_id: Target agent ID, e.g. "001".
            file: Exact path to look up, e.g. "/etc/passwd".
            entry_type: Restrict to "file", "registry_key" or "registry_value".
            search: Substring match across the entries.
            query: Wazuh query syntax, e.g. "mtime>2024-01-01;perm=100644".
            hash_value: Look up entries by md5, sha1 or sha256 — the way to check
                whether a known-bad hash is present on the host.
            limit: Entries to return.
            offset: Entries to skip, for paging.
        """
        runtime = get_runtime()
        padded = pad_agent_id(agent_id)
        result = await runtime.api.get_items(
            f"/syscheck/{padded}",
            file=file,
            type=entry_type,
            search=search,
            q=query,
            hash=hash_value,
            limit=runtime.clamp(limit),
            offset=offset,
            select="file,type,size,perm,uid,gid,uname,gname,mtime,date,md5,sha1,sha256",
        )
        return from_api(result, agent_id=padded)

    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_sca_policies(agent_id: str) -> dict[str, Any]:
        """List Security Configuration Assessment policies applied to an agent, with scores.

        Returns each policy's pass/fail counts and overall score — the fast way to
        judge whether a host is hardened before drilling into individual checks.

        Args:
            agent_id: Target agent ID, e.g. "001".
        """
        runtime = get_runtime()
        padded = pad_agent_id(agent_id)
        result = await runtime.api.get_items(f"/sca/{padded}")
        return from_api(result, agent_id=padded)

    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_sca_checks(
        agent_id: str,
        policy_id: str,
        result_filter: str | None = "failed",
        search: str | None = None,
        query: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> dict[str, Any]:
        """List individual SCA checks for a policy, including the remediation text.

        Defaults to failed checks, since those are the actionable ones.

        Args:
            agent_id: Target agent ID, e.g. "001".
            policy_id: Policy identifier from wazuh_sca_policies,
                e.g. "cis_debian10" or "cis_win2019".
            result_filter: "failed", "passed" or "not applicable". Pass null for all.
            search: Substring match across check titles and descriptions.
            query: Wazuh query syntax for finer filters.
            limit: Checks to return.
            offset: Checks to skip, for paging.
        """
        runtime = get_runtime()
        padded = pad_agent_id(agent_id)
        result = await runtime.api.get_items(
            f"/sca/{padded}/checks/{policy_id}",
            result=result_filter,
            search=search,
            q=query,
            limit=runtime.clamp(limit),
            offset=offset,
            select="id,title,result,rationale,remediation,condition,compliance,reason",
        )
        return from_api(result, agent_id=padded, policy_id=policy_id)

    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_rootcheck_findings(
        agent_id: str,
        status: str | None = "outstanding",
        search: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> dict[str, Any]:
        """List rootcheck / anomaly-detection findings for an agent.

        Rootcheck covers hidden processes and ports, suspicious files and known
        rootkit signatures — the checks worth reading when a host is suspected
        of being compromised rather than merely misconfigured.

        Args:
            agent_id: Target agent ID, e.g. "001".
            status: "outstanding" for still-present findings or "all" to include
                ones already resolved.
            search: Substring match across the finding text.
            limit: Findings to return.
            offset: Findings to skip, for paging.
        """
        runtime = get_runtime()
        padded = pad_agent_id(agent_id)
        result = await runtime.api.get_items(
            f"/rootcheck/{padded}",
            status=status,
            search=search,
            limit=runtime.clamp(limit),
            offset=offset,
        )
        return from_api(result, agent_id=padded)
