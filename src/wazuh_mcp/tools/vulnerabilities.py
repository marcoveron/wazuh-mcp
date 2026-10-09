"""Vulnerability state from the Wazuh Indexer.

From Wazuh 4.8 onward the vulnerability detector writes current state into
`wazuh-states-vulnerabilities-*` rather than exposing it through the Server API,
so these tools query the indexer. Each document is one (agent, package, CVE)
triple that is *currently* open, not a historical event.
"""

from __future__ import annotations

from typing import Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from ..envelope import from_buckets, from_hits
from ..errors import WazuhError
from ..formatting import buckets_to_rows, compact_vulnerability
from ..query import (
    bool_query,
    pad_agent_ids,
    parse_extra_query,
    query_string_clause,
    range_clause,
    terms_clause,
    time_range,
)
from ..runtime import get_runtime

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=True)

_GROUPABLE = {
    "vulnerability.severity",
    "vulnerability.id",
    "agent.id",
    "agent.name",
    "package.name",
    "package.version",
    "vulnerability.category",
    "vulnerability.classification",
}

# Ordering severity by name is meaningless; rank it the way an analyst reads it.
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "untriaged": 4}


def _vuln_filters(
    *,
    agent_ids: list[str] | None = None,
    agent_names: list[str] | None = None,
    severities: list[str] | None = None,
    cves: list[str] | None = None,
    packages: list[str] | None = None,
    min_score: float | None = None,
    detected_from: str | None = None,
    detected_to: str | None = None,
    search: str | None = None,
    extra_query: dict[str, Any] | str | None = None,
) -> dict[str, Any]:
    normalized = [s.strip().capitalize() for s in severities] if severities else None
    return bool_query(
        [
            terms_clause("agent.id", pad_agent_ids(agent_ids)),
            terms_clause("agent.name", agent_names),
            terms_clause("vulnerability.severity", normalized),
            terms_clause("vulnerability.id", [c.upper() for c in cves] if cves else None),
            terms_clause("package.name", packages),
            range_clause("vulnerability.score.base", min_score, None),
            time_range("vulnerability.detected_at", detected_from, detected_to),
            query_string_clause(search),
            parse_extra_query(extra_query),
        ]
    )


def register(mcp: MCPServer) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_list_vulnerabilities(
        agent_ids: list[str] | None = None,
        agent_names: list[str] | None = None,
        severities: list[str] | None = None,
        cves: list[str] | None = None,
        packages: list[str] | None = None,
        min_score: float | None = None,
        detected_from: str | None = None,
        detected_to: str | None = None,
        search: str | None = None,
        extra_query: dict[str, Any] | str | None = None,
        sort_by_severity: bool = True,
        limit: int = 25,
        offset: int = 0,
        full_documents: bool = False,
    ) -> dict[str, Any]:
        """List currently-open vulnerabilities per agent and package.

        Each result is one CVE affecting one package on one agent. Use
        wazuh_vulnerability_summary first when the question is "how bad is it"
        rather than "which exact findings".

        Args:
            agent_ids: Restrict to these agent IDs, e.g. ["001"].
            agent_names: Restrict to these agent names.
            severities: Severity levels: Critical, High, Medium, Low, Untriaged.
            cves: Specific CVE identifiers, e.g. ["CVE-2024-3094"].
            packages: Restrict to these package names, e.g. ["openssl"].
            min_score: Minimum CVSS base score, e.g. 9.0 for the critical tier.
            detected_from: Only findings first detected after this point
                ("7d", "now-30d", ISO-8601). Useful for "what is new this week".
            detected_to: Only findings detected before this point.
            search: Free-text Lucene query across the finding.
            extra_query: Raw OpenSearch query-DSL clause, as an object or JSON string.
            sort_by_severity: Order by CVSS base score descending. When false,
                order by detection time, newest first.
            limit: Findings to return.
            offset: Findings to skip, for paging.
            full_documents: Return complete raw documents instead of the projection.
        """
        runtime = get_runtime()
        indexer = runtime.require_indexer()

        sort: list[dict[str, Any]] = (
            [
                {"vulnerability.score.base": {"order": "desc", "missing": "_last"}},
                {"vulnerability.detected_at": {"order": "desc"}},
            ]
            if sort_by_severity
            else [{"vulnerability.detected_at": {"order": "desc"}}]
        )

        body = {
            "query": _vuln_filters(
                agent_ids=agent_ids, agent_names=agent_names, severities=severities,
                cves=cves, packages=packages, min_score=min_score,
                detected_from=detected_from, detected_to=detected_to,
                search=search, extra_query=extra_query,
            ),
            "size": runtime.clamp(limit),
            "from": max(0, offset),
            "sort": sort,
        }
        response = await indexer.search(indexer.config.vulnerabilities_index, body)
        return from_hits(
            response,
            compact_vulnerability,
            full_documents=full_documents,
            index=indexer.config.vulnerabilities_index,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_vulnerability_summary(
        group_by: str = "vulnerability.severity",
        agent_ids: list[str] | None = None,
        severities: list[str] | None = None,
        packages: list[str] | None = None,
        min_score: float | None = None,
        search: str | None = None,
        top: int = 20,
    ) -> dict[str, Any]:
        """Aggregate open vulnerabilities to see where exposure concentrates.

        Group by agent.name to rank the worst hosts, by vulnerability.id to find
        the CVE with the widest blast radius, or by package.name to find the one
        upgrade that closes the most findings. `items` are the buckets; `total`
        counts the findings aggregated over, and `context.severity_breakdown`
        carries the same findings split by severity.

        Args:
            group_by: One of vulnerability.severity, vulnerability.id, agent.id,
                agent.name, package.name, package.version, vulnerability.category,
                vulnerability.classification.
            agent_ids: Restrict to these agent IDs.
            severities: Restrict to these severities before aggregating.
            packages: Restrict to these package names.
            min_score: Minimum CVSS base score.
            search: Free-text Lucene query applied before aggregating.
            top: Number of buckets to return.
        """
        runtime = get_runtime()
        indexer = runtime.require_indexer()

        field = group_by.strip()
        if not field:
            raise WazuhError(f"group_by is empty. Known fields: {', '.join(sorted(_GROUPABLE))}")

        body = {
            "query": _vuln_filters(
                agent_ids=agent_ids, severities=severities, packages=packages,
                min_score=min_score, search=search,
            ),
            "size": 0,
            "aggs": {
                "grouped": {
                    "terms": {"field": field, "size": max(1, min(top, 100))},
                    "aggs": {
                        "affected_agents": {"cardinality": {"field": "agent.id"}},
                        "max_score": {"max": {"field": "vulnerability.score.base"}},
                    },
                },
                "by_severity": {
                    "terms": {"field": "vulnerability.severity", "size": 10},
                },
            },
        }
        response = await indexer.search(indexer.config.vulnerabilities_index, body)
        severity_rows = buckets_to_rows(response.get("aggregations", {}).get("by_severity", {}))
        severity_rows.sort(key=lambda row: _SEVERITY_RANK.get(str(row["key"]).lower(), 99))
        return from_buckets(
            response,
            "grouped",
            group_by=field,
            severity_breakdown=severity_rows,
            index=indexer.config.vulnerabilities_index,
        )
