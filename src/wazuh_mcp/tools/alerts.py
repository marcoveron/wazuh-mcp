"""Alert search, aggregation and trending against the Wazuh Indexer.

Three shapes of question, three tools:
  - "show me the alerts"      -> wazuh_search_alerts (documents)
  - "what is going on"        -> wazuh_alert_stats   (aggregated counts)
  - "when did it start"       -> wazuh_alert_timeline (date histogram)

Reach for the aggregations first. Paging documents to answer a counting question
burns context and usually misses the long tail.
"""

from __future__ import annotations

from typing import Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from ..envelope import INDEXER, envelope, from_buckets, from_hits
from ..errors import WazuhError
from ..formatting import compact_alert, total_hits
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

# Field name -> the aggregatable field in the Wazuh alerts template.
_GROUPABLE: dict[str, str] = {
    "rule.id": "rule.id",
    "rule.description": "rule.description",
    "rule.level": "rule.level",
    "rule.groups": "rule.groups",
    "rule.mitre.id": "rule.mitre.id",
    "rule.mitre.tactic": "rule.mitre.tactic",
    "rule.mitre.technique": "rule.mitre.technique",
    "agent.id": "agent.id",
    "agent.name": "agent.name",
    "agent.ip": "agent.ip",
    "location": "location",
    "decoder.name": "decoder.name",
    "data.srcip": "data.srcip",
    "data.dstip": "data.dstip",
    "data.srcuser": "data.srcuser",
    "data.dstuser": "data.dstuser",
    "data.win.eventdata.targetUserName": "data.win.eventdata.targetUserName",
    "syscheck.path": "syscheck.path",
}


def _alert_filters(
    *,
    time_from: str | None = None,
    time_to: str | None = None,
    agent_ids: list[str] | None = None,
    agent_names: list[str] | None = None,
    rule_ids: list[str] | None = None,
    rule_groups: list[str] | None = None,
    min_level: int | None = None,
    max_level: int | None = None,
    mitre_ids: list[str] | None = None,
    src_ips: list[str] | None = None,
    dst_ips: list[str] | None = None,
    users: list[str] | None = None,
    search: str | None = None,
    extra_query: dict[str, Any] | str | None = None,
) -> dict[str, Any]:
    return bool_query(
        [
            time_range("timestamp", time_from, time_to),
            terms_clause("agent.id", pad_agent_ids(agent_ids)),
            terms_clause("agent.name", agent_names),
            terms_clause("rule.id", rule_ids),
            terms_clause("rule.groups", rule_groups),
            range_clause("rule.level", min_level, max_level),
            terms_clause("rule.mitre.id", mitre_ids),
            terms_clause("data.srcip", src_ips),
            terms_clause("data.dstip", dst_ips),
            terms_clause("data.srcuser", users),
            query_string_clause(search),
            parse_extra_query(extra_query),
        ]
    )


def register(mcp: MCPServer) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_search_alerts(
        time_from: str | None = "24h",
        time_to: str | None = None,
        agent_ids: list[str] | None = None,
        agent_names: list[str] | None = None,
        rule_ids: list[str] | None = None,
        rule_groups: list[str] | None = None,
        min_level: int | None = None,
        max_level: int | None = None,
        mitre_ids: list[str] | None = None,
        src_ips: list[str] | None = None,
        dst_ips: list[str] | None = None,
        users: list[str] | None = None,
        search: str | None = None,
        extra_query: dict[str, Any] | str | None = None,
        sort_desc: bool = True,
        limit: int = 20,
        offset: int = 0,
        fields: list[str] | None = None,
        full_documents: bool = False,
    ) -> dict[str, Any]:
        """Search Wazuh alerts. The primary tool for investigating what happened.

        `items` holds a compact projection of each alert by default. `total`
        reflects every alert that matched, not just the page returned, so use it
        to decide whether to narrow the filters before paging — and check
        `total_is_exact`, which is false once OpenSearch stops counting.

        Args:
            time_from: Start of the window. Accepts a duration ("24h", "7d"),
                date math ("now-1h", "now/d") or ISO-8601. Defaults to the last
                24 hours; pass null to search all time.
            time_to: End of the window; defaults to now.
            agent_ids: Restrict to these agent IDs, e.g. ["001", "007"].
            agent_names: Restrict to these agent names.
            rule_ids: Restrict to these Wazuh rule IDs, e.g. ["5710", "5712"].
            rule_groups: Restrict to these rule groups, e.g.
                ["authentication_failed", "syscheck", "sca", "web"].
            min_level: Minimum rule severity (0-15). Use 7+ to skip routine noise,
                12+ for the alerts that usually matter.
            max_level: Maximum rule severity.
            mitre_ids: MITRE ATT&CK technique IDs, e.g. ["T1110", "T1059.001"].
            src_ips: Source IPs from the alert data.
            dst_ips: Destination IPs from the alert data.
            users: Usernames from data.srcuser.
            search: Free-text Lucene query across the alert, e.g.
                'full_log:*powershell* AND NOT rule.level:3'.
            extra_query: A raw OpenSearch query-DSL clause, ANDed with the other
                filters. Accepts an object or a JSON string. Use for anything the
                named filters cannot express, e.g.
                {"wildcard": {"data.win.eventdata.image": "*\\\\mimikatz.exe"}}.
            sort_desc: Newest alerts first when true, oldest first when false.
            limit: Alerts to return per call. Keep it small; aggregate instead of paging.
            offset: Alerts to skip, for paging.
            fields: Return exactly these dotted field paths instead of the default
                projection, e.g. ["timestamp", "rule.description", "data.srcip"].
            full_documents: Return the complete raw alert documents. Expensive —
                use only when the default projection has dropped something needed.
        """
        runtime = get_runtime()
        indexer = runtime.require_indexer()
        page = runtime.clamp(limit)

        body = {
            "query": _alert_filters(
                time_from=time_from, time_to=time_to, agent_ids=agent_ids,
                agent_names=agent_names, rule_ids=rule_ids, rule_groups=rule_groups,
                min_level=min_level, max_level=max_level, mitre_ids=mitre_ids,
                src_ips=src_ips, dst_ips=dst_ips, users=users, search=search,
                extra_query=extra_query,
            ),
            "size": page,
            "from": max(0, offset),
            "sort": [{"timestamp": {"order": "desc" if sort_desc else "asc"}}],
        }
        response = await indexer.search(indexer.config.alerts_index, body)
        return from_hits(
            response,
            compact_alert,
            full_documents=full_documents,
            fields=fields,
            index=indexer.config.alerts_index,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_alert_stats(
        group_by: str = "rule.description",
        time_from: str | None = "24h",
        time_to: str | None = None,
        agent_ids: list[str] | None = None,
        agent_names: list[str] | None = None,
        rule_ids: list[str] | None = None,
        rule_groups: list[str] | None = None,
        min_level: int | None = None,
        max_level: int | None = None,
        mitre_ids: list[str] | None = None,
        src_ips: list[str] | None = None,
        search: str | None = None,
        extra_query: dict[str, Any] | str | None = None,
        secondary_group_by: str | None = None,
        top: int = 20,
    ) -> dict[str, Any]:
        """Aggregate alert counts by a field. Use this before paging documents.

        One call answers "what are the top rules firing", "which agents are
        noisiest", "which ATT&CK techniques are we seeing" — questions that would
        otherwise need hundreds of documents. `items` are the buckets; `total`
        counts the documents aggregated over, not the buckets.

        Args:
            group_by: Field to bucket on. One of: rule.id, rule.description,
                rule.level, rule.groups, rule.mitre.id, rule.mitre.tactic,
                rule.mitre.technique, agent.id, agent.name, agent.ip, location,
                decoder.name, data.srcip, data.dstip, data.srcuser, data.dstuser,
                data.win.eventdata.targetUserName, syscheck.path.
            time_from: Start of the window ("24h", "7d", "now-1h", ISO-8601).
            time_to: End of the window; defaults to now.
            agent_ids: Restrict to these agent IDs.
            agent_names: Restrict to these agent names.
            rule_ids: Restrict to these rule IDs.
            rule_groups: Restrict to these rule groups.
            min_level: Minimum rule severity (0-15).
            max_level: Maximum rule severity.
            mitre_ids: MITRE ATT&CK technique IDs.
            src_ips: Source IPs from the alert data.
            search: Free-text Lucene query applied before aggregating.
            extra_query: Raw OpenSearch query-DSL clause, as an object or JSON string.
            secondary_group_by: Optional second field, nested inside each bucket —
                e.g. group_by "agent.name" with secondary "rule.description" shows
                each host's top rules.
            top: Number of buckets to return per level.
        """
        runtime = get_runtime()
        indexer = runtime.require_indexer()

        primary = _resolve_field(group_by)
        size = max(1, min(top, 100))
        aggregation: dict[str, Any] = {
            "terms": {"field": primary, "size": size, "order": {"_count": "desc"}},
        }
        if secondary_group_by:
            aggregation["aggs"] = {
                "breakdown": {
                    "terms": {
                        "field": _resolve_field(secondary_group_by),
                        "size": size,
                        "order": {"_count": "desc"},
                    }
                }
            }
        # Severity context per bucket: a bucket of 500 level-3 alerts and one of
        # 5 level-12 alerts are very different findings.
        aggregation.setdefault("aggs", {})["max_level"] = {"max": {"field": "rule.level"}}
        aggregation["aggs"]["agents"] = {"cardinality": {"field": "agent.id"}}

        body = {
            "query": _alert_filters(
                time_from=time_from, time_to=time_to, agent_ids=agent_ids,
                agent_names=agent_names, rule_ids=rule_ids, rule_groups=rule_groups,
                min_level=min_level, max_level=max_level, mitre_ids=mitre_ids,
                src_ips=src_ips, search=search, extra_query=extra_query,
            ),
            "size": 0,
            "aggs": {"grouped": aggregation},
        }
        response = await indexer.search(indexer.config.alerts_index, body)
        return from_buckets(
            response,
            "grouped",
            group_by=primary,
            secondary_group_by=secondary_group_by,
            index=indexer.config.alerts_index,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_alert_timeline(
        interval: str = "1h",
        time_from: str | None = "24h",
        time_to: str | None = None,
        agent_ids: list[str] | None = None,
        rule_ids: list[str] | None = None,
        rule_groups: list[str] | None = None,
        min_level: int | None = None,
        mitre_ids: list[str] | None = None,
        search: str | None = None,
        extra_query: dict[str, Any] | str | None = None,
        split_by: str | None = None,
        top: int = 5,
    ) -> dict[str, Any]:
        """Bucket alerts over time to spot spikes, bursts and when an incident began.

        Args:
            interval: Bucket width as date math: "1m", "5m", "1h", "1d".
            time_from: Start of the window ("24h", "7d", "now-1h", ISO-8601).
            time_to: End of the window; defaults to now.
            agent_ids: Restrict to these agent IDs.
            rule_ids: Restrict to these rule IDs.
            rule_groups: Restrict to these rule groups.
            min_level: Minimum rule severity (0-15).
            mitre_ids: MITRE ATT&CK technique IDs.
            search: Free-text Lucene query applied before bucketing.
            extra_query: Raw OpenSearch query-DSL clause, as an object or JSON string.
            split_by: Optionally break each time bucket down by this field,
                e.g. "agent.name" or "rule.description".
            top: Number of series to keep when split_by is set.
        """
        runtime = get_runtime()
        indexer = runtime.require_indexer()

        histogram: dict[str, Any] = {
            "date_histogram": {
                "field": "timestamp",
                _interval_key(interval): interval,
                "min_doc_count": 0,
            }
        }
        if split_by:
            histogram["aggs"] = {
                "series": {
                    "terms": {"field": _resolve_field(split_by), "size": max(1, min(top, 20))}
                }
            }

        body = {
            "query": _alert_filters(
                time_from=time_from, time_to=time_to, agent_ids=agent_ids,
                rule_ids=rule_ids, rule_groups=rule_groups, min_level=min_level,
                mitre_ids=mitre_ids, search=search, extra_query=extra_query,
            ),
            "size": 0,
            "aggs": {"over_time": histogram},
        }
        response = await indexer.search(indexer.config.alerts_index, body)
        return from_buckets(
            response,
            "over_time",
            key_name="time",
            interval=interval,
            split_by=split_by,
            index=indexer.config.alerts_index,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_indexer_query(
        body: dict[str, Any] | str,
        index: str | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        """Run a raw OpenSearch search body against a Wazuh index. Escape hatch.

        Use when the structured alert tools cannot express the query: unusual
        aggregations, scripted fields, `significant_terms`, joins across custom
        decoder output. Prefer wazuh_search_alerts and wazuh_alert_stats when they fit.

        Args:
            body: The full `_search` request body, as an object or a JSON
                string, e.g. {"query": {"term": {"rule.id": "5710"}}, "size": 5}.
            index: Index pattern to search. Defaults to the configured alerts
                pattern. Other useful patterns: the archives and the
                vulnerability-states indices.
            limit: Cap applied to `size` when the body does not set one.
        """
        runtime = get_runtime()
        indexer = runtime.require_indexer()
        parsed = parse_extra_query(body)
        if parsed is None:
            raise WazuhError("body must be a non-empty JSON object.")
        if "query" not in parsed and "aggs" not in parsed and "aggregations" not in parsed:
            raise WazuhError(
                "body must contain at least a 'query' or 'aggs' key; it is the "
                "OpenSearch _search request body, not just the query clause."
            )
        parsed.setdefault("size", runtime.clamp(limit))
        parsed["size"] = runtime.clamp(int(parsed["size"])) if parsed["size"] else 0

        target = index or indexer.config.alerts_index
        response = await indexer.search(target, parsed)
        total = total_hits(response)
        return envelope(
            [
                {"_id": h.get("_id"), "_index": h.get("_index"), **(h.get("_source") or {})}
                for h in response.get("hits", {}).get("hits", [])
            ],
            source=INDEXER,
            total=total["value"],
            total_is_exact=total["relation"] == "eq",
            index=target,
            aggregations=response.get("aggregations"),
        )


def _interval_key(interval: str) -> str:
    """Pick the date_histogram parameter that accepts this interval.

    `calendar_interval` only takes a singular unit ("1d", "1M"), so anything with
    a multiplier — or any sub-day unit — has to go through `fixed_interval`.
    """
    value = (interval or "").strip()
    if not value:
        raise WazuhError('interval is empty; use date math such as "5m", "1h" or "1d".')
    unit = value[-1]
    if unit in "smhd":
        return "fixed_interval"
    if unit in "wMqy":
        return "calendar_interval"
    raise WazuhError(
        f'interval {interval!r} is not date math; use a number plus one of '
        "s, m, h, d, w, M, q, y (e.g. \"15m\", \"1h\", \"7d\")."
    )


def _resolve_field(name: str) -> str:
    field = _GROUPABLE.get(name.strip())
    if field is not None:
        return field
    # Unknown fields are allowed — custom decoders add their own — but say what
    # is known so a typo does not silently return an empty aggregation.
    if not name.strip():
        raise WazuhError(f"group_by is empty. Known fields: {', '.join(sorted(_GROUPABLE))}")
    return name.strip()
