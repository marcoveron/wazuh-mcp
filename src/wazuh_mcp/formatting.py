"""Shrink Wazuh documents into something a model can actually reason over.

A single Wazuh alert can be several kilobytes of nested Windows event data. Ten
of them raw will crowd out the investigation itself, so every read tool returns a
compact projection by default and exposes a `full_documents` escape hatch for the
cases where the detail is the point.
"""

from __future__ import annotations

from typing import Any

FULL_LOG_LIMIT = 1200

# Ordered so the compact alert reads top-down like a triage note.
_ALERT_FIELDS: tuple[str, ...] = (
    "timestamp",
    "rule.level",
    "rule.id",
    "rule.description",
    "rule.groups",
    "rule.mitre.id",
    "rule.mitre.tactic",
    "rule.mitre.technique",
    "agent.id",
    "agent.name",
    "agent.ip",
    "location",
    "decoder.name",
    "data.srcip",
    "data.srcport",
    "data.dstip",
    "data.srcuser",
    "data.dstuser",
    "data.win.eventdata.image",
    "data.win.eventdata.commandLine",
    "data.win.eventdata.targetUserName",
    "data.win.system.eventID",
    "syscheck.path",
    "syscheck.event",
    "syscheck.md5_after",
    "syscheck.sha256_after",
    "full_log",
)

_VULNERABILITY_FIELDS: tuple[str, ...] = (
    "agent.id",
    "agent.name",
    "vulnerability.id",
    "vulnerability.severity",
    "vulnerability.score.base",
    "vulnerability.score.version",
    "vulnerability.detected_at",
    "vulnerability.published_at",
    "vulnerability.description",
    "vulnerability.reference",
    "package.name",
    "package.version",
    "package.architecture",
)


def dig(source: dict[str, Any], path: str) -> Any:
    """Read a dotted path, tolerating Wazuh docs that mix nested and flat keys."""
    if path in source:
        return source[path]
    current: Any = source
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def project(source: dict[str, Any], fields: tuple[str, ...] | list[str]) -> dict[str, Any]:
    """Pull the listed dotted paths into a flat dict, dropping anything absent."""
    out: dict[str, Any] = {}
    for path in fields:
        value = dig(source, path)
        if value is None or value == [] or value == {} or value == "":
            continue
        out[path] = value
    return out


def compact_alert(source: dict[str, Any]) -> dict[str, Any]:
    alert = project(source, _ALERT_FIELDS)
    full_log = alert.get("full_log")
    if isinstance(full_log, str) and len(full_log) > FULL_LOG_LIMIT:
        alert["full_log"] = full_log[:FULL_LOG_LIMIT] + "… [truncated]"
    return alert


def compact_vulnerability(source: dict[str, Any]) -> dict[str, Any]:
    vuln = project(source, _VULNERABILITY_FIELDS)
    description = vuln.get("vulnerability.description")
    if isinstance(description, str) and len(description) > 400:
        vuln["vulnerability.description"] = description[:400] + "…"
    return vuln


def hits_to_items(
    response: dict[str, Any],
    compactor,
    *,
    full_documents: bool,
    fields: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Turn an OpenSearch response's hits into the shape a tool returns."""
    items: list[dict[str, Any]] = []
    for hit in response.get("hits", {}).get("hits", []):
        source = hit.get("_source", {}) or {}
        if full_documents:
            item = dict(source)
        elif fields:
            item = project(source, fields)
        else:
            item = compactor(source)
        item["_id"] = hit.get("_id")
        item["_index"] = hit.get("_index")
        items.append(item)
    return items


def total_hits(response: dict[str, Any]) -> dict[str, Any]:
    """Report the hit count along with whether OpenSearch capped it."""
    total = response.get("hits", {}).get("total", {})
    if isinstance(total, dict):
        return {"value": total.get("value", 0), "relation": total.get("relation", "eq")}
    return {"value": total, "relation": "eq"}


def buckets_to_rows(
    aggregation: dict[str, Any], *, key_name: str = "key"
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for bucket in aggregation.get("buckets", []):
        row: dict[str, Any] = {key_name: bucket.get("key"), "count": bucket.get("doc_count")}
        for name, value in bucket.items():
            # Sub-aggregations come back as nested objects alongside the scalars.
            if name in {"key", "doc_count", "key_as_string"}:
                continue
            if isinstance(value, dict):
                if "buckets" in value:
                    row[name] = buckets_to_rows(value)
                elif "value" in value:
                    row[name] = value["value"]
        if "key_as_string" in bucket:
            row[key_name] = bucket["key_as_string"]
        rows.append(row)
    return rows
