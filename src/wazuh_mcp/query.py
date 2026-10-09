"""Helpers that turn SOC-shaped filters into backend queries.

Mostly OpenSearch query DSL, plus the agent-ID normalisation both backends
need — it lives here so the Server API path and the Indexer path cannot
drift apart on what "agent 1" means.
"""

from __future__ import annotations

import re
from typing import Any

from .errors import WazuhError

_RELATIVE = re.compile(r"^\d+[smhdwMy]$")


def pad_agent_id(agent_id: str | int) -> str:
    """Wazuh keys agents by zero-padded string IDs; models tend to pass ints.

    This has to be applied on both backends. The Server API will happily
    resolve an unpadded ID, but `agent.id` in the indexer is a keyword field:
    a term query for "1" matches nothing at all, so an unpadded ID would
    return an empty result set rather than an error — silence that reads as
    "no alerts on that host".
    """
    text = str(agent_id).strip()
    return text.zfill(3) if text.isdigit() else text


def pad_agent_ids(agent_ids: list[str] | None) -> list[str] | None:
    if not agent_ids:
        return None
    return [pad_agent_id(a) for a in agent_ids]


def normalize_time(value: str | None, *, default: str | None = None) -> str | None:
    """Accept `24h`, `now-24h`, `now/d` or an ISO-8601 timestamp.

    Bare durations are the form a model reaches for first, so we translate them
    into the date-math OpenSearch actually understands instead of failing.
    """
    raw = (value or default or "").strip()
    if not raw:
        return None
    if _RELATIVE.match(raw):
        return f"now-{raw}"
    if raw.startswith("-") and _RELATIVE.match(raw[1:]):
        return f"now{raw}"
    return raw


def time_range(
    field: str, time_from: str | None, time_to: str | None
) -> dict[str, Any] | None:
    bounds: dict[str, Any] = {}
    start = normalize_time(time_from)
    end = normalize_time(time_to)
    if start:
        bounds["gte"] = start
    if end:
        bounds["lte"] = end
    if not bounds:
        return None
    return {"range": {field: bounds}}


def terms_clause(field: str, values: list[str] | None) -> dict[str, Any] | None:
    cleaned = [str(v).strip() for v in (values or []) if str(v).strip()]
    if not cleaned:
        return None
    if len(cleaned) == 1:
        return {"term": {field: cleaned[0]}}
    return {"terms": {field: cleaned}}


def range_clause(
    field: str, minimum: float | None = None, maximum: float | None = None
) -> dict[str, Any] | None:
    bounds: dict[str, Any] = {}
    if minimum is not None:
        bounds["gte"] = minimum
    if maximum is not None:
        bounds["lte"] = maximum
    if not bounds:
        return None
    return {"range": {field: bounds}}


def query_string_clause(search: str | None, fields: list[str] | None = None) -> dict[str, Any] | None:
    """Free-text Lucene search, kept lenient so a bad field name narrows rather than errors."""
    if not search or not search.strip():
        return None
    clause: dict[str, Any] = {
        "query_string": {
            "query": search.strip(),
            "default_operator": "AND",
            "lenient": True,
        }
    }
    if fields:
        clause["query_string"]["fields"] = fields
    return clause


def bool_query(
    must: list[dict[str, Any] | None] | None = None,
    must_not: list[dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """Assemble a bool query, dropping the `None`s that inactive filters produce."""
    filters = [clause for clause in (must or []) if clause]
    excludes = [clause for clause in (must_not or []) if clause]
    if not filters and not excludes:
        return {"match_all": {}}
    query: dict[str, Any] = {"bool": {}}
    if filters:
        query["bool"]["filter"] = filters
    if excludes:
        query["bool"]["must_not"] = excludes
    return query


def parse_extra_query(raw: dict[str, Any] | str | None) -> dict[str, Any] | None:
    """Accept a raw DSL fragment either as an object or a JSON string."""
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw or None
    text = raw.strip()
    if not text:
        return None
    import json

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise WazuhError(f"extra_query is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise WazuhError("extra_query must be a JSON object, e.g. {\"term\": {...}}")
    return parsed or None
