"""What matters here is the query that reaches OpenSearch, not the canned response."""

from __future__ import annotations

import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from wazuh_mcp.config import Config
from wazuh_mcp.runtime import Runtime, set_runtime
from wazuh_mcp.server import build_server


@pytest.fixture
def server(runtime, api_config, indexer_config):
    """A real server wired to the mocked clients from the runtime fixture."""
    return build_server(
        Config(api=api_config, indexer=indexer_config, allow_active_response=True)
    )


async def call(server, name: str, **arguments):
    result = await server.call_tool(name, arguments)
    assert not result.is_error, result.content
    return result


def filters(recorder) -> list[dict]:
    """The filter clauses of the last query; empty when nothing narrowed it."""
    query = recorder.last_json()["query"]
    return query.get("bool", {}).get("filter", [])


async def test_default_window_is_the_last_day(server, recorder):
    await call(server, "wazuh_search_alerts")
    assert {"range": {"timestamp": {"gte": "now-24h"}}} in filters(recorder)


async def test_bare_durations_become_date_math(server, recorder):
    await call(server, "wazuh_search_alerts", time_from="7d", time_to="1h")
    assert {"range": {"timestamp": {"gte": "now-7d", "lte": "now-1h"}}} in filters(recorder)


async def test_iso_timestamps_pass_through_untouched(server, recorder):
    await call(server, "wazuh_search_alerts", time_from="2026-01-01T00:00:00Z")
    assert {"range": {"timestamp": {"gte": "2026-01-01T00:00:00Z"}}} in filters(recorder)


async def test_null_time_from_searches_all_history(server, recorder):
    await call(server, "wazuh_search_alerts", time_from=None)
    assert recorder.last_json()["query"] == {"match_all": {}}


async def test_single_value_uses_term_and_many_use_terms(server, recorder):
    await call(server, "wazuh_search_alerts", rule_ids=["5710"])
    assert {"term": {"rule.id": "5710"}} in filters(recorder)

    await call(server, "wazuh_search_alerts", rule_ids=["5710", "5712"])
    assert {"terms": {"rule.id": ["5710", "5712"]}} in filters(recorder)


async def test_severity_bounds_become_one_range_clause(server, recorder):
    await call(server, "wazuh_search_alerts", min_level=7, max_level=12)
    assert {"range": {"rule.level": {"gte": 7, "lte": 12}}} in filters(recorder)


async def test_inactive_filters_leave_no_trace(server, recorder):
    await call(server, "wazuh_search_alerts", rule_ids=[], agent_ids=None, search="   ")
    clauses = filters(recorder)
    assert len(clauses) == 1, f"only the default time window should remain: {clauses}"


@pytest.mark.parametrize("as_json_string", [False, True])
async def test_extra_query_is_anded_with_the_named_filters(server, recorder, as_json_string):
    """Clients may send raw DSL either way; the SDK pre-parses JSON-looking strings."""
    raw = {"wildcard": {"data.win.eventdata.image": "*\\mimikatz.exe"}}
    await call(
        server,
        "wazuh_search_alerts",
        min_level=7,
        extra_query=json.dumps(raw) if as_json_string else raw,
    )
    clauses = filters(recorder)
    assert raw in clauses
    assert {"range": {"rule.level": {"gte": 7}}} in clauses


async def test_malformed_extra_query_is_rejected_with_a_readable_message(server):
    with pytest.raises(ToolError, match="not valid JSON"):
        await server.call_tool("wazuh_search_alerts", {"extra_query": "{not json"})


async def test_limit_is_clamped_to_the_context_budget(api_config, indexer_config,
                                                      api_client, indexer_client, recorder):
    config = Config(api=api_config, indexer=indexer_config, max_results=50)
    set_runtime(Runtime(config=config, api=api_client, indexer=indexer_client))
    try:
        server = build_server(config)
        await call(server, "wazuh_search_alerts", limit=100000)
        assert recorder.last_json()["size"] == 50
    finally:
        set_runtime(None)


async def test_sort_direction_follows_the_flag(server, recorder):
    await call(server, "wazuh_search_alerts", sort_desc=False)
    assert recorder.last_json()["sort"] == [{"timestamp": {"order": "asc"}}]


async def test_stats_aggregates_instead_of_returning_documents(server, recorder):
    await call(server, "wazuh_alert_stats", group_by="agent.name", top=5)
    body = recorder.last_json()
    assert body["size"] == 0, "an aggregation must not also page documents"
    assert body["aggs"]["grouped"]["terms"] == {
        "field": "agent.name", "size": 5, "order": {"_count": "desc"}
    }


async def test_stats_carries_severity_context_per_bucket(server, recorder):
    """A bucket's count alone cannot distinguish noise from a real finding."""
    await call(server, "wazuh_alert_stats")
    sub_aggs = recorder.last_json()["aggs"]["grouped"]["aggs"]
    assert "max_level" in sub_aggs
    assert "agents" in sub_aggs


async def test_secondary_grouping_nests_inside_the_primary(server, recorder):
    await call(server, "wazuh_alert_stats", group_by="agent.name",
               secondary_group_by="rule.description")
    sub_aggs = recorder.last_json()["aggs"]["grouped"]["aggs"]
    assert sub_aggs["breakdown"]["terms"]["field"] == "rule.description"


async def test_sub_day_intervals_use_fixed_and_months_use_calendar(server, recorder):
    await call(server, "wazuh_alert_timeline", interval="15m")
    assert "fixed_interval" in recorder.last_json()["aggs"]["over_time"]["date_histogram"]

    await call(server, "wazuh_alert_timeline", interval="1M")
    assert "calendar_interval" in recorder.last_json()["aggs"]["over_time"]["date_histogram"]


async def test_nonsense_interval_is_rejected(server):
    with pytest.raises(ToolError, match="date math"):
        await server.call_tool("wazuh_alert_timeline", {"interval": "fortnight"})


async def test_raw_query_requires_a_search_body_not_a_bare_clause(server):
    """A bare clause would silently match everything; say what was expected instead."""
    with pytest.raises(ToolError, match="_search request body"):
        await server.call_tool("wazuh_indexer_query", {"body": {"term": {"rule.id": "5710"}}})


async def test_raw_query_accepts_an_aggregation_only_body(server, recorder):
    body = {"aggs": {"levels": {"terms": {"field": "rule.level"}}}, "size": 0}
    await call(server, "wazuh_indexer_query", body=json.dumps(body))
    assert recorder.last_json()["size"] == 0


async def test_indexer_tools_explain_themselves_when_it_is_not_configured(
    api_config, api_client
):
    config = Config(api=api_config, indexer=None)
    set_runtime(Runtime(config=config, api=api_client, indexer=None))
    try:
        server = build_server(config)
        with pytest.raises(ToolError, match="WAZUH_INDEXER_URL"):
            await server.call_tool("wazuh_search_alerts", {})
    finally:
        set_runtime(None)


async def test_agent_ids_are_padded_for_the_indexer_too(server, recorder):
    """agent.id is a keyword field: an unpadded "1" matches nothing, silently.

    The Server API tolerates an unpadded ID, so without this the same argument
    would resolve a host through wazuh_get_agent and return zero alerts through
    wazuh_search_alerts — a blind spot that reads as "this host is quiet".
    """
    await call(server, "wazuh_search_alerts", agent_ids=["1", "web-01"])
    assert {"terms": {"agent.id": ["001", "web-01"]}} in filters(recorder)


async def test_vulnerability_agent_ids_are_padded(server, recorder):
    await call(server, "wazuh_list_vulnerabilities", agent_ids=["7"])
    assert {"term": {"agent.id": "007"}} in filters(recorder)
