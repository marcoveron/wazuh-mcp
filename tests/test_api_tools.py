"""Server API tools: the endpoint and query string are the contract."""

from __future__ import annotations

import httpx2 as httpx
import pytest

from wazuh_mcp.api_client import WazuhAPIClient
from wazuh_mcp.config import Config
from wazuh_mcp.runtime import Runtime, set_runtime
from wazuh_mcp.server import build_server

from .conftest import make_jwt, mock_transport


@pytest.fixture
def server(runtime, api_config, indexer_config):
    return build_server(Config(api=api_config, indexer=indexer_config))


async def call(server, name, **arguments):
    result = await server.call_tool(name, arguments)
    assert not result.is_error, result.content
    return result


def component(result, name):
    """Pull one component row out of wazuh_health's envelope."""
    for item in result.structured_content["items"]:
        if item["component"] == name:
            return item
    raise AssertionError(f"{name} missing from {result.structured_content['items']}")


async def test_agent_ids_are_zero_padded_for_wazuh(server, recorder):
    """Wazuh keys agents by "001"; a model will reach for 1."""
    await call(server, "wazuh_get_agent", agent_id="1")
    assert recorder.last().url.params["agents_list"] == "001"


async def test_non_numeric_agent_identifiers_are_left_alone(server, recorder):
    await call(server, "wazuh_get_agent", agent_id="web-01")
    assert recorder.last().url.params["agents_list"] == "web-01"


async def test_agent_listing_selects_a_compact_field_set(server, recorder):
    """Fetching whole agent records would spend context on configuration noise."""
    await call(server, "wazuh_list_agents", status=["active", "pending"])
    params = recorder.last().url.params
    assert params["status"] == "active,pending"
    assert "lastKeepAlive" in params["select"]
    assert "mergedSum" not in params.get("select", "")


async def test_os_platform_reaches_wazuh_under_its_dotted_name(server, recorder):
    await call(server, "wazuh_list_agents", os_platform="windows")
    assert recorder.last().url.params["os.platform"] == "windows"


async def test_agent_summary_gathers_status_os_and_groups(server, recorder):
    await call(server, "wazuh_agent_summary")
    paths = [r.url.path for r in recorder.requests]
    assert "/agents/summary/status" in paths
    assert "/agents/summary/os" in paths
    assert "/groups" in paths


async def test_fim_lookup_by_hash_uses_the_hash_parameter(server, recorder):
    """Checking a known-bad hash against a host is the common FIM question."""
    await call(server, "wazuh_fim_findings", agent_id="2", hash_value="d41d8cd98f00b204e980")
    request = recorder.last()
    assert request.url.path == "/syscheck/002"
    assert request.url.params["hash"] == "d41d8cd98f00b204e980"


async def test_sca_checks_default_to_the_failures(server, recorder):
    await call(server, "wazuh_sca_checks", agent_id="001", policy_id="cis_debian10")
    request = recorder.last()
    assert request.url.path == "/sca/001/checks/cis_debian10"
    assert request.url.params["result"] == "failed"
    assert "remediation" in request.url.params["select"]


async def test_sca_checks_can_be_widened_to_everything(server, recorder):
    await call(server, "wazuh_sca_checks", agent_id="001", policy_id="cis_debian10",
               result_filter=None)
    assert "result" not in recorder.last().url.params


async def test_rule_ids_are_sent_as_a_comma_list(server, recorder):
    await call(server, "wazuh_get_rules", rule_ids=["5710", "5712"])
    assert recorder.last().url.params["rule_ids"] == "5710,5712"


async def test_manager_logs_come_back_newest_first(server, recorder):
    await call(server, "wazuh_manager_logs", level="error")
    params = recorder.last().url.params
    assert params["level"] == "error"
    assert params["sort"] == "-timestamp"


async def test_health_reports_stopped_daemons_as_unhealthy(api_config, indexer_client, recorder):
    """The whole point of the tool: silence from a stopped analysisd is not calm."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": make_jwt()}})
        if path == "/manager/status":
            items = [{"wazuh-analysisd": "stopped", "wazuh-remoted": "running"}]
        elif path == "/manager/info":
            items = [{"version": "v4.9.0", "node_name": "master", "type": "manager"}]
        elif path == "/cluster/status":
            return httpx.Response(200, json={"data": {"enabled": "no", "running": "no"}})
        else:
            items = []
        return httpx.Response(
            200, json={"data": {"affected_items": items, "total_affected_items": len(items)}}
        )

    client = WazuhAPIClient(api_config)
    client._client = httpx.AsyncClient(
        base_url=api_config.url, transport=mock_transport(handler, recorder)
    )
    config = Config(api=api_config, indexer=indexer_client.config)
    set_runtime(Runtime(config=config, api=client, indexer=indexer_client))
    try:
        server = build_server(config)
        result = await call(server, "wazuh_health")
        manager = component(result, "manager")
        assert manager["healthy"] is False
        assert manager["stopped_daemons"] == ["wazuh-analysisd"]
        assert manager["version"] == "v4.9.0"
        assert result.structured_content["context"]["healthy"] is False
    finally:
        set_runtime(None)


async def test_standalone_manager_is_not_reported_as_a_cluster_failure(
    api_config, indexer_client, recorder
):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": make_jwt()}})
        if path == "/cluster/status":
            return httpx.Response(200, json={"data": {"enabled": "no", "running": "no"}})
        return httpx.Response(
            200, json={"data": {"affected_items": [{}], "total_affected_items": 1}}
        )

    client = WazuhAPIClient(api_config)
    client._client = httpx.AsyncClient(
        base_url=api_config.url, transport=mock_transport(handler, recorder)
    )
    config = Config(api=api_config, indexer=indexer_client.config)
    set_runtime(Runtime(config=config, api=client, indexer=indexer_client))
    try:
        result = await call(build_server(config), "wazuh_health")
        assert component(result, "cluster") == {
            "component": "cluster", "healthy": True, "enabled": False, "mode": "standalone"
        }
    finally:
        set_runtime(None)


async def test_an_unreachable_indexer_does_not_sink_the_whole_health_check(
    api_config, indexer_config, api_client, recorder
):
    """Health has to keep reporting the manager even when the indexer is down."""
    from wazuh_mcp.indexer_client import WazuhIndexerClient

    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    indexer = WazuhIndexerClient(indexer_config)
    indexer._client = httpx.AsyncClient(
        base_url=indexer_config.url, transport=mock_transport(handler, recorder)
    )
    config = Config(api=api_config, indexer=indexer_config)
    set_runtime(Runtime(config=config, api=api_client, indexer=indexer))
    try:
        result = await call(build_server(config), "wazuh_health")
        assert component(result, "indexer")["reachable"] is False
        assert component(result, "manager") is not None
        # One dead component must not be reported as a healthy stack.
        assert result.structured_content["context"]["healthy"] is False
    finally:
        set_runtime(None)
