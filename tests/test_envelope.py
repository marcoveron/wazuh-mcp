"""The response contract: every tool answers in the same shape.

This is the test that keeps the server linkable. An agent framework consuming it
reads `items`, `total` and `source` without knowing which tool it called, so a
new tool that invents its own key names is a regression even when it works.
"""

from __future__ import annotations

import httpx2 as httpx
import pytest

from wazuh_mcp.api_client import WazuhAPIClient
from wazuh_mcp.config import Config
from wazuh_mcp.indexer_client import WazuhIndexerClient
from wazuh_mcp.runtime import Runtime, set_runtime
from wazuh_mcp.server import build_server

from .conftest import Recorder, make_jwt, mock_transport

# Minimal arguments per tool, so every registered tool can actually be invoked.
REQUIRED_ARGUMENTS: dict[str, dict] = {
    "wazuh_get_agent": {"agent_id": "001"},
    "wazuh_agent_processes": {"agent_id": "001"},
    "wazuh_agent_ports": {"agent_id": "001"},
    "wazuh_agent_packages": {"agent_id": "001"},
    "wazuh_fim_findings": {"agent_id": "001"},
    "wazuh_sca_policies": {"agent_id": "001"},
    "wazuh_sca_checks": {"agent_id": "001", "policy_id": "cis_debian10"},
    "wazuh_rootcheck_findings": {"agent_id": "001"},
    "wazuh_get_rule_file": {"filename": "0095-sshd_rules.xml"},
    "wazuh_indexer_query": {"body": {"query": {"match_all": {}}}},
    "wazuh_active_response": {"command": "firewall-drop", "agent_ids": ["001"]},
    "wazuh_restart_agents": {"agent_ids": ["001"]},
}


@pytest.fixture
def config(api_config, indexer_config):
    return Config(api=api_config, indexer=indexer_config, allow_active_response=True)


@pytest.fixture
def server(config, api_client, indexer_client):
    set_runtime(Runtime(config=config, api=api_client, indexer=indexer_client))
    yield build_server(config)
    set_runtime(None)


async def test_every_tool_returns_the_same_envelope(server):
    tools = await server.list_tools()
    assert len(tools) >= 20, "tool registration regressed"

    for tool in tools:
        result = await server.call_tool(tool.name, REQUIRED_ARGUMENTS.get(tool.name, {}))
        assert not result.is_error, f"{tool.name}: {result.content}"
        payload = result.structured_content

        missing = {"items", "returned", "total", "total_is_exact", "source", "context"} - set(
            payload
        )
        assert not missing, f"{tool.name} is missing {sorted(missing)}"
        assert isinstance(payload["items"], list), f"{tool.name} items is not a list"
        assert payload["returned"] == len(payload["items"]), f"{tool.name} miscounts returned"
        assert isinstance(payload["total"], int), f"{tool.name} total is not an int"
        assert isinstance(payload["total_is_exact"], bool), f"{tool.name} total_is_exact"
        assert payload["source"] in {"api", "indexer", "mixed"}, f"{tool.name} source"
        assert isinstance(payload["context"], dict), f"{tool.name} context is not a dict"
        for item in payload["items"]:
            assert isinstance(item, dict), f"{tool.name} yielded a bare {type(item).__name__}"


async def test_capped_indexer_counts_are_flagged_as_inexact(config, api_client, indexer_config):
    """OpenSearch stops counting at 10k; reporting that as exact invents certainty."""

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"hits": {"total": {"value": 10000, "relation": "gte"}, "hits": []}}
        )

    indexer = WazuhIndexerClient(indexer_config)
    indexer._client = httpx.AsyncClient(
        base_url=indexer_config.url, transport=mock_transport(handler, Recorder())
    )
    set_runtime(Runtime(config=config, api=api_client, indexer=indexer))
    try:
        result = await build_server(config).call_tool("wazuh_search_alerts", {})
        assert result.structured_content["total"] == 10000
        assert result.structured_content["total_is_exact"] is False
    finally:
        set_runtime(None)


async def test_server_api_counts_are_exact(server):
    result = await server.call_tool("wazuh_list_agents", {})
    assert result.structured_content["total_is_exact"] is True
    assert result.structured_content["source"] == "api"


async def test_raw_rule_files_survive_being_xml(api_config, indexer_client, recorder):
    """`raw=true` answers with XML; decoding it as JSON is how this used to fail."""
    xml = '<group name="syslog,sshd,"><rule id="5710" level="5"></rule></group>'

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": make_jwt()}})
        return httpx.Response(200, text=xml, headers={"Content-Type": "application/xml"})

    client = WazuhAPIClient(api_config)
    client._client = httpx.AsyncClient(
        base_url=api_config.url, transport=mock_transport(handler, recorder)
    )
    config = Config(api=api_config, indexer=indexer_client.config)
    set_runtime(Runtime(config=config, api=client, indexer=indexer_client))
    try:
        result = await build_server(config).call_tool(
            "wazuh_get_rule_file", {"filename": "0095-sshd_rules.xml"}
        )
        assert not result.is_error, result.content
        assert result.structured_content["items"][0]["content"] == xml
        assert recorder.last().url.params["raw"] == "true"
    finally:
        set_runtime(None)
