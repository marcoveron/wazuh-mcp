"""These tools reach production hosts, so the guardrails are the behaviour under test."""

from __future__ import annotations

import httpx2 as httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from wazuh_mcp.api_client import WazuhAPIClient
from wazuh_mcp.config import Config
from wazuh_mcp.indexer_client import WazuhIndexerClient
from wazuh_mcp.runtime import Runtime, set_runtime
from wazuh_mcp.server import build_server

from .conftest import make_jwt, mock_transport


def build(api_config, indexer_config, api_client, indexer_client, **overrides):
    config = Config(
        api=api_config, indexer=indexer_config, allow_active_response=True, **overrides
    )
    set_runtime(Runtime(config=config, api=api_client, indexer=indexer_client))
    return build_server(config)


@pytest.fixture
def server(api_config, indexer_config, api_client, indexer_client):
    yield build(api_config, indexer_config, api_client, indexer_client)
    set_runtime(None)


async def test_not_registered_when_the_deployment_disables_it(api_config, indexer_config):
    """A read-only deployment should not even advertise the write tools."""
    config = Config(api=api_config, indexer=indexer_config, allow_active_response=False)
    tools = {t.name: t for t in await build_server(config).list_tools()}
    assert "wazuh_active_response" not in tools
    assert "wazuh_restart_agents" not in tools
    # Listing commands is read-only, so a triage agent can still propose one.
    assert tools["wazuh_active_response_commands"].annotations.read_only_hint is True


async def test_registered_and_marked_destructive_when_enabled(server):
    tools = {t.name: t for t in await server.list_tools()}
    for name in ("wazuh_active_response", "wazuh_restart_agents"):
        assert tools[name].annotations.destructive_hint is True
        assert tools[name].annotations.read_only_hint is False


async def test_targets_the_named_agents_with_padded_ids(server, recorder):
    await server.call_tool(
        "wazuh_active_response",
        {"command": "firewall-drop", "agent_ids": ["1", "004"],
         "arguments": ["203.0.113.10"]},
    )
    request = recorder.last()
    assert request.method == "PUT"
    assert request.url.path == "/active-response"
    assert request.url.params["agents_list"] == "001,004"
    assert recorder.last_json() == {
        "command": "firewall-drop", "arguments": ["203.0.113.10"]
    }


async def test_fleet_wide_action_needs_explicit_confirmation(server, recorder):
    """A firewall-drop against every agent is an outage, not a query."""
    before = len(recorder.requests)
    with pytest.raises(ToolError, match="confirm_all_agents"):
        await server.call_tool(
            "wazuh_active_response",
            {"command": "firewall-drop", "agent_ids": ["*"], "arguments": ["10.0.0.5"]},
        )
    assert len(recorder.requests) == before, "nothing should have been sent"


async def test_fleet_wide_action_proceeds_once_confirmed(server, recorder):
    await server.call_tool(
        "wazuh_active_response",
        {"command": "firewall-drop", "agent_ids": ["all"], "arguments": ["10.0.0.5"],
         "confirm_all_agents": True},
    )
    assert recorder.last().url.params["agents_list"] == "*"


async def test_empty_agent_list_is_refused(server):
    with pytest.raises(ToolError, match="agent_ids is empty"):
        await server.call_tool(
            "wazuh_active_response", {"command": "firewall-drop", "agent_ids": []}
        )


async def test_allowlist_blocks_commands_it_does_not_name(
    api_config, indexer_config, api_client, indexer_client
):
    server = build(
        api_config, indexer_config, api_client, indexer_client,
        active_response_allowlist=frozenset({"firewall-drop"}),
    )
    try:
        with pytest.raises(ToolError, match="not in the allowlist"):
            await server.call_tool(
                "wazuh_active_response",
                {"command": "disable-account", "agent_ids": ["001"]},
            )
        # The "!" prefix only changes script resolution, so it must still pass.
        await server.call_tool(
            "wazuh_active_response", {"command": "!firewall-drop", "agent_ids": ["001"]}
        )
    finally:
        set_runtime(None)


async def test_restart_hits_the_agent_restart_endpoint(server, recorder):
    await server.call_tool("wazuh_restart_agents", {"agent_ids": ["7"]})
    request = recorder.last()
    assert request.method == "PUT"
    assert request.url.path == "/agents/restart"
    assert request.url.params["agents_list"] == "007"


async def test_restart_also_guards_the_whole_fleet(server):
    with pytest.raises(ToolError, match="confirm_all_agents"):
        await server.call_tool("wazuh_restart_agents", {"agent_ids": ["*"]})


def _config_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/security/user/authenticate":
        return httpx.Response(200, json={"data": {"token": make_jwt()}})
    return httpx.Response(
        200,
        json={
            "data": {
                "affected_items": [
                    {
                        "command": [
                            {"name": "firewall-drop", "executable": "firewall-drop.sh",
                             "timeout_allowed": "yes"},
                            {"name": "disable-account", "executable": "disable-account.sh",
                             "timeout_allowed": "no"},
                        ]
                    }
                ],
                "total_affected_items": 1,
            },
            "error": 0,
        },
    )


async def test_lists_the_manager_s_configured_commands(api_config, indexer_config, recorder):
    client = WazuhAPIClient(api_config)
    client._client = httpx.AsyncClient(
        base_url=api_config.url, transport=mock_transport(_config_handler, recorder)
    )
    server = build(api_config, indexer_config, client, WazuhIndexerClient(indexer_config))
    try:
        result = await server.call_tool("wazuh_active_response_commands", {})
        assert recorder.last().url.path == "/manager/configuration"
        assert recorder.last().url.params["section"] == "command"
        names = {item["name"] for item in result.structured_content["items"]}
        assert names == {"firewall-drop", "disable-account"}
    finally:
        set_runtime(None)


async def test_flags_commands_the_allowlist_permits(api_config, indexer_config, recorder):
    client = WazuhAPIClient(api_config)
    client._client = httpx.AsyncClient(
        base_url=api_config.url, transport=mock_transport(_config_handler, recorder)
    )
    server = build(
        api_config, indexer_config, client, WazuhIndexerClient(indexer_config),
        active_response_allowlist=frozenset({"firewall-drop"}),
    )
    try:
        result = await server.call_tool("wazuh_active_response_commands", {})
        by_name = {item["name"]: item["allowed"] for item in result.structured_content["items"]}
        assert by_name == {"firewall-drop": True, "disable-account": False}
        assert result.structured_content["context"]["allowlist"] == ["firewall-drop"]
    finally:
        set_runtime(None)
