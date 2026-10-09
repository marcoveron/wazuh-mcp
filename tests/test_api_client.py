"""The JWT lifecycle is the part of the API client most likely to break silently."""

from __future__ import annotations

import httpx2 as httpx
import pytest

from wazuh_mcp.api_client import WazuhAPIClient
from wazuh_mcp.errors import WazuhAuthError, WazuhError

from .conftest import Recorder, make_jwt, mock_transport


async def test_authenticates_once_and_reuses_the_token(api_client, recorder):
    await api_client.get("/agents")
    await api_client.get("/rules")

    paths = [r.url.path for r in recorder.requests]
    assert paths.count("/security/user/authenticate") == 1
    assert paths == ["/security/user/authenticate", "/agents", "/rules"]
    assert recorder.last().headers["Authorization"].startswith("Bearer ")


async def test_reauthenticates_when_the_manager_revokes_the_token(api_config, recorder):
    """Wazuh can invalidate a token before its `exp`; one silent retry recovers."""
    state = {"rejections": 1}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": make_jwt()}})
        if state["rejections"]:
            state["rejections"] -= 1
            return httpx.Response(401, json={"title": "Unauthorized"})
        return httpx.Response(200, json={"data": {"affected_items": [], "total_affected_items": 0}})

    client = WazuhAPIClient(api_config)
    client._client = httpx.AsyncClient(
        base_url=api_config.url, transport=mock_transport(handler, recorder)
    )

    result = await client.get_items("/agents")

    assert result["total"] == 0
    paths = [r.url.path for r in recorder.requests]
    assert paths.count("/security/user/authenticate") == 2, "should re-auth after the 401"
    assert paths.count("/agents") == 2, "should retry the original call once"


async def test_a_second_401_is_not_retried_forever(api_config, recorder):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": make_jwt()}})
        return httpx.Response(401, json={"title": "Unauthorized"})

    client = WazuhAPIClient(api_config)
    client._client = httpx.AsyncClient(
        base_url=api_config.url, transport=mock_transport(handler, recorder)
    )

    with pytest.raises(WazuhError):
        await client.get("/agents")
    assert [r.url.path for r in recorder.requests].count("/agents") == 2


async def test_bad_credentials_say_which_variables_to_fix(api_config, recorder):
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"title": "Invalid credentials"})

    client = WazuhAPIClient(api_config)
    client._client = httpx.AsyncClient(
        base_url=api_config.url, transport=mock_transport(handler, recorder)
    )

    with pytest.raises(WazuhAuthError, match="WAZUH_API_USER"):
        await client.get("/agents")


async def test_403_points_at_rbac_rather_than_credentials(api_config, recorder):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": make_jwt()}})
        return httpx.Response(403, json={"title": "Permission denied"})

    client = WazuhAPIClient(api_config)
    client._client = httpx.AsyncClient(
        base_url=api_config.url, transport=mock_transport(handler, recorder)
    )

    with pytest.raises(WazuhAuthError, match="RBAC"):
        await client.get("/agents")


async def test_none_valued_params_are_dropped(api_client, recorder):
    """Unset tool arguments must not become `?group=None` on the wire."""
    await api_client.get("/agents", status="active", group=None, limit=10)

    query = recorder.last().url.params
    assert "group" not in query
    assert query["status"] == "active"
    assert query["limit"] == "10"


async def test_affected_items_envelope_is_unwrapped(api_client):
    result = await api_client.get_items("/agents")
    assert result == {"items": [{"id": "001"}], "total": 1}


async def test_failure_with_no_successes_is_raised(api_config, recorder):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": make_jwt()}})
        return httpx.Response(
            200,
            json={
                "data": {
                    "affected_items": [],
                    "total_affected_items": 0,
                    "failed_items": [{"error": {"message": "Agent does not exist"}}],
                }
            },
        )

    client = WazuhAPIClient(api_config)
    client._client = httpx.AsyncClient(
        base_url=api_config.url, transport=mock_transport(handler, recorder)
    )

    with pytest.raises(WazuhError, match="Agent does not exist"):
        await client.get_items("/agents")


async def test_unreachable_manager_mentions_the_ssl_setting(api_config):
    """Self-signed certificates are the usual first-run failure; say so."""

    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("certificate verify failed")

    client = WazuhAPIClient(api_config)
    client._client = httpx.AsyncClient(
        base_url=api_config.url, transport=mock_transport(handler, Recorder())
    )

    with pytest.raises(WazuhError, match="WAZUH_VERIFY_SSL"):
        await client.get("/agents")
