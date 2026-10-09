from __future__ import annotations

import base64
import json
import time
from collections.abc import Callable
from typing import Any

import httpx2 as httpx
import pytest

from wazuh_mcp.api_client import WazuhAPIClient
from wazuh_mcp.config import Config, IndexerConfig, ServerApiConfig
from wazuh_mcp.indexer_client import WazuhIndexerClient
from wazuh_mcp.runtime import Runtime, set_runtime


def make_jwt(ttl: int = 900) -> str:
    """A structurally valid JWT so the client's expiry parsing has something to read."""
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": int(time.time()) + ttl, "sub": "wazuh"}).encode()
    ).decode().rstrip("=")
    return f"header.{payload}.signature"


class Recorder:
    """Captures every request a client makes, so tests can assert on the wire format."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def last(self) -> httpx.Request:
        assert self.requests, "no request was made"
        return self.requests[-1]

    def last_json(self) -> dict[str, Any]:
        return json.loads(self.last().content)


def mock_transport(
    handler: Callable[[httpx.Request], httpx.Response], recorder: Recorder
) -> httpx.MockTransport:
    def wrapped(request: httpx.Request) -> httpx.Response:
        recorder.requests.append(request)
        return handler(request)

    return httpx.MockTransport(wrapped)


@pytest.fixture
def api_config() -> ServerApiConfig:
    return ServerApiConfig(
        url="https://wazuh.test:55000", user="analyst", password="secret", verify_ssl=False
    )


@pytest.fixture
def indexer_config() -> IndexerConfig:
    return IndexerConfig(
        url="https://wazuh.test:9200", user="analyst", password="secret", verify_ssl=False
    )


@pytest.fixture
def recorder() -> Recorder:
    return Recorder()


@pytest.fixture
def api_client(api_config, recorder):
    """An API client whose transport is mocked but whose auth logic is real."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": make_jwt()}})
        return httpx.Response(
            200,
            json={
                "data": {"affected_items": [{"id": "001"}], "total_affected_items": 1,
                         "failed_items": []},
                "error": 0,
            },
        )

    client = WazuhAPIClient(api_config)
    client._client = httpx.AsyncClient(
        base_url=api_config.url, transport=mock_transport(handler, recorder)
    )
    return client


@pytest.fixture
def indexer_client(indexer_config, recorder):
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "hits": {"total": {"value": 3, "relation": "eq"}, "hits": []},
                "aggregations": {},
            },
        )

    client = WazuhIndexerClient(indexer_config)
    client._client = httpx.AsyncClient(
        base_url=indexer_config.url, transport=mock_transport(handler, recorder)
    )
    return client


@pytest.fixture
def runtime(api_client, indexer_client, api_config, indexer_config):
    config = Config(api=api_config, indexer=indexer_config, allow_active_response=True)
    rt = Runtime(config=config, api=api_client, indexer=indexer_client)
    set_runtime(rt)
    yield rt
    set_runtime(None)
