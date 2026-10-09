"""Async client for the Wazuh Indexer (OpenSearch, default :9200).

This is where alerts and vulnerability state actually live. The Server API knows
about agents and configuration; anything historical — hunting, triage, trend
analysis — has to come from here.
"""

from __future__ import annotations

from typing import Any

import httpx2 as httpx

from .config import IndexerConfig
from .errors import WazuhAuthError, WazuhError


class WazuhIndexerClient:
    def __init__(self, config: IndexerConfig) -> None:
        self._config = config
        self._client = httpx.AsyncClient(
            base_url=config.url,
            verify=config.ca_bundle or config.verify_ssl,
            timeout=config.timeout,
            follow_redirects=True,
            auth=(config.user, config.password),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )

    @property
    def config(self) -> IndexerConfig:
        return self._config

    async def aclose(self) -> None:
        await self._client.aclose()

    async def search(
        self,
        index: str,
        body: dict[str, Any],
        *,
        track_total: bool | int = True,
    ) -> dict[str, Any]:
        """Run a `_search` against an index pattern and return the raw response."""
        params: dict[str, Any] = {
            # A missing index pattern means "nothing indexed yet", not an error we
            # want the model to trip over mid-investigation.
            "ignore_unavailable": "true",
            "allow_no_indices": "true",
            "track_total_hits": "true" if track_total is True else str(track_total).lower(),
        }
        return await self._post(f"/{index}/_search", body, params)

    async def count(self, index: str, query: dict[str, Any]) -> int:
        body = await self._post(
            f"/{index}/_count",
            {"query": query},
            {"ignore_unavailable": "true", "allow_no_indices": "true"},
        )
        return int(body.get("count", 0))

    async def cluster_health(self) -> dict[str, Any]:
        return await self._get("/_cluster/health")

    async def indices(self, pattern: str) -> list[dict[str, Any]]:
        body = await self._get(
            f"/_cat/indices/{pattern}",
            {"format": "json", "h": "index,health,status,docs.count,store.size", "s": "index"},
        )
        return body if isinstance(body, list) else []

    # ----------------------------------------------------------- internals

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        try:
            response = await self._client.get(path, params=params)
        except httpx.RequestError as exc:
            raise WazuhError(
                f"Cannot reach the Wazuh Indexer at {self._config.url}: {exc}. "
                "Check WAZUH_INDEXER_URL and WAZUH_INDEXER_VERIFY_SSL."
            ) from exc
        return _decode(response, "GET", path)

    async def _post(
        self, path: str, body: dict[str, Any], params: dict[str, Any] | None = None
    ) -> Any:
        try:
            response = await self._client.post(path, json=body, params=params)
        except httpx.RequestError as exc:
            raise WazuhError(
                f"Cannot reach the Wazuh Indexer at {self._config.url}: {exc}. "
                "Check WAZUH_INDEXER_URL and WAZUH_INDEXER_VERIFY_SSL."
            ) from exc
        return _decode(response, "POST", path)


def _decode(response: httpx.Response, method: str, path: str) -> Any:
    if response.status_code in (401, 403):
        raise WazuhAuthError(
            f"Wazuh Indexer rejected {method} {path} (HTTP {response.status_code}). "
            "Check WAZUH_INDEXER_USER / WAZUH_INDEXER_PASSWORD and the role's "
            "index permissions."
        )
    if response.status_code >= 400:
        raise WazuhError(
            f"Wazuh Indexer {method} {path} returned HTTP {response.status_code}: "
            f"{_short_body(response)}"
        )
    try:
        return response.json()
    except ValueError as exc:
        raise WazuhError(
            f"Wazuh Indexer {method} {path} returned a non-JSON body: {_short_body(response)}"
        ) from exc


def _short_body(response: httpx.Response, limit: int = 400) -> str:
    text = response.text.strip().replace("\n", " ")
    return text[:limit] + ("…" if len(text) > limit else "")
