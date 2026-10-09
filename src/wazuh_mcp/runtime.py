"""Process-wide handles to the Wazuh clients.

Tools reach for these instead of taking them as arguments, so every tool stays a
plain function with an LLM-friendly signature. `lifespan()` owns the lifecycle.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from .api_client import WazuhAPIClient
from .config import Config
from .errors import WazuhNotConfigured
from .indexer_client import WazuhIndexerClient


@dataclass(slots=True)
class Runtime:
    config: Config
    api: WazuhAPIClient
    indexer: WazuhIndexerClient | None

    def require_indexer(self) -> WazuhIndexerClient:
        if self.indexer is None:
            raise WazuhNotConfigured(
                "This tool queries the Wazuh Indexer, which is not configured. "
                "Set WAZUH_INDEXER_URL (and WAZUH_INDEXER_USER / "
                "WAZUH_INDEXER_PASSWORD if they differ from the API credentials)."
            )
        return self.indexer

    def clamp(self, limit: int) -> int:
        """Keep any single tool result inside the configured context budget."""
        return max(1, min(int(limit), self.config.max_results))


_runtime: Runtime | None = None


def get_runtime() -> Runtime:
    if _runtime is None:
        raise RuntimeError(
            "Wazuh runtime is not initialised; the server lifespan did not run."
        )
    return _runtime


def set_runtime(runtime: Runtime | None) -> None:
    global _runtime
    _runtime = runtime


@asynccontextmanager
async def lifespan(config: Config) -> AsyncIterator[Runtime]:
    api = WazuhAPIClient(config.api)
    indexer = WazuhIndexerClient(config.indexer) if config.indexer else None
    runtime = Runtime(config=config, api=api, indexer=indexer)
    set_runtime(runtime)
    try:
        yield runtime
    finally:
        set_runtime(None)
        await api.aclose()
        if indexer is not None:
            await indexer.aclose()
