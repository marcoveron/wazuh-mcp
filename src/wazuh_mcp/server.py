"""MCP server exposing a Wazuh deployment to a model."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator

from mcp.server import MCPServer

from . import prompts, resources
from .config import Config
from .runtime import Runtime
from .runtime import lifespan as wazuh_lifespan
from .tools import register_all

INSTRUCTIONS = """Query and operate a Wazuh SIEM/XDR deployment.

Two backends sit behind these tools, and picking the right one matters:
  - The Wazuh Server API holds current state: agents, rules, decoders, file
    integrity, configuration assessment, manager health.
  - The Wazuh Indexer holds history: alerts and open vulnerabilities. Anything
    time-based comes from here.

Every tool answers in the same envelope, so results can be read without knowing
which tool produced them:

  {"items": [...], "returned": 12, "total": 4231, "total_is_exact": false,
   "source": "indexer", "context": {"index": "wazuh-alerts-*"}}

  - `items` are the rows; `returned` is how many came back and `total` how many
    matched on the backend. When they differ, narrow the filters or page.
  - `total_is_exact` is false when the Indexer stopped counting (it caps at
    10,000 by default). Report such a figure as "at least N", never as exact.
  - For the aggregation tools `items` are buckets while `total` still counts the
    documents aggregated over, so the two are deliberately different units.
  - `context` carries per-tool detail: the index searched, the agent, the
    grouping field, and `failed_items` when part of a request did not apply.

Working effectively:
  - Aggregate before you page. wazuh_alert_stats answers "what is happening" in
    one call; pulling hundreds of alert documents to count them wastes context
    and misses the tail.
  - Alert volume is meaningless without wazuh_health. Stopped daemons and dropped
    events look exactly like a quiet network.
  - Rule severity runs 0-15. Level 7+ is worth attention, 12+ usually demands it.
    Filtering on min_level is the single most effective way to cut noise.
  - Read the rule before judging the alert: wazuh_get_rules explains what a
    detection actually asserts.
  - Compare against a baseline. A rule firing 500 times today means one thing if
    it fired 500 times yesterday and another if it never fired before.

Active Response tools change production hosts and are only present when the
deployment enables them. Confirm the target and blast radius before calling one."""


def build_server(config: Config | None = None) -> MCPServer:
    """Construct the server. Config is read from the environment unless supplied."""
    settings = config or Config.from_env()

    @contextlib.asynccontextmanager
    async def _lifespan(_: MCPServer) -> AsyncIterator[Runtime]:
        async with wazuh_lifespan(settings) as runtime:
            yield runtime

    mcp = MCPServer(
        name="wazuh",
        title="Wazuh SIEM",
        instructions=INSTRUCTIONS,
        version="0.1.0",
        lifespan=_lifespan,
    )
    register_all(mcp, settings)
    resources.register(mcp)
    prompts.register(mcp)
    return mcp
