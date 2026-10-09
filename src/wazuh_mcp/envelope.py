"""The one response shape every tool returns.

A calling agent should not have to know which tool it invoked in order to read
the result. Before this module each tool named its payload after its own domain
— `agents`, `entries`, `lines`, `buckets` — and reported its count as `total`,
`total_matching` or `total_findings`, as an int from the Server API and as a
`{value, relation}` object from the Indexer. Anything consuming the server
generically had to special-case twenty tools.

So every tool returns exactly this:

    {
      "items":          [...],      # the rows this call produced
      "returned":       12,         # len(items)
      "total":          4231,       # records matching the filters, backend-side
      "total_is_exact": False,      # False when the backend capped its count
      "source":         "indexer",  # which backend answered: api, indexer, mixed
      "context":        {...}       # per-tool detail: index, agent_id, group_by…
    }

`total` counts what matched on the backend, not what came back. For the
aggregation tools that means the documents aggregated over, while `items` holds
the buckets — so `returned` and `total` are deliberately different units there,
and the bucket list is capped by `top` rather than by `total`.

`total_is_exact` exists because OpenSearch stops counting at 10,000 by default
and reports `relation: "gte"`. Silently presenting that as an exact figure is
how an agent ends up reporting "10000 alerts" for a quiet night and a breach
alike.
"""

from __future__ import annotations

from typing import Any

from .formatting import buckets_to_rows, hits_to_items, total_hits

API = "api"
INDEXER = "indexer"
MIXED = "mixed"


def envelope(
    items: list[dict[str, Any]],
    *,
    source: str,
    total: int | None = None,
    total_is_exact: bool = True,
    **context: Any,
) -> dict[str, Any]:
    """Wrap rows in the standard shape. `total` defaults to the number of rows."""
    return {
        "items": items,
        "returned": len(items),
        "total": len(items) if total is None else int(total),
        "total_is_exact": total_is_exact,
        "source": source,
        "context": {k: v for k, v in context.items() if v is not None},
    }


def from_api(result: dict[str, Any], **context: Any) -> dict[str, Any]:
    """Wrap a Server API `affected_items` result.

    Per-item failures and the manager's own message are real outcomes, not
    noise, so they ride along in `context` rather than being dropped.
    """
    items = result.get("items", [])
    return envelope(
        items,
        source=API,
        total=result.get("total", len(items)),
        failed_items=result.get("failed_items"),
        message=result.get("message"),
        **context,
    )


def from_hits(
    response: dict[str, Any],
    compactor,
    *,
    full_documents: bool = False,
    fields: list[str] | None = None,
    **context: Any,
) -> dict[str, Any]:
    """Wrap an OpenSearch search response's documents."""
    total = total_hits(response)
    return envelope(
        hits_to_items(response, compactor, full_documents=full_documents, fields=fields),
        source=INDEXER,
        total=total["value"],
        total_is_exact=total["relation"] == "eq",
        **context,
    )


def from_buckets(
    response: dict[str, Any],
    aggregation_name: str,
    *,
    key_name: str = "key",
    **context: Any,
) -> dict[str, Any]:
    """Wrap an aggregation's buckets. `total` stays the document count."""
    total = total_hits(response)
    aggregation = response.get("aggregations", {}).get(aggregation_name, {})
    return envelope(
        buckets_to_rows(aggregation, key_name=key_name),
        source=INDEXER,
        total=total["value"],
        total_is_exact=total["relation"] == "eq",
        **context,
    )
