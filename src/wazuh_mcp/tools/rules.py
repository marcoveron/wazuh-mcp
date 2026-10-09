"""Rule and decoder lookup.

An alert is only as meaningful as the rule behind it. When triaging, reading the
rule tells you what the detection actually asserts, which groups and compliance
mappings it carries, and how much to trust it.
"""

from __future__ import annotations

from typing import Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from ..envelope import API, envelope, from_api
from ..runtime import get_runtime

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=True)


def register(mcp: MCPServer) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_get_rules(
        rule_ids: list[str] | None = None,
        level: str | None = None,
        group: str | None = None,
        filename: str | None = None,
        mitre_id: str | None = None,
        search: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Look up Wazuh detection rules — what a rule ID actually detects.

        Call this whenever an alert's rule ID needs explaining before you judge
        whether it is a true positive.

        Args:
            rule_ids: Specific rule IDs to fetch, e.g. ["5710", "100200"].
            level: Severity or range, e.g. "10" or "10-15".
            group: Rule group, e.g. "authentication_failed", "web", "syscheck".
            filename: Restrict to a ruleset file, e.g. "0095-sshd_rules.xml".
            mitre_id: MITRE ATT&CK technique the rule maps to, e.g. "T1110".
            search: Substring match across rule descriptions.
            limit: Rules to return.
            offset: Rules to skip, for paging.
        """
        runtime = get_runtime()
        result = await runtime.api.get_items(
            "/rules",
            rule_ids=",".join(rule_ids) if rule_ids else None,
            level=level,
            group=group,
            filename=filename,
            mitre_id=mitre_id,
            search=search,
            limit=runtime.clamp(limit),
            offset=offset,
        )
        return from_api(result)

    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_get_rule_file(filename: str) -> dict[str, Any]:
        """Read the raw XML of a ruleset file, to see a rule's exact match conditions.

        Args:
            filename: Ruleset file name as reported by wazuh_get_rules,
                e.g. "0095-sshd_rules.xml" or "local_rules.xml".
        """
        runtime = get_runtime()
        # `raw=true` makes Wazuh answer with the XML itself rather than JSON.
        content = await runtime.api.get_text(f"/rules/files/{filename}", raw="true")
        return envelope(
            [{"filename": filename, "content": content}], source=API, filename=filename
        )

    @mcp.tool(annotations=READ_ONLY)
    async def wazuh_get_decoders(
        decoder_names: list[str] | None = None,
        filename: str | None = None,
        search: str | None = None,
        limit: int = 25,
    ) -> dict[str, Any]:
        """Look up decoders — how Wazuh parses a raw log into the fields rules match on.

        Useful when an alert's `data.*` fields are missing or unexpected: the
        decoder, not the rule, decides what gets extracted.

        Args:
            decoder_names: Specific decoder names, e.g. ["sshd", "windows_eventchannel"].
            filename: Restrict to a decoder file, e.g. "0310-ssh_decoders.xml".
            search: Substring match across decoder names.
            limit: Decoders to return.
        """
        runtime = get_runtime()
        result = await runtime.api.get_items(
            "/decoders",
            decoder_names=",".join(decoder_names) if decoder_names else None,
            filename=filename,
            search=search,
            limit=runtime.clamp(limit),
        )
        return from_api(result)
