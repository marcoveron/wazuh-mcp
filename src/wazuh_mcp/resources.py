"""Resources describing the deployment, so a model can orient without spending tool calls."""

from __future__ import annotations

import json
from typing import Any

from mcp.server import MCPServer

from .runtime import get_runtime


def register(mcp: MCPServer) -> None:
    @mcp.resource(
        "wazuh://deployment",
        name="Wazuh deployment",
        description="Which Wazuh endpoints this server talks to and what is enabled.",
        mime_type="application/json",
    )
    def deployment() -> str:
        runtime = get_runtime()
        config = runtime.config
        payload: dict[str, Any] = {
            "server_api": {"url": config.api.url, "verify_ssl": config.api.verify_ssl},
            "indexer": (
                {
                    "url": config.indexer.url,
                    "alerts_index": config.indexer.alerts_index,
                    "vulnerabilities_index": config.indexer.vulnerabilities_index,
                    "verify_ssl": config.indexer.verify_ssl,
                }
                if config.indexer
                else None
            ),
            "active_response_enabled": config.allow_active_response,
            "active_response_allowlist": sorted(config.active_response_allowlist) or "any",
            "max_results_per_call": config.max_results,
        }
        return json.dumps(payload, indent=2)

    @mcp.resource(
        "wazuh://severity-levels",
        name="Wazuh rule severity levels",
        description="What Wazuh's 0-15 rule levels mean, for calibrating triage.",
        mime_type="text/markdown",
    )
    def severity_levels() -> str:
        return """# Wazuh rule levels

| Level | Meaning | Triage posture |
|-------|---------|----------------|
| 0 | Ignored — no action | Never alerted on |
| 1-3 | System low priority: informational, successful ops | Noise unless correlated |
| 4-6 | System low priority errors, bad config | Batch review |
| 7 | "Bad word" matches: denied, error, unauthorized | Worth a look |
| 8 | First-time seen events | Interesting when a host is new to a behaviour |
| 9 | Error from an invalid source, failed auth as a privileged user | Investigate |
| 10 | Multiple user-generated errors — repeated failed logins | Investigate |
| 11 | Integrity checking warning, file changes | Investigate |
| 12 | High-importance event: error or warning from a system component | Respond |
| 13 | Unusual error, commonly an attack pattern | Respond |
| 14 | High-importance security event, usually correlated | Respond now |
| 15 | Severe attack — no chance of a false positive | Respond now |

Filtering at `min_level=7` removes most operational noise; `min_level=12` leaves
only what typically warrants a response.
"""

    @mcp.resource(
        "wazuh://alert-fields",
        name="Wazuh alert fields",
        description="The alert document fields available for filtering and aggregating.",
        mime_type="text/markdown",
    )
    def alert_fields() -> str:
        return """# Wazuh alert document fields

Use these in `fields`, `group_by`, `split_by`, Lucene `search` strings and raw
`extra_query` DSL.

## Always present
- `timestamp` (date) — when the manager processed the event
- `rule.id` (keyword), `rule.level` (long), `rule.description` (keyword)
- `rule.groups` (keyword array) — e.g. `authentication_failed`, `syscheck`, `sca`, `web`
- `rule.firedtimes` (long), `rule.mail` (bool)
- `agent.id`, `agent.name`, `agent.ip` (keyword)
- `manager.name` (keyword), `location` (keyword), `decoder.name` (keyword)
- `full_log` (text) — the raw log line; the only full-text field

## Compliance and ATT&CK mappings
- `rule.mitre.id`, `rule.mitre.tactic`, `rule.mitre.technique`
- `rule.pci_dss`, `rule.gdpr`, `rule.hipaa`, `rule.nist_800_53`, `rule.tsc`, `rule.gpg13`

## Network / auth context (decoder-dependent)
- `data.srcip`, `data.dstip`, `data.srcport`, `data.dstport`
- `data.srcuser`, `data.dstuser`, `data.protocol`, `data.action`, `data.status`

## Windows events
- `data.win.system.eventID`, `data.win.system.channel`, `data.win.system.computer`
- `data.win.eventdata.image`, `data.win.eventdata.commandLine`
- `data.win.eventdata.parentImage`, `data.win.eventdata.targetUserName`
- `data.win.eventdata.logonType`, `data.win.eventdata.ipAddress`

## File integrity monitoring
- `syscheck.path`, `syscheck.event` (added/modified/deleted)
- `syscheck.md5_after`, `syscheck.sha1_after`, `syscheck.sha256_after`
- `syscheck.uname_after`, `syscheck.mtime_after`, `syscheck.size_after`

`data.*` fields depend on the decoder that parsed the log, so they are present on
some alerts and absent on others. When a field you expect is missing, check the
decoder with `wazuh_get_decoders` rather than assuming the event did not occur.
"""
