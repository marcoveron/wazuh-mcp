# wazuh-mcp

An MCP server that puts a Wazuh SIEM/XDR deployment in reach of a model — agent
inventory, alert hunting, vulnerability state, configuration assessment and
Active Response — as the foundation for an autonomous SOC.

## Design

Wazuh splits across two backends, and the tools follow that split because it
determines what each one can answer:

| Backend | Port | Holds | Tools |
|---------|------|-------|-------|
| **Server API** | 55000 | Current state: agents, rules, decoders, FIM, SCA, rootcheck, manager health | `wazuh_list_agents`, `wazuh_fim_findings`, `wazuh_get_rules`, `wazuh_health`, … |
| **Indexer** (OpenSearch) | 9200 | History: alerts, open vulnerabilities | `wazuh_search_alerts`, `wazuh_alert_stats`, `wazuh_list_vulnerabilities`, … |

Four decisions shape the whole thing:

**One response shape, every tool.** Nothing consuming this server should have to
know which tool it called in order to read the answer:

```json
{
  "items": [],
  "returned": 12,
  "total": 4231,
  "total_is_exact": false,
  "source": "indexer",
  "context": { "index": "wazuh-alerts-*" }
}
```

`total` counts what matched on the backend, not what came back. `total_is_exact`
is false when the Indexer stopped counting — it caps at 10,000 by default, and
presenting that as an exact figure is how an agent reports the same number for a
quiet night and a breach. `source` is `api`, `indexer` or `mixed`. `context`
holds the per-tool detail: the index searched, the agent, the grouping field,
`failed_items` when part of a request did not apply.

For the aggregation tools `items` are the buckets while `total` still counts the
documents aggregated over, so `returned` and `total` are different units there
by design.

**Aggregate before you page.** A model asked "what happened last night" will
otherwise pull 200 alert documents and count them by hand. `wazuh_alert_stats`
answers it in one call with a `terms` aggregation, carrying `max_level` and
agent cardinality per bucket so a count of 500 level-3 alerts is visibly
different from 5 level-12 ones.

**Compact by default.** One Windows Sysmon alert is several kilobytes of nested
event data, almost none of which changes a verdict. Every read tool returns a
projection of the fields that matter, truncates `full_log`, and offers
`full_documents=true` for when the detail really is the point.

**Write tools are opt-in and absent otherwise.** `WAZUH_ALLOW_ACTIVE_RESPONSE`
is off by default, and when off the Active Response write tools are never
registered — the model cannot see them, let alone call them. Only the read-only
listing of configured commands stays, so an agent can propose a real one.

## Setup

```bash
uv sync
cp .env.example .env    # then fill in URLs and credentials
```

Create a dedicated Wazuh API user rather than reusing `wazuh-wui`, and give it
only the RBAC policies these tools need (`agent:read`, `rules:read`,
`syscheck:read`, `sca:read`, `rootcheck:read`, `manager:read`, plus
`active-response:command` if you enable Active Response).

Wazuh ships self-signed certificates, so a first run usually needs
`WAZUH_VERIFY_SSL=false`. In production, point `WAZUH_CA_BUNDLE` at the root CA
(`/var/ossec/api/configuration/ssl/` on the manager) and turn verification back on.

Verify the connection before wiring it to a client:

```bash
uv run python -c "
import anyio
from wazuh_mcp.runtime import lifespan
from wazuh_mcp.config import Config
async def main():
    async with lifespan(Config.from_env()) as rt:
        print(await rt.api.get_items('/manager/info'))
anyio.run(main)"
```

## Connecting a client

OpenClaw:

```bash
openclaw mcp add wazuh \
  --command uv --arg run --arg wazuh-mcp \
  --cwd /path/to/wazuh-mcp

openclaw mcp doctor wazuh --probe
```

On a server deployment, if the MCP is installed
under the same user that runs the OpenClaw gateway, whose systemd service
doesn't necessarily have `~/.local/bin` on `PATH` — point `--command` at the
full path instead:

```bash
openclaw mcp add wazuh \
  --command "$HOME/.local/bin/uv" \
  --arg run \
  --arg wazuh-mcp \
  --cwd "$HOME/wazuh-mcp"

openclaw mcp doctor wazuh --probe
```

Credentials come from `.env`, which is looked up from `--cwd` — without it the
server starts with no configuration. Once it's connected, cut the tool surface
down to a basic set for a first pass with `openclaw mcp tools wazuh --include
...`, then `openclaw mcp reload` to pick up any `.env` change.

Claude Code, or by config file for any other MCP client:

```bash
claude mcp add wazuh -- uv --directory /path/to/wazuh-mcp run wazuh-mcp
```

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "uv",
      "args": ["--directory", "/path/to/wazuh-mcp", "run", "wazuh-mcp"]
    }
  }
}
```

For a remote client, the cheapest option is to keep stdio and let SSH carry it,
which also keeps the Wazuh ports on loopback; to serve it over HTTP instead,
set `WAZUH_MCP_TRANSPORT=streamable-http` (`WAZUH_MCP_HOST` / `WAZUH_MCP_PORT` /
`WAZUH_MCP_PATH` control where it binds, defaulting to `127.0.0.1:8000/mcp`).
**This server has no auth of its own**, so that default is loopback
deliberately: put something that authenticates in front of it before widening
the bind.

## Tools

### Agents
| Tool | Purpose |
|------|---------|
| `wazuh_agent_summary` | Fleet health in one call: counts by status, OS and group |
| `wazuh_list_agents` | Filter the inventory by status, group, platform, version |
| `wazuh_get_agent` | Full record for one agent |
| `wazuh_agent_processes` | Running processes (syscollector) |
| `wazuh_agent_ports` | Open and listening ports (syscollector) |
| `wazuh_agent_packages` | Installed packages — confirm a CVE's package is really present |

### Alerts
| Tool | Purpose |
|------|---------|
| `wazuh_search_alerts` | The main investigation tool: filter by time, agent, rule, level, ATT&CK, IP, user, free-text |
| `wazuh_alert_stats` | Aggregate counts by any field, with an optional second dimension |
| `wazuh_alert_timeline` | Date histogram — find spikes and when an incident began |
| `wazuh_indexer_query` | Raw OpenSearch DSL, for what the structured tools cannot express |

### Vulnerabilities
| Tool | Purpose |
|------|---------|
| `wazuh_vulnerability_summary` | Where exposure concentrates: by host, CVE, package or severity |
| `wazuh_list_vulnerabilities` | Individual findings, filterable by CVE, severity, CVSS, package |

### Endpoint state
| Tool | Purpose |
|------|---------|
| `wazuh_fim_findings` | File integrity state, including lookup by known-bad hash |
| `wazuh_sca_policies` | Configuration-assessment policies and their scores |
| `wazuh_sca_checks` | Individual checks with remediation text (failed ones by default) |
| `wazuh_rootcheck_findings` | Hidden processes and ports, rootkit signatures |

### Detection content
| Tool | Purpose |
|------|---------|
| `wazuh_get_rules` | What a rule ID actually detects — read this before judging an alert |
| `wazuh_get_rule_file` | Raw rule XML, for exact match conditions |
| `wazuh_get_decoders` | How a log is parsed into the `data.*` fields rules match on |

### Stack health
| Tool | Purpose |
|------|---------|
| `wazuh_health` | Manager daemons, cluster and indexer — run this before trusting a quiet period |
| `wazuh_manager_logs` | `ossec.log`, filterable by level and daemon |
| `wazuh_manager_stats` | Throughput: events received, **dropped**, alerts written |

### Active Response — writes off unless enabled
| Tool | Purpose |
|------|---------|
| `wazuh_active_response_commands` | List the AR commands actually declared on the manager, and which the allowlist permits. Read-only, always registered |
| `wazuh_active_response` | Run a configured AR command (firewall-drop, host-deny, …) on agents |
| `wazuh_restart_agents` | Restart the agent process on specific hosts |

## Prompts

Four workflows encoding the order a SOC analyst actually works in:

- **`soc_briefing`** — shift handover: health first, then fleet, then aggregates,
  then documents. Separates findings from noise from blind spots.
- **`triage_alert`** — read the rule, read the alerts, check the timeline,
  establish a baseline, pivot on entities, then reach a verdict — including
  "insufficient evidence" as a legitimate answer.
- **`investigate_host`** — one host end to end: alerts, FIM, rootcheck, SCA,
  vulnerabilities, processes, ports.
- **`hunt`** — hypothesis-driven, stating up front what would falsify it.

## Resources

- `wazuh://deployment` — which endpoints this server talks to, what is enabled
- `wazuh://severity-levels` — what Wazuh's 0-15 rule levels mean
- `wazuh://alert-fields` — the alert fields available for filtering and aggregating

## Safety

Active Response reaches real machines. Three layers stand in the way:

1. **`WAZUH_ALLOW_ACTIVE_RESPONSE=false`** by default — the tools are not registered.
2. **`WAZUH_ACTIVE_RESPONSE_COMMANDS`** — an optional allowlist of permitted commands.
3. **`confirm_all_agents`** — targeting `*` is refused without it, so a
   fleet-wide `firewall-drop` cannot happen on a single inference.

Both write tools carry `destructive_hint`, so a client can prompt before running
them. `WAZUH_MAX_RESULTS` caps how much any one call can return.

## Development

```bash
uv sync --extra dev
uv run pytest        # 92 tests, no Wazuh instance needed
uv run ruff check src tests
```

Tests drive the real clients and the real server through `httpx2.MockTransport`,
asserting on the requests that reach the wire — the query DSL, the endpoints and
the query strings — rather than on canned responses.

`tests/test_envelope.py` enumerates every registered tool and asserts the
response contract on each one, so a tool added later that invents its own key
names fails the suite rather than the integration.

## Toward an autonomous SOC

What is here is the read/act substrate. What it still needs:

- **State** — alerts seen, cases opened, verdicts reached. Without it every cycle
  re-triages the same alerts. A small SQLite store behind a `wazuh_case_*` tool set.
- **Enrichment** — threat intel on IPs, hashes and CVEs. Separate MCP servers
  (MISP, VirusTotal, OpenCTI) rather than more tools here.
- **A loop** — a scheduled agent running `soc_briefing`, escalating what crosses
  a threshold. Claude Code's `/loop` or a cron-driven agent covers this.
- **A verdict trail** — every automated conclusion needs its evidence recorded,
  or nobody will trust the automation enough to let it act.
