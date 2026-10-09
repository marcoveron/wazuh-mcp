"""Reusable investigation workflows exposed as MCP prompts.

These encode the order of operations a SOC analyst actually follows, so the
calling model starts from situational awareness rather than from whichever tool
it happened to notice first. They are the seed of the autonomous loop.
"""

from __future__ import annotations

from mcp.server import MCPServer


def register(mcp: MCPServer) -> None:
    @mcp.prompt()
    def soc_briefing(hours: int = 24) -> str:
        """Produce a shift-handover briefing over the last N hours."""
        return f"""Produce a SOC briefing covering the last {hours} hours.

Work in this order and do not skip step 1:

1. Call wazuh_health. If any manager daemon is stopped, the cluster is degraded,
   or the indexer is not green, say so first — alert volume is not interpretable
   until the pipeline is known to be running.
2. Call wazuh_agent_summary. Note agents that are disconnected or never_connected;
   those are blind spots, not quiet hosts.
3. Call wazuh_alert_stats with group_by="rule.description", min_level=7,
   time_from="{hours}h". This is the shape of the period.
4. Call wazuh_alert_stats with group_by="agent.name", min_level=10 to see whether
   severity concentrates on particular hosts.
5. Call wazuh_alert_stats with group_by="rule.mitre.id", min_level=7 for ATT&CK coverage.
6. Call wazuh_alert_timeline with interval="1h" to locate spikes.
7. For anything at level 12+ or any cluster of related alerts, pull the actual
   documents with wazuh_search_alerts and read them.

Then write the briefing:
- Headline: the single most important thing that happened, or "nothing requiring
  action" if that is the honest answer.
- Findings worth attention, each with: what fired, which hosts, how many times,
  when it started, and your assessment of true positive vs. benign.
- Noise: high-volume low-value rules that should be tuned, with the rule ID.
- Blind spots: disconnected agents, stopped daemons, dropped events.
- Recommended actions, ordered by urgency.

Distinguish what you observed from what you inferred. If the evidence does not
support a conclusion, say what additional query would settle it."""

    @mcp.prompt()
    def triage_alert(rule_id: str, agent_id: str = "", hours: int = 24) -> str:
        """Triage a specific rule firing on a host: true positive or not?"""
        scope = f" on agent {agent_id}" if agent_id else ""
        agent_hint = f', agent_ids=["{agent_id}"]' if agent_id else ""
        return f"""Triage rule {rule_id}{scope} over the last {hours} hours.

1. Call wazuh_get_rules with rule_ids=["{rule_id}"] and read what the rule
   actually asserts — its level, groups, ATT&CK mapping and description. Do not
   reason about the alert before you know what the detection means.
2. Call wazuh_search_alerts with rule_ids=["{rule_id}"]{agent_hint},
   time_from="{hours}h" and read the real documents, including full_log.
3. Call wazuh_alert_timeline with rule_ids=["{rule_id}"], interval="1h". Is this
   a steady background rate or a burst? A burst that starts abruptly is the
   interesting case.
4. Establish a baseline: run the same search over a longer window (for example
   time_from="30d") and compare. A rule that fires constantly is probably
   environmental; one that fired for the first time today is not.
5. Pivot on the entities in the alerts — source IPs, usernames, processes, paths.
   Use wazuh_alert_stats grouped by data.srcip or data.srcuser to see whether one
   actor dominates.
6. If a host is implicated, characterise it: wazuh_get_agent, then
   wazuh_agent_processes / wazuh_agent_ports for what is running, and
   wazuh_fim_findings for recent file changes.

Conclude with:
- Verdict: true positive, false positive, or insufficient evidence. If it is the
  third, say so rather than guessing.
- The evidence that decided it, quoted from the alerts.
- Scope: which hosts, which accounts, what time window.
- Recommended containment, if any — and be explicit that Active Response
  commands change production hosts and need confirmation before running.
- Tuning suggestion if this is benign and high-volume."""

    @mcp.prompt()
    def investigate_host(agent_id: str, hours: int = 72) -> str:
        """Build a full picture of one host: alerts, integrity, configuration, exposure."""
        return f"""Investigate agent {agent_id} over the last {hours} hours.

1. wazuh_get_agent — platform, version, last keep-alive, group membership. If the
   agent has been disconnected, everything below is stale; say when data ends.
2. wazuh_alert_stats with agent_ids=["{agent_id}"], group_by="rule.description",
   time_from="{hours}h" — what this host has been generating.
3. wazuh_search_alerts with agent_ids=["{agent_id}"], min_level=10 — the alerts
   that matter, read in full.
4. wazuh_fim_findings — what file integrity monitoring is tracking. Look for
   changes to binaries, startup paths, scheduled tasks and credential stores.
5. wazuh_rootcheck_findings — hidden processes, suspicious files, rootkit signatures.
6. wazuh_sca_policies, then wazuh_sca_checks on the lowest-scoring policy — the
   misconfigurations an attacker would use.
7. wazuh_list_vulnerabilities with agent_ids=["{agent_id}"], severities=["Critical","High"]
   — what is exploitable on this host today.
8. wazuh_agent_processes and wazuh_agent_ports — what is actually running and listening.

Write the result as: what this host is, what it has been doing, what is wrong
with it, and what to do about it — in that order. Separate confirmed compromise
indicators from ordinary hygiene problems; conflating them wastes the responder's
time."""

    @mcp.prompt()
    def hunt(hypothesis: str, hours: int = 168) -> str:
        """Run a structured threat hunt against a stated hypothesis."""
        return f"""Threat hunt over the last {hours} hours.

Hypothesis: {hypothesis}

Hunt properly rather than searching once:

1. State what would have to be true in the data if the hypothesis holds, and what
   would falsify it. Write both down before querying.
2. Translate that into concrete queries. wazuh_search_alerts and
   wazuh_alert_stats cover the named filters; use wazuh_indexer_query with raw
   OpenSearch DSL for anything they cannot express — wildcards on command lines,
   `significant_terms`, scripted conditions.
3. Search broadly first and count, do not page documents. Establish the normal
   rate before deciding something is anomalous.
4. Where the hypothesis implicates hosts, corroborate on the endpoint:
   wazuh_agent_processes, wazuh_agent_ports, wazuh_fim_findings.
5. Follow the entities, not the alerts: an IP, an account or a hash that appears
   in one finding is the pivot into the next.

Report: what you looked for, what you found, what you did not find, and your
confidence. A hunt that falsifies its hypothesis is a successful hunt — say so
plainly instead of stretching weak evidence. End with the detection rule or
query that would catch this faster next time."""
