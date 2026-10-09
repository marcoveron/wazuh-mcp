"""Compaction is what keeps an investigation inside the context window."""

from __future__ import annotations

from wazuh_mcp.formatting import (
    FULL_LOG_LIMIT,
    buckets_to_rows,
    compact_alert,
    dig,
    hits_to_items,
    project,
    total_hits,
)

WINDOWS_ALERT = {
    "timestamp": "2026-09-18T10:00:00.000+0000",
    "rule": {
        "id": "92052",
        "level": 12,
        "description": "Powershell executed with encoded command",
        "groups": ["windows", "sysmon"],
        "mitre": {"id": ["T1059.001"], "tactic": ["Execution"]},
        "firedtimes": 4,
    },
    "agent": {"id": "003", "name": "DC01", "ip": "10.0.0.3"},
    "data": {"win": {"eventdata": {"image": "C:\\powershell.exe", "commandLine": "-enc AAA"}}},
    "full_log": "x" * (FULL_LOG_LIMIT + 500),
    "manager": {"name": "wazuh-master"},
    "decoder": {"name": "windows_eventchannel"},
    "input": {"type": "log"},
    "predecoder": {"timestamp": "..."},
}


def test_dig_reads_nested_and_flat_keys_alike():
    assert dig(WINDOWS_ALERT, "rule.level") == 12
    assert dig({"rule.level": 7}, "rule.level") == 7
    assert dig(WINDOWS_ALERT, "rule.nonexistent") is None
    assert dig(WINDOWS_ALERT, "full_log.deeper") is None


def test_project_drops_absent_and_empty_values():
    result = project({"a": 1, "b": None, "c": [], "d": ""}, ["a", "b", "c", "d", "e"])
    assert result == {"a": 1}


def test_compact_alert_keeps_the_triage_fields_and_drops_the_plumbing():
    compact = compact_alert(WINDOWS_ALERT)

    assert compact["rule.id"] == "92052"
    assert compact["rule.level"] == 12
    assert compact["agent.name"] == "DC01"
    assert compact["rule.mitre.id"] == ["T1059.001"]
    assert compact["data.win.eventdata.commandLine"] == "-enc AAA"
    # Fields that never change a verdict should not be paid for.
    assert "input.type" not in compact
    assert "predecoder.timestamp" not in compact
    assert "rule.firedtimes" not in compact


def test_compact_alert_truncates_a_runaway_full_log():
    compact = compact_alert(WINDOWS_ALERT)
    assert compact["full_log"].endswith("… [truncated]")
    assert len(compact["full_log"]) < FULL_LOG_LIMIT + 50


def test_compact_alert_leaves_a_short_full_log_intact():
    compact = compact_alert({**WINDOWS_ALERT, "full_log": "sshd: failed password"})
    assert compact["full_log"] == "sshd: failed password"


def test_full_documents_bypasses_compaction():
    response = {"hits": {"hits": [{"_id": "abc", "_index": "wazuh-alerts-4.x-2026.09.18",
                                   "_source": WINDOWS_ALERT}]}}

    compacted = hits_to_items(response, compact_alert, full_documents=False)
    assert "input" not in compacted[0]

    full = hits_to_items(response, compact_alert, full_documents=True)
    assert full[0]["input"] == {"type": "log"}
    assert full[0]["_id"] == "abc"


def test_explicit_fields_win_over_the_default_projection():
    response = {"hits": {"hits": [{"_id": "abc", "_source": WINDOWS_ALERT}]}}
    items = hits_to_items(
        response, compact_alert, full_documents=False, fields=["timestamp", "agent.name"]
    )
    assert set(items[0]) == {"timestamp", "agent.name", "_id", "_index"}


def test_total_hits_preserves_the_gte_relation():
    """OpenSearch caps counts; reporting 10000 as exact would mislead the model."""
    assert total_hits({"hits": {"total": {"value": 10000, "relation": "gte"}}}) == {
        "value": 10000, "relation": "gte"
    }
    assert total_hits({"hits": {"total": 42}}) == {"value": 42, "relation": "eq"}


def test_buckets_flatten_with_their_sub_aggregations():
    rows = buckets_to_rows(
        {
            "buckets": [
                {
                    "key": "DC01",
                    "doc_count": 120,
                    "max_level": {"value": 12.0},
                    "agents": {"value": 1},
                    "breakdown": {"buckets": [{"key": "Logon failure", "doc_count": 118}]},
                }
            ]
        }
    )
    assert rows[0]["key"] == "DC01"
    assert rows[0]["count"] == 120
    assert rows[0]["max_level"] == 12.0
    assert rows[0]["breakdown"] == [{"key": "Logon failure", "count": 118}]


def test_date_histogram_buckets_report_the_readable_timestamp():
    rows = buckets_to_rows(
        {"buckets": [{"key": 1758196800000, "key_as_string": "2026-09-18T12:00:00.000Z",
                      "doc_count": 5}]},
        key_name="time",
    )
    assert rows[0] == {"time": "2026-09-18T12:00:00.000Z", "count": 5}
