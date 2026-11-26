"""The evidence-plane scenarios, asserted through the same API the CLI uses.

Each test asserts the verdict, and then asserts the number that makes the
verdict true -- that the canary decoded, that the entry really split in two,
that the counter really never left the kernel. A test that only checked the
verdict label could pass while proving nothing.
"""

from __future__ import annotations

import pytest

from tatewari.evidence_pipeline import SCENARIOS, run_matrix, summary
from tatewari.observer_model import (
    ArenaTable,
    DNS_MAX_NAMES_PER_IP,
    NET_BUCKETS,
    ROLE_INITIATOR,
    TABLE_STEPS,
    Exe,
    Ident,
    hash_words,
    ipv4_addr_words,
    net_key_words,
)


@pytest.fixture(scope="module")
def matrix():
    return {f.name: f for f in run_matrix()}


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_scenario_reaches_expected_verdict(matrix, name):
    finding = matrix[name]
    assert finding.verdict == finding.expected, (
        f"{name}: expected {finding.expected}, got {finding.verdict}: {finding.claim}")


def test_export_partial_destroys_a_record_the_kernel_held(matrix):
    evidence = matrix["export_partial"].evidence
    assert evidence["arrived"] >= 1
    assert evidence["first_page"]["done"] is False
    assert evidence["restart"]["lost"] >= 1
    assert evidence["restart"]["records"] == []


def test_export_stall_refuses_by_insertion_order(matrix):
    evidence = matrix["export_stall"].evidence
    assert evidence["export"]["overflow"] > 0
    assert evidence["carrier_present"] is False
    assert evidence["first_filler_present"] is True


def test_attribution_blank_keeps_bytes_and_drops_the_name(matrix):
    evidence = matrix["attribution_blank"].evidence
    blank = evidence["unattributed_records"]
    named = evidence["attributed_records"]
    assert blank and named
    assert all(r["key"][1] is None and r["key"][2] is None for r in blank)
    assert all(r["tx_bytes"] > 0 for r in blank)
    assert all(r["key"][1] is not None for r in named)


def test_dns_qtype_counter_never_leaves_the_kernel(matrix):
    evidence = matrix["dns_qtype_txt"].evidence
    assert evidence["counter"] >= 1
    assert evidence["counter_exported"] is False
    assert evidence["dns_records"] == 0


def test_nxdomain_channel_decodes_through_absent_records(matrix):
    evidence = matrix["dns_nxdomain"].evidence
    assert evidence["decoded"] == evidence["sent"]
    assert sum(evidence["bits"]) < 8
    recorded = {r["key"][3] for r in evidence["dns_records"]}
    assert len(recorded) == sum(evidence["bits"])


def test_name_launder_keeps_the_count_and_loses_the_name(matrix):
    evidence = matrix["dns_name_launder"].evidence
    assert len(evidence["recorded_names"]) == DNS_MAX_NAMES_PER_IP
    assert evidence["asked"][0] not in evidence["recorded_names"]


def test_bucket_collision_splits_one_peer_into_two_entries(matrix):
    evidence = matrix["bucket_collision"].evidence
    carrier = evidence["carrier_entries"]
    control = evidence["control_entries"]
    assert len(carrier) == 2
    assert len(control) == 1
    assert [e["val"]["tx_pkts"] for e in carrier] == [1, 1]
    assert control[0]["val"]["tx_pkts"] == 2


def test_flip_destroys_an_undrained_interval():
    table = ArenaTable("net", 64, 32)
    for i in range(3):
        table.touch([i + 1], ("peer", i))
    partial = table.export(100, ship=1)
    assert partial.done is False
    assert len(partial.records) == 1
    restart = table.export(200)
    assert restart.lost == 3
    assert restart.records == []
    assert table.lost == 0


def test_a_completed_export_leaves_nothing_behind():
    table = ArenaTable("net", 64, 32)
    table.touch([1], ("peer", 1))
    export = table.export(100)
    assert export.done is True and len(export.records) == 1
    assert table.export(200).records == []


def test_probe_limit_is_eight_links():
    assert TABLE_STEPS == 8
    ident = Ident(Exe(1, 2), 3)
    groups: dict[int, list[int]] = {}
    for port in range(1024, 65536):
        words = net_key_words(ident, 2, 17, ROLE_INITIATOR, port,
                              ipv4_addr_words("127.0.0.1"))
        groups.setdefault(hash_words(words) & (NET_BUCKETS - 1), []).append(port)
    assert max(len(v) for v in groups.values()) > TABLE_STEPS


def test_summary_matches_the_scenario_table():
    findings = run_matrix(["dns_offport"])
    result = summary(findings)
    assert result["scenarios"] == 1
    assert result["matched_expected"] == 1
