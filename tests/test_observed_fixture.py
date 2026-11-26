# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of tatewari
"""The observed run is checked in, so its claims stay tied to its numbers.

These tests read `observed/target-kernel-obs.json` -- one run of the ten
scenarios against a real shirudo target -- and hold it to the same rules the
model is held to: a verdict comes from the enumerated vocabulary, a claim of
absence carries a control, and the two places where the target disagreed with
the model stay disagreements until someone reruns the target, not until someone
edits a number here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURE = Path(__file__).resolve().parent.parent / "observed" / "target-kernel-obs.json"

VERDICTS = {
    "lost",
    "refused",
    "split",
    "unrecorded",
    "unattributed",
    "unjoined",
    "evicted",
    "confused",
    "survived",
    "inconclusive",
}

# The model's expectation, and what the target actually did. Two rows differ,
# and each difference is a finding in its own right; a change to either is a
# change to the write-up, so it is asserted rather than described.
DIVERGENCES = {
    "unsocketed_packet": (
        "unrecorded",
        "unattributed",
    ),
    "export_partial": (
        "lost",
        "survived",
    ),
}


@pytest.fixture(scope="module")
def run() -> dict:
    return json.loads(FIXTURE.read_text())


def test_the_target_was_a_real_one(run: dict) -> None:
    facts = run["target_facts"]
    assert facts["kernel"].startswith("7.4-shirudo-ci"), facts["kernel"]
    conditions = facts["status_conditions"]
    attached = {c["type"]: c["status"] for c in conditions}
    assert attached["LsmAttached"] == "OK"
    assert attached["KeyringSealed"] == "OK"
    assert attached["UpatchesMeasured"] == "OK"
    assert "linux" not in facts["kernel"].lower()


def test_ten_scenarios_are_recorded(run: dict) -> None:
    names = [f["scenario"] for f in run["findings"]]
    assert len(names) == len(set(names)) == 10
    assert set(names) == set(DIVERGENCES) | {
        "attribution_blank",
        "dns_offport",
        "dns_qtype_txt",
        "dns_nxdomain",
        "dns_name_launder",
        "dns_id_confusion",
        "bucket_collision",
        "export_stall",
    }


def test_every_verdict_is_from_the_vocabulary(run: dict) -> None:
    for finding in run["findings"]:
        assert finding["verdict"] in VERDICTS, finding["scenario"]
        assert finding["basis"] == "observed", finding["scenario"]
        assert finding["notes"], finding["scenario"]
        assert finding["evidence"], finding["scenario"]


def test_only_the_two_known_divergences_differ_from_the_model(run: dict) -> None:
    for finding in run["findings"]:
        name = finding["scenario"]
        if name in DIVERGENCES:
            expected, observed = DIVERGENCES[name]
            assert finding["expected"] == expected, name
            assert finding["verdict"] == observed, name
        else:
            assert finding["verdict"] == finding["expected"], name


def test_absence_claims_carry_a_control(run: dict) -> None:
    absence = {"unjoined", "unrecorded", "unattributed", "evicted", "confused"}
    for finding in run["findings"]:
        if finding["verdict"] not in absence:
            continue
        control = finding["evidence"]["control"]
        assert control["arrived"] is True, finding["scenario"]
        assert control["recorded"] is True, finding["scenario"]


def _by_name(run: dict, name: str) -> dict:
    return next(f for f in run["findings"] if f["scenario"] == name)


def test_the_split_lands_on_the_kernels_own_probe_limit(run: dict) -> None:
    """OBS_T_STEPS is 8 in obs_net.bpf.c:153; the entry must move on the eighth."""
    evidence = _by_name(run, "bucket_collision")["evidence"]
    assert evidence["fillers_to_split"] == 8
    totals = evidence["totals"]
    assert len(totals) == 2
    assert totals[0][2] != totals[1][2], "the two entries must be different entries"


def test_the_refusal_lands_on_the_kernels_own_capacity(run: dict) -> None:
    evidence = _by_name(run, "export_stall")["evidence"]
    assert evidence["offered"] > evidence["recorded"]
    assert evidence["overflow"] > 0
    assert evidence["first_recorded"] is True
    assert evidence["last_recorded"] is False


def test_the_byte_crossed_the_gap_and_came_back(run: dict) -> None:
    evidence = _by_name(run, "dns_nxdomain")["evidence"]
    assert evidence["decoded"] == evidence["payload_byte"]
    assert evidence["payload_byte"] != 0


def test_the_unjoined_verdicts_hold_no_names(run: dict) -> None:
    for name in ("dns_offport", "dns_qtype_txt"):
        snapshot = _by_name(run, name)["evidence"]["dns_snapshot"]
        assert snapshot["records"] == [], name


def test_the_partial_export_lost_nothing_so_the_claim_is_marked_survived(
    run: dict,
) -> None:
    evidence = _by_name(run, "export_partial")["evidence"]
    assert evidence["next_lost"] == 0
    assert evidence["capped_records"] <= evidence["interval_used"]
