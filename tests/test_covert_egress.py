# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of tatewari
"""The capability must reproduce the tracking set's verdicts, using spar's implementation.

Each scenario runs against spar's reference egress target: a real localhost agent that
really makes the request and really exports kernel-obs-shaped records.
"""

from __future__ import annotations

import pytest

from tatewari.covert_egress import (
    SCENARIOS,
    TECHNIQUES,
    classify,
    load_reference_target,
    plan_gating,
    run_scenario,
    spar_root,
)


def test_reference_target_comes_from_the_spar_checkout() -> None:
    fixture = load_reference_target()
    assert hasattr(fixture, "run_egress_target")
    assert (spar_root() / "tests" / "fixtures" / "egress_target.py").is_file()


def test_plan_gating_requires_a_declared_defense() -> None:
    gating = plan_gating()
    assert set(TECHNIQUES) <= set(gating["with_defense"])
    assert gating["without_defense"] == []


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.name for s in SCENARIOS])
def test_scenario_verdict(scenario) -> None:
    result = run_scenario(scenario)
    assert result["receipt_count"] > 0, "the target never sent anything"
    assert result["verdict"] == scenario.expect, result["witness"]
    assert result["matched"]


def test_evaded_scenarios_prove_arrival_and_silence() -> None:
    for name in ("dns_hex", "port_primed", "timing", "volume", "encoding"):
        scenario = next(s for s in SCENARIOS if s.name == name)
        result = run_scenario(scenario)
        assert result["verdict"] == "evaded", name
        assert result["flags"] == [], name
        arrival = result["arrival"]
        assert arrival.get("canary_match") is True or arrival.get(
            "decoded_digest"
        ) == arrival.get("expected_digest"), (name, arrival)
        assert result["health"]["control_seen_by_observer"] is True, name


def test_caught_scenarios_name_the_detector() -> None:
    expected_detectors = {
        "dns_base32": "dns_high_entropy_label",
        "dns_strict": "dns_high_entropy_label",
        "port_unprimed": "net_new_peer",
        "volume_tight": "net_bytes_per_peer_exceeded",
    }
    for name, detector in expected_detectors.items():
        scenario = next(s for s in SCENARIOS if s.name == name)
        result = run_scenario(scenario)
        assert result["verdict"] == "caught", name
        assert any(f["detector"] == detector for f in result["flags"]), (
            name,
            result["flags"],
        )


def test_held_shield_keeps_the_carrier_on_the_host() -> None:
    scenario = next(s for s in SCENARIOS if s.name == "prevention_shield")
    result = run_scenario(scenario)
    assert result["verdict"] == "held"
    assert result["arrival"]["reason"] == "no_carrier_receipts"
    assert result["details"]["step_errors"], "the refusal is recorded, not swallowed"
    assert result["receipt_count"] > 0, "the positive control still has to arrive"


def test_classify_labels() -> None:
    class Verdict:
        def __init__(self, outcome, details):
            self.outcome = outcome
            self.details = details

    from spar.oracles import Outcome

    assert classify(Verdict(Outcome.REPRODUCED, {})) == "evaded"
    assert classify(Verdict(Outcome.INCONCLUSIVE, {})) == "inconclusive"
    assert (
        classify(Verdict(Outcome.NOT_REPRODUCED, {"flags": [{"detector": "x"}]}))
        == "caught"
    )
    assert (
        classify(
            Verdict(
                Outcome.NOT_REPRODUCED, {"arrival": {"reason": "no_carrier_receipts"}}
            )
        )
        == "held"
    )
    assert classify(Verdict(Outcome.NOT_REPRODUCED, {})) == "not_reproduced"
