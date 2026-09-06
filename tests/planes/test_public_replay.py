"""Measurement integrity of the SIMULATED public-report replay."""

import asyncio
from pathlib import Path
from typing import Any

import pytest

from nemesis.audit.trail import AppendOnlyAuditTrail
from nemesis.core.claims import ClaimKind
from nemesis.evidence.vault import FileSystemEvidenceVault
from nemesis.pilotbench.replay import BreadthFirstPilot, read_cases, run_replay, score_report

CORPUS = Path(__file__).resolve().parents[2] / "data/benchmarks/public-replay-v1/inputs.json"


@pytest.mark.parametrize("index", [0, 1, 2])
def test_baseline_retrieves_report_records_through_real_sealing(index, tmp_path):
    case = read_cases(CORPUS)[index]
    run = asyncio.run(run_replay(case, BreadthFirstPilot(), workspace=tmp_path, max_moves=8))
    assert set(run["observed_record_ids"]) == {r.record_id for r in case.records}
    assert run["duplicate_queries"] == 0
    assert run["failed_queries"] == 0
    assert run["query_cost_units"] <= 8
    for claim in run["claims"]:
        if claim["kind"] == ClaimKind.OBSERVATION.value:
            assert claim["supported_by_evidence"]
    assert asyncio.run(FileSystemEvidenceVault(tmp_path / "vault").verify_integrity()).is_intact
    assert asyncio.run(AppendOnlyAuditTrail(tmp_path / "audit.jsonl").verify_chain())
    briefings = str(run["briefings"])
    for withheld in ("expected_record_ids", "source_sections", "Mandiant", "Microsoft"):
        assert withheld not in briefings
    # Source assertions are retained for the evaluator but are not exposed by Briefing.
    assert "Report records a historical DNS resolution" not in briefings


def test_scorer_counts_unique_hits_and_does_not_call_unlabelled_claims_false():
    run: dict[str, Any] = {
        "case_id": "R",
        "pilot": "test",
        "observed_record_ids": ["a", "a", "unknown"],
    }
    for key in (
        "elapsed_seconds",
        "moves",
        "connector_calls",
        "duplicate_queries",
        "failed_queries",
        "empty_queries",
        "refused_moves",
        "reported_tokens",
        "tokens_complete",
        "monetary_cost",
        "halted_reason",
        "concluded",
    ):
        run[key] = None
    score = score_report(run, {"a", "b"})
    assert score["retrieved"] == 1
    assert score["recall"] == 0.5
    assert score["missing"] == ["b"]
    assert score["unexpected_record_ids"] == ["unknown"]
    assert score["false_positive_rate"] is None
    assert score["attribution_accuracy"] is None


def test_provider_failure_remains_visible_and_does_not_become_zero_cost(tmp_path):
    class BrokenPilot:
        name = "unavailable"

        async def propose(self, briefing):
            raise RuntimeError("Model unavailable")

    case = read_cases(CORPUS)[0]
    run = asyncio.run(run_replay(case, BrokenPilot(), workspace=tmp_path, max_moves=2))
    assert run["observed_record_ids"] == []
    assert run["refused_moves"] > 0
    assert run["reported_tokens"] is None
    assert run["monetary_cost"] is None
    assert run["concluded"] is False
    assert run["halted_reason"]


def test_replay_rejects_live_connectors_before_driving(tmp_path):
    from types import SimpleNamespace
    from typing import cast

    from nemesis.pilotbench import DEFAULT_CORPUS, run_scenario
    from nemesis.ports.collection import IntelligenceConnector

    live = cast(
        IntelligenceConnector, SimpleNamespace(capabilities=SimpleNamespace(is_simulated=False))
    )
    with pytest.raises(ValueError, match="only simulated"):
        asyncio.run(
            run_scenario(
                DEFAULT_CORPUS[0], BreadthFirstPilot(), workspace=tmp_path, connectors=(live,)
            )
        )
    assert not list(tmp_path.iterdir())


def test_unsupported_query_is_an_attempt_not_a_connector_call(tmp_path):
    from nemesis.pilot.moves import RunPivot
    from nemesis.ports.collection import PivotType

    class UnsupportedPilot:
        name = "unsupported-query"

        async def propose(self, briefing):
            return RunPivot(
                entity_id=briefing.entities[0].entity_id,
                pivot_type=PivotType.REGISTRATION_RECORD,
            )

    run = asyncio.run(
        run_replay(read_cases(CORPUS)[0], UnsupportedPilot(), workspace=tmp_path, max_moves=1)
    )
    assert run["query_attempts"] == 1
    assert run["failed_queries"] == 1
    assert run["connector_calls"] == 0
    assert run["query_cost_units"] == 0
