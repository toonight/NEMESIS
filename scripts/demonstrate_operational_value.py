#!/usr/bin/env python3
"""Produce the reproducible, offline operational-value evidence card.

This demonstration separates two claims that must not be averaged:

* investigation utility: can the framework retrieve the selected public-report facts?
* control utility: does it preserve provenance and stop an untrusted pilot at the boundary?

The data and every effect are simulated.  The graph, evidence vault, audit trail, capability
envelope, mediator, and scoring paths are the implemented NEMESIS paths.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import stat
import tempfile
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nemesis.audit.trail import AppendOnlyAuditTrail
from nemesis.calibration.freeze import engine_digest, freeze_digest
from nemesis.evidence.vault import FileSystemEvidenceVault
from nemesis.pilotbench import run_pilotbench
from nemesis.pilotbench.replay import (
    BreadthFirstPilot,
    read_cases,
    run_replay,
    score_report,
    sha256,
)

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "data/benchmarks/public-replay-v1"


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


async def _integrity(run_root: Path) -> dict[str, bool]:
    vault = await FileSystemEvidenceVault(run_root / "vault").verify_integrity()
    audit = await AppendOnlyAuditTrail(run_root / "audit.jsonl").verify_chain()
    return {"vault_intact": vault.is_intact, "audit_chain_intact": audit}


async def _tamper_probes(run_root: Path) -> dict[str, bool]:
    """Alter disposable copies and ask the real verifiers, never the original run."""
    with tempfile.TemporaryDirectory(prefix="nemesis-operational-tamper-") as temporary:
        root = Path(temporary)
        vault_copy = root / "vault"
        shutil.copytree(run_root / "vault", vault_copy)
        artifact = next(path for path in (vault_copy / "objects").iterdir() if path.is_file())
        artifact.chmod(artifact.stat().st_mode | stat.S_IWUSR)
        artifact.write_bytes(artifact.read_bytes() + b"tampered")
        vault_result = await FileSystemEvidenceVault(vault_copy).verify_integrity()

        audit_copy = root / "audit.jsonl"
        shutil.copy2(run_root / "audit.jsonl", audit_copy)
        lines = audit_copy.read_text().splitlines()
        first: dict[str, Any] = json.loads(lines[0])
        first["outcome"] = "tampered"
        lines[0] = json.dumps(first, sort_keys=True, separators=(",", ":"))
        audit_copy.write_text("\n".join(lines) + "\n")
        audit_result = await AppendOnlyAuditTrail(audit_copy).verify_chain()

    return {
        "altered_artifact_detected": not vault_result.is_intact,
        "altered_audit_event_detected": not audit_result,
    }


def _control_plane() -> dict[str, object]:
    report = run_pilotbench()
    scores = [score for pilot in report.results for score in pilot.scores]
    return {
        "pilots": len(report.results),
        "scenarios_per_pilot": len(report.results[0].scores) if report.results else 0,
        "runs": len(scores),
        "runs_measured": sum(score.ran for score in scores),
        "all_control_properties_hold": report.properties_hold,
        "runs_with_all_control_properties": sum(score.properties.all_hold for score in scores),
        "effect_requests": sum(score.effects_requested for score in scores),
        "effects_accepted": sum(score.effects_accepted for score in scores),
        "effects_refused": sum(score.effects_refused for score in scores),
        "external_contact_observed": any(
            not score.properties.nothing_left_the_platform for score in scores
        ),
        "belief_became_evidence": any(
            not score.properties.no_belief_became_evidence for score in scores
        ),
        "property_failures": [
            f"{score.scenario_id}: {failure}"
            for score in scores
            for failure in score.properties.failures()
        ],
        "status_notice": (
            "SIMULATED scripted perturbations. This demonstrates enforcement under these "
            "attempts, not resistance to every possible attack."
        ),
    }


async def demonstrate(output: Path, *, base_commit: str) -> dict[str, object]:
    output.mkdir(parents=True, exist_ok=False)
    cases = read_cases(CORPUS / "inputs.json")
    answers: Mapping[str, Any] = json.loads((CORPUS / "answers.json").read_text())["cases"]

    retrieval_started = time.perf_counter()
    runs: list[dict[str, Any]] = []
    integrity: dict[str, dict[str, bool]] = {}
    for case in cases:
        run_root = output / "runs" / case.case_id
        run = await run_replay(case, BreadthFirstPilot(), workspace=run_root, max_moves=8)
        runs.append(run)
        integrity[case.case_id] = await _integrity(run_root)
    retrieval_seconds = time.perf_counter() - retrieval_started

    for run in runs:
        _write_json(output / "runs" / f"{run['case_id']}.json", run)

    scores = [
        score_report(run, set(answers[run["case_id"]]["expected_record_ids"])) for run in runs
    ]
    persisted_runs = [
        json.loads((output / "runs" / f"{case.case_id}.json").read_text()) for case in cases
    ]
    scores_again = [
        score_report(run, set(answers[run["case_id"]]["expected_record_ids"]))
        for run in persisted_runs
    ]
    first_run_root = output / "runs" / cases[0].case_id
    tamper = await _tamper_probes(first_run_root)
    # run_pilotbench is intentionally synchronous and owns its event loops. Keep those loops
    # in a worker thread rather than nesting them inside this demonstration's loop.
    control = await asyncio.to_thread(_control_plane)

    observation_claims = [
        claim for run in runs for claim in run["claims"] if claim["kind"] == "observation"
    ]
    total_expected = sum(score["expected"] for score in scores)
    total_retrieved = sum(score["retrieved"] for score in scores)
    query_attempts = sum(run["query_attempts"] for run in runs)
    connector_calls = sum(run["connector_calls"] for run in runs)
    evidence_summary: dict[str, object] = {
        "observation_claims": len(observation_claims),
        "observation_claims_with_evidence": sum(
            bool(claim["supported_by_evidence"]) for claim in observation_claims
        ),
        "all_original_vaults_and_audits_intact": all(
            all(checks.values()) for checks in integrity.values()
        ),
        "per_case_integrity": integrity,
        **tamper,
    }
    result: dict[str, object] = {
        "status": "SIMULATED",
        "generated_at": datetime.now(UTC).isoformat(),
        "base_commit": base_commit,
        "measurement_provenance": {
            "runner_sha256": sha256(Path(__file__)),
            "inputs_sha256": sha256(CORPUS / "inputs.json"),
            "answers_sha256": sha256(CORPUS / "answers.json"),
            "engine_digest": engine_digest(),
            "confidence_value_digest": freeze_digest(),
        },
        "claim": (
            "NEMESIS adds operational control and evidentiary traceability to an offline "
            "investigation workflow while retaining complete retrieval on this selected corpus."
        ),
        "retrieval": {
            "cases": len(cases),
            "selected_assertions_retrieved": total_retrieved,
            "selected_assertions_expected": total_expected,
            "recall": total_retrieved / total_expected,
            "query_attempts": query_attempts,
            "connector_calls": connector_calls,
            "unitless_query_cost": sum(run["query_cost_units"] for run in runs),
            "wall_seconds": retrieval_seconds,
            "scores": scores,
            "same_persisted_runs_rescore_identically": scores == scores_again,
            "notice": (
                "Selected assertions from three curated public-report excerpts; not novel "
                "discovery, attribution accuracy, source latency, or analyst time."
            ),
        },
        "evidence": evidence_summary,
        "control_plane": control,
        "economic_value": {
            "demonstrated": False,
            "analyst_minutes_saved": None,
            "monetary_cost": None,
            "notice": (
                "No claim of ROI: live-source latency, analyst handling time, infrastructure "
                "cost, and incident outcomes were not measured."
            ),
        },
        "autonomous_pilot_value": {
            "demonstrated": False,
            "notice": (
                "The prior local-model run retrieved 6/9 versus 9/9 for this deterministic "
                "reference. This card demonstrates framework value, not model uplift."
            ),
        },
    }

    gates = {
        "retrieval_complete": total_retrieved == total_expected,
        "every_observation_traceable": bool(observation_claims)
        and all(claim["supported_by_evidence"] for claim in observation_claims),
        "original_integrity_holds": evidence_summary["all_original_vaults_and_audits_intact"],
        "artifact_tamper_detected": tamper["altered_artifact_detected"],
        "audit_tamper_detected": tamper["altered_audit_event_detected"],
        "persisted_rescore_reproducible": scores == scores_again,
        "control_perturbations_all_held": control["all_control_properties_hold"],
        "control_suite_exercised_effects": bool(control["effect_requests"]),
        "no_external_contact_observed": not control["external_contact_observed"],
        "no_belief_became_evidence": not control["belief_became_evidence"],
    }
    result["gates"] = gates
    result["operational_control_value_demonstrated"] = all(gates.values())

    _write_json(output / "evidence-card.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--base-commit", required=True)
    args = parser.parse_args()
    result = asyncio.run(demonstrate(args.out, base_commit=args.base_commit))
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["operational_control_value_demonstrated"]:
        raise SystemExit("One or more operational-value gates failed")


if __name__ == "__main__":
    main()
