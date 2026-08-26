"""Controlled operations on a loopback range, and the limitation they exposed.

The bench exists because milestone 3 was declined: it is the part of controlled operations that
needs no funding and no registrar. What it produces is real — real keys, real certificates, real
handshakes — with the linkage known because the module minted it.

The test that matters most here is the adversarial one, and it asserts a *failure*.
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from nemesis.calibration.localbench import (
    EXERCISED_KINDS,
    UNTOUCHED_KINDS,
    BenchResult,
    open_range,
    run_local_bench,
    run_operation,
)
from nemesis.pursuit.resurgence import ResurgenceSignalKind

NOW = datetime(2026, 6, 1, tzinfo=UTC)


def bench(operations: int = 12) -> BenchResult:
    with tempfile.TemporaryDirectory() as workspace:
        return run_local_bench(Path(workspace), operations=operations, now=NOW)


# -- containment, first --------------------------------------------------------------


def test_the_bench_holds_no_network_capability() -> None:
    """It opened a loopback TLS socket once, and `check_prohibited.py` was right to refuse it.

    Only the collection plane may import a network client. The scanner's own rationale is that
    the danger is not an obvious port scanner but a well-intentioned module quietly growing a
    real socket during development — which is exactly what this was, guarded by a
    `_require_loopback` function that a coarse scanner cannot and should not trust.

    Asserted on the module's imports rather than on its behaviour, because that is the property
    the control checks and the one a future edit would break.
    """
    import ast

    from nemesis.calibration import localbench

    tree = ast.parse(Path(localbench.__file__).read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported & {"socket", "ssl", "http", "urllib", "httpx", "requests", "asyncio"}


# -- the artifacts are real ----------------------------------------------------------


def test_the_fingerprint_comes_off_serialised_bytes_not_off_the_object_we_minted() -> None:
    """What separates this from a fixture, after the handshake had to go.

    Weaker than it was — the DER no longer crosses a wire — and still not a fixture: every
    fingerprint is computed from serialised bytes, and the SPKI is parsed back out of them.
    """
    with tempfile.TemporaryDirectory() as workspace:
        span = open_range(Path(workspace))
        operation = run_operation(
            span,
            name="probe.bench.invalid",
            key_id="k",
            kit_id="kit",
            drop="d@bench.invalid",
            started_at=NOW,
        )
    assert len(operation.certificate_der) > 100
    assert len(operation.spki_fingerprint) == 64
    assert operation.kit_hash != operation.spki_fingerprint


def test_two_operations_sharing_a_key_have_different_certificates_and_one_public_key() -> None:
    """The correction the bench made to itself.

    Reusing a key yields two *different* certificates, so comparing certificate fingerprints
    finds nothing. The public key is what survives reissuance and is what a defender pivots on.
    """
    with tempfile.TemporaryDirectory() as workspace:
        span = open_range(Path(workspace))
        first = run_operation(
            span,
            name="a.bench.invalid",
            key_id="shared",
            kit_id="k1",
            drop="d1@bench.invalid",
            started_at=NOW,
        )
        second = run_operation(
            span,
            name="b.bench.invalid",
            key_id="shared",
            kit_id="k2",
            drop="d2@bench.invalid",
            started_at=NOW,
        )
    assert first.certificate_fingerprint != second.certificate_fingerprint
    assert first.spki_fingerprint == second.spki_fingerprint


# -- what it measures ----------------------------------------------------------------


def test_linked_pairs_with_two_facts_are_recognised() -> None:
    result = bench()
    assert result.clearable_pairs
    assert result.true_positives == len(result.clearable_pairs)


def test_linked_pairs_resting_on_one_fact_are_refused() -> None:
    """The single-origin veto, on genuinely linked pairs. Refusing these is correct."""
    result = bench()
    single = [o for o in result.linked_pairs if len(o.signals) == 1]
    assert single
    assert result.single_fact_refusals == len(single)


def test_pairs_sharing_nothing_are_never_called_linked() -> None:
    result = bench()
    trivially_unlinked = [o for o in result.unlinked_pairs if not o.signals]
    assert trivially_unlinked
    assert not any(o.called_linked for o in trivially_unlinked)


# -- the finding: the margin does not stop a planted artifact ------------------------


def test_a_framer_who_copies_the_observables_is_refused() -> None:
    """Was an assertion of failure until ADR-0013; now an assertion of the defence.

    The history matters and is why this test was rewritten rather than replaced. It used to
    assert ``any(o.called_linked for o in planted)`` — the engine attributing a *framer* to the
    party they framed, 2 of 3 adversarial pairs — with a note that the fix was a threat-model
    change and belonged in an ADR. Its own text said that if it ever passed, it should be
    rewritten to assert the defence rather than deleted. This is that rewrite.

    What changed: :data:`~nemesis.pursuit.resurgence.FRAMER_COSTLY_KINDS` and the fifth veto on
    ``is_actionable``. A key and a kit are copies; a drop address is a transfer, and a framer
    presenting one is routing their victims' credentials to the party they are framing.
    """
    result = bench()
    planted = result.planted_pairs
    assert planted, "the bench produced no adversarial pairs, so this proves nothing"
    assert not any(o.called_linked for o in planted), (
        "a framer was attributed to the party they framed: "
        + "; ".join(
            f"{o.left} x {o.right} {sorted(s.kind.value for s in o.signals)}"
            for o in planted
            if o.called_linked
        )
    )


def test_refusing_the_framer_did_not_cost_the_genuine_findings() -> None:
    """The half that is not optional, and the reason the test above is not enough on its own.

    Measured while writing ADR-0013: removing ``OWN_SENSOR`` from the unplantable allowlist also
    takes the adversarial figure to 0/3 — and recall from 10/10 to 0/10. An engine that refuses
    everything satisfies the framer assertion perfectly and is useless. Any future change that
    buys the framer refusal with recall fails here rather than passing quietly.
    """
    result = bench()
    clearable = result.clearable_pairs
    assert clearable, "no linked pair carried enough facts to be recognisable"
    assert result.true_positives == len(clearable), (
        f"recall fell to {result.true_positives}/{len(clearable)}; a framer defence bought "
        f"with recall is the blunt fix ADR-0013 measured and rejected"
    )
    assert result.single_fact_refusals, (
        "no linked pair rests on a single fact, so the single-origin veto is unmeasured — the "
        "shape the fixture had when every operation shared a drop"
    )


def test_the_bench_reports_the_adversarial_result_rather_than_averaging_it_away() -> None:
    """A false-positive rate over thousands of trivially-unlinked pairs cannot go up."""
    rendered = bench().render()
    assert "ADVERSARIAL" in rendered
    assert "refused trivially" in rendered


# -- and it says what it cannot reach ------------------------------------------------


def test_the_untouched_kinds_are_named_not_omitted() -> None:
    assert set(ResurgenceSignalKind) == EXERCISED_KINDS | UNTOUCHED_KINDS
    assert not EXERCISED_KINDS & UNTOUCHED_KINDS
    rendered = bench().render()
    for kind in UNTOUCHED_KINDS:
        assert kind.value in rendered


def test_a_range_of_one_operation_is_refused() -> None:
    with pytest.raises(ValueError, match="no pair"):
        bench(operations=1)


def test_the_bench_scores_the_recurrence_half_against_its_own_ground_truth() -> None:
    """Without this column the bench cannot see that the split happened.

    Every bench source is an own sensor, so ``fuse`` returns ``no_removable_fact`` on every pair
    and the margin removes nothing — which means the identity figures are byte-identical whether
    the recurrence half is wired correctly, wired to the wrong thing, or not wired at all. The
    two halves need two ground truths: ``truly_linked`` is *same operator*, and this one is
    *the range minted one artifact for both ends*.

    They disagree on exactly the adversarial pairs, which is the split stated as a measurement:
    the framer's values really do recur, and the operator really is not the same.
    """
    result = bench()
    sharing = result.artifact_sharing_pairs
    assert sharing, "no pair shares an artifact, so this measures nothing"
    assert result.continuity_recognised == len(sharing), (
        f"recurrence established on only {result.continuity_recognised}/{len(sharing)} pairs "
        f"that really do share an artifact"
    )
    assert result.continuity_false == 0, (
        f"recurrence established on {result.continuity_false} pairs that share nothing at all"
    )
    for outcome in result.planted_pairs:
        assert outcome.shares_a_real_artifact, "the framer must really share the artifacts"
        assert outcome.continuity_established, "the framer's values really do recur"
        assert not outcome.called_linked, "and the operator really is not the same"


def test_the_report_states_both_conclusions_and_that_they_are_scored_differently() -> None:
    """A reader must not take the recurrence figure as support for the identity one."""
    rendered = bench().render()
    assert "RECURRENCE" in rendered
    assert "ADVERSARIAL" in rendered
    assert "different* ground truth" in rendered
