"""The study that measures how much two unvalidated numbers matter.

It is not calibration and the module says so at length. What these tests protect is that the
study is capable of finding something — a probe set where nothing ever moves reports perfect
stability and means nothing — and that running it leaves the shipped constants exactly as it
found them.
"""

from __future__ import annotations

from nemesis.calibration.ceilings import (
    FLOOR_PERTURBATIONS,
    PROBE_AT,
    PROBE_POPULATION,
    _actionable_at,
    measure_ceiling_sensitivity,
    measure_floor_sensitivity,
    probe_cases,
)
from nemesis.pursuit.resurgence import ACTIONABLE_FLOOR, BELIEF_CEILING, ResurgenceEngine


def test_the_probe_set_discriminates() -> None:
    """A study over cases that all land the same way measures nothing.

    Asserted first because every other figure here is meaningless without it: perfect stability
    over a set that cannot move is the shape of a control that has quietly stopped working.
    """
    result = measure_ceiling_sensitivity()
    verdicts = {actionable for _, actionable in result.baseline}
    assert verdicts == {True, False}, "the probe set does not span the decision boundary"


def test_the_study_can_find_something() -> None:
    """At least one perturbation must move a verdict, or the instrument is blunt."""
    result = measure_ceiling_sensitivity()
    assert any(not item.stable for item in result.results)


def test_running_the_study_leaves_the_shipped_ceilings_untouched() -> None:
    """The worst possible bug in a module about not trusting these numbers.

    The table is mutated in place because the engine reads it through a module-level name, and
    a probe that left it perturbed would silently change every verdict the platform reaches
    afterwards.
    """
    before = dict(BELIEF_CEILING)
    measure_ceiling_sensitivity()
    measure_floor_sensitivity()
    assert dict(BELIEF_CEILING) == before


def test_the_floor_study_does_not_rebind_the_shipped_threshold() -> None:
    """It recomputes the verdict instead, which needs no mutation and cannot leak."""
    import nemesis.pursuit.resurgence as engine_module

    measure_floor_sensitivity()
    assert engine_module.ACTIONABLE_FLOOR == ACTIONABLE_FLOOR


def test_the_parameterised_verdict_agrees_with_the_shipped_one_at_the_shipped_floor() -> None:
    """Otherwise the floor study would be measuring a different function from the engine's."""
    engine = ResurgenceEngine()
    for case in probe_cases():
        assessment = engine.assess(
            campaign="probe",
            signals=case.signals,
            candidate_population=PROBE_POPULATION,
            assessed_at=PROBE_AT,
        )
        assert _actionable_at(assessment, ACTIONABLE_FLOOR) == assessment.is_actionable


def test_the_claim_verdict_follows_from_the_measurements() -> None:
    """``claim_holds`` is derived, not decided.

    Deliberately not asserting *which* way it comes out. Pinning the current answer would turn
    a finding into a fixture, and the point of the study is that the answer can change when the
    ceilings, the probe set or the engine do.
    """
    result = measure_ceiling_sensitivity()
    expected = result.order_preserving_moves == 0 and result.order_breaking_moves > 0
    assert result.claim_holds is expected


def test_the_report_says_which_way_the_claim_went() -> None:
    """A reader must not have to infer it from the table."""
    result = measure_ceiling_sensitivity()
    rendered = result.render()
    assert "NOT calibration" in rendered
    assert (
        ("claim holds" in rendered)
        or ("claim does NOT hold" in rendered)
        or ("Inconclusive" in rendered)
    )


def test_the_floor_study_probes_both_sides_of_the_shipped_value() -> None:
    """A one-sided probe would only ever find the threshold too strict or too loose."""
    assert any(floor < ACTIONABLE_FLOOR for floor in FLOOR_PERTURBATIONS)
    assert any(floor > ACTIONABLE_FLOOR for floor in FLOOR_PERTURBATIONS)
