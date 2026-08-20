"""The calibration harness, and the limits it is required to state.

Two things are tested here that are easy to get wrong in opposite directions: the scoring
maths, which must be exactly right, and the harness's own claims about itself, which must be
exactly modest. A harness that overstates what it proves is worse than none, because its
output is designed to be trusted.
"""

from __future__ import annotations

import random

import pytest

from nemesis.calibration.generator import CaseGenerator, CaseKind, GeneratorAssumptions
from nemesis.calibration.harness import ACTIONABLE_BANDS, run_calibration
from nemesis.calibration.scoring import brier_decomposition, discrimination_auc

# --- The decomposition maths --------------------------------------------------


def test_murphys_identity_is_exact_for_discrete_forecasts() -> None:
    """BS = REL - RES + UNC, exactly, when each bin isolates one forecast value.

    This is the test that says the implementation is right. Any residual here is a bug,
    unlike the residual on continuous forecasts, which is a property of binning.
    """
    rng = random.Random(11)
    forecasts = [rng.choice([0.05, 0.25, 0.45, 0.65, 0.85]) for _ in range(600)]
    outcomes = [rng.random() < value for value in forecasts]

    result = brier_decomposition(forecasts, outcomes)
    assert result.binning_discrepancy < 1e-12


def test_binning_continuous_forecasts_leaves_a_discrepancy_and_that_is_expected() -> None:
    """Pins the corrected understanding.

    An earlier docstring called this residual evidence that every number was wrong. It is
    not: it is a measure of bin coarseness, and it would have fired on every real run
    because NEMESIS produces continuous forecasts.
    """
    rng = random.Random(7)
    forecasts = [rng.random() for _ in range(500)]
    outcomes = [rng.random() < value for value in forecasts]

    result = brier_decomposition(forecasts, outcomes)
    assert result.binning_discrepancy > 0.0
    assert result.binning_discrepancy < 0.05


def test_a_forecaster_that_always_says_the_base_rate_scores_well_and_resolves_nothing() -> None:
    """The degenerate case the decomposition exists to expose.

    NEMESIS could earn an excellent Brier score by refusing to say anything. Reliability
    alone would call that success; resolution is what catches it.
    """
    rng = random.Random(3)
    outcomes = [rng.random() < 0.4 for _ in range(800)]
    base = sum(1 for o in outcomes if o) / len(outcomes)
    forecasts = [base] * len(outcomes)

    result = brier_decomposition(forecasts, outcomes)
    assert result.reliability == pytest.approx(0.0, abs=1e-9)
    assert result.resolution == pytest.approx(0.0, abs=1e-9)
    assert result.skill_against_base_rate == pytest.approx(0.0, abs=1e-9)
    assert "resolution is near zero" in result.render()


def test_auc_is_none_rather_than_a_number_when_one_class_is_absent() -> None:
    """Returning 0.5 there would look like a measurement of something."""
    assert discrimination_auc([0.2, 0.8], [True, True]) is None
    assert discrimination_auc([0.2, 0.8], [False, False]) is None


def test_auc_counts_ties_as_half() -> None:
    """A system that refuses produces many identical forecasts; counting those as wins
    would flatter it."""
    assert discrimination_auc([0.5, 0.5], [True, False]) == pytest.approx(0.5)
    assert discrimination_auc([0.9, 0.1], [True, False]) == pytest.approx(1.0)


def test_scoring_refuses_mismatched_or_empty_input() -> None:
    with pytest.raises(ValueError, match="same length"):
        brier_decomposition([0.5], [True, False])
    with pytest.raises(ValueError, match="empty sample"):
        brier_decomposition([], [])


# --- The generator ------------------------------------------------------------


def test_the_generator_is_reproducible() -> None:
    """A calibration figure nobody can re-run is an assertion, not a measurement."""
    first = CaseGenerator().generate(count=40, seed=99)
    second = CaseGenerator().generate(count=40, seed=99)

    assert [c.case_id for c in first] == [c.case_id for c in second]
    assert [c.truth for c in first] == [c.truth for c in second]
    assert [c.source_count for c in first] == [c.source_count for c in second]


def test_a_laundered_case_has_many_sources_and_one_real_origin() -> None:
    """The gap between those two numbers is the entire measurement."""
    cases = CaseGenerator().generate_kind(CaseKind.LAUNDERED, count=20, seed=5)
    for case in cases:
        assert case.distinct_real_origins == 1
        assert case.source_count >= 3
        assert case.truth is False


def test_generator_assumptions_are_reported_verbatim() -> None:
    """Every conditional number rests on these, so they travel with the report."""
    lines = " ".join(GeneratorAssumptions().as_lines())
    assert "prevalence" in lines
    assert "inflates any score" in lines


# --- The harness's claims about itself ----------------------------------------


def test_the_report_leads_with_what_it_cannot_tell_you() -> None:
    """Before any figure. A page of confident numbers with the caveat at the bottom is a
    page of confident numbers."""
    rendered = run_calibration(cases=120).render()
    limits = rendered.index("WHAT THIS CANNOT TELL YOU")
    first_number = rendered.index("PROPERTIES")

    assert limits < first_number
    assert "is not calibration" in rendered or "Nothing here is calibration" in rendered
    assert "ADR-0003" in rendered


def test_every_structural_property_holds() -> None:
    """These stand on their own: each perturbs the input in a way we control."""
    report = run_calibration(cases=120)
    failures = [item.name for item in report.properties if not item.holds]
    assert not failures, f"structural properties failed: {failures}"


def test_laundering_adds_exactly_no_confidence() -> None:
    report = run_calibration(cases=120)
    assert report.laundering_inflation == pytest.approx(0.0, abs=1e-9)


def test_one_planted_fact_no_longer_reaches_an_actionable_band() -> None:
    """The fix, asserted directly rather than by equality of two rates.

    An earlier version of this test asserted that the laundering and single-source rates
    were EQUAL, which was the correct way to state the defect: the defence stopped
    amplification and the attack never needed it. Once the robustness margin landed, both
    rates went to zero and that equality began to pass vacuously — it would have kept
    passing if the fix were reverted and both rates returned to 100%.

    Asserting the rates are zero cannot pass vacuously in either direction.
    """
    report = run_calibration(cases=120)
    assert report.laundering_false_match_rate == 0.0
    assert report.single_source_false_match_rate == 0.0


def test_the_aggregate_score_is_reported_with_a_per_kind_breakdown() -> None:
    """The case mix is deliberately adversarial, so the aggregate mixes cases where
    discrimination is possible with cases where refusing is correct. Reporting only the
    aggregate would read as a verdict on the forecaster."""
    report = run_calibration(cases=120)
    kinds = {kind for kind, _, _ in report.per_kind_brier}

    assert CaseKind.GENUINE_INDEPENDENT.value in kinds
    assert CaseKind.LAUNDERED.value in kinds
    assert "not a verdict on the system" in report.render()


def test_the_actionable_threshold_starts_at_likely() -> None:
    """An investigation starts well below certainty, so the false-match question is asked
    at the band where somebody would act, not at the band where they would be sure."""
    from nemesis.core.confidence import ConfidenceBand

    assert ConfidenceBand.LIKELY in ACTIONABLE_BANDS
    assert ConfidenceBand.ROUGHLY_EVEN not in ACTIONABLE_BANDS
    assert ConfidenceBand.INSUFFICIENT_BASIS not in ACTIONABLE_BANDS
