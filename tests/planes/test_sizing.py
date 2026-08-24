"""The arithmetic that turns "we need a corpus" into a number somebody can fund.

None of this is milestone 3 and none of it produces ground truth. What these tests protect is
that the sizing is a derivation from measured inputs rather than a number in prose — the failure
mode being a plan that quotes a corpus size nobody can reproduce or challenge.
"""

from __future__ import annotations

import math

import pytest

from nemesis.calibration.sizing import (
    ASSUMED_RATE,
    TARGET_MARGINS,
    sample_size_for_margin,
    size_milestone_three,
)


def test_a_tighter_margin_costs_more_cases() -> None:
    sizes = [sample_size_for_margin(margin) for margin in sorted(TARGET_MARGINS, reverse=True)]
    assert sizes == sorted(sizes)


def test_halving_the_margin_roughly_quadruples_the_requirement() -> None:
    """The relationship that makes precision expensive, and the reason ±2% is a programme."""
    assert sample_size_for_margin(0.05) == pytest.approx(4 * sample_size_for_margin(0.10), rel=0.02)


def test_the_sizing_assumes_the_worst_case_rate() -> None:
    """p(1-p) peaks at a half, so any other assumption plans against a smaller corpus.

    Sizing at an optimistic rate produces one that turns out too small exactly when the answer
    is interesting.
    """
    assert ASSUMED_RATE == 0.5
    for rate in (0.1, 0.3, 0.7, 0.9):
        assert sample_size_for_margin(0.05, rate=rate) <= sample_size_for_margin(0.05)


def test_a_margin_outside_the_unit_interval_is_refused() -> None:
    for bad in (0.0, 1.0, -0.1, 1.5):
        with pytest.raises(ValueError, match="proportion"):
            sample_size_for_margin(bad)


def test_the_requirement_is_inflated_by_the_discriminating_fraction() -> None:
    """Pairs that cannot move under any perturbation teach a calibration nothing.

    Sizing against the raw precision arithmetic would under-order the corpus by the reciprocal
    of that fraction — roughly sixfold on the current grid.
    """
    report = size_milestone_three()
    assert 0.0 < report.discriminating_fraction < 1.0
    for requirement in report.requirements:
        assert requirement.total_pairs > requirement.discriminating_pairs
        assert requirement.total_pairs == math.ceil(
            requirement.discriminating_pairs / report.discriminating_fraction
        )


def test_pairs_per_operation_is_a_parameter_not_a_buried_constant() -> None:
    """How many usable pairs one operation yields is a design decision, not arithmetic."""
    lean = size_milestone_three(pairs_per_operation=1)
    rich = size_milestone_three(pairs_per_operation=4)
    assert lean.requirements[0].operations > rich.requirements[0].operations


def test_an_operation_yielding_no_pairs_is_refused() -> None:
    with pytest.raises(ValueError, match="no pairs"):
        size_milestone_three(pairs_per_operation=0)


def test_the_report_refuses_to_be_read_as_ground_truth() -> None:
    rendered = size_milestone_three().render()
    assert "NOT milestone 3" in rendered
    assert "order of magnitude" in rendered
