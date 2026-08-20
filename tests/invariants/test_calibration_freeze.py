"""Freeze before evaluate, enforced rather than promised.

The largest declared weakness of this project is that no confidence figure it produces has ever
been scored against a known-correct answer. Closing that needs a corpus of resolved cases, and
a corpus is worth nothing if the engine can be adjusted while it is being graded: a score
obtained by tuning against the cases that measure you is a score of your tuning.

Every calibration constant here is a documented *choice*, which makes the temptation concrete —
each is a dial, and each moves a number somebody is about to grade. These tests are what stops
"we froze first" from being a claim in a protocol document that nobody can check.
"""

from __future__ import annotations

import pytest

from nemesis.calibration.freeze import (
    CALIBRATION_CONSTANTS,
    FROZEN_DIGEST,
    drifted,
    freeze_digest,
    observed_values,
    unregistered_calibration_constants,
)
from nemesis.core.confidence import Opinion
from nemesis.core.fusion import cumulative_belief_fusion, weighted_belief_fusion

pytestmark = pytest.mark.invariant


# --- The constants -----------------------------------------------------------


def test_no_calibration_constant_has_moved_since_the_freeze() -> None:
    """THE ONE THIS FILE EXISTS FOR.

    A mismatch is not a bug in the code. It means a dial moved, and it forces the question that
    matters: did that happen *before* an evaluation or *during* one? Constants should change
    when there is a reason — what must not happen is that they change quietly, which is exactly
    what a promise in a document permits.

    Updating `FROZEN_DIGEST` is the deliberate act: one line, in its own commit, with the
    reason. That is the whole mechanism.
    """
    assert freeze_digest() == FROZEN_DIGEST, (
        "a calibration constant changed. If that was deliberate, update FROZEN_DIGEST in its "
        "own commit and say why; if it was not, this is the drift the freeze exists to catch"
    )
    assert drifted() == ()


def test_every_scoring_constant_is_registered() -> None:
    """The way to defeat a freeze is to add a dial and not list it.

    An enumerated registry cannot notice its own omissions, so the modules where confidence is
    decided are scanned for module-level numbers that are neither registered nor recognised as
    operational. A new constant has to be one or the other — never neither.
    """
    stray = unregistered_calibration_constants()

    assert stray == (), (
        f"these numbers live in a scoring module and are not registered: {stray}. Either add "
        "them to CALIBRATION_CONSTANTS, or — if they are operational rather than epistemic — "
        "name them in _NOT_CALIBRATION with that reasoning"
    )


def test_the_registry_reads_the_real_modules() -> None:
    """Imported, not parsed. A constant that was renamed or moved must fail loudly here rather
    than being read from a stale copy of the source and silently frozen at the wrong value."""
    values = observed_values()

    assert len(values) == len(CALIBRATION_CONSTANTS)
    assert all(isinstance(value, int | float) for value in values.values())
    # Spot-check two that carry very different meanings, so a wholesale rewiring of the
    # registry to a single module could not pass this.
    assert values["nemesis.resolve.signals:STYLOMETRY_BELIEF_CEILING"] == 0.15
    assert values["nemesis.attribute.engine:DECEPTION_BASE_RATE"] == 0.25


# --- The behaviour -----------------------------------------------------------


def test_the_fusion_operators_still_answer_the_same() -> None:
    """Golden vectors: fixed inputs, fixed outputs.

    Hashing the source of the fusion operators would have been easier and worse — a reworded
    comment would break it while a changed sign would not, which is the wrong sensitivity in
    both directions. What has to hold across an evaluation is not that the code is identical
    but that it **answers the same**.

    These numbers were **read off the engine**, not predicted. The first draft of this test
    guessed them and would have frozen four wrong assertions — which is the failure a golden
    vector exists to prevent, committed inside the mechanism meant to prevent it. If one moves
    later, the engine's behaviour changed, and any measurement taken before that point
    describes a different system.
    """
    weak = Opinion(belief=0.2, disbelief=0.1, uncertainty=0.7, base_rate=0.5)
    strong = Opinion(belief=0.7, disbelief=0.1, uncertainty=0.2, base_rate=0.5)
    against = Opinion(belief=0.1, disbelief=0.6, uncertainty=0.3, base_rate=0.5)

    # Two independent origins agreeing: cumulative fusion should reduce uncertainty below
    # either input, which is the whole reason independence is worth establishing.
    agreed = cumulative_belief_fusion((weak, strong))
    assert round(agreed.belief, 6) == 0.697368
    assert round(agreed.uncertainty, 6) == 0.184211
    assert agreed.uncertainty < min(weak.uncertainty, strong.uncertainty)

    # The same two, treated as one dependence group: averaging, not accumulating. A weaker
    # answer than the above, and deliberately so — sources that may share an origin must not
    # compound.
    averaged = weighted_belief_fusion((weak, strong))
    assert round(averaged.belief, 6) == 0.651613
    assert round(averaged.uncertainty, 6) == 0.248387
    assert averaged.uncertainty > agreed.uncertainty  # averaging never compounds

    # Disagreement must not average away into a confident middle.
    conflicted = cumulative_belief_fusion((strong, against))
    assert round(conflicted.belief, 6) == 0.522727
    assert round(conflicted.disbelief, 6) == 0.340909
    assert round(conflicted.uncertainty, 6) == 0.136364


def test_a_vacuous_opinion_stays_vacuous_through_fusion() -> None:
    """The property that keeps "we do not know" from becoming "we mildly believe" by being
    fused with other things that also do not know. Pinned at the freeze because it is the
    behaviour an evaluation would most easily flatter."""
    nothing = Opinion(belief=0.0, disbelief=0.0, uncertainty=1.0, base_rate=0.5)

    assert cumulative_belief_fusion((nothing, nothing)).uncertainty == 1.0
    assert weighted_belief_fusion((nothing, nothing)).uncertainty == 1.0
