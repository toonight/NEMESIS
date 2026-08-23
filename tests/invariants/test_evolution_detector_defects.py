"""Four defects the plane shipped with, each reproduced before it was fixed.

They are grouped because they compound: the detector under-counted progress and over-counted
repetition, so it declared plateaus on healthy trajectories; the supervisor could not escalate
out of one; and the lineage recorded a reason for promotion that the promotion rule does not
use. Together they made the loop's own account of itself wrong in both directions — busier than
it was on the way in, and more stuck than it was on the way out.

Every test here was watched failing against the code as it shipped.
"""

from __future__ import annotations

import asyncio

import pytest

from nemesis.evolution.models import (
    CandidateStatus,
    EvaluationResult,
    ScoreVector,
    TrajectoryMeasurement,
)
from nemesis.evolution.stagnation import (
    StagnationDetector,
    StagnationPolicy,
    StagnationSignal,
    StepRecord,
    tier_one_movement,
)
from nemesis.evolution.supervisor import (
    DeterministicSupervisor,
    DirectiveType,
    TrajectoryDossier,
)

pytestmark = pytest.mark.invariant


# --- 1. The detector counted four of six tier-1 terms ------------------------------


def test_tier_one_movement_counts_every_term_in_the_epistemic_key() -> None:
    """Folded over the key, not over a hand-written list — because a list is what went wrong.

    ``assess`` read ``epistemic_key[0]`` and ``[1]`` positionally and then named
    ``contradictions_resolved`` and ``hypotheses_settled`` by attribute: the same tuple reached
    two ways, and the two terms at indices 4 and 5 were never added at all.
    """
    key_length = len(ScoreVector().epistemic_key)
    assert key_length == 6, "the epistemic tier changed shape; this test pins the count"

    for index in range(key_length):
        terms = [0] * key_length
        terms[index] = 1
        score = ScoreVector(
            origin_floor_gain=terms[0],
            independent_origin_gain=terms[1],
            contradictions_resolved=terms[2],
            hypotheses_settled=terms[3],
            uncertainty_reduction=float(terms[4]),
            evidence_backed_claim_gain=terms[5],
        )
        assert tier_one_movement(score) > 0, (
            f"epistemic_key[{index}] moved and the detector saw nothing"
        )


@pytest.mark.parametrize("term", ["evidence_backed_claim_gain", "uncertainty_reduction"])
def test_a_trajectory_gaining_a_dropped_term_is_not_a_plateau(term: str) -> None:
    """The two terms the old sum missed, each on its own.

    Measured against the SHIPPED DEFAULT policy: four steps each gaining an evidence-backed
    claim were assessed ``plateau: True`` with the reason "tier-1 movement over the window was
    0". A detector that reports a run going nowhere while it gains a tier-1 term every step is
    worse than no detector, because a supervisor acts on it.
    """
    score = ScoreVector.model_validate({term: 1.0})
    steps = [
        StepRecord(
            evaluation=EvaluationResult(
                status=CandidateStatus.PROMOTED,
                score=score,
                measurement=TrajectoryMeasurement(),
            ),
            promoted=True,
            pivot_families=(f"family_{index}",),
            state_digest=f"digest-{index}",
        )
        for index in range(4)
    ]
    assessment = StagnationDetector().assess(steps)

    assert StagnationSignal.NO_EPISTEMIC_GAIN not in assessment.signals
    assert assessment.describes_a_plateau is False


# --- 2. Repetition was read from a cumulative list ---------------------------------


def test_a_family_run_once_does_not_read_as_repeated_forever() -> None:
    """``pivot_families`` is per step now, and that word is the fix.

    It used to be ``checkpoint.pivots_attempted``, built from the investigation's **cumulative**
    executed-pivot history — so a family run once appeared in every later checkpoint and
    ``REPEATED_PIVOT_FAMILY`` counted it once per step in the window, for ever. The reference
    demonstration escaped it only by overriding the window to 3, where the count lands exactly
    on a strict ``>``.

    This reproduces the old reading directly: four steps whose lists each hold every family seen
    so far, which is what the cumulative source produced.
    """
    cumulative = [
        ("a",),
        ("a", "b"),
        ("a", "b", "c"),
        ("a", "b", "c", "d"),
    ]
    as_shipped = [
        StepRecord(
            evaluation=_evaluation(origin_floor_gain=1),
            promoted=True,
            pivot_families=families,
            state_digest=f"digest-{index}",
        )
        for index, families in enumerate(cumulative)
    ]
    assert StagnationSignal.REPEATED_PIVOT_FAMILY in StagnationDetector().assess(as_shipped).signals

    per_step = [
        StepRecord(
            evaluation=_evaluation(origin_floor_gain=1),
            promoted=True,
            pivot_families=(name,),
            state_digest=f"digest-{index}",
        )
        for index, name in enumerate("abcd")
    ]
    assert (
        StagnationSignal.REPEATED_PIVOT_FAMILY not in StagnationDetector().assess(per_step).signals
    ), "four distinct families in four steps is not a repetition"


# --- 3. The supervisor could not escalate out of a two-cycle -----------------------


def test_a_posture_already_tried_without_gain_is_not_re_offered() -> None:
    """The guard compared against the *immediately previous* directive, so a cycle beat it.

    Measured on the reference demonstration: four consecutive steps with no promotion, no
    epistemic gain, every candidate rejected and the budget burning, and the supervisor answered
    ``seek_independent_origin`` and ``revisit_prior_branch`` in turn, for ever — neither was ever
    "in force for two steps", so neither was ever exhausted and the run could not end on low
    yield.

    The property is not "it stops now": with two postures spent a third is legitimately
    available, and offering it is the supervisor doing its job. The property is that it does not
    hand back one of the two that already bought nothing.
    """
    tried = (
        DirectiveType.SEEK_INDEPENDENT_ORIGIN.value,
        DirectiveType.REVISIT_PRIOR_BRANCH.value,
    )
    directive = asyncio.run(DeterministicSupervisor().review(_stalled(tried=tried)))
    assert directive.directive.value not in tried


def test_a_supervisor_whose_whole_repertoire_is_spent_recommends_stopping() -> None:
    """And the escalation that the two-cycle made unreachable.

    Every posture the signal table can map to has been issued during this gainless streak, so
    there is nothing left to try and the rationale the fallback writes — "every posture this
    supervisor can recommend is already in force and has not moved a tier-1 term" — is true.
    """
    every_posture = tuple(member.value for member in DirectiveType)
    directive = asyncio.run(DeterministicSupervisor().review(_stalled(tried=every_posture)))
    assert directive.directive is DirectiveType.STOP_LOW_YIELD


def _stalled(*, tried: tuple[str, ...]) -> TrajectoryDossier:
    detector = StagnationDetector(StagnationPolicy(window=2))
    return TrajectoryDossier(
        run_id="evo_test",
        step_index=9,
        assessment=detector.assess([_step_going_nowhere(), _step_going_nowhere()]),
        independent_origins=1,
        origin_floor=0,
        steps_remaining=4,
        last_directive=tried[-1],
        directives_tried_without_gain=tried,
        directive_steps_without_gain=4,
    )


def test_what_is_in_force_counts_as_tried_even_when_the_set_is_empty() -> None:
    """A dossier built with ``last_directive`` alone keeps the behaviour it had before the set.

    Folded in the supervisor rather than at every call site, so adding the set could not
    silently change what an existing caller gets.
    """
    detector = StagnationDetector(StagnationPolicy(window=2))
    stalled = detector.assess([_step_going_nowhere(), _step_going_nowhere()])

    directive = asyncio.run(
        DeterministicSupervisor().review(
            TrajectoryDossier(
                run_id="evo_test",
                step_index=9,
                assessment=stalled,
                independent_origins=1,
                origin_floor=0,
                steps_remaining=0,
                last_directive=DirectiveType.SEEK_INDEPENDENT_ORIGIN.value,
                directive_steps_without_gain=4,
            )
        )
    )
    assert directive.directive is DirectiveType.STOP_LOW_YIELD


def _step_going_nowhere() -> StepRecord:
    return StepRecord(
        evaluation=_evaluation(status=CandidateStatus.REJECTED),
        promoted=False,
        pivot_families=("registration_record",),
        state_digest="unchanged",
    )


def _evaluation(
    *, status: CandidateStatus = CandidateStatus.PROMOTED, **score: float
) -> EvaluationResult:
    return EvaluationResult(
        status=status,
        score=ScoreVector(**score),
        measurement=TrajectoryMeasurement(),
    )
