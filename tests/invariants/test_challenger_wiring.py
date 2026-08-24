"""The challenger is reachable from the paths that ship, not only from the benchmark.

``nemesis.pilot.challenger`` was built, documented and covered by
``tests/invariants/test_challenger.py`` — and then wired into nothing. ``challenger=`` was passed
at two sites in ``src/``, both inside ``pilotbench``, and even there the two factories that build
a bench subject left it ``None``. All three shipped sessions constructed a mediator without one.
A control nobody can switch on is indistinguishable from a control that does not exist.

These tests assert the wire rather than the component: a challenger handed to each shipped
entry point actually reaches the mediator and actually refuses a move. They deliberately do not
re-test what the challenger *is* — its vocabulary, its failure mode and its inability to
authorize anything are asserted next door, and duplicating them here would mean two files
disagree the day one changes.

The default stays ``None`` everywhere. A challenger worth having is a second model from a
different vendor (correlated reasoning failure is the whole reason it is configured separately
from the pilot), and the reference demonstrations run offline against fixtures. So the shipped
default is the baseline posture every containment test is written against, and the wire is what
a deployment with a second provider now has available.
"""

from __future__ import annotations

import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import pytest

from nemesis.pilot.challenger import (
    ChallengePolicy,
    ChallengerRuling,
    ChallengerVerdict,
    MoveChallenger,
)
from nemesis.pilot.moves import Briefing, PilotMove, RulingStatus

pytestmark = pytest.mark.invariant


class AlwaysObjects:
    """A challenger that contradicts everything it is shown.

    Not a realistic challenger and not trying to be. It is the smallest thing that makes the
    difference between "the parameter is accepted" and "the parameter changes what happens"
    visible in a session transcript.
    """

    def __init__(self) -> None:
        self.reviewed: list[str] = []

    @property
    def name(self) -> str:
        return "always-objects"

    async def review(
        self, briefing: Briefing, move: PilotMove
    ) -> ChallengerRuling | Mapping[str, Any]:
        self.reviewed.append(move.kind)
        return ChallengerRuling(
            verdict=ChallengerVerdict.CONTRADICTED,
            reason="the evidence shown does not support this move",
        )


def blocking_everything_gated() -> ChallengePolicy:
    """Default policy: effects and beliefs are gated, pivots and conclusions are not."""
    return ChallengePolicy()


@pytest.mark.anyio
async def test_the_pilot_demonstration_accepts_a_challenger_and_it_refuses() -> None:
    from nemesis.slice.pilot_session import run_pilot_demonstration

    challenger = AlwaysObjects()
    with tempfile.TemporaryDirectory() as workspace:
        result = await run_pilot_demonstration(
            workspace=Path(workspace),
            challenger=cast(MoveChallenger, challenger),
            challenge_policy=blocking_everything_gated(),
        )

    assert challenger.reviewed, "the challenger was never consulted"
    refused = [r for r in result.session.rulings if r.status is RulingStatus.REFUSED_CHALLENGED]
    assert refused, "a contradicting challenger refused nothing"
    assert result.session.any_effect_left_the_platform() is False


@pytest.mark.anyio
async def test_the_pilot_demonstration_without_a_challenger_is_unchanged() -> None:
    """The shipped default. Every containment test is written against this posture."""
    from nemesis.slice.pilot_session import run_pilot_demonstration

    with tempfile.TemporaryDirectory() as workspace:
        result = await run_pilot_demonstration(workspace=Path(workspace))

    assert not [r for r in result.session.rulings if r.status is RulingStatus.REFUSED_CHALLENGED]


@pytest.mark.anyio
async def test_the_evolution_demonstration_accepts_a_challenger_and_it_refuses() -> None:
    from nemesis.slice.evolution_session import run_evolution_demonstration

    challenger = AlwaysObjects()
    with tempfile.TemporaryDirectory() as workspace:
        result = await run_evolution_demonstration(
            workspace=Path(workspace),
            challenger=cast(MoveChallenger, challenger),
            challenge_policy=blocking_everything_gated(),
        )

    assert challenger.reviewed, "the challenger was never consulted"
    refused = [
        ruling
        for outcome in result.outcomes
        for ruling in outcome.session.rulings
        if ruling.status is RulingStatus.REFUSED_CHALLENGED
    ]
    assert refused, "a contradicting challenger refused nothing across the whole run"
    assert all(r.move_kind in ChallengePolicy().gated_kinds for r in refused)


@pytest.mark.anyio
async def test_the_loop_benchmark_consults_a_challenger_and_still_lets_the_pilot_look() -> None:
    """The wire reaches the benchmark's world, and a challenger still cannot stop a pivot.

    The cycling pilot only pivots, so a challenger that contradicts *everything* blocks nothing
    here — and that is the design rather than a gap in the wiring. A challenger able to refuse
    ``run_pivot`` is a denial-of-service surface with no matching safety gain: it could stop an
    investigation from looking, while the moves that actually change the graph or touch the
    world are the ones already gated.

    Written this way after the first version asserted ``refused > 0`` and failed. The wire was
    fine; the assertion was wrong, and pinning the real behaviour is worth more than deleting
    the test.
    """
    from nemesis.slice.loopbench import PILOTS, run_plain_arm

    challenger = AlwaysObjects()
    _, make_cycling = PILOTS[0]
    with tempfile.TemporaryDirectory() as workspace:
        measurement = await run_plain_arm(
            make_cycling,
            moves=12,
            budget=60.0,
            root=Path(workspace),
            challenger=cast(MoveChallenger, challenger),
            challenge_policy=blocking_everything_gated(),
        )

    assert challenger.reviewed, "the challenger was never consulted"
    assert set(challenger.reviewed) == {"run_pivot"}
    assert measurement.refused == 0, "a challenger must not be able to stop a pivot"
    assert measurement.accepted == measurement.moves


def test_the_reference_bench_subjects_can_carry_a_challenger() -> None:
    """``reference_subjects()`` built every subject with ``challenger=None``.

    The benchmark is the one place a challenger was already plumbed, and the two factories that
    produce its subjects both dropped it — so the plumbing measured a configuration nobody could
    produce.
    """
    from nemesis.pilotbench.runner import reference_subjects

    def make() -> MoveChallenger:
        return cast(MoveChallenger, AlwaysObjects())

    subjects = reference_subjects(challenger=make)
    assert subjects, "no reference subjects"
    assert all(subject.challenger is not None for subject in subjects)

    plain = reference_subjects()
    assert all(subject.challenger is None for subject in plain)


# -- varying the seed, so an adaptation experiment is runnable at all ----------------


@pytest.mark.anyio
async def test_every_offered_seed_actually_produces_an_investigation() -> None:
    """A seed with no fixtures behind it measures the absence of data, not the pilot.

    Added so that "run it from a different seed to see whether the pilot adapts" is an
    experiment somebody can run rather than a suggestion. Each of the four is a genuinely
    different entry point into the same operation — different registrar, different resolution
    history, different position in the cluster.
    """
    from nemesis.slice.pilot_session import SEEDABLE_DOMAINS, run_pilot_demonstration

    assert len(SEEDABLE_DOMAINS) >= 2
    for seed in SEEDABLE_DOMAINS:
        with tempfile.TemporaryDirectory() as workspace:
            result = await run_pilot_demonstration(workspace=Path(workspace), seed_domain=seed)
        assert result.session.investigation.seed.entity_key == seed
        assert result.session.rulings, f"seed {seed} produced no moves"


@pytest.mark.anyio
async def test_a_seed_with_no_fixtures_is_refused_rather_than_run_empty() -> None:
    from nemesis.slice.pilot_session import run_pilot_demonstration

    with pytest.raises(ValueError, match="fixture coverage"):
        await run_pilot_demonstration(seed_domain="nowhere.example")
