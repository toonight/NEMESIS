"""The reference long-horizon run, asserted rather than described.

`docs/architecture/evolution-plane.md` claims an arc: memory that pays for itself, a plateau, a
redirect, a hostile hint that goes nowhere, and a hard edge that does not move. Documentation that
contradicts the code is a defect in this repository, so every one of those claims is a test here.

One module-scoped fixture, because the run does real collection and real sealing and is expensive
enough that eight tests should not each pay for it — the pattern `test_end_to_end.py` already uses.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from nemesis.evolution.lineage import LineageEventKind, active_lineage, verify_lineage_chain
from nemesis.evolution.models import StopReason
from nemesis.slice.evolution_session import (
    BENIGN_HINT,
    DEAD_DIRECTION,
    HOSTILE_HINT,
    EvolutionDemonstration,
    run_evolution_demonstration,
)

pytestmark = pytest.mark.slice


@pytest.fixture(scope="module")
def demonstration(tmp_path_factory: pytest.TempPathFactory) -> EvolutionDemonstration:
    workspace: Path = tmp_path_factory.mktemp("evolution")
    return asyncio.run(run_evolution_demonstration(workspace=workspace))


def test_the_run_makes_progress_at_all(demonstration: EvolutionDemonstration) -> None:
    """A guard against the guard. A demonstration in which nothing was promoted would make every
    assertion below true for the wrong reason."""
    assert demonstration.outcomes, "the run took no steps"
    assert len(demonstration.promoted) >= 2, (
        "nothing was promoted; the rest of this file is vacuous"
    )


def test_a_direction_that_returns_nothing_is_recorded_and_then_dropped(
    demonstration: EvolutionDemonstration,
) -> None:
    """THE MECHANISM THE PLANE EXISTS FOR.

    The pilot asks a question no connector can answer, repeatedly. Nothing refuses it — the mediator
    refuses moves and this plane never becomes a second one. What happens instead is that the
    trajectory records the failure, the next briefing carries it, and the pilot stops asking.
    """
    narration = " | ".join(demonstration.narration)
    assert f"Trying {DEAD_DIRECTION.value}" in narration, "the dead direction was never tried"
    assert "is exhausted" in narration, "the memory never told the pilot the direction was spent"

    memory = demonstration.state.memory
    assert DEAD_DIRECTION.value in memory.exhausted_pivot_families
    tried = [r for r in memory.failed_directions if r.pivot_family == DEAD_DIRECTION.value]
    assert tried and tried[0].occurrences >= 2, "repeats were duplicated instead of counted"


def test_repeating_a_spent_direction_is_counted_as_a_cost(
    demonstration: EvolutionDemonstration,
) -> None:
    """It is a cost, not a refusal. A plane that refused a move would be a second limiter."""
    assert demonstration.redundant_pivots > 0
    penalised = [o for o in demonstration.outcomes if o.evaluation.score.redundant_pivots > 0]
    assert penalised, "no step was charged for redundant work"
    assert not any(o.promoted for o in penalised), "a step of pure repetition was promoted"


def test_a_plateau_is_detected_and_produces_a_directive(
    demonstration: EvolutionDemonstration,
) -> None:
    assert demonstration.plateaus > 0, "no plateau fired in a run that clearly stalled"
    assert demonstration.directives, "a plateau fired and no directive was issued"
    assert "seek_independent_origin" in demonstration.directives


def test_the_run_stops_on_a_deterministic_condition(
    demonstration: EvolutionDemonstration,
) -> None:
    """Long horizon is not the same as unbounded, and a stop is a condition rather than a mood."""
    assert demonstration.state.stop_reason is not None
    assert demonstration.state.stop_reason in set(StopReason)
    assert demonstration.state.stop_reason is StopReason.LOW_YIELD


def test_the_hijacked_effect_is_refused_exactly_as_it_is_without_a_research_loop(
    demonstration: EvolutionDemonstration,
) -> None:
    """The claim the whole plane rests on. Running many sessions with a memory above the seam does
    not make the seam more permissive."""
    assert demonstration.refused_effects >= 1, "the pilot never over-reached; the test is vacuous"
    assert demonstration.any_effect_left_the_platform() is False
    assert demonstration.envelope.verify_chain()


def test_the_hostile_hint_is_kept_classified_and_never_shown_to_the_pilot(
    demonstration: EvolutionDemonstration,
) -> None:
    benign, hostile = demonstration.hints
    assert benign.imperative == ()
    assert benign.projectable is True
    assert hostile.imperative, f"{HOSTILE_HINT[:40]!r} was not classified as instruction-shaped"
    assert hostile.projectable is False

    memory = demonstration.state.memory
    assert len(memory.untrusted_hints) == 2, "a hint was deleted rather than quarantined"
    projected = memory.projectable("untrusted_hints")
    assert BENIGN_HINT in projected
    assert all("widen the scope" not in line for line in projected)


def test_the_trajectory_keeps_what_was_rejected_and_verifies(
    demonstration: EvolutionDemonstration,
) -> None:
    entries = demonstration.entries
    assert verify_lineage_chain(entries), "the trajectory does not reconstruct"

    rejected = [e for e in entries if e.kind is LineageEventKind.CANDIDATE_REJECTED]
    promoted = [e for e in entries if e.kind is LineageEventKind.CHECKPOINT_PROMOTED]
    assert rejected, "no candidate was rejected; the run cannot show the property"
    assert promoted
    assert len(active_lineage(entries)) == len(promoted)
    assert len(entries) > len(promoted) + len(rejected), "the trajectory records only verdicts"


def test_every_meaningful_decision_reaches_the_trajectory(
    demonstration: EvolutionDemonstration,
) -> None:
    """Invariant 11 does not exempt the plane that decides what to ask next."""
    kinds = {entry.kind for entry in demonstration.entries}
    for expected in (
        LineageEventKind.RUN_STARTED,
        LineageEventKind.STEP_ATTEMPTED,
        LineageEventKind.CHECKPOINT_PROMOTED,
        LineageEventKind.CANDIDATE_REJECTED,
        LineageEventKind.PLATEAU_DETECTED,
        LineageEventKind.SUPERVISOR_CONSULTED,
        LineageEventKind.DIRECTIVE_ISSUED,
        LineageEventKind.DIRECTIVE_APPLIED,
        LineageEventKind.HINT_ACCEPTED,
        LineageEventKind.HINT_QUARANTINED,
        LineageEventKind.RUN_STOPPED,
    ):
        assert expected in kinds, f"{expected.value} never reached the trajectory"


def test_the_trajectory_survives_a_restart(demonstration: EvolutionDemonstration) -> None:
    """An investigation that runs for days must survive the process that started it."""
    from nemesis.evolution.lineage import FileLineageStore

    reloaded = FileLineageStore.open(demonstration.workspace / "evolution")
    entries = reloaded.entries(demonstration.state.run_id)
    assert entries == demonstration.entries
    assert reloaded.verify()


def test_no_checkpoint_carries_internal_classified_material(
    demonstration: EvolutionDemonstration,
) -> None:
    """A checkpoint is durable and projectable. Founder decision D1 governs it exactly as it governs
    an export."""
    from nemesis.core.disclosure import scan_for_internal_material

    for entry in demonstration.entries:
        if entry.checkpoint is None:
            continue
        leaked = scan_for_internal_material(
            {"checkpoint": entry.checkpoint.model_dump_json(), "detail": entry.detail}
        )
        assert not leaked, f"a checkpoint carries internal material: {leaked}"
