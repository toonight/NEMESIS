"""The loop benchmark, checked against the one thing that would make its headline meaningless.

`nemesis.slice.loopbench` compares one uninterrupted `PilotMediator.drive` against the same
allowance of moves cut into segments by `EvolutionController.run`, and reports the difference as
work the machinery did. That report is only worth reading if the two arms differ in the machinery
and in nothing else, so the load-bearing test in this file is not a number: it is that the pilot
which ignores the memory entirely comes out of both arms with the same distinct pivots, the same
repeats and the same sealed evidence. If that ever stops holding, something other than the loop is
moving the figures and every comparison the module prints is confounded.

That control is worthless on its own, though, because a benchmark in which nothing happens anywhere
satisfies it. So it is asserted twice: once on a run too short for the memory to have accumulated
anything, and once on a run long enough that the aware pilot demonstrably diverges — with the blind
pilot still identical across both arms in the second case. The pair is the argument; neither half
is.

The pilots are pinned separately, because they are this benchmark's instrument and a bent instrument
reads as a result. `_cross_product` walking a diagonal instead of the full (entity, family) grid is
the defect that was found by reading the first run's numbers rather than by reading the code, and it
capped the distinct pivots either arm could possibly reach — the benchmark's own denominator.
`CyclingPilot` must ignore the research context and `MemoryAwarePilot` must read it, because two
archetypes that quietly behave the same measure nothing at all. `_exhausted_families` parses prose
the loop composed rather than a structured list, so it matches by containment; a stricter parser
would read every line as "not a match" the day the wording changed, and the aware pilot would look
memory-blind for a reason nobody would find.

The rest guards the report. `compare` pairs the arms on the moves they were *given*, never on the
moves they took: pairing on the latter let a run that stopped early be graded against whichever
other run happened to be nearest, so stopping early both was the result and chose what the result
was compared with. `render` prints the caveats above the table for the same reason the pilotbench
report does — production value reads as confidence, and a table with its limits underneath is read
as a table.

Everything here is synthetic and offline. The runs are real collection against fixtures, real
sealing and real rulings, and are kept deliberately short.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest

from nemesis.pilot.moves import (
    Briefing,
    Conclude,
    EntityView,
    EnvelopeView,
    ResearchContext,
    RunPivot,
)
from nemesis.slice.evolution_session import APPROVED_DOMAIN
from nemesis.slice.loopbench import (
    CAVEATS,
    PIVOT_CYCLE,
    CyclingPilot,
    LoopMeasurement,
    MemoryAwarePilot,
    _build_world,
    _cross_product,
    _exhausted_families,
    compare,
    render,
    run_loopbench,
)

pytestmark = pytest.mark.slice


# --- fixtures ----------------------------------------------------------------


def _briefing(entities: int = 3, exhausted: tuple[str, ...] | None = None) -> Briefing:
    """A briefing built by hand, so a pilot can be interrogated without driving a world.

    ``exhausted=None`` means no research context at all, which is what every plain-arm briefing
    carries and what the pilots must survive.
    """
    return Briefing(
        investigation_id="inv_loopbench_test",
        seed="domain seed.example",
        step_count=0,
        budget_remaining=100.0,
        moves_remaining=40,
        hypotheses=(),
        entities=tuple(
            EntityView(
                entity_id=f"ent_{index}", entity_type="domain", natural_key=f"h{index}.example"
            )
            for index in range(entities)
        ),
        envelope=EnvelopeView(
            permitted_operations=("simulation",),
            forbidden_operations=("registrar_suspension",),
            approved_target_entity_ids=("ent_0",),
            expires_at=datetime(2026, 12, 1, tzinfo=UTC),
            max_effect="one rehearsed operation that does nothing",
        ),
        research_context=(
            None if exhausted is None else ResearchContext(exhausted_directions=exhausted)
        ),
    )


def _measurement(
    arm: str,
    pilot: str,
    *,
    allowance: int,
    moves: int,
    distinct: int,
    repeats: int,
    evidence: int = 0,
) -> LoopMeasurement:
    """A measurement assembled directly, so the reporting functions can be tested on inputs a
    real run would take minutes to produce and could not produce on demand."""
    return LoopMeasurement(
        arm=arm,
        pilot=pilot,
        allowance=allowance,
        moves=moves,
        accepted=moves,
        refused=0,
        distinct_pivots=distinct,
        repeated_pivots=repeats,
        entities_discovered=5,
        evidence_sealed=evidence,
        budget_spent=float(moves),
        stop_reason="concluded" if moves < allowance else "ceiling",
    )


@pytest.fixture(scope="module")
def short_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[LoopMeasurement, ...]:
    """Two segments of three moves: the smallest run that still drives both arms end to end."""
    workspace: Path = tmp_path_factory.mktemp("loopbench-short")
    return asyncio.run(run_loopbench(lengths=(2,), moves_per_segment=3, workspace=workspace))


@pytest.fixture(scope="module")
def long_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[LoopMeasurement, ...]:
    """Eight segments of six moves: long enough that the memory has something to say.

    Still under a second, and it has to be this long: the fixture world answers enough pivots that
    nothing is exhausted before the later segments, so a shorter run would show the aware pilot and
    the blind one behaving identically and would report that as a control holding.
    """
    workspace: Path = tmp_path_factory.mktemp("loopbench-long")
    return asyncio.run(run_loopbench(lengths=(8,), moves_per_segment=6, workspace=workspace))


def _by_arm(results: tuple[LoopMeasurement, ...]) -> dict[tuple[str, str], LoopMeasurement]:
    return {(item.arm, item.pilot): item for item in results}


# --- the instrument: the scripted pilots -------------------------------------


def test_the_cross_product_reaches_every_entity_and_family_rather_than_a_diagonal() -> None:
    """The defect that capped the benchmark's own denominator.

    The first version advanced the entity and the family on the same index, so three entities and
    six families produced a six-long diagonal and never reached the other twelve pairs. Both arms
    saw it equally, which is exactly why nobody noticed: the comparison still looked sound while
    the number being compared was a third of what the world could answer.
    """
    briefing = _briefing(entities=3)
    available = 3 * len(PIVOT_CYCLE)

    pairs = [_cross_product(briefing, index) for index in range(available)]

    assert len(set(pairs)) == available, "the walk revisits a pair before covering the grid"
    assert {family for _, family in pairs} == set(PIVOT_CYCLE)
    assert {entity for entity, _ in pairs} == {"ent_0", "ent_1", "ent_2"}


def test_the_cross_product_wraps_instead_of_running_off_the_end() -> None:
    """A pilot with more moves than pairs keeps proposing rather than raising IndexError. The
    repeats that follow are the redundancy the benchmark is there to count."""
    briefing = _briefing(entities=3)
    available = 3 * len(PIVOT_CYCLE)

    assert _cross_product(briefing, available) == _cross_product(briefing, 0)
    assert _cross_product(briefing, available + 5) == _cross_product(briefing, 5)


def test_the_cycling_pilot_proposes_a_family_the_briefing_calls_exhausted() -> None:
    """The control pilot has to be genuinely blind to the memory, not merely uninterested in it.

    If it ever started reading ``exhausted_directions``, the benchmark would lose the only arm that
    can tell a mechanical difference from a cooperative one, and every "the machinery made no
    difference here" result would become unreadable.
    """
    spent = PIVOT_CYCLE[0]
    briefing = _briefing(entities=1, exhausted=(f"the {spent.value} family returned nothing",))

    move = asyncio.run(CyclingPilot(4).propose(briefing))

    assert isinstance(move, RunPivot)
    assert move.pivot_type is spent, "the cycling pilot read the context it must ignore"


def test_the_memory_aware_pilot_steps_past_a_family_the_briefing_calls_exhausted() -> None:
    """The other half of the same comparison, on the identical briefing: the two archetypes must
    disagree here, or the benchmark is running one policy twice under two names."""
    spent = PIVOT_CYCLE[:2]
    briefing = _briefing(
        entities=1, exhausted=tuple(f"{family.value} is exhausted" for family in spent)
    )

    move = asyncio.run(MemoryAwarePilot(4).propose(briefing))

    assert isinstance(move, RunPivot)
    assert move.pivot_type is PIVOT_CYCLE[2]
    assert move.pivot_type not in spent


def test_the_memory_aware_pilot_concludes_when_every_direction_is_exhausted() -> None:
    """Concluding is the honest move. A pilot that kept proposing here would manufacture exactly
    the redundancy this arm exists to avoid, and the benchmark would credit the memory with
    producing the waste it was meant to prevent."""
    briefing = _briefing(
        entities=2, exhausted=tuple(f"{family.value} is exhausted" for family in PIVOT_CYCLE)
    )

    move = asyncio.run(MemoryAwarePilot(6).propose(briefing))

    assert isinstance(move, Conclude)
    assert "exhausted" in move.summary


def test_both_pilots_conclude_rather_than_fail_on_a_briefing_with_no_entities() -> None:
    """``_cross_product`` divides by the entity count, so an empty briefing is a ZeroDivisionError
    one guard away. A pilot that raises is recorded by the mediator as a refused move and a halted
    session, which would show up in the table as the machinery having stopped the run."""
    empty = _briefing(entities=0)

    assert isinstance(asyncio.run(CyclingPilot(4).propose(empty)), Conclude)
    assert isinstance(asyncio.run(MemoryAwarePilot(4).propose(empty)), Conclude)


def test_a_pilot_out_of_moves_concludes_instead_of_proposing() -> None:
    assert isinstance(asyncio.run(CyclingPilot(0).propose(_briefing(entities=1))), Conclude)
    assert isinstance(asyncio.run(MemoryAwarePilot(0).propose(_briefing(entities=1))), Conclude)


def test_the_exhausted_families_are_matched_by_containment_not_by_equality() -> None:
    """The context lines are prose the loop composed, not a structured list. A parser demanding an
    exact format would read every line as "not a match" the day the wording changed, and the aware
    pilot would go memory-blind silently — reported as the mechanism not working."""
    spent = PIVOT_CYCLE[0]

    found = _exhausted_families(
        _briefing(
            entities=1,
            exhausted=(
                f"Direction {spent.value} produced nothing across 3 entities and was dropped.",
            ),
        )
    )

    assert found == frozenset({spent.value})


def test_a_family_the_briefing_never_mentions_is_not_reported_as_exhausted() -> None:
    """The control for the containment match: a matcher loose enough to catch everything would
    make the aware pilot conclude immediately and look like a spectacular success."""
    assert _exhausted_families(_briefing(entities=1, exhausted=("nothing of note",))) == frozenset()


def test_the_exhausted_families_are_empty_when_the_briefing_carries_no_research_context() -> None:
    """Every plain-arm briefing is this case, because ``drive`` has no parameter for a context. If
    it raised or invented a family here, the plain arm would not be the same pilot as the
    evolution arm and the whole comparison would be against a different policy."""
    assert _exhausted_families(_briefing(entities=1, exhausted=None)) == frozenset()
    assert _exhausted_families(_briefing(entities=1, exhausted=())) == frozenset()


# --- what a run leaves behind ------------------------------------------------


def test_the_redundancy_rate_is_repeats_over_the_pivots_actually_executed() -> None:
    measurement = _measurement("plain", "cycling", allowance=40, moves=40, distinct=30, repeats=10)

    assert measurement.redundancy_rate == pytest.approx(0.25)


def test_the_redundancy_rate_is_zero_rather_than_undefined_when_nothing_executed() -> None:
    """A run whose every move was refused executes no pivot. The headline number must be 0.0 and
    not a ZeroDivisionError raised while rendering a report about a run that already went badly."""
    measurement = _measurement("plain", "cycling", allowance=6, moves=6, distinct=0, repeats=0)

    assert measurement.redundancy_rate == 0.0


# --- the world both arms start from ------------------------------------------


def test_a_freshly_built_world_has_not_been_driven_yet(tmp_path: Path) -> None:
    """Both arms have to start from the same standing start. A world that arrived with pivots
    already run would hand whichever arm was built second a head start that the table would print
    as the machinery's doing."""
    world = asyncio.run(_build_world(root=tmp_path / "world", max_moves=3))

    entities = world.graph.entities()
    assert len(entities) == 1, [entity.natural_key for entity in entities]
    assert entities[0].natural_key == APPROVED_DOMAIN
    assert world.claims.claims() == ()
    moves = asyncio.run(world.audit.query(action="pilot.move", limit=1_000))
    assert list(moves) == [], [event.action for event in moves]


def test_two_worlds_built_for_the_two_arms_are_equal_and_share_nothing(tmp_path: Path) -> None:
    """Identical has to mean the same construction, not the same object.

    Sharing a graph, a vault or an envelope between the arms would let the first arm's work show up
    as the second arm's result — and the budget is debited before execution and never refunded, so
    a shared envelope would make the second arm's autonomy a fact about the first.
    """
    first = asyncio.run(_build_world(root=tmp_path / "a", max_moves=3))
    second = asyncio.run(_build_world(root=tmp_path / "b", max_moves=3))

    assert first.graph is not second.graph
    assert first.claims is not second.claims
    assert first.mediator is not second.mediator
    assert first.root != second.root
    assert first.seed == second.seed
    assert [entity.natural_key for entity in first.graph.entities()] == [
        entity.natural_key for entity in second.graph.entities()
    ]
    assert first.graph.entities()[0].entity_id != second.graph.entities()[0].entity_id


# --- the headline: the control arm ------------------------------------------


def test_a_short_loopbench_measures_every_pilot_in_every_arm_once(
    short_run: tuple[LoopMeasurement, ...],
) -> None:
    """Two arms times two pilots, and both arms given the same allowance.

    The equal allowance is the precondition for everything the report says. If the plain arm were
    handed the segment ceiling rather than the total, the evolution arm would win on move count
    alone and the table would read as the machinery having found more.
    """
    assert len(short_run) == 4
    assert {(item.arm, item.pilot) for item in short_run} == {
        ("plain", "cycling"),
        ("evolution", "cycling"),
        ("plain", "memory-aware"),
        ("evolution", "memory-aware"),
    }
    assert {item.allowance for item in short_run} == {6}


def test_the_control_pilot_behaves_identically_in_both_arms(
    short_run: tuple[LoopMeasurement, ...],
) -> None:
    """THE VALIDITY CHECK FOR THE WHOLE BENCHMARK.

    ``CyclingPilot`` never reads the research context, so the machinery has no channel through which
    to change what it does. Its two arms must therefore agree on what was reached, what was repeated
    and what was sealed. Any difference here is the harness — a different world, a different
    allowance, a different connector set — and every figure the module prints for the *other* pilot
    would then be that difference plus the memory, with no way to tell the two apart.
    """
    arms = _by_arm(short_run)
    plain, evolution = arms[("plain", "cycling")], arms[("evolution", "cycling")]

    assert plain.distinct_pivots == evolution.distinct_pivots
    assert plain.repeated_pivots == evolution.repeated_pivots
    assert plain.evidence_sealed == evolution.evidence_sealed
    assert plain.moves == evolution.moves
    assert plain.entities_discovered == evolution.entities_discovered
    assert evolution.segments == 2, "the evolution arm did not actually segment the run"


def test_the_control_holds_where_the_machinery_demonstrably_moves_the_other_pilot(
    long_run: tuple[LoopMeasurement, ...],
) -> None:
    """The short run satisfies the control by having nothing happen anywhere, which is the way this
    file could pass while measuring nothing. So the same identity is asserted at a length where the
    memory has visibly done something to the pilot that reads it.

    What the aware pilot gains is waste avoided, not ground covered: it reaches the same distinct
    pivots and stops before spending its allowance. That is the module's own caveat — the pilots
    enumerate a fixed cross-product, so no memory could improve their coverage — asserted rather
    than trusted.
    """
    arms = _by_arm(long_run)
    cycling_plain, cycling_evolution = arms[("plain", "cycling")], arms[("evolution", "cycling")]
    aware_plain, aware_evolution = (
        arms[("plain", "memory-aware")],
        arms[("evolution", "memory-aware")],
    )

    assert aware_evolution.repeated_pivots < aware_plain.repeated_pivots, (
        "the memory changed nothing for the pilot that reads it; the control below is vacuous"
    )
    assert aware_evolution.moves < aware_evolution.allowance, "the aware pilot never stopped early"
    assert aware_evolution.distinct_pivots == aware_plain.distinct_pivots

    assert cycling_plain.distinct_pivots == cycling_evolution.distinct_pivots
    assert cycling_plain.repeated_pivots == cycling_evolution.repeated_pivots
    assert cycling_plain.evidence_sealed == cycling_evolution.evidence_sealed
    assert cycling_evolution.moves == cycling_evolution.allowance


def test_the_two_pilots_are_indistinguishable_in_the_plain_arm(
    long_run: tuple[LoopMeasurement, ...],
) -> None:
    """The plain arm has no context to read, so the aware pilot degenerates into the blind one
    there. That is what isolates the difference reported for it to the memory alone."""
    arms = _by_arm(long_run)
    blind, aware = arms[("plain", "cycling")], arms[("plain", "memory-aware")]

    assert blind.distinct_pivots == aware.distinct_pivots
    assert blind.repeated_pivots == aware.repeated_pivots
    assert blind.moves == aware.moves


# --- the report --------------------------------------------------------------


def test_compare_pairs_the_arms_on_the_allowance_rather_than_on_the_moves_taken() -> None:
    """The bug this pins graded the benchmark on its own outcome.

    ``compare`` used to key on the moves a run *took*, so an evolution arm that stopped early was
    paired against whichever plain run happened to be nearest — a forty-eight-move plain arm
    against a twelve-move evolution arm from an entirely different run length. Stopping early is a
    result; it must not also decide what the result is compared with.
    """
    results = (
        _measurement("plain", "cycling", allowance=12, moves=12, distinct=12, repeats=0),
        _measurement("evolution", "cycling", allowance=12, moves=12, distinct=12, repeats=0),
        _measurement("plain", "cycling", allowance=48, moves=48, distinct=30, repeats=18),
        _measurement("evolution", "cycling", allowance=48, moves=43, distinct=30, repeats=12),
    )

    lines = compare(results)

    assert len(lines) == 2, lines
    long_line = next(line for line in lines if line.strip().startswith("48"))
    assert "moves 48->43" in long_line, long_line
    assert "repeats 18->12" in long_line, long_line
    assert not any("moves 48->12" in line for line in lines), lines


def test_compare_reports_each_pilot_separately_and_never_averages_across_them() -> None:
    """An average over a pilot that reads the memory and one that ignores it describes neither, and
    it would move with the mix of pilots rather than with the machinery."""
    results = (
        _measurement("plain", "cycling", allowance=48, moves=48, distinct=30, repeats=18),
        _measurement("evolution", "cycling", allowance=48, moves=48, distinct=30, repeats=18),
        _measurement("plain", "memory-aware", allowance=48, moves=48, distinct=30, repeats=18),
        _measurement("evolution", "memory-aware", allowance=48, moves=43, distinct=30, repeats=12),
    )

    lines = compare(results)

    assert len(lines) == 2, lines
    assert sum("cycling" in line for line in lines) == 1
    assert sum("memory-aware" in line for line in lines) == 1
    cycling = next(line for line in lines if "cycling" in line)
    aware = next(line for line in lines if "memory-aware" in line)
    assert "repeats 18->18" in cycling, cycling
    assert "repeats 18->12" in aware, aware


def test_compare_says_nothing_about_a_pilot_that_ran_only_one_arm() -> None:
    """Half a pair is not a comparison, and printing it beside real ones would read as one."""
    half = _measurement("plain", "cycling", allowance=6, moves=6, distinct=6, repeats=0)

    assert compare((half,)) == ()


def test_the_caveats_are_printed_before_the_table_and_not_beneath_it() -> None:
    """Production value reads as confidence. A table of numbers with its limits underneath is read
    as a table of numbers, so the ordering is load-bearing rather than decorative."""
    results = (
        _measurement("plain", "cycling", allowance=48, moves=48, distinct=30, repeats=18),
        _measurement("evolution", "cycling", allowance=48, moves=43, distinct=30, repeats=12),
    )

    rendered = render(results)
    lines = rendered.splitlines()
    header = next(
        index for index, line in enumerate(lines) if line.split()[:3] == ["moves", "arm", "pilot"]
    )

    assert lines[0] == "WHAT THIS CANNOT TELL YOU"
    assert all(lines.index(caveat) < header for caveat in CAVEATS)
    assert "plain" not in "\n".join(lines[:header]), "a measurement appears above the caveats"
    assert any(line.split()[:2] == ["48", "plain"] for line in lines[header + 1 :])


def test_the_rendered_table_carries_one_row_per_measurement(
    short_run: tuple[LoopMeasurement, ...],
) -> None:
    """A renderer that silently dropped a row would hide exactly the arm that went badly."""
    lines = render(short_run).splitlines()
    header = next(
        index for index, line in enumerate(lines) if line.split()[:3] == ["moves", "arm", "pilot"]
    )

    rows = [line for line in lines[header + 1 :] if line.strip()]
    assert len(rows) == len(short_run)
    assert sum("cycling" in row for row in rows) == 2
    assert sum("memory-aware" in row for row in rows) == 2
