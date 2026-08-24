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
archetypes that quietly behave the same measure nothing at all. `ConjuringPilot` must keep naming an
entity no briefing offered, and must keep doing it on only some of its moves: a variant that quietly
stopped conjuring would put the `ref` column back to zero, and one that conjured on every move would
execute nothing and so measure neither loop. `_exhausted_families` parses prose the loop composed
rather than a structured list, so it matches by containment; a stricter parser would read every line
as "not a match" the day the wording changed, and the aware pilot would look memory-blind for a
reason nobody would find.

`LoopMeasurement` says every one of its fields is counted from the mediator's rulings and not from
what a pilot proposed. That stayed prose for as long as both shipped archetypes only ever named an
entity the briefing had surfaced: `refused` was 0 in every cell the benchmark had ever printed, so
the sentence had never once been exercised and the `ref` column was decoration. The two halves of it
are checked separately here, because a suite that ran them together could pass on the wrong one —
that the refusal is the *unknown-entity* ruling and not the vocabulary check firing, which would pin
a different control on a different code path; and that such a move costs a move, executes no pivot
and spends no budget.

Counting them correctly is not the same as printing them, and both halves above stop at
`LoopMeasurement`. So the `ref` and `ok` columns are read back out of the rendered row as well:
a table that printed a literal 0 there would be exactly as green under every other assertion in
this file, and a literal 0 in that column is the state the third archetype exists to end.

The magnitudes are pinned rather than bounded away from zero, and the evolution arm is why.
"Some refused and some accepted" is satisfied by any division of the moves at all, so an arm that
swapped its two counters, or reported one refusal out of sixteen, read as correct — and that arm
sums its counters across segments, where a segment counted into the wrong column shows up nowhere
else on the table.

`redundancy_rate` gets a test of its own because its docstring claimed the opposite of what the
run does: that a refused pilot "divides by fewer executed pivots and scores better", inviting a
reader to discount the number. Dividing the same repeats by fewer executed pivots *raises* the
rate, and there is nothing to discount — the refusals shorten the walk, and a refused run is
exactly as redundant as a clean run that executed as many pivots. That identity is asserted here
against a real clean run, because a claim that was wrong in prose for a release is not one to
restate in prose.

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

from nemesis.pilot.mediator import DEFAULT_MAX_CONSECUTIVE_MALFORMED, PilotSession
from nemesis.pilot.moves import (
    Briefing,
    Conclude,
    EntityView,
    EnvelopeView,
    ResearchContext,
    RulingStatus,
    RunPivot,
)
from nemesis.slice.evolution_session import APPROVED_DOMAIN
from nemesis.slice.loopbench import (
    CAVEATS,
    DEFAULT_BUDGET,
    PIVOT_CYCLE,
    ConjuringPilot,
    CyclingPilot,
    LoopMeasurement,
    MemoryAwarePilot,
    _build_world,
    _cross_product,
    _exhausted_families,
    compare,
    render,
    run_loopbench,
    run_plain_arm,
)

pytestmark = pytest.mark.slice

_REFUSED_RUN_MOVES = 2 * DEFAULT_MAX_CONSECUTIVE_MALFORMED
"""The ceiling for the runs below in which every single move is refused.

Derived from the mediator's malformed tolerance rather than written as a number, because the
property being measured is a comparison against it: an unknown-entity refusal is ruled inside
``_apply``, after ``_validate`` has already accepted the move as well-formed, so it never touches
the malformed streak. A run of this length that ends at its ceiling could not have ended at the
streak guard; a run of three could not tell the two apart, and would pass either way.
"""


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
    refused: int = 0,
) -> LoopMeasurement:
    """A measurement assembled directly, so the reporting functions can be tested on inputs a
    real run would take minutes to produce and could not produce on demand.

    ``refused`` defaults to 0 because most callers here are testing the report rather than the
    accounting, but it has to be expressible: a helper that could only build refusal-free
    measurements would make every property asserted through it a property of the case that was
    already true before the third archetype existed.
    """
    return LoopMeasurement(
        arm=arm,
        pilot=pilot,
        allowance=allowance,
        moves=moves,
        accepted=moves - refused,
        refused=refused,
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


class _AlwaysConjuringPilot(ConjuringPilot):
    """The shipped archetype with its cadence turned all the way up: every move invents an entity.

    A subclass rather than a second scripted policy, so the id being invented and the body that
    proposes it are the ones that ship. A hand-written stand-in would keep every assertion below
    green on the day :class:`ConjuringPilot` stopped conjuring, which is the one day they exist to
    fail.

    Pure where the sweep's archetype is deliberately mixed, and that is the point: a run with no
    accepted turn in it leaves no second explanation for anything the refusal accounting reports.
    """

    CONJURE_EVERY = 1


@pytest.fixture(scope="module")
def refused_session(tmp_path_factory: pytest.TempPathFactory) -> PilotSession:
    """One drive in which the mediator refused every move, kept as the transcript itself.

    Driven straight through ``_build_world`` and ``mediator.drive`` rather than through an arm,
    because the arms hand back counts and the questions here are about the rulings those counts
    were derived from: which refusal fired, and how many turns a streak of them cost.
    """
    workspace: Path = tmp_path_factory.mktemp("loopbench-refused")

    async def driven() -> PilotSession:
        world = await _build_world(root=workspace / "world", max_moves=_REFUSED_RUN_MOVES)
        return await world.mediator.drive(
            _AlwaysConjuringPilot(_REFUSED_RUN_MOVES), world.seed, total_budget=DEFAULT_BUDGET
        )

    return asyncio.run(driven())


@pytest.fixture(scope="module")
def refused_measurement(tmp_path_factory: pytest.TempPathFactory) -> LoopMeasurement:
    """The same pilot, same ceiling and same budget, counted the way the benchmark counts.

    The session fixture above says what the mediator ruled; this one says what the table would
    print about it. Both are needed because the gap being closed is precisely that the second was
    never checked against the first.
    """
    workspace: Path = tmp_path_factory.mktemp("loopbench-refused-arm")
    return asyncio.run(
        run_plain_arm(
            _AlwaysConjuringPilot,
            moves=_REFUSED_RUN_MOVES,
            budget=DEFAULT_BUDGET,
            root=workspace / "plain",
        )
    )


@pytest.fixture(scope="module")
def equal_work_control(
    long_run: tuple[LoopMeasurement, ...], tmp_path_factory: pytest.TempPathFactory
) -> LoopMeasurement:
    """A never-refused run handed exactly as many moves as the refused run executed pivots.

    The control the table cannot print. ``compare`` pairs rows on the allowance, which is right
    for one pilot across two arms and wrong for one arm across two pilots: a refused pilot given
    48 moves does the work of a clean pilot given 32, so the row printed beside it is not the run
    it should be read against. Derived from the refused run's own executed count rather than
    written as a number, because the point is the equality and a literal would survive the day
    the fixture world changes what it answers.
    """
    refused = _by_arm(long_run)[("plain", "conjuring")]
    executed = refused.distinct_pivots + refused.repeated_pivots
    workspace: Path = tmp_path_factory.mktemp("loopbench-equal-work")
    return asyncio.run(
        run_plain_arm(CyclingPilot, moves=executed, budget=DEFAULT_BUDGET, root=workspace / "plain")
    )


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


def test_the_conjuring_pilot_proposes_a_family_the_briefing_calls_exhausted() -> None:
    """It is a cycling variant so that refusals are the only thing that differs between the two,
    and that only holds while it stays as blind to the memory as the control is.

    If it started reading ``exhausted_directions``, whatever its row shows and the control's does
    not would be the memory and the refusals mixed together, with no way to separate them — and
    the row is in the sweep to be read against the control's.
    """
    spent = PIVOT_CYCLE[0]
    briefing = _briefing(entities=1, exhausted=(f"the {spent.value} family returned nothing",))

    move = asyncio.run(ConjuringPilot(4).propose(briefing))

    assert isinstance(move, RunPivot)
    assert move.pivot_type is spent, "the conjuring pilot read the context it must ignore"


def test_only_the_conjuring_pilot_invents_an_entity_and_only_on_every_third_move() -> None:
    """The differential that keeps the third archetype from collapsing into the first.

    Both halves matter and neither is enough alone. A conjuring pilot that stopped inventing ids
    would leave ``refused`` at 0 and the ``ref`` column decorative again, which is the state this
    archetype was added to end. A cycling pilot that started inventing them would refuse the
    control arm's moves too, and the benchmark's validity check — the blind pilot reaching the
    same pivots in both arms — would be comparing two damaged runs rather than two clean ones.

    Pinning the *cadence* rather than only the fact is what separates the mixed archetype from a
    pilot refused on every move: the latter executes nothing, and a run that executed nothing
    measures neither loop.
    """
    briefing = _briefing(entities=3)
    offered = {view.entity_id for view in briefing.entities}
    conjuring, cycling = ConjuringPilot(6), CyclingPilot(6)

    invented: list[int] = []
    for move_number in range(1, 7):
        conjured = asyncio.run(conjuring.propose(briefing))
        cycled = asyncio.run(cycling.propose(briefing))
        assert isinstance(conjured, RunPivot) and isinstance(cycled, RunPivot)
        assert cycled.entity_id in offered, "the control pilot named an entity nobody showed it"
        if conjured.entity_id not in offered:
            invented.append(move_number)

    assert invented == [3, 6], invented


def test_every_pilot_concludes_rather_than_failing_on_a_briefing_with_no_entities() -> None:
    """``_cross_product`` divides by the entity count, so an empty briefing is a ZeroDivisionError
    one guard away. A pilot that raises is recorded by the mediator as a refused move and a halted
    session, which would show up in the table as the machinery having stopped the run.

    Asserted of the conjuring archetype too, and there it is worse than a wrong number: that pilot
    is the one whose row is *expected* to carry refusals, so a raised exception would be counted
    into the very column this benchmark now reports and read as the thing it was measuring.
    """
    empty = _briefing(entities=0)

    assert isinstance(asyncio.run(CyclingPilot(4).propose(empty)), Conclude)
    assert isinstance(asyncio.run(MemoryAwarePilot(4).propose(empty)), Conclude)
    assert isinstance(asyncio.run(ConjuringPilot(4).propose(empty)), Conclude)


def test_a_pilot_out_of_moves_concludes_instead_of_proposing() -> None:
    assert isinstance(asyncio.run(CyclingPilot(0).propose(_briefing(entities=1))), Conclude)
    assert isinstance(asyncio.run(MemoryAwarePilot(0).propose(_briefing(entities=1))), Conclude)
    assert isinstance(asyncio.run(ConjuringPilot(0).propose(_briefing(entities=1))), Conclude)


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


def test_a_refused_move_leaves_the_redundancy_rate_alone_rather_than_diluting_it() -> None:
    """The denominator is the pivots that ran, and adding the refusals to it is the plausible
    wrong answer — the moves are what the row's first column reports, so a reader summing the
    columns would arrive at exactly it.

    It is the wrong answer because a refused move executed nothing, so counting it as a
    non-repeat credits the pilot with tidiness for work no connector ever did — the same
    accounting error, in the opposite direction, that ``_count`` avoids by refusing to put a
    refused pivot into ``seen``. Asserted as *identity between two measurements* rather than
    against a literal, because the property is that the refusals make no difference at all.
    """
    clean = _measurement("plain", "cycling", allowance=32, moves=32, distinct=30, repeats=2)
    refused = _measurement(
        "plain", "conjuring", allowance=48, moves=48, distinct=30, repeats=2, refused=16
    )

    assert refused.refused == 16, "the refused measurement was built without any refusals in it"
    assert refused.redundancy_rate == clean.redundancy_rate
    assert refused.redundancy_rate == pytest.approx(2 / 32)


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
    """Two arms times three pilots, and both arms given the same allowance.

    The equal allowance is the precondition for everything the report says. If the plain arm were
    handed the segment ceiling rather than the total, the evolution arm would win on move count
    alone and the table would read as the machinery having found more.

    The set is spelled out rather than counted because it is also the only place the sweep's
    membership is checked: an archetype defined but never added to ``PILOTS`` would be tested to
    death here and exercise nothing the benchmark prints.
    """
    assert len(short_run) == 6
    assert {(item.arm, item.pilot) for item in short_run} == {
        ("plain", "cycling"),
        ("evolution", "cycling"),
        ("plain", "memory-aware"),
        ("evolution", "memory-aware"),
        ("plain", "conjuring"),
        ("evolution", "conjuring"),
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
    assert plain.budget_spent == evolution.budget_spent, (
        "identical work cost a different amount, so the arms are not spending the same budget"
    )
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


def test_the_blind_and_the_aware_pilot_are_indistinguishable_in_the_plain_arm(
    long_run: tuple[LoopMeasurement, ...],
) -> None:
    """The plain arm has no context to read, so the aware pilot degenerates into the blind one
    there. That is what isolates the difference reported for it to the memory alone.

    Named for the two archetypes it means rather than for their number. The conjuring pilot is
    deliberately not one of them: it diverges from both by being refused, which is a difference
    the *pilot* made and not one either arm did.
    """
    arms = _by_arm(long_run)
    blind, aware = arms[("plain", "cycling")], arms[("plain", "memory-aware")]

    assert blind.distinct_pivots == aware.distinct_pivots
    assert blind.repeated_pivots == aware.repeated_pivots
    assert blind.moves == aware.moves


# --- the refusal accounting --------------------------------------------------


def test_every_ruling_against_a_pilot_that_only_conjures_is_the_unknown_entity_refusal(
    refused_session: PilotSession,
) -> None:
    """THE ANTI-VACUITY CHECK FOR EVERY REFUSAL FIGURE BELOW.

    A suite that only counted refusals would be exactly as green if the mediator were rejecting
    these moves as *malformed*. That would pin the vocabulary check — a real control, on a
    different code path, refusing before ``_validate`` ever returns — while the pivot refusal
    the ``ref`` column actually reports stayed untested, and the module's docstring would still
    read as though it had been measured.

    ``RunPivot.entity_id`` is an unconstrained string, so an invented id is a *well-formed* move
    and reaches ``_apply_pivot``, which asks the graph and refuses what it does not hold. Naming
    that status is what keeps the two refusals apart.
    """
    statuses = {turn.ruling.status for turn in refused_session.transcript}

    assert statuses == {RulingStatus.REFUSED_UNKNOWN_ENTITY}, statuses
    assert all(isinstance(turn.move, RunPivot) for turn in refused_session.transcript), (
        "the mediator recorded a move it could not parse, so this refused for the wrong reason"
    )


def test_a_refused_pivot_costs_a_move_and_a_streak_of_them_does_not_end_the_session(
    refused_session: PilotSession,
) -> None:
    """Half of what :class:`LoopMeasurement` claims: the proposal cost a move.

    One turn per proposal is what makes ``moves`` the moves *taken* rather than the moves that
    worked, and the ceiling is what proves the turns were spent rather than skipped. The run is
    twice the malformed tolerance long precisely so the second assertion can be made: an
    unknown-entity refusal is ruled inside ``_apply``, after ``_validate`` has already succeeded
    and reset the streak, so it never counts towards the guard that ends a session. Were that to
    change, this run would stop at the tolerance and the benchmark would quietly be reporting a
    shorter run than the one it was asked for — as the machinery's doing, in the evolution arm.
    """
    assert len(refused_session.transcript) == _REFUSED_RUN_MOVES
    assert refused_session.concluded is False
    assert "ceiling" in (refused_session.halted_reason or ""), refused_session.halted_reason


def test_a_run_of_nothing_but_refusals_executes_no_pivot_and_spends_no_budget(
    refused_measurement: LoopMeasurement,
) -> None:
    """The other half: the move executed no pivot, and the budget is the independent witness.

    ``_count`` credits a pivot into ``seen`` only when the ruling accepted it, and a version that
    forgot the second condition would report distinct pivots for work no connector ever did —
    crediting a pilot for exactly the work the docstring says a benchmark counting proposals
    would credit it for. The budget cannot be talked into agreeing: ``_apply_pivot`` refuses
    before the engine is reached, so an executed pivot is a spent one and 0.0 here means none ran.

    ``redundancy_rate`` is asserted on a real run of this shape and not only on a hand-built
    measurement, because it is the column a reader compares across pilots, and a refusal-heavy
    run divides by fewer executed pivots than it took moves.
    """
    assert refused_measurement.moves == _REFUSED_RUN_MOVES
    assert refused_measurement.refused == _REFUSED_RUN_MOVES
    assert refused_measurement.accepted == 0
    assert refused_measurement.distinct_pivots == 0
    assert refused_measurement.repeated_pivots == 0
    assert refused_measurement.entities_discovered == 0
    assert refused_measurement.evidence_sealed == 0
    assert refused_measurement.budget_spent == 0.0, (
        "a refused pivot reached the engine, so the refusal is not before the connector"
    )
    assert refused_measurement.redundancy_rate == 0.0


def test_every_measurement_accounts_for_each_move_as_either_accepted_or_refused(
    short_run: tuple[LoopMeasurement, ...],
) -> None:
    """The arithmetic that makes the docstring's claim true of the benchmark and not of one probe.

    ``accepted`` and ``refused`` are counted turn by turn from the rulings while ``moves`` is the
    length of the transcript, so the three agreeing is the evidence that no move was counted
    twice or dropped — in either arm, where the evolution arm sums its counts across segments and
    a lost segment would show up here and nowhere else on the table.

    The identity is trivially satisfied by a sweep in which nothing was ever refused, which is the
    state this file was in until the third archetype existed, so the last assertion is what stops
    it going quietly back to being about nothing.
    """
    for item in short_run:
        assert item.accepted + item.refused == item.moves, item

    assert any(item.refused for item in short_run), (
        "no cell in the sweep was refused anything, so the identity above holds vacuously"
    )


def test_the_conjuring_pilot_is_refused_on_some_of_its_moves_and_accepted_on_others(
    short_run: tuple[LoopMeasurement, ...],
) -> None:
    """The sweep's new row is a lie in one direction or the other unless both are true.

    With no refusals it is the cycling row under a second name, and ``ref`` is decoration again.
    With nothing but refusals it executes no pivot, and a row whose every other column is 0
    describes neither loop while looking like a measurement of both.

    The divergence between the moves taken and the pivots executed is asserted inside a single
    run, which is the whole reason the archetype is mixed rather than pure: it needs no second
    run to compare against, so it cannot be explained by the two runs differing.

    The split is pinned to the cadence rather than bounded away from zero, and the evolution arm
    is the reason. "Some refusals and some acceptances" is satisfied by *any* division of the
    moves, so an arm that swapped the two counters, or reported a single refusal out of six, read
    as correct — and the evolution arm is where that matters most, because it sums its counters
    across segments and a segment counted into the wrong column shows up nowhere else. Derived
    from ``CONJURE_EVERY`` rather than written as 2, so a change to the cadence moves the pilot
    and this assertion together instead of leaving one describing the other.
    """
    arms = _by_arm(short_run)

    for arm in ("plain", "evolution"):
        item = arms[(arm, "conjuring")]
        expected_refused = item.moves // ConjuringPilot.CONJURE_EVERY
        assert expected_refused > 0, "this run is too short to contain a conjured move at all"
        assert item.refused == expected_refused, (
            f"{arm}: {item.refused} refusals over {item.moves} moves is not the pilot's cadence"
        )
        assert item.accepted == item.moves - expected_refused, (
            f"{arm}: accepted and refused do not divide the moves the way the pilot proposed them"
        )
        assert item.moves > item.distinct_pivots + item.repeated_pivots, (
            f"{arm}: every move taken executed a pivot, so no move was spent on a refusal"
        )


def test_a_refused_run_is_exactly_as_redundant_as_a_clean_run_that_did_the_same_work(
    long_run: tuple[LoopMeasurement, ...], equal_work_control: LoopMeasurement
) -> None:
    """The ``redun%`` column's own docstring, which said the opposite of this until it was
    measured.

    It claimed a refused pilot "divides by fewer executed pivots and scores better", inviting a
    reader to discount the number. Both halves were wrong. Dividing the same repeats by fewer
    executed pivots *raises* the rate, and there is nothing to discount: distinct pivots saturate
    at what the world can answer, so past that point every executed pivot is a repeat and the
    rate is a function of walk length alone. The refusals shortened the walk; they did not
    flatter the rate, and a reader who applied the stated correction would move further from the
    truth than one who read the number as printed.

    Asserted as an identity against a run that executed the same number of pivots without being
    refused once, because that is the only comparison that isolates the refusals — and asserted
    against the row ``compare`` actually prints beside it, which is the *wrong* comparison and
    the reason the caveat has to name which one it is. Adding ``refused`` to the denominator, the
    plausible wrong answer, breaks the first assertion and not the second.

    This is also the only assertion in the file on a long-run conjuring cell: every other refusal
    figure is checked at six moves, where nothing has repeated yet and the rate is 0.0 whatever
    the denominator is.
    """
    arms = _by_arm(long_run)
    refused, same_allowance = arms[("plain", "conjuring")], arms[("plain", "cycling")]
    executed = refused.distinct_pivots + refused.repeated_pivots

    assert refused.refused > 0, "the conjuring cell was refused nothing, so this compares nothing"
    assert refused.repeated_pivots > 0, "nothing repeated here, so every rate below is 0.0"
    assert equal_work_control.refused == 0, "the control was refused too, so it controls for it"
    assert equal_work_control.moves == executed
    assert equal_work_control.distinct_pivots + equal_work_control.repeated_pivots == executed

    assert refused.redundancy_rate == equal_work_control.redundancy_rate, (
        "the refusals changed the rate, so they are in the denominator where only pivots belong"
    )
    assert refused.redundancy_rate == pytest.approx(refused.repeated_pivots / executed)
    assert refused.redundancy_rate < same_allowance.redundancy_rate, (
        "the row printed beside it reads the same, so the caveat about which to compare is moot"
    )


def test_the_machinery_did_not_cut_the_refused_run_short(
    long_run: tuple[LoopMeasurement, ...],
) -> None:
    """The negative result, pinned so that prose cannot drift into claiming the opposite.

    A loop that segmented a run, watched its yield and redirected it is the kind of thing a
    reader expects to have *noticed* a pilot being refused a third of its moves. It does not: a
    refusal is ruled below the seam, costs a move, spends no budget, and reaches the evolution
    plane only as a turn that produced nothing. So the refused pilot spends its whole allowance
    here, exactly as the never-refused control does, and the module says so rather than implying
    the machinery limited the damage.
    """
    arms = _by_arm(long_run)
    refused, control = arms[("evolution", "conjuring")], arms[("evolution", "cycling")]

    assert refused.refused > 0, "nothing was refused, so this says nothing about a refused run"
    assert refused.moves == refused.allowance, (
        "the refused run stopped early; the module docstring says it does not"
    )
    assert control.moves == control.allowance, (
        "the control stopped early too, so the line above is about the length and not the refusals"
    )


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
    """A renderer that silently dropped a row would hide exactly the arm that went badly.

    Every pilot is counted by name, not just the rows totalled. ``len(rows) == len(short_run)``
    stays true on its own however many archetypes there are, so the conjuring rows — the ones
    that went badly, and the only ones carrying a non-zero ``ref`` — could go missing under an
    assertion whose stated purpose is that they cannot.
    """
    lines = render(short_run).splitlines()
    header = next(
        index for index, line in enumerate(lines) if line.split()[:3] == ["moves", "arm", "pilot"]
    )

    rows = [line for line in lines[header + 1 :] if line.strip()]
    assert len(rows) == len(short_run)
    assert sum("cycling" in row for row in rows) == 2
    assert sum("memory-aware" in row for row in rows) == 2
    assert sum("conjuring" in row for row in rows) == 2


def test_the_rendered_ok_and_ref_columns_carry_what_the_measurement_counted(
    short_run: tuple[LoopMeasurement, ...],
) -> None:
    """The ``ref`` column is the whole reason the third archetype exists, and nothing read it.

    Every other test in this file asserts on :class:`LoopMeasurement`, which is upstream of the
    renderer. So the counting could be perfect and the table still print a literal 0 there — the
    exact state the ``ref`` column was in before this pilot shipped, and one that would restore
    it silently. The same hole covers ``ok``: a formatter that printed ``accepted`` in both slots
    would show a pilot refusing everything it accepted, and no assertion here would move.

    Read by whitespace position rather than by column offset, so it fails on a lost value and not
    on a widened field, and paired with the measurements by index because ``render`` iterates the
    results in order — which makes a reordered table a failure here too, and it should be: a row
    is only readable if it belongs to the run whose name it carries.
    """
    lines = render(short_run).splitlines()
    header = next(
        index for index, line in enumerate(lines) if line.split()[:3] == ["moves", "arm", "pilot"]
    )
    rows = [line for line in lines[header + 1 :] if line.strip()]

    assert any(item.refused for item in short_run), (
        "no cell in this sweep was refused anything, so the ref column below is all zeros"
    )
    for row, item in zip(rows, short_run, strict=True):
        moves, arm, pilot, ok, ref = row.split()[:5]
        assert (arm, pilot) == (item.arm, item.pilot), row
        assert moves == str(item.moves), row
        assert ok == str(item.accepted), f"the ok column is not the accepted count: {row}"
        assert ref == str(item.refused), f"the ref column is not the refused count: {row}"
