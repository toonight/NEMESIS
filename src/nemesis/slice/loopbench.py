"""What the Evolution loop's machinery does, measured against the loop without it.

`PROJECT_STATE.md` milestone 1 asked whether structured lineage plus negative-result memory
plus plateau redirection lets a **frontier model** keep making progress after **hundreds of
pivots**. Neither half of that is available: no model is wired to any provider seat, and the
shipped fixture world holds 37 answerable `(pivot type, entity)` pairs. So this module
measures the half that *is* available — the loop's mechanics, driven by deterministic pilots
— and the report says so before it says anything else.

**What is being compared.** Both arms get the same world, the same pilot, the same total move
allowance and the same pursuit budget over **one** investigation. The plain arm is a single
`PilotMediator.drive`: one uninterrupted move loop, no memory, no evaluator, no directive. The
evolution arm is `EvolutionController.run`: the same moves cut into bounded segments through
`continue_session`, with a `ResearchContext` projected into each briefing. Nothing else
differs, so anything that differs is the machinery.

**Why three pilots and not one.** The memory is a *briefing field*. The plane cannot make a
pilot read it — that is the containment property the seam exists for, and it is also the
mechanism's limit. A benchmark with one pilot would report that limit as either a success or
a failure depending on which pilot it happened to pick. So every archetype runs through both
arms:

- :class:`CyclingPilot` ignores the context entirely and will therefore repeat itself.
- :class:`MemoryAwarePilot` reads ``exhausted_directions`` and skips what is in it.
- :class:`ConjuringPilot` ignores it too, and every third move pivots on an entity it
  invented — which the mediator refuses before any connector runs.

The interesting cell is the interaction between the first two. If the memory works
mechanically, the aware pilot differs between arms and the blind pilot does not — and that
pair of results says something neither alone can. The third pilot is not part of that pair.
It is here because every field of :class:`LoopMeasurement` claims to be counted from the
mediator's rulings rather than from what a pilot proposed, and with only cooperating pilots
shipped that claim had never once been exercised: ``refused`` was 0 in every cell this
benchmark had ever printed, and the ``ref`` column was decoration.

What that archetype settles is the accounting and nothing beyond it, and the rest is worth
stating as the negative it is: **the machinery does not limit a pilot that keeps proposing
work it will be refused for.** The refusals cost moves and no budget, and nothing above the
mediator reacted to them — at 12, 24 and 48 allowed moves the evolution arm spent the refused
pilot's entire allowance, and at 72 it ran to move 66 where the never-refused pilot stopped at
60, because refusals slow the arrival of repeats and so *delay* the plateau the detector is
watching for. Being refused is a fact about the pilot; the loop neither notices it nor is
meant to.

**What this cannot tell you**, stated here because a benchmark's caveats belong above its
numbers and not beneath them:

- Nothing about a frontier model. All three pilots are fixed policies; a model's behaviour is
  not a policy and the difference is the whole reason the milestone wanted one.
- Nothing about long horizons. The fixture world is exhausted in tens of pivots, so a
  "plateau" here is mostly the world running out, which is a property of the corpus.
- Nothing about whether the *directives* help. Eight of the nine directive types change only
  the wording of the next briefing, so a deterministic pilot that does not parse prose cannot
  respond to them, and this measures nothing about them.
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from nemesis.audit.trail import AppendOnlyAuditTrail
from nemesis.authz.envelope import AutonomyEnvelope
from nemesis.authz.gateway import RevocationRegistry
from nemesis.authz.keys import CapabilitySigningKey
from nemesis.authz.store import SqliteAuthorizationStore
from nemesis.collect.simulated import simulated_connectors
from nemesis.core.entities import Entity, EntityType
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.temporal import TemporalExtent
from nemesis.effects.isolation import InProcessEffectsExecutor
from nemesis.effects.registry import default_registry
from nemesis.evidence.vault import FileSystemEvidenceVault
from nemesis.evolution.controller import EvolutionController
from nemesis.evolution.evaluator import PursuitEvaluator
from nemesis.evolution.lineage import InMemoryLineageStore
from nemesis.evolution.models import StopReason
from nemesis.evolution.stagnation import StagnationDetector, StagnationPolicy
from nemesis.evolution.supervisor import DeterministicSupervisor
from nemesis.graph.memory import InMemoryClaimStore, InMemoryGraphStore
from nemesis.pilot.challenger import ChallengePolicy, MoveChallenger
from nemesis.pilot.mediator import PilotMediator, PilotSession
from nemesis.pilot.moves import Briefing, Conclude, PilotMove, RunPivot
from nemesis.pilot.stagnation import SessionStagnationDetector, SessionStagnationPolicy
from nemesis.ports.collection import PivotType
from nemesis.pursuit.engine import ConnectorRegistry, PursuitEngine
from nemesis.pursuit.investigation import IncidentSeed
from nemesis.slice.evolution_session import (
    APPROVED_DOMAIN,
    APPROVED_STATE,
    SCENARIO_NOW,
    _signed_envelope,
)

DEFAULT_SEGMENTS: Final = 8
DEFAULT_MOVES_PER_SEGMENT: Final = 6
DEFAULT_BUDGET: Final = 400.0

PIVOT_CYCLE: Final = (
    PivotType.RESOLUTION_HISTORY,
    PivotType.CERTIFICATE_REUSE,
    PivotType.REGISTRATION_RECORD,
    PivotType.NETWORK_OWNERSHIP,
    PivotType.SUBDOMAIN_DISCOVERY,
    PivotType.WALLET_CLUSTERING,
)
"""The families a scripted pilot works through, in a fixed order.

Six rather than the full vocabulary, and deliberately more than the fixture world answers
well, so a run reaches the point where repeating becomes the cheapest thing to do. That point
is what the memory exists to notice.
"""


# --- the three pilot archetypes ----------------------------------------------------


class CyclingPilot:
    """Works through the families in order, per entity, and never reads the context.

    The control arm. It repeats as soon as it wraps, and it repeats identically in both loops
    — so any difference the benchmark reports for this pilot is a difference the machinery
    made *without* the pilot's cooperation.
    """

    name = "cycling"

    def __init__(self, moves: int) -> None:
        self._remaining = moves
        self._index = 0

    async def propose(self, briefing: Briefing) -> PilotMove:
        if self._remaining <= 0 or not briefing.entities:
            return Conclude(summary="out of moves")
        self._remaining -= 1
        entity, family = _cross_product(briefing, self._index)
        self._index += 1
        return RunPivot(entity_id=entity, pivot_type=family, rationale="scripted")


class MemoryAwarePilot:
    """The same policy, except that it skips what the briefing says is exhausted.

    Reads ``research_context.exhausted_directions`` — a list of family names the loop has
    recorded as spent — and steps past them. That is the whole of the cooperation the memory
    asks for, and a real model would have to do at least this much for the mechanism to be
    worth anything.

    In the plain arm the context is always empty, because ``drive`` has no parameter for one.
    So this pilot behaves exactly like :class:`CyclingPilot` there, which is the point: the
    difference between the two arms for *this* pilot is the memory, isolated.
    """

    name = "memory-aware"

    def __init__(self, moves: int) -> None:
        self._remaining = moves
        self._index = 0

    async def propose(self, briefing: Briefing) -> PilotMove:
        if self._remaining <= 0 or not briefing.entities:
            return Conclude(summary="out of moves")
        self._remaining -= 1

        exhausted = _exhausted_families(briefing)
        for offset in range(len(PIVOT_CYCLE) * max(1, len(briefing.entities))):
            entity, family = _cross_product(briefing, self._index + offset)
            if family.value not in exhausted:
                self._index += offset + 1
                return RunPivot(
                    entity_id=entity,
                    pivot_type=family,
                    rationale="scripted, skipping what the briefing calls exhausted",
                )
        # Every family is spent. Concluding is the honest move, and a pilot that kept going
        # here would be manufacturing the redundancy this arm exists to avoid.
        return Conclude(summary="every direction the briefing offers is exhausted")


class ConjuringPilot:
    """The cycling policy, except that every third move pivots on an entity it invented.

    :class:`LoopMeasurement` claims every one of its fields is counted from the mediator's own
    rulings rather than from what a pilot said it would do, because a refused proposal costs a
    move and executes no pivot. Both cooperating archetypes only ever name an entity the
    briefing surfaced, so that claim was never exercised end to end — ``refused`` was 0 in every
    cell and the ``ref`` column of the table was decoration. This archetype is what makes the
    claim measurable: the gap between :attr:`LoopMeasurement.moves` and the pivots actually
    executed opens up inside a single run.

    A pilot naming an entity it was never shown is the canonical untrusted-pilot failure the
    seam exists for (invariant 5). The briefing is the only place a pilot learns what exists,
    and ``PilotMediator._apply_pivot`` refuses an id the graph does not hold before it reaches a
    connector — so this is a realistic failure to script rather than a contrived one.

    Mixed rather than pure. A pilot refused on every move executes nothing, and a run that
    executed nothing measures neither loop; two moves in three land here, so one run carries
    the work and the waste together and the divergence between them is visible without
    comparing runs.

    Like :class:`CyclingPilot` it does **not** read the research context, and that is
    deliberate: refusals are then the only thing that differs between the two archetypes, so
    whatever the table shows for this one and not for that one is attributable to them.
    """

    name = "conjuring"

    CONJURED_ENTITY_ID = "ent_conjured_by_the_pilot"
    """An id no world in this benchmark can hold — :func:`_build_world` mints its entity ids
    through ``new_id``. Well-formed enough to be routed like any other, so the refusal is the
    mediator ruling on an invented lead and never a name collision or a rejected shape."""

    CONJURE_EVERY = 3
    """Moves per conjured one.

    A conjured move does **not** advance the cross-product walk, and that is load-bearing rather
    than incidental. Advancing it was measured first: three divides the six families, so the
    conjured moves landed on ``PIVOT_CYCLE[2]`` and ``PIVOT_CYCLE[5]`` and on nothing else at
    every run length, and those two families were then never executed once. That is not the
    cycling policy with a third of its moves refused — it is a policy that permanently lost a
    third of its vocabulary, which would have made the missing families a second new variable
    beside the refusals and left neither of them isolated. Leaving the walk in place keeps the
    pivots this pilot executes identical to the ones :class:`CyclingPilot` executes.
    """

    def __init__(self, moves: int) -> None:
        self._remaining = moves
        self._index = 0
        self._proposed = 0

    async def propose(self, briefing: Briefing) -> PilotMove:
        if self._remaining <= 0 or not briefing.entities:
            return Conclude(summary="out of moves")
        self._remaining -= 1
        self._proposed += 1

        entity, family = _cross_product(briefing, self._index)
        if self._proposed % self.CONJURE_EVERY == 0:
            return RunPivot(
                entity_id=self.CONJURED_ENTITY_ID,
                pivot_type=family,
                rationale="scripted, naming an entity no briefing surfaced",
            )
        self._index += 1
        return RunPivot(entity_id=entity, pivot_type=family, rationale="scripted")


def _cross_product(briefing: Briefing, index: int) -> tuple[str, PivotType]:
    """The index-th (entity, family) pair, covering the cross-product rather than a diagonal.

    The first version advanced both counters on the same index, so with 3 entities and 6
    families it walked a 6-long diagonal and never reached the other 12 pairs. That is a defect
    in the *pilot*, not in either loop — both arms saw it equally — but it capped the distinct
    pivots either loop could possibly reach, which is the benchmark's headline denominator.
    Found by reading the first run's numbers rather than by reading the code: 7 distinct pivots
    out of 18 available was too round a number to be the world's doing.
    """
    families = len(PIVOT_CYCLE)
    family = PIVOT_CYCLE[index % families]
    entity = briefing.entities[(index // families) % len(briefing.entities)]
    return entity.entity_id, family


def _exhausted_families(briefing: Briefing) -> frozenset[str]:
    """Family names the briefing reports as spent, read defensively.

    The context lines are prose the loop composed, not a structured list, so this matches on
    containment rather than equality. A parser that demanded an exact format would silently
    read every line as "not a match" the day the wording changed, and the pilot would look
    memory-blind for a reason nobody would find.
    """
    context = getattr(briefing, "research_context", None)
    if context is None:
        return frozenset()
    lines = tuple(getattr(context, "exhausted_directions", ()))
    return frozenset(
        family.value for family in PIVOT_CYCLE if any(family.value in line for line in lines)
    )


# --- what a run leaves behind ------------------------------------------------------


@dataclass(frozen=True)
class LoopMeasurement:
    """One arm, one pilot, counted from what the run actually did.

    Every field is derived from the mediator's own rulings rather than from what a pilot said
    it would do — a proposal the mediator refused cost a move and executed no pivot, and a
    benchmark that counted proposals would credit a pilot for work that never happened.
    """

    arm: str
    pilot: str
    allowance: int
    """Total moves the arm was *given*, which is what pairs two arms.

    Distinct from :attr:`moves`, the number actually taken, because the evolution arm can
    stop early — and the first version of :func:`compare` keyed on the moves taken, so a
    43-move evolution run was paired against whichever plain run happened to be nearest.
    Stopping early is a *result*; it must not also be the thing that decides what the
    result is compared with."""

    moves: int
    accepted: int
    refused: int
    distinct_pivots: int
    repeated_pivots: int
    entities_discovered: int
    evidence_sealed: int
    budget_spent: float
    stop_reason: str
    segments: int = 1

    @property
    def redundancy_rate(self) -> float:
        """Repeats as a share of executed pivots. The headline number for the memory claim.

        The denominator is the pivots that *ran*, so a refused move neither raises nor lowers
        this number — it shortens the walk behind it. This docstring got that backwards once,
        and wrongly in both halves: it said a refused pilot "divides by fewer of them and scores
        better", but dividing the *same* repeats by fewer executed pivots raises the rate (the
        cycling pilot's 18 repeats over its own 48 executed is 37.5%, over 32 it is 56.2%), and
        there is no distortion to correct for in the first place. Distinct pivots saturate at
        what the world can answer, so past that point every executed pivot is a repeat and this
        rate is a function of walk length alone: the conjuring pilot *given* 48 moves executes
        32 of them and reads 6.2%, which is exactly what the cycling pilot reads when it is
        given 32.

        So the column is safe to read down an arm and unsafe to read across pilots, because
        :func:`compare` pairs rows on the allowance and the cycling pilot at that same allowance
        of 48 reads 37.5%. :attr:`refused` is what tells a reader which of those two comparisons
        they are making — the honest control for a refused row is a clean run of equal *executed*
        length, which is not a row this table prints.
        """
        executed = self.distinct_pivots + self.repeated_pivots
        return self.repeated_pivots / executed if executed else 0.0


@dataclass
class _Counters:
    seen: set[tuple[str, str]] = field(default_factory=set)
    repeated: int = 0
    accepted: int = 0
    refused: int = 0
    entities: set[str] = field(default_factory=set)
    evidence: set[str] = field(default_factory=set)


def _count(counters: _Counters, session: PilotSession) -> None:
    for turn in session.transcript:
        if turn.ruling.accepted:
            counters.accepted += 1
        else:
            counters.refused += 1
        counters.entities.update(turn.ruling.entities_discovered)
        counters.evidence.update(turn.ruling.evidence_sealed)
        move = turn.move
        if not isinstance(move, RunPivot) or not turn.ruling.accepted:
            continue
        key = (move.entity_id, move.pivot_type.value)
        if key in counters.seen:
            counters.repeated += 1
        else:
            counters.seen.add(key)


# --- the world both arms start from ------------------------------------------------


@dataclass(frozen=True)
class _World:
    """One built world, nothing driven yet.

    Built here rather than borrowed from ``nemesis.pilotbench``, and the reason is a contract
    rather than convenience: ``pilot-does-not-know-about-evolution`` forbids the pilot seam
    **and its benchmark** from importing the Evolution plane, because a benchmark that certifies
    the seam's containment must not be able to condition that certification on whether a
    research loop is driving. A comparison between the two loops therefore has to be made from
    above both, which is this plane. The first draft of this module put it in ``pilotbench`` and
    the contract caught it.
    """

    root: Path
    graph: InMemoryGraphStore
    claims: InMemoryClaimStore
    vault: FileSystemEvidenceVault
    audit: AppendOnlyAuditTrail
    engine: PursuitEngine
    mediator: PilotMediator
    seed: IncidentSeed


async def _build_world(
    *,
    root: Path,
    max_moves: int,
    challenger: MoveChallenger | None = None,
    challenge_policy: ChallengePolicy | None = None,
) -> _World:
    """The reference world the evolution demonstration uses, with the ceiling as a parameter."""
    root.mkdir(parents=True, exist_ok=True)
    graph = InMemoryGraphStore()
    claims = InMemoryClaimStore()
    vault = FileSystemEvidenceVault(root / "vault")
    audit = AppendOnlyAuditTrail(root / "audit.jsonl")

    approved = Entity.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type=EntityType.DOMAIN,
        observed_form=APPROVED_DOMAIN,
        attributes=dict(APPROVED_STATE),
        extent=TemporalExtent.at(SCENARIO_NOW),
        is_synthetic=True,
    )
    await graph.upsert_entity(approved)

    signer = CapabilitySigningKey.generate()
    envelope = AutonomyEnvelope(
        _signed_envelope(signer, approved, now=datetime.now(UTC)),
        max_autonomous_effects=2,
        ledger=SqliteAuthorizationStore(root / "authorization.sqlite3"),
    )
    engine = PursuitEngine(
        graph=graph,
        claims=claims,
        vault=vault,
        audit=audit,
        connectors=ConnectorRegistry(simulated_connectors(as_of=SCENARIO_NOW)),
    )
    mediator = PilotMediator(
        engine=engine,
        graph=graph,
        envelope=envelope,
        # A measurement harness, not a deployment. Effects run in this process so the
        # figures describe the limiter rather than process-spawn latency, and the report
        # on every ruling says `mechanism=none; network=NOT DENIED` rather than letting
        # the absence of confinement go unrecorded.
        effects=InProcessEffectsExecutor(
            default_registry(verifying_key=signer.verifying_key, revocations=RevocationRegistry())
        ),
        claims=claims,
        audit=audit,
        max_moves=max_moves,
        challenger=challenger,
        challenge_policy=challenge_policy,
        # A measurement harness, not a production session: it drives deliberately pathological
        # pilots and must run them to the end to characterise what the limiter does. The stall
        # is still detected and still recorded on the session — only the stopping is declined.
        # See `SessionStagnationPolicy.halt_on_stall`.
        stagnation=SessionStagnationDetector(SessionStagnationPolicy(halt_on_stall=False)),
    )
    seed = IncidentSeed(
        entity_type=EntityType.DOMAIN,
        entity_key=APPROVED_DOMAIN,
        observed_at=SCENARIO_NOW,
        detected_by="loopbench fixture (SIMULATED)",
    )
    return _World(root, graph, claims, vault, audit, engine, mediator, seed)


# --- the two arms ------------------------------------------------------------------


async def run_plain_arm(
    make_pilot: Callable[[int], object],
    *,
    moves: int,
    budget: float,
    root: Path,
    challenger: MoveChallenger | None = None,
    challenge_policy: ChallengePolicy | None = None,
) -> LoopMeasurement:
    """One uninterrupted `drive`. The conventional loop, given the same allowance.

    A challenger, if one is supplied, is measured rather than hidden: a blocked move costs a
    move and executes no pivot, exactly like any other refusal, so it lands in ``refused`` and
    the arms stay comparable.
    """
    world = await _build_world(
        root=root,
        max_moves=moves,
        challenger=challenger,
        challenge_policy=challenge_policy,
    )
    pilot = make_pilot(moves)
    session = await world.mediator.drive(pilot, world.seed, total_budget=budget)  # type: ignore[arg-type]

    counters = _Counters()
    _count(counters, session)
    total = session.investigation.total_budget
    return LoopMeasurement(
        arm="plain",
        pilot=getattr(pilot, "name", "?"),
        allowance=moves,
        moves=len(session.transcript),
        accepted=counters.accepted,
        refused=counters.refused,
        distinct_pivots=len(counters.seen),
        repeated_pivots=counters.repeated,
        entities_discovered=len(counters.entities),
        evidence_sealed=len(counters.evidence),
        budget_spent=round(total - session.investigation.budget_remaining, 2),
        stop_reason="concluded" if session.concluded else (session.halted_reason or "halted"),
    )


async def run_evolution_arm(
    make_pilot: Callable[[int], object],
    *,
    segments: int,
    moves_per_segment: int,
    budget: float,
    root: Path,
    challenger: MoveChallenger | None = None,
    challenge_policy: ChallengePolicy | None = None,
) -> LoopMeasurement:
    """The same total moves, cut into segments, with the machinery on."""
    moves = segments * moves_per_segment
    world = await _build_world(
        root=root,
        max_moves=moves_per_segment,
        challenger=challenger,
        challenge_policy=challenge_policy,
    )
    pilot = make_pilot(moves)

    controller = EvolutionController(
        mediator=world.mediator,
        evaluator=PursuitEvaluator(entities=world.graph, claims=world.claims, evidence=world.vault),
        lineage=InMemoryLineageStore(),
        detector=StagnationDetector(StagnationPolicy(window=3)),
        supervisor=DeterministicSupervisor(),
        max_steps=segments,
        moves_per_step=moves_per_segment,
    )
    investigation = await world.engine.start(world.seed, total_budget=budget)
    state = controller.start(investigation)
    outcomes = await controller.run(state, pilot)  # type: ignore[arg-type]

    counters = _Counters()
    total_moves = 0
    for outcome in outcomes:
        _count(counters, outcome.session)
        total_moves += len(outcome.session.transcript)

    return LoopMeasurement(
        arm="evolution",
        pilot=getattr(pilot, "name", "?"),
        allowance=moves,
        moves=total_moves,
        accepted=counters.accepted,
        refused=counters.refused,
        distinct_pivots=len(counters.seen),
        repeated_pivots=counters.repeated,
        entities_discovered=len(counters.entities),
        evidence_sealed=len(counters.evidence),
        budget_spent=round(budget - state.investigation.budget_remaining, 2),
        stop_reason=(state.stop_reason or StopReason.STEP_BUDGET_EXHAUSTED).value,
        segments=state.step_index,
    )


# --- the comparison ----------------------------------------------------------------


PILOTS: Final[tuple[tuple[str, Callable[[int], object]], ...]] = (
    ("cycling", lambda moves: CyclingPilot(moves)),
    ("memory-aware", lambda moves: MemoryAwarePilot(moves)),
    ("conjuring", lambda moves: ConjuringPilot(moves)),
)

RUN_LENGTHS: Final = (2, 4, 8, 12)
"""Segments to sweep, at a fixed segment size.

The axis is **run length**, not scenario variety, because the claim under test is about a
pilot on move three hundred rather than about a pilot in an unusual world. Sweeping length is
the closest this corpus allows to asking whether the memory's benefit grows with the horizon —
and the answer being visible at four points is worth more than the same point measured in eight
different fixtures.
"""


async def run_loopbench(
    *,
    lengths: Sequence[int] = RUN_LENGTHS,
    moves_per_segment: int = DEFAULT_MOVES_PER_SEGMENT,
    budget: float = DEFAULT_BUDGET,
    workspace: Path | None = None,
) -> tuple[LoopMeasurement, ...]:
    """Every pilot through both arms at every run length. Sequential and deterministic."""
    root = Path(workspace or tempfile.mkdtemp(prefix="nemesis-loopbench-"))
    results: list[LoopMeasurement] = []
    for segments in lengths:
        moves = segments * moves_per_segment
        for name, make in PILOTS:
            results.append(
                await run_plain_arm(
                    make, moves=moves, budget=budget, root=root / f"{segments}-plain-{name}"
                )
            )
            results.append(
                await run_evolution_arm(
                    make,
                    segments=segments,
                    moves_per_segment=moves_per_segment,
                    budget=budget,
                    root=root / f"{segments}-evolution-{name}",
                )
            )
    return tuple(results)


CAVEATS: Final = (
    "WHAT THIS CANNOT TELL YOU",
    "  No frontier model was involved: all three pilots are fixed policies, and a model's",
    "  behaviour is not a policy.",
    "  The fixture world holds 37 answerable (pivot type, entity) pairs, so nothing here is a",
    "  long-horizon result and a plateau is mostly the corpus running out.",
    "  All three pilots enumerate a fixed cross-product, so their coverage is policy-determined",
    "  and no memory could improve it. This can see waste avoided; it cannot see coverage",
    "  gained.",
    "  A refused move costs a move and executes no pivot, so for the conjuring pilot moves and",
    "  executed pivots are different columns. redun% divides by the pivots that ran: read it",
    "  down an arm, never across pilots. At 48 allowed it reads 6.2% against cycling's 37.5%,",
    "  but 6.2% is also what cycling reads when it is *given* 32 moves — the refusals moved the",
    "  walk length, not the rate. The honest control is a clean run of equal executed length,",
    "  and this table does not print one.",
    "  The refusals are one scripted failure, an invented entity id every third move. That the",
    "  accounting survives it says the accounting is right; the cadence is a dial nobody has",
    "  measured against a model, so no rate in the ref column predicts anything.",
    "  The loop did not limit the refused pilot: it spent its whole allowance at 12, 24 and 48,",
    "  and at 72 ran to move 66 where the never-refused pilot stopped at 60.",
    "  Eight of nine directive types change only briefing wording, so a scripted pilot cannot",
    "  respond to them and this measures nothing about redirection.",
)


def render(results: Sequence[LoopMeasurement]) -> str:
    """The table, with the caveats above it. The ordering is not decoration."""
    lines = [
        *CAVEATS,
        "",
        f"{'moves':>5} {'arm':10} {'pilot':13} {'ok':>4} {'ref':>4} {'distinct':>8} "
        f"{'repeat':>6} {'redun%':>7} {'ent':>4} {'evid':>5} {'budget':>7}  stop",
    ]
    for r in results:
        lines.append(
            f"{r.moves:>5} {r.arm:10} {r.pilot:13} {r.accepted:>4} {r.refused:>4} "
            f"{r.distinct_pivots:>8} {r.repeated_pivots:>6} {r.redundancy_rate * 100:>6.1f}% "
            f"{r.entities_discovered:>4} {r.evidence_sealed:>5} {r.budget_spent:>7.1f}  "
            f"{r.stop_reason[:34]}"
        )
    return "\n".join(lines)


def compare(results: Sequence[LoopMeasurement]) -> tuple[str, ...]:
    """The paired differences, per run length and pilot, as plain statements.

    Paired on :attr:`LoopMeasurement.allowance` — the moves each arm was given — never on the
    moves it took. Never averaged across pilots either: an average over a pilot that reads the
    memory and one that ignores it describes neither, and it would move with the mix rather
    than with the machinery.
    """
    keyed = {(r.allowance, r.pilot, r.arm): r for r in results}
    out: list[str] = []
    for allowance in sorted({r.allowance for r in results}):
        for pilot, _ in PILOTS:
            plain = keyed.get((allowance, pilot, "plain"))
            evo = keyed.get((allowance, pilot, "evolution"))
            if plain is None or evo is None:
                continue
            out.append(
                f"{allowance:>3} allowed  {pilot:13} "
                f"moves {plain.moves}->{evo.moves}, "
                f"distinct {plain.distinct_pivots}->{evo.distinct_pivots}, "
                f"repeats {plain.repeated_pivots}->{evo.repeated_pivots}, "
                f"evidence {plain.evidence_sealed}->{evo.evidence_sealed}, "
                f"budget {plain.budget_spent:.1f}->{evo.budget_spent:.1f}"
            )
    return tuple(out)


__all__ = [
    "CAVEATS",
    "DEFAULT_BUDGET",
    "DEFAULT_MOVES_PER_SEGMENT",
    "DEFAULT_SEGMENTS",
    "PILOTS",
    "PIVOT_CYCLE",
    "RUN_LENGTHS",
    "ConjuringPilot",
    "CyclingPilot",
    "LoopMeasurement",
    "MemoryAwarePilot",
    "compare",
    "render",
    "run_evolution_arm",
    "run_loopbench",
    "run_plain_arm",
]
