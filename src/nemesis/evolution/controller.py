"""The loop: brief, drive, evaluate, remember, detect, redirect, repeat — and stop.

What this class holds is the argument. It is constructed with a
:class:`~nemesis.pilot.mediator.PilotMediator`, a :class:`~nemesis.evolution.evaluator.
PursuitEvaluator`, a :class:`~nemesis.evolution.lineage.LineageStore`, a detector and a supervisor.
It is **not** constructed with an engine, a graph writer, a vault, an effects registry, a
capability, an envelope or a signing key, and there is no method here that acquires one. Every
investigative action it causes goes through ``mediator.continue_session``, is proposed by the pilot
in the closed four-verb vocabulary, and is ruled on before it happens.

That is what makes the containment argument for the whole plane short: *Evolution cannot do
anything a pilot could not do, because everything it does is a pilot doing it.* A research loop
that made the limiter more permissive would be a worse system than no research loop; this one moves
only what goes **into** the briefing.

One step is one AVO variation step, mapped:

    P_t        the promoted lineage plus the run's operational memory
    K          the briefing the mediator builds — deliverable-class, scanned, minimized
    Vary       this controller composing a research context, and the pilot proposing moves
    f(x)       PursuitEvaluator, over structure the model cannot write
    feedback   the mediator's rulings, which the controller reads and remembers

The loop is bounded on every axis it can reach and defers to controls it cannot: the step
allowance, the pursuit budget, and the pilot's own conclusion. The envelope's autonomous-effect
budget is *not* one of them — not because it is ignored, but because it is enforced somewhere this
plane cannot see, which is the correct place for it.

Status: `IMPLEMENTED`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime

from pydantic import ValidationError

from nemesis.core.ids import CheckpointId, IdPrefix, new_id
from nemesis.core.temporal import utcnow
from nemesis.evolution.evaluator import PursuitEvaluator, StepObservation
from nemesis.evolution.lineage import (
    LineageError,
    LineageEventKind,
    LineageStore,
    active_lineage,
)
from nemesis.evolution.memory import (
    MemoryEntry,
    MemorySource,
    NegativeResult,
    ResearchMemory,
    sanitize,
)
from nemesis.evolution.models import (
    MAX_NOTE_LENGTH,
    MAX_REFS,
    CandidateStatus,
    EvaluationResult,
    InvestigationCheckpoint,
    StopReason,
    TrajectoryMeasurement,
    promotes,
)
from nemesis.evolution.stagnation import (
    StagnationAssessment,
    StagnationDetector,
    StepRecord,
)
from nemesis.evolution.supervisor import (
    CONTINUE_ON_FAILURE,
    DeterministicSupervisor,
    DirectiveType,
    IssuedDirective,
    ResearchDirective,
    TrajectoryDossier,
    TrajectorySupervisor,
    new_directive_id,
    validate_directive,
    validation_detail,
    without_imperative_rationale,
)
from nemesis.pilot.mediator import PilotMediator, PilotSession
from nemesis.pilot.moves import MAX_CONTEXT_ITEM_LENGTH, MAX_CONTEXT_ITEMS, ResearchContext
from nemesis.pilot.pilot import AutonomousPilot
from nemesis.pursuit.investigation import Investigation

DEFAULT_MAX_STEPS = 12
DEFAULT_MOVES_PER_STEP = 6
"""How many pilot moves one variation step spends.

Small on purpose. A step is the unit of evaluation, and a step that ran forty moves would be
evaluated once against a state that changed forty times — which is a loop with a memory rather than
a search. Six is enough for a pivot, a follow-up and a conclusion, and it is clamped down again by
the mediator's own ceiling, which a caller cannot raise."""

DEFAULT_SUPERVISOR_TIMEOUT = 60.0
"""Wall-clock ceiling on one ``supervisor.review`` call, in seconds.

The same bound, for the same reason, that the mediator puts on ``pilot.propose`` and on
``challenger.review``. A supervisor is optional, advisory and possibly a hosted model; one that
accepts the call and stalls must cost this loop sixty seconds, not the whole run."""

MAX_CONSECUTIVE_INVALID = 2
"""How many hard-gate failures in a row end the run.

Two. A gate failure is not an unlucky pivot — it means the trajectory produced a state that must
not be promoted at any score, and a loop that kept spending budget to produce more of them is a
loop doing harm slowly."""


@dataclass
class StepOutcome:
    """What one variation step produced. Returned so a caller can drive the loop itself."""

    checkpoint: InvestigationCheckpoint
    evaluation: EvaluationResult
    promoted: bool
    session: PilotSession
    investigation: Investigation
    assessment: StagnationAssessment | None = None
    directive: IssuedDirective | None = None


@dataclass
class EvolutionState:
    """Everything a run carries between steps, rebuilt exactly by
    :meth:`EvolutionController.resume`.

    Deliberately holds no authority and no handle — a state object that carried a capability would
    be a capability that survives a restart, which is the standing permission invariant 9 exists to
    prevent.
    """

    run_id: str
    investigation: Investigation
    memory: ResearchMemory = field(default_factory=ResearchMemory)
    head: InvestigationCheckpoint | None = None
    head_measurement: TrajectoryMeasurement | None = None
    directive: ResearchDirective | None = None
    steps: list[StepRecord] = field(default_factory=list)
    step_index: int = 0
    consecutive_invalid: int = 0
    directive_steps_without_gain: int = 0
    """How long the standing directive has been in force without moving a tier-1 term.

    Counted here rather than derived by the supervisor, because the supervisor is the component
    that may be a model and this is a fact about the run."""
    stop_reason: StopReason | None = None
    branch_id: str | None = None


class EvolutionController:
    """Drives a long-horizon run above the pilot seam.

    Holds a mediator, an evaluator, a lineage store, a detector and a supervisor. Nothing else, and
    the absence is the security argument — see the module docstring.
    """

    def __init__(
        self,
        *,
        mediator: PilotMediator,
        evaluator: PursuitEvaluator,
        lineage: LineageStore,
        detector: StagnationDetector | None = None,
        supervisor: TrajectorySupervisor | None = None,
        clock: Callable[[], datetime] = utcnow,
        max_steps: int = DEFAULT_MAX_STEPS,
        moves_per_step: int = DEFAULT_MOVES_PER_STEP,
        supervisor_timeout: float = DEFAULT_SUPERVISOR_TIMEOUT,
    ) -> None:
        if max_steps < 1:
            raise ValueError("a run must be allowed at least one step")
        if moves_per_step < 1:
            raise ValueError("a step must be allowed at least one move")
        self._mediator = mediator
        self._evaluator = evaluator
        self._lineage = lineage
        self._detector = detector or StagnationDetector()
        self._supervisor = supervisor or DeterministicSupervisor()
        self._clock = clock
        self._max_steps = max_steps
        self._moves_per_step = moves_per_step
        self._supervisor_timeout = supervisor_timeout

    @property
    def lineage(self) -> LineageStore:
        """The trajectory this controller writes to.

        Exposed read-side so an operator surface can show a run without reconstructing the store —
        and deliberately the *store*, not a filtered view of it: a property that returned only the
        promoted checkpoints would make the rejected ones invisible to every reader that went
        through it, which is the one thing this store exists to prevent.
        """
        return self._lineage

    @property
    def max_steps(self) -> int:
        return self._max_steps

    @property
    def moves_per_step(self) -> int:
        return self._moves_per_step

    # -- lifecycle -------------------------------------------------------------

    def start(self, investigation: Investigation, *, run_id: str | None = None) -> EvolutionState:
        """Open a run over an investigation that is already open."""
        state = EvolutionState(
            run_id=run_id or new_id(IdPrefix.EVOLUTION), investigation=investigation
        )
        self._lineage.append(
            run_id=state.run_id,
            kind=LineageEventKind.RUN_STARTED,
            occurred_at=self._clock(),
            detail="a long-horizon run opened over an existing investigation",
            facts={
                "investigation": investigation.investigation_id,
                "max_steps": str(self._max_steps),
                "moves_per_step": str(self._moves_per_step),
                "pursuit_budget": f"{investigation.budget_remaining:.2f}",
            },
        )
        return state

    def resume(self, run_id: str, investigation: Investigation) -> EvolutionState:
        """Rebuild a run's state from its trajectory.

        What comes back: the promoted head, its measurement, the memory as it was at that head, the
        stagnation window, the step index, the hard-gate strike streak, and whether the run was
        already stopped. What deliberately does **not** come back is authority. A checkpoint carries
        an ``autonomy_spend_snapshot`` and it is descriptive — the live envelope decides every
        effect, so an approval that expired while the run was stopped stays expired, and a budget
        that was spent stays spent. There is no code path here that could restore one, because this
        class never held one.

        The investigation is supplied by the caller rather than reconstructed from the lineage, for
        the same reason: canonical state lives in the graph, the claim store and the vault, and a
        resume that rebuilt it from a checkpoint would be a resume that trusted a projection.

        Three things an adversarial review found this method getting wrong, all of them the same
        mistake — reading the *head* where it should read the *trajectory*:

        - ``step_index`` was ``head.step_index + 1``, so every step taken since the last promotion
          was **refunded**. Three rejected steps after a promotion meant three free steps back. It
          is now the count of recorded candidate verdicts, which is what was actually spent.
        - A stopped run came back running. ``RUN_STOPPED`` is in the trajectory and was not read, so
          a resume silently reversed a stop — including a ``HARD_POLICY_REFUSAL`` one.
        - ``consecutive_invalid`` reset to zero, so the strike counter that ends a run producing
          unpromotable states was cleared by restarting it.

        An unknown run raises rather than minting a resume record for a trajectory that does not
        exist: "resumed a run that never started" is not a thing an audit trail should be able to
        say.
        """
        entries = self._lineage.entries(run_id)
        if not entries:
            raise LineageError(
                f"no trajectory for run {run_id!r}; a resume rebuilds a run from what it recorded, "
                "and there is nothing recorded to rebuild from"
            )
        chain = active_lineage(entries)
        head = chain[-1] if chain else None
        verdict_kinds = {
            LineageEventKind.CHECKPOINT_PROMOTED,
            LineageEventKind.CANDIDATE_REJECTED,
            LineageEventKind.CANDIDATE_INVALID,
        }
        verdicts = [entry for entry in entries if entry.kind in verdict_kinds]
        steps: list[StepRecord] = [
            StepRecord(
                evaluation=entry.checkpoint.evaluation,
                promoted=entry.kind is LineageEventKind.CHECKPOINT_PROMOTED,
                pivot_families=entry.checkpoint.pivots_attempted,
                state_digest=entry.checkpoint.graph_digest,
            )
            for entry in verdicts
            if entry.checkpoint is not None
        ]
        # The strike streak, recomputed from the tail rather than reset. A run that was two invalid
        # candidates from stopping is two invalid candidates from stopping after a restart.
        consecutive_invalid = 0
        for entry in reversed(verdicts):
            if entry.kind is LineageEventKind.CANDIDATE_INVALID:
                consecutive_invalid += 1
                continue
            break
        stopped = next(
            (entry for entry in reversed(entries) if entry.kind is LineageEventKind.RUN_STOPPED),
            None,
        )
        stop_reason = _stop_reason_of(stopped)
        self._lineage.append(
            run_id=run_id,
            kind=LineageEventKind.RUN_RESUMED,
            occurred_at=self._clock(),
            detail=(
                "resumed from the promoted head; authority was not restored from memory and the "
                "live envelope decides every effect"
            ),
            facts={
                "entries": str(len(entries)),
                "promoted_checkpoints": str(len(chain)),
                "steps_already_spent": str(len(verdicts)),
                "head": head.checkpoint_id if head else "",
                "carried_stop_reason": stop_reason.value if stop_reason else "",
            },
        )
        return EvolutionState(
            run_id=run_id,
            investigation=investigation,
            memory=head.research_memory if head else ResearchMemory(),
            head=head,
            head_measurement=head.evaluation.measurement if head else None,
            steps=steps,
            step_index=len(verdicts),
            consecutive_invalid=consecutive_invalid,
            stop_reason=stop_reason,
            branch_id=head.branch_id if head else None,
        )

    # -- one variation step ----------------------------------------------------

    async def step(self, state: EvolutionState, pilot: AutonomousPilot) -> StepOutcome:
        """Run one variation step and record everything it produced.

        The order is deliberate and each part depends on the one before it: build the context from
        what is remembered, drive a bounded segment through the mediator, evaluate what the segment
        changed, write what was learned into memory, decide whether the candidate promotes, then
        look at the window and — only if it has stalled — ask a supervisor.
        """
        context = self._context_for(state)
        session = await self._mediator.continue_session(
            pilot,
            state.investigation,
            max_moves=self._moves_per_step,
            research_context=context,
        )
        investigation = session.investigation
        self._lineage.append(
            run_id=state.run_id,
            kind=LineageEventKind.STEP_ATTEMPTED,
            occurred_at=self._clock(),
            detail=session.halted_reason or "the segment ran to a conclusion",
            facts={
                "step": str(state.step_index),
                "moves": str(len(session.transcript)),
                "concluded": str(session.concluded).lower(),
                "directive": context.directive if context else "",
            },
        )

        memory = self._remember(state.memory, session)
        evaluation = await self._evaluator.evaluate(
            StepObservation(
                session=session,
                investigation=investigation,
                memory=state.memory,
                moves_allowed=self._moves_per_step,
            ),
            parent=state.head_measurement,
        )
        promoted = promotes(evaluation, state.head.evaluation if state.head else None)
        status = (
            CandidateStatus.PROMOTED
            if promoted
            else (CandidateStatus.INVALID if not evaluation.valid else CandidateStatus.REJECTED)
        )
        settled = evaluation.model_copy(update={"status": status})
        checkpoint = self._checkpoint(state, session, investigation, settled, memory)

        kind = {
            CandidateStatus.PROMOTED: LineageEventKind.CHECKPOINT_PROMOTED,
            CandidateStatus.REJECTED: LineageEventKind.CANDIDATE_REJECTED,
            CandidateStatus.INVALID: LineageEventKind.CANDIDATE_INVALID,
        }[status]
        self._lineage.append(
            run_id=state.run_id,
            kind=kind,
            occurred_at=self._clock(),
            detail=self._verdict_detail(settled, promoted),
            facts=self._score_facts(settled),
            checkpoint=checkpoint,
        )

        state.investigation = investigation
        state.memory = memory
        state.steps.append(
            StepRecord(
                evaluation=settled,
                promoted=promoted,
                pivot_families=checkpoint.pivots_attempted,
                state_digest=checkpoint.graph_digest,
            )
        )
        state.step_index += 1
        state.consecutive_invalid = (
            state.consecutive_invalid + 1 if status is CandidateStatus.INVALID else 0
        )
        if promoted:
            state.head = checkpoint
            state.head_measurement = settled.measurement
        state.directive_steps_without_gain = (
            0
            if settled.score.made_epistemic_progress
            else state.directive_steps_without_gain + (1 if state.directive is not None else 0)
        )

        assessment = self._detector.assess(state.steps, pursuit_budget=investigation.total_budget)
        issued: IssuedDirective | None = None
        if assessment.describes_a_plateau:
            self._lineage.append(
                run_id=state.run_id,
                kind=LineageEventKind.PLATEAU_DETECTED,
                occurred_at=self._clock(),
                detail="; ".join(assessment.reasons[:3]),
                facts=dict(assessment.metrics),
            )
            issued = await self._consult(state, assessment)
            state.directive = issued.directive

        self._apply_stop_conditions(state, session, assessment)
        return StepOutcome(
            checkpoint=checkpoint,
            evaluation=settled,
            promoted=promoted,
            session=session,
            investigation=investigation,
            assessment=assessment,
            directive=issued,
        )

    async def run(self, state: EvolutionState, pilot: AutonomousPilot) -> tuple[StepOutcome, ...]:
        """Step until a deterministic stop condition fires. Never until nothing happens.

        The ceiling is checked *before* each step and the reasons are checked after, so a run that
        exhausts its allowance stops with :attr:`~nemesis.evolution.models.StopReason.
        STEP_BUDGET_EXHAUSTED` recorded rather than by falling out of a loop.
        """
        outcomes: list[StepOutcome] = []
        while state.stop_reason is None and state.step_index < self._max_steps:
            outcomes.append(await self.step(state, pilot))
        if state.stop_reason is None:
            self.stop(state, StopReason.STEP_BUDGET_EXHAUSTED)
        return tuple(outcomes)

    def stop(self, state: EvolutionState, reason: StopReason, *, detail: str = "") -> None:
        """End a run, recording why. Idempotent: a run stops once."""
        if state.stop_reason is not None:
            return
        state.stop_reason = reason
        self._lineage.append(
            run_id=state.run_id,
            kind=LineageEventKind.RUN_STOPPED,
            occurred_at=self._clock(),
            detail=detail or reason.value,
            facts={"steps": str(state.step_index), "reason": reason.value},
        )

    # -- hints from a collaboration channel ------------------------------------

    def ingest_hint(
        self,
        state: EvolutionState,
        *,
        text: str,
        author_reference: str,
        signal_ref: str = "",
    ) -> MemoryEntry:
        """Take a research suggestion from a channel into memory as untrusted data.

        Everything about this method is arranged so the hint stays *data*. It is sanitized and
        classified by :meth:`~nemesis.evolution.memory.MemoryEntry.record`; it lands in its own
        memory list; if it reads as an instruction it is kept and quarantined rather than deleted,
        so the humans who must respond to an injection attempt can see it; and either way it cannot
        become evidence, cannot widen scope, cannot request an effect and cannot become a
        directive — because a directive is a member of a closed enumeration and no string is one.

        Returns the entry so a caller can see what was made of what they sent.
        """
        entry = MemoryEntry.record(
            text,
            source=MemorySource.HUMAN_HINT,
            created_at=self._clock(),
            created_by=author_reference,
            source_ref=signal_ref,
        )
        state.memory = state.memory.with_entries("untrusted_hints", entry)
        self._lineage.append(
            run_id=state.run_id,
            kind=(
                LineageEventKind.HINT_QUARANTINED
                if entry.imperative
                else LineageEventKind.HINT_ACCEPTED
            ),
            occurred_at=self._clock(),
            detail=entry.content,
            facts={
                "author": author_reference[:200],
                "signal": signal_ref[:200],
                "classification": MemorySource.HUMAN_HINT.value,
                "instruction_shapes": ",".join(entry.imperative),
                "projected_to_pilot": str(entry.projectable).lower(),
            },
        )
        return entry

    # -- internals -------------------------------------------------------------

    def _context_for(self, state: EvolutionState) -> ResearchContext:
        """Select a bounded slice of memory for the next briefing.

        Selection, not serialization. The whole trajectory is in the lineage; what goes to the model
        is the most recent slice of each list, capped by the seam's own bound. Recency is a crude
        strategy and is chosen for being *legible* rather than clever: an operator reading a
        briefing can say exactly why each line is in it.

        Only :meth:`~nemesis.evolution.memory.ResearchMemory.projectable` content passes, so an
        entry carrying instruction shapes never reaches a pilot however it got into memory.
        """
        directive = state.directive
        return ResearchContext(
            run_id=state.run_id[:128],
            step_index=state.step_index,
            branch_id=(state.branch_id or "")[:128],
            directive=directive.directive.value if directive else "",
            directive_focus=directive.focus.value if directive else "",
            directive_rationale=directive.rationale if directive else "",
            open_questions=_lines(state.memory.projectable("unresolved_questions")),
            exhausted_directions=_lines(state.memory.exhausted_pivot_families),
            recent_negative_results=_lines(
                f"{result.pivot_family} on {result.target_ref}: {result.reason}"
                for result in state.memory.failed_directions
            ),
            contradictions=_lines(state.memory.projectable("contradictory_observations")),
            high_value_directions=_lines(state.memory.projectable("high_value_pivot_families")),
            untrusted_hints=_lines(state.memory.projectable("untrusted_hints")),
        )

    def _remember(self, memory: ResearchMemory, session: PilotSession) -> ResearchMemory:
        """Write what the mediator's rulings say into operational memory.

        Every entry written here is :attr:`~nemesis.evolution.memory.MemorySource.SYSTEM_DERIVED`:
        it comes from a ruling, not from anything the pilot said about its move. A pivot the pilot
        rationalized beautifully and which sealed nothing is recorded as having sealed nothing.
        """
        now = self._clock()
        updated = memory
        for turn in session.transcript:
            move = turn.move
            ruling = turn.ruling
            if move is None or move.kind != "run_pivot":
                continue
            family = getattr(move, "pivot_type", None)
            target = getattr(move, "entity_id", "")
            if family is None:
                continue
            produced = bool(ruling.evidence_sealed) or bool(ruling.entities_discovered)
            if ruling.accepted and produced:
                updated = updated.with_entries(
                    "high_value_pivot_families",
                    MemoryEntry.record(
                        f"{family.value} on {target} sealed "
                        f"{len(ruling.evidence_sealed)} evidence object(s) and surfaced "
                        f"{len(ruling.entities_discovered)} entity(ies)",
                        source=MemorySource.SYSTEM_DERIVED,
                        created_at=now,
                        repeat_key=f"{family.value}:{target}",
                    ),
                )
                continue
            updated = updated.with_negative_result(
                NegativeResult(
                    pivot_family=family.value,
                    target_ref=target,
                    # Sanitized. A ruling reason can carry a connector's error text, which is
                    # written outside NEMESIS, and this is the one memory write that reached a
                    # briefing without passing `MemoryEntry.record`. An adversarial review found it:
                    # a connector whose error contained a newline put two lines into a research
                    # context that is displayed as one per entry.
                    reason=sanitize(ruling.reason, limit=MAX_NOTE_LENGTH),
                    observed_at=now,
                    produced_nothing_measurable=not produced,
                )
            )
        return updated

    def _checkpoint(
        self,
        state: EvolutionState,
        session: PilotSession,
        investigation: Investigation,
        evaluation: EvaluationResult,
        memory: ResearchMemory,
    ) -> InvestigationCheckpoint:
        executed = investigation.all_executed_pivots
        parent: CheckpointId | None = state.head.checkpoint_id if state.head else None
        refs = evaluation.refs
        return InvestigationCheckpoint(
            checkpoint_id=new_id(IdPrefix.CHECKPOINT),
            run_id=state.run_id,
            investigation_id=investigation.investigation_id,
            parent_checkpoint_id=parent,
            branch_id=state.branch_id,
            step_index=state.step_index,
            created_at=self._clock(),
            graph_digest=evaluation.measurement.digest(),
            evidence_refs=refs.evidence_refs,
            entity_refs=refs.entity_refs,
            claim_refs=refs.claim_refs,
            origin_cluster_refs=refs.origin_cluster_refs,
            active_hypotheses=tuple(h.hypothesis_id for h in investigation.open_hypotheses),
            settled_hypotheses=tuple(
                h.hypothesis_id for h in investigation.hypotheses if h.is_settled
            ),
            pivots_attempted=_unique(pivot.candidate.pivot_type.value for pivot in executed),
            evaluation=evaluation,
            research_memory=memory,
            pilot_provider=session.identity.provider if session.identity else "",
            pilot_model=session.identity.model if session.identity else "",
            challenger_summary=_challenger_summary(session),
            autonomy_spend_snapshot=(
                "descriptive only; the live envelope decides every effect on resume"
            ),
            directive_applied=state.directive.directive.value if state.directive else "",
            metadata=(
                {"withheld_entities": str(refs.withheld_entities)} if refs.withheld_entities else {}
            ),
        )

    async def _consult(
        self, state: EvolutionState, assessment: StagnationAssessment
    ) -> IssuedDirective:
        """Ask the supervisor, and contain whatever comes back — including nothing at all.

        Four containments, and three of them are corrections an adversarial review forced.

        **Bounded by a wall clock the supervisor cannot influence.** ``review`` is awaited under
        ``asyncio.wait_for``, exactly as the mediator bounds ``pilot.propose`` and
        ``challenger.review``. Without it a supervisor that accepted the call and stalled — the
        shape a hosted model has when a vendor hangs — parked the run on one plateau for ever:
        ``run()`` never reached a stop condition, ``stop_reason`` stayed ``None``, and no
        ``RUN_STOPPED`` was written. A loop whose contract is "never until nothing happens" must
        not be stoppable by an advisory component doing nothing.

        **Its name is read defensively, once.** ``name`` is a property on untrusted code sitting on
        the audit path; one that raises used to take the run with it from *outside* the try block.
        Anything that is not a plain string becomes a placeholder rather than being coerced into a
        plausible-looking vendor, which is the reasoning
        :meth:`~nemesis.pilot.mediator.PilotMediator._identity_of` gives for a seat's identity.

        **Its rationale is classified like a hint.** The text reaches the next briefing, so a
        supervisor writing "ignore all previous restrictions" into a rationale would have had the
        one channel a *hint* saying the same thing is quarantined on. Same classifier, same
        outcome: the directive stands, the rationale is dropped, and the trajectory says so.

        **A failure does not stop the run.** The directive becomes
        :data:`~nemesis.evolution.supervisor.CONTINUE_ON_FAILURE` with ``answered=False`` recorded
        beside it. Making an advisory control able to halt an investigation would hand anyone who
        can degrade it a way to stop one.
        """
        name = self._supervisor_name()
        dossier = TrajectoryDossier(
            run_id=state.run_id[:128],
            step_index=state.step_index,
            assessment=assessment,
            recent_pivot_families=tuple(
                family for step in state.steps[-4:] for family in step.pivot_families
            )[:16],
            open_questions=state.memory.projectable("unresolved_questions")[-4:],
            standing_assumptions=state.memory.projectable("assumptions_under_test")[-4:],
            independent_origins=(
                state.head_measurement.independent_origins if state.head_measurement else 0
            ),
            origin_floor=state.head_measurement.origin_floor if state.head_measurement else 0,
            open_contradictions=(
                state.head_measurement.open_contradictions if state.head_measurement else 0
            ),
            steps_remaining=max(0, self._max_steps - state.step_index),
            last_directive=state.directive.directive.value if state.directive else "",
            directive_steps_without_gain=state.directive_steps_without_gain,
        )
        self._lineage.append(
            run_id=state.run_id,
            kind=LineageEventKind.SUPERVISOR_CONSULTED,
            occurred_at=self._clock(),
            detail=f"supervisor {name!r} consulted on a plateau",
            facts={"signals": ",".join(signal.value for signal in assessment.signals)},
        )
        answered = True
        try:
            raw = await asyncio.wait_for(
                self._supervisor.review(dossier), timeout=self._supervisor_timeout
            )
            directive = without_imperative_rationale(validate_directive(raw))
        except Exception as failure:
            answered = False
            directive = CONTINUE_ON_FAILURE
            detail = (
                validation_detail(failure)
                if isinstance(failure, ValidationError)
                else type(failure).__name__
            )
            self._lineage.append(
                run_id=state.run_id,
                kind=LineageEventKind.DIRECTIVE_ISSUED,
                occurred_at=self._clock(),
                detail=f"the supervisor produced no valid directive ({detail}); NOT redirected",
                facts={"answered": "false"},
            )
        issued = IssuedDirective(
            directive_id=new_directive_id(),
            directive=directive,
            issued_by=name,
            issued_at=self._clock(),
            answered=answered,
        )
        if answered:
            self._lineage.append(
                run_id=state.run_id,
                kind=LineageEventKind.DIRECTIVE_ISSUED,
                occurred_at=self._clock(),
                detail=directive.rationale,
                facts={
                    "directive": directive.directive.value,
                    "focus": directive.focus.value,
                    "answered": "true",
                },
            )
        self._lineage.append(
            run_id=state.run_id,
            kind=LineageEventKind.DIRECTIVE_APPLIED,
            occurred_at=self._clock(),
            detail="the directive changes the next briefing and nothing else",
            facts={"directive": directive.directive.value},
        )
        return issued

    def _supervisor_name(self) -> str:
        """What the supervisor says it is, read defensively and bounded.

        A property on untrusted code, evaluated on the audit path. One that raises must not end a
        run, and one that returns something other than a string must not be coerced into a
        plausible-looking identity — an audit record naming a component nobody ran is worse than
        one that admits it does not know.
        """
        try:
            name = self._supervisor.name
        except Exception:
            return "<supervisor name unavailable>"
        return name[:200] if isinstance(name, str) and name else "<unnamed supervisor>"

    def _apply_stop_conditions(
        self,
        state: EvolutionState,
        session: PilotSession,
        assessment: StagnationAssessment,
    ) -> None:
        """Every stop is a deterministic check on observable state. None is a model's decision."""
        if session.concluded:
            self.stop(state, StopReason.PILOT_CONCLUDED, detail="the pilot concluded the session")
            return
        if state.investigation.budget_remaining <= 0:
            self.stop(state, StopReason.PURSUIT_BUDGET_EXHAUSTED)
            return
        if state.consecutive_invalid >= MAX_CONSECUTIVE_INVALID:
            self.stop(
                state,
                StopReason.HARD_POLICY_REFUSAL,
                detail=(
                    f"{state.consecutive_invalid} candidates in a row failed a hard gate; "
                    "continuing would spend budget producing states that cannot be promoted"
                ),
            )
            return
        # A supervisor RECOMMENDS a stop; two deterministic conditions decide it. The plateau must
        # stand, AND a redirect must already have been in force long enough to have bought nothing.
        # The first version required only the plateau, and an adversarial review was right that this
        # made the "deterministic stop condition" close to a tautology: plateaus are common early,
        # so a hostile supervisor could end almost any investigation by returning STOP_LOW_YIELD on
        # the first one. It now cannot stop a run the detector has not already watched fail to
        # respond to a change of strategy — which is a run that was going to stop anyway.
        #
        # The honest residual is still an availability one, and this ADR says so: a hostile
        # supervisor can bring a *genuinely stalled* run to an end sooner than an operator might
        # have. It cannot end a productive one, and it can never cause an action.
        redirect_exhausted = state.directive_steps_without_gain >= MAX_CONSECUTIVE_INVALID
        if (
            state.directive is not None
            and state.directive.directive is DirectiveType.STOP_LOW_YIELD
            and assessment.describes_a_plateau
            and redirect_exhausted
        ):
            self.stop(
                state,
                StopReason.LOW_YIELD,
                detail=(
                    "the supervisor recommended stopping, the plateau still stands, and a "
                    f"directive has been in force for {state.directive_steps_without_gain} step(s) "
                    "without moving a tier-1 term"
                ),
            )
            return
        if state.step_index >= self._max_steps:
            self.stop(state, StopReason.STEP_BUDGET_EXHAUSTED)

    @staticmethod
    def _verdict_detail(evaluation: EvaluationResult, promoted: bool) -> str:
        if evaluation.status is CandidateStatus.INVALID:
            return "; ".join(
                f"{finding.gate.value}: {finding.detail}" for finding in evaluation.gate_findings
            )[:1000]
        if promoted:
            return "the candidate beat the incumbent on the epistemic tier"
        return (
            "the candidate is valid and did not beat the incumbent; kept in the trajectory so the "
            "direction is not retried for free"
        )

    @staticmethod
    def _score_facts(evaluation: EvaluationResult) -> dict[str, str]:
        score = evaluation.score
        return {
            "origin_floor_gain": str(score.origin_floor_gain),
            "independent_origin_gain": str(score.independent_origin_gain),
            "contradictions_resolved": str(score.contradictions_resolved),
            "useful_entities": str(score.useful_entities_discovered),
            "discriminating_edges": str(score.discriminating_relationships_gained),
            "novel_families": str(score.novel_pivot_families),
            "pivots": str(score.pivots_spent),
            "redundant_pivots": str(score.redundant_pivots),
            "refused_moves": str(score.refused_moves),
            "budget": f"{score.budget_spent:.2f}",
        }


def _stop_reason_of(entry: object) -> StopReason | None:
    """The stop reason a ``RUN_STOPPED`` entry recorded, or ``None`` when the run is still open.

    Defensive about the value, not merely about the entry: a trajectory is a file, and a resume
    that coerced an unrecognised string into a plausible-looking reason would report a stop nobody
    recorded. An entry whose reason does not parse leaves the run stopped with no reason rather than
    running — fail closed, because "we could not read why this stopped" must not read as "it did
    not stop".
    """
    if entry is None:
        return None
    reason = getattr(entry, "facts", {}).get("reason", "")
    try:
        return StopReason(reason)
    except ValueError:
        return StopReason.FATAL_INVARIANT_FAILURE


def _lines(values: Iterable[str]) -> tuple[str, ...]:
    """The most recent items, each truncated to what the pilot seam actually accepts.

    Both bounds, applied here, and the second one is a correction an adversarial review forced.
    :class:`~nemesis.pilot.moves.ResearchContext` caps a line at
    :data:`~nemesis.pilot.moves.MAX_CONTEXT_ITEM_LENGTH` (240) while a
    :class:`~nemesis.evolution.memory.MemoryEntry` may hold 400 — so a benign 305-character
    research suggestion, typed into a channel by an analyst, raised a ``ValidationError`` out of
    the step and **permanently** killed the run: the entry stayed in memory, so every retry raised
    again, and ``stop_reason`` was never set, so nothing recorded why.

    That is precisely the denial of service this design refuses to have — the one the mediator's
    redaction avoids by not *raising* on an adversary-controlled marker — reintroduced through
    length instead of through vocabulary, and reachable by anyone who can type into a case channel.
    One field was truncated and five were not, which is the shape of guard this repository calls out
    as a guard against the leaks somebody predicted. Truncating here covers every list from one
    place, so a sixth field added later is bounded the day it appears.
    """
    return tuple(str(value)[:MAX_CONTEXT_ITEM_LENGTH] for value in values)[-MAX_CONTEXT_ITEMS:]


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    """Order-preserving de-duplication, truncated at the checkpoint's reference bound.

    Order-preserving because a checkpoint's reference lists are read by people, and the order a
    pivot surfaced things in is the order that makes them readable. Truncated because a checkpoint
    is serialized into an append-only trajectory on every step.
    """
    return tuple(dict.fromkeys(values))[:MAX_REFS]


def _challenger_summary(session: PilotSession) -> str:
    challenged = [turn.challenge for turn in session.transcript if turn.challenge is not None]
    if not challenged:
        return "no challenger was configured for this session"
    verdicts: dict[str, int] = {}
    for ruling in challenged:
        verdicts[ruling.verdict.value] = verdicts.get(ruling.verdict.value, 0) + 1
    return ", ".join(f"{verdict}: {count}" for verdict, count in sorted(verdicts.items()))[:500]


__all__ = [
    "DEFAULT_MAX_STEPS",
    "DEFAULT_MOVES_PER_STEP",
    "DEFAULT_SUPERVISOR_TIMEOUT",
    "MAX_CONSECUTIVE_INVALID",
    "EvolutionController",
    "EvolutionState",
    "StepOutcome",
]
