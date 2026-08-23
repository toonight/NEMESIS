"""The objects a long-horizon run is made of, and the one modelling decision that matters most.

AVO's candidate ``x_i`` is a program and its fitness ``f(x_i)`` is a benchmark. Cyber attribution
has no such oracle, and the tempting substitution — make the candidate an attribution and the
fitness its confidence — is a **Goodhart trap** with a specific, foreseeable failure: the system
would learn to raise a number rather than to find out what is true, and it would do so
convincingly, because producing a confident-sounding attribution is exactly what a frontier model
is good at. Attributing a criminal organization wrongly is a serious error; the machinery that
optimises for that error is not one to build and then supervise.

So the candidate here is an :class:`InvestigationCheckpoint` — the epistemic and operational state
of an investigation at a point in its trajectory — and what is measured is whether the state
*improved as an investigation*: more independent origins, fewer contradictions, discriminating
rather than voluminous discoveries, and progress that survives losing a plantable artifact. A
checkpoint that asserted a stronger conclusion and learned nothing scores zero here, by
construction rather than by a check somebody has to remember.

**A checkpoint references; it does not contain.** Evidence stays in the vault, canonical facts
stay in the graph, claims stay in the claim store. What a checkpoint holds is identifiers, digests
and its own operational memory. That separation is the same one invariant 2 draws between the
Intelligence Graph and the Evidence Graph, and it is why nothing in this module can become
evidence: there is no field for an artifact and no constructor that takes one.

Status: `IMPLEMENTED`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Final, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.core.canonical import canonical_bytes
from nemesis.core.ids import CheckpointId, EvolutionBranchId, EvolutionRunId, InvestigationId
from nemesis.core.temporal import require_utc
from nemesis.evolution.memory import ResearchMemory

MAX_REFS: Final = 256
"""How many references of one kind a checkpoint carries. Bounded because a checkpoint is
serialized into an append-only trajectory on every step, and an unbounded reference list would
make the trajectory grow quadratically in the length of the run."""

MAX_NOTE_LENGTH: Final = 500


class EpistemicGate(StrEnum):
    """The hard validity checks. Failing any one makes a candidate unpromotable, full stop.

    AVO's analogue is correctness: a CUDA kernel that computes the wrong answer very fast is not
    an improvement, whatever the benchmark says. The NEMESIS analogue is stronger, because an
    epistemically invalid trajectory does not merely fail to improve — it is the thing the whole
    platform exists to prevent, and a search that could promote one would be optimising toward it.

    Deliberately checked *before* any gain is looked at, and deliberately not weighted against it.
    A gate is not a term in a score.
    """

    SCOPE = "scope"
    """Every entity the checkpoint names is one this investigation actually surfaced. A checkpoint
    that referenced an entity the graph does not hold would be a resumable pointer at nothing."""

    PROVENANCE = "provenance"
    """Every evidence reference resolves in the vault. Invariant 3: no claim of progress whose
    derivation chain cannot be followed back to collected material."""

    SOURCE_INDEPENDENCE = "source_independence"
    """Sources with no established lineage contribute at most one origin between them. The
    measurement is re-derived and checked here, so a future change to the clustering that turned
    missing provenance into asserted independence fails a gate rather than raising a score."""

    EVIDENCE_SEMANTICS = "evidence_semantics"
    """Every claim the pilot recorded in this segment is a HYPOTHESIS derived from a
    MODEL_ASSERTION. Invariant 1 already enforces this at construction; checking it again at the
    point where a *search* would benefit from it being false is not redundancy, it is the place
    the pressure actually applies."""

    IDENTITY = "identity"
    """Nothing the checkpoint names is internal-classified. Founder decision D1: persona linkage
    directs an investigation and does not travel — and a checkpoint travels, into a durable
    trajectory and into a collaboration channel."""

    AUTHORIZATION_BOUNDARY = "authorization_boundary"
    """No effect in this segment reported contact with the outside world, and none was accepted
    that the envelope did not permit. Fail-closed: an accepted effect that came back without
    saying counts as having left."""

    POLICY = "policy"
    """The segment stayed inside the move ceiling and produced only moves in the closed
    vocabulary."""


class GateFinding(BaseModel):
    """One hard-validity failure, named so an operator can act on it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    gate: EpistemicGate
    detail: Annotated[str, Field(min_length=1, max_length=MAX_NOTE_LENGTH)]


class TrajectoryMeasurement(BaseModel):
    """The structural state of an investigation at one moment. Absolute, not a delta.

    Every field is something the platform can *observe*: an object in a store, a class on an
    entity type, a population size a connector reported. Not one of them is a model's opinion about
    its own work, and that is the property :class:`ScoreVector` inherits.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_count: Annotated[int, Field(ge=0)] = 0
    independent_origins: Annotated[int, Field(ge=0)] = 0
    """Distinct provenance clusters among the sealed evidence. Five feeds reselling one upstream
    are one origin; ten sources with no stated lineage are also one, because
    :meth:`~nemesis.core.provenance.SourceDescriptor.provenance_cluster` collapses them rather
    than reading missing provenance as independence."""

    origin_floor: Annotated[int, Field(ge=0)] = 0
    """Origins that survive removing the most load-bearing *plantable* cluster.

    The counterfactual ADR-0004 applies to a fused opinion, applied here to a trajectory. It is
    what distinguishes one spectacular artifact an adversary could have planted from several
    moderate origins they could not have planted all of — and ordering the score on it first is
    how "robust beats fragile" stops being a slogan."""

    unplantable_origins: Annotated[int, Field(ge=0)] = 0
    claim_count: Annotated[int, Field(ge=0)] = 0
    evidence_backed_claims: Annotated[int, Field(ge=0)] = 0
    open_contradictions: Annotated[int, Field(ge=0)] = 0
    settled_hypotheses: Annotated[int, Field(ge=0)] = 0
    total_hypothesis_uncertainty: Annotated[float, Field(ge=0.0)] = 0.0
    """Summed subjective-logic uncertainty over the investigation's hypotheses. Summed rather than
    averaged so that settling one hypothesis and opening another is not invisible."""

    useful_entities: Annotated[int, Field(ge=0)] = 0
    """Discovered entities that are not shared-infrastructure types. +200 domains on a CDN address
    is not 200 discoveries."""

    shared_infrastructure_entities: Annotated[int, Field(ge=0)] = 0
    discriminating_relationships: Annotated[int, Field(ge=0)] = 0
    """Edges whose :class:`~nemesis.core.relationships.PivotSelectivity` is informative — a counted
    population narrow enough to mean something, or an attribute unique by construction. Uncounted
    populations weigh nothing here for the same reason they weigh nothing in an edge."""

    pivots_executed: Annotated[int, Field(ge=0)] = 0
    informative_pivots: Annotated[int, Field(ge=0)] = 0
    budget_spent: Annotated[float, Field(ge=0.0)] = 0.0

    def digest(self) -> str:
        """A short digest of the whole measurement, for a checkpoint to carry."""
        return hashlib.sha256(canonical_bytes(self.model_dump(mode="json"))).hexdigest()[:16]


class ScoreVector(BaseModel):
    """What one variation step changed, in three tiers that are compared lexicographically.

    Never summed. A weighted sum lets a large gain in a cheap dimension buy a loss in an expensive
    one — the failure mode a single "fitness" number has in every domain where the dimensions are
    not commensurable, and attribution is emphatically such a domain. What is compared instead is
    :meth:`ordering_key`, a tuple: a candidate wins on epistemic progress or it does not get to
    argue about anything else.

    The ordering *within* tier one is itself a choice and is stated here so it can be argued with
    rather than discovered: robustness first, then independent origins, then contradictions
    resolved, then hypotheses settled, then uncertainty reduced, then evidence-backed claims. Its
    cost is real — a candidate that resolves two contradictions loses to one that adds a single
    robust origin — and it is accepted deliberately, because the alternative ordering is the one
    that prefers a fragile spectacular finding.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    # -- tier 1: epistemic progress --------------------------------------------
    origin_floor_gain: int = 0
    independent_origin_gain: int = 0
    contradictions_resolved: int = 0
    hypotheses_settled: int = 0
    uncertainty_reduction: float = 0.0
    evidence_backed_claim_gain: int = 0

    # -- tier 2: investigation utility -----------------------------------------
    useful_entities_discovered: int = 0
    discriminating_relationships_gained: int = 0
    novel_pivot_families: int = 0
    """Pivot families this run had not tried before. Novelty is measured against the trajectory's
    own memory, so a run that keeps proposing the same family stops being rewarded for it."""

    # -- tier 3: efficiency ----------------------------------------------------
    pivots_spent: Annotated[int, Field(ge=0)] = 0
    moves_spent: Annotated[int, Field(ge=0)] = 0
    budget_spent: Annotated[float, Field(ge=0.0)] = 0.0
    redundant_pivots: Annotated[int, Field(ge=0)] = 0
    """Pivots re-run on a family and target the memory already records as spent. Counted as a cost
    rather than refused, because the mediator is the only thing that refuses moves and this plane
    does not get to become a second one."""

    refused_moves: Annotated[int, Field(ge=0)] = 0

    @property
    def epistemic_key(self) -> tuple[int, int, int, int, float, int]:
        return (
            self.origin_floor_gain,
            self.independent_origin_gain,
            self.contradictions_resolved,
            self.hypotheses_settled,
            round(self.uncertainty_reduction, 6),
            self.evidence_backed_claim_gain,
        )

    @property
    def utility_key(self) -> tuple[int, int, int]:
        return (
            self.useful_entities_discovered,
            self.discriminating_relationships_gained,
            self.novel_pivot_families,
        )

    @property
    def efficiency_key(self) -> tuple[int, int, int, float, int]:
        """Negated, so that "more is better" holds for every element of :meth:`ordering_key`.

        Efficiency is a tie-break and nothing more. A cheaper run never outranks a better one,
        because this tuple is only ever reached when the two above it are equal.

        ``moves_spent`` is here because :meth:`PursuitEvaluator._score`'s prose says a
        ``record_belief`` "appears in exactly one term below — ``moves_spent``, a cost", and an
        adversarial review checked. It did not: the term existed on the model and appeared in no
        ordering key, so a belief was entirely free and the documented cost did not exist. A claim
        about a cost that nothing charges is worse than no claim.
        """
        return (
            -self.redundant_pivots,
            -self.pivots_spent,
            -self.moves_spent,
            -round(self.budget_spent, 6),
            -self.refused_moves,
        )

    def ordering_key(self) -> tuple[object, ...]:
        return (self.epistemic_key, self.utility_key, self.efficiency_key)

    @property
    def made_epistemic_progress(self) -> bool:
        return self.epistemic_key > (0, 0, 0, 0, 0.0, 0)

    @property
    def made_any_progress(self) -> bool:
        return self.made_epistemic_progress or self.utility_key > (0, 0, 0)


class CheckpointRefs(BaseModel):
    """The references a candidate may carry, as the evaluator validated them.

    Produced by :class:`~nemesis.evolution.evaluator.PursuitEvaluator` rather than assembled by the
    controller, and the split is a correction an adversarial review forced. The controller used to
    build a checkpoint's reference lists from the investigation directly while the gates checked the
    same material separately — so an entity that failed the ``IDENTITY`` gate was still written into
    a durable, projectable checkpoint, and the gate then invalidated *every later candidate* because
    the offending pivot never leaves an investigation's cumulative history. One internal-class
    discovery permanently killed a run.

    Filtering is the right direction here and it is the direction the mediator's briefing already
    takes with an internal-class entity: a projection is *redacted*, not refused. So a checkpoint
    carries the deliverable-class references and records how many it dropped, and the gate stays as
    a fail-closed backstop over what the checkpoint actually carries.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_refs: tuple[str, ...] = ()
    entity_refs: tuple[str, ...] = ()
    claim_refs: tuple[str, ...] = ()
    origin_cluster_refs: tuple[str, ...] = ()
    withheld_entities: Annotated[int, Field(ge=0)] = 0
    """How many entities were dropped for being internal-classified. Reported rather than silent —
    a recipient told nothing about persona linkage should know that something was withheld."""


class CandidateStatus(StrEnum):
    """What became of a candidate checkpoint. Every value is recorded in the trajectory."""

    INVALID = "invalid"
    """A hard gate failed. Not promotable at any score."""

    REJECTED = "rejected"
    """Valid, and did not beat the incumbent. Kept, so the direction is not retried for free."""

    PROMOTED = "promoted"


class EvaluationResult(BaseModel):
    """The evaluator's verdict on one candidate: valid or not, and by how much it moved."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: CandidateStatus
    score: ScoreVector
    measurement: TrajectoryMeasurement
    refs: CheckpointRefs = Field(default_factory=CheckpointRefs)
    gate_findings: tuple[GateFinding, ...] = ()
    notes: tuple[Annotated[str, Field(max_length=MAX_NOTE_LENGTH)], ...] = ()

    @model_validator(mode="after")
    def _invalid_needs_a_finding(self) -> Self:
        if self.status is CandidateStatus.INVALID and not self.gate_findings:
            raise ValueError(
                "an INVALID candidate must name the gate that failed; an unexplained "
                "invalidation is indistinguishable from an evaluator defect"
            )
        if self.status is not CandidateStatus.INVALID and self.gate_findings:
            raise ValueError(
                "a candidate with gate findings cannot be valid: a failed hard gate is not a "
                "score to be outweighed"
            )
        return self

    @property
    def valid(self) -> bool:
        return self.status is not CandidateStatus.INVALID


def promotes(candidate: EvaluationResult, incumbent: EvaluationResult | None = None) -> bool:
    """Whether a candidate should become the new head of a linear lineage.

    Two rules, and the second one is a correction that running the reference demonstration forced:

    1. An invalid candidate never promotes. Not "scores low" — cannot, at any gain.
    2. A valid candidate promotes when it **made measurable progress over its parent**, which is
       what its score already is: every term in a :class:`ScoreVector` is a delta against the
       incumbent's measurement. A candidate that changed nothing does not promote, and that is what
       keeps a plateau visible — a run that promoted an empty step every step would look busy to
       every detector watching promotions.

    The first version of this function compared the candidate's ordering key against the
    *incumbent's* ordering key, and it was wrong in a way only a run showed. Both keys are deltas,
    so the comparison asked "did this step improve more than the previous step did" — which means a
    run that makes one large discovery and then steady smaller ones never promotes again, and its
    head freezes at step one while the investigation goes on learning. Comparing deltas is the
    right question for **siblings** (several variations of the same parent, which is what AVO
    selects between) and the wrong one for a chain. :func:`best_of` is the sibling comparison and
    is where the ordering key belongs.

    ``incumbent`` is still read for one case: a head that failed a hard gate is not a head worth
    keeping, so anything valid replaces it.
    """
    if not candidate.valid:
        return False
    if incumbent is not None and not incumbent.valid:
        return True
    return candidate.score.made_any_progress


def best_of(candidates: Sequence[EvaluationResult]) -> EvaluationResult | None:
    """The strongest of several candidates for the same parent, by the lexicographic ordering.

    The sibling comparison — AVO's selection step. Invalid candidates are excluded rather than
    ranked last, because a hard gate is not a low score; a set containing nothing valid has no
    winner, and returning the least-bad one would be exactly the promotion the gate exists to
    prevent.

    Ties resolve to the **earliest** candidate. Deterministic on purpose: invariant 11 asks for
    replayable, and a selection that broke ties by iteration order over a set would make two
    replays of one trajectory diverge.
    """
    valid = [candidate for candidate in candidates if candidate.valid]
    if not valid:
        return None
    best = valid[0]
    for candidate in valid[1:]:
        if candidate.score.ordering_key() > best.score.ordering_key():
            best = candidate
    return best


class InvestigationCheckpoint(BaseModel):
    """One candidate: the state of an investigation at a meaningful point in its trajectory.

    Immutable, references rather than contains, and carries its own operational memory so that a
    resume restores the memory *as it was at that point* rather than whatever a mutable store holds
    now.

    ``autonomy_spend_snapshot`` deserves its own warning, written here because this is where
    somebody would be tempted to trust it: it is **descriptive**. It records what the envelope had
    left when the checkpoint was written, so a run can be explained. It is not authority and a
    resume does not read it as authority — the live envelope decides, every time, and an approval
    that expired while the run was stopped stays expired.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    checkpoint_id: CheckpointId
    run_id: EvolutionRunId
    investigation_id: InvestigationId
    parent_checkpoint_id: CheckpointId | None = None
    branch_id: EvolutionBranchId | None = None
    step_index: Annotated[int, Field(ge=0)] = 0

    created_at: datetime

    graph_digest: Annotated[str, Field(max_length=64)] = ""
    """A digest over the measurement, not over the graph's bytes. Two checkpoints with the same
    digest are two moments the investigation looked structurally identical — which is exactly what
    a plateau is, and why the digest is worth carrying."""

    evidence_refs: tuple[Annotated[str, Field(max_length=200)], ...] = ()
    entity_refs: tuple[Annotated[str, Field(max_length=200)], ...] = ()
    claim_refs: tuple[Annotated[str, Field(max_length=200)], ...] = ()
    origin_cluster_refs: tuple[Annotated[str, Field(max_length=200)], ...] = ()
    """The provenance clusters this state rests on, by key. Kept so "how many independent origins"
    is answerable from the checkpoint without re-reading the vault."""

    active_hypotheses: tuple[Annotated[str, Field(max_length=200)], ...] = ()
    settled_hypotheses: tuple[Annotated[str, Field(max_length=200)], ...] = ()
    unresolved_questions: tuple[Annotated[str, Field(max_length=MAX_NOTE_LENGTH)], ...] = ()
    contradictions: tuple[Annotated[str, Field(max_length=MAX_NOTE_LENGTH)], ...] = ()

    pivots_attempted: tuple[Annotated[str, Field(max_length=200)], ...] = ()

    evaluation: EvaluationResult
    research_memory: ResearchMemory = Field(default_factory=ResearchMemory)

    pilot_provider: Annotated[str, Field(max_length=64)] = ""
    pilot_model: Annotated[str, Field(max_length=128)] = ""
    challenger_summary: Annotated[str, Field(max_length=MAX_NOTE_LENGTH)] = ""

    autonomy_spend_snapshot: Annotated[str, Field(max_length=200)] = ""
    """Descriptive. See the class docstring: a resume reads the live envelope, never this."""

    directive_applied: Annotated[str, Field(max_length=64)] = ""
    metadata: dict[str, Annotated[str, Field(max_length=MAX_NOTE_LENGTH)]] = Field(
        default_factory=dict
    )

    @model_validator(mode="after")
    def _bounded_and_utc(self) -> Self:
        require_utc(self.created_at, "created_at")
        for name in (
            "evidence_refs",
            "entity_refs",
            "claim_refs",
            "origin_cluster_refs",
            "active_hypotheses",
            "settled_hypotheses",
            "unresolved_questions",
            "contradictions",
            "pivots_attempted",
        ):
            value = getattr(self, name)
            if len(value) > MAX_REFS:
                raise ValueError(
                    f"{name} carries {len(value)} entries, at most {MAX_REFS} may be checkpointed; "
                    "a checkpoint references state, it does not copy it"
                )
        if self.parent_checkpoint_id == self.checkpoint_id:
            raise ValueError("a checkpoint cannot be its own parent")
        return self


class BranchStatus(StrEnum):
    """Where an alternative investigative direction stands."""

    ACTIVE = "active"
    PLATEAUED = "plateaued"
    PROMOTED = "promoted"
    PRUNED = "pruned"
    EXHAUSTED = "exhausted"


class EvolutionBranch(BaseModel):
    """One alternative investigative direction, with its own memory and its own share of a budget.

    Named ``EvolutionBranch`` and not ``InvestigationBranch`` because
    :class:`~nemesis.pursuit.investigation.InvestigationBranch` already exists and means something
    narrower: one line of enquiry *inside* one investigation, with a focus entity. This is a
    strategic direction across checkpoints — "pursue the false-flag hypothesis" — and collapsing
    the two names would make two different objects answer to one word in a codebase where the
    distinction decides which store a thing lives in.

    A branch shares the canonical evidence vault, the graph, the scope, the provenance rules and
    the authorization boundary. What it does not share is its memory, its lineage and its slice of
    the pivot budget. Three branches are three ways of spending one budget, never three budgets.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    branch_id: EvolutionBranchId
    run_id: EvolutionRunId
    parent_checkpoint_id: CheckpointId | None = None
    objective: Annotated[str, Field(min_length=1, max_length=MAX_NOTE_LENGTH)]
    hypothesis_refs: tuple[Annotated[str, Field(max_length=200)], ...] = ()
    status: BranchStatus = BranchStatus.ACTIVE
    created_at: datetime
    closed_at: datetime | None = None
    closure_reason: Annotated[str, Field(max_length=MAX_NOTE_LENGTH)] = ""

    step_allowance: Annotated[int, Field(ge=0)] = 0
    """Variation steps this branch may take from the run's shared allowance. Assigned by
    :class:`~nemesis.evolution.portfolio.BranchPortfolio`, which partitions and never creates."""

    steps_taken: Annotated[int, Field(ge=0)] = 0
    memory: ResearchMemory = Field(default_factory=ResearchMemory)

    @model_validator(mode="after")
    def _closure_needs_a_reason(self) -> Self:
        require_utc(self.created_at, "created_at")
        if self.closed_at is not None:
            require_utc(self.closed_at, "closed_at")
        if self.status in {BranchStatus.PRUNED, BranchStatus.EXHAUSTED} and not self.closure_reason:
            raise ValueError(
                f"branch {self.branch_id} is {self.status.value} without a stated reason; an "
                "unexplained closure is indistinguishable from a direction nobody explored"
            )
        return self

    @property
    def is_open(self) -> bool:
        return self.status is BranchStatus.ACTIVE

    @property
    def steps_remaining(self) -> int:
        return max(0, self.step_allowance - self.steps_taken)


class StopReason(StrEnum):
    """Why a run ended. There is no value meaning "still going" — a stopped run says why.

    Long horizon is not the same thing as unbounded, and every member here is a *deterministic*
    condition the controller checks. None of them is a model's decision.
    """

    PILOT_CONCLUDED = "pilot_concluded"
    STEP_BUDGET_EXHAUSTED = "step_budget_exhausted"
    PURSUIT_BUDGET_EXHAUSTED = "pursuit_budget_exhausted"
    ENVELOPE_EXHAUSTED = "envelope_exhausted"
    ALL_BRANCHES_CLOSED = "all_branches_closed"
    LOW_YIELD = "low_yield"
    """The supervisor's ``STOP_LOW_YIELD`` directive, applied by the controller. A directive is a
    recommendation the controller acts on; the supervisor still stops nothing itself."""

    HARD_POLICY_REFUSAL = "hard_policy_refusal"
    """A candidate failed a hard gate in a way that repeats. Continuing would spend budget
    producing more unpromotable states."""

    HUMAN_STOP = "human_stop"
    FATAL_INVARIANT_FAILURE = "fatal_invariant_failure"


class EvolutionRun(BaseModel):
    """One long-horizon run over one investigation.

    Bounded on three axes at construction — steps, moves per step, and the pursuit budget it
    inherits — because "long horizon" is a property of the *investigation*, not a licence for an
    unbounded loop. The one budget it does **not** carry is the autonomous-effect budget: that
    belongs to the envelope, which this plane cannot reach, cannot read and cannot spend.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: EvolutionRunId
    investigation_id: InvestigationId
    case_id: Annotated[str, Field(max_length=128)] = ""
    started_at: datetime
    max_steps: Annotated[int, Field(ge=1, le=1000)] = 20
    moves_per_step: Annotated[int, Field(ge=1, le=100)] = 6
    """How many pilot moves one variation step may spend. Clamped again by the mediator against
    its own ceiling, which a caller cannot raise."""

    steps_taken: Annotated[int, Field(ge=0)] = 0
    head_checkpoint_id: CheckpointId | None = None
    active_branch_id: EvolutionBranchId | None = None
    stopped_at: datetime | None = None
    stop_reason: StopReason | None = None

    @model_validator(mode="after")
    def _utc_and_consistent_stop(self) -> Self:
        require_utc(self.started_at, "started_at")
        if self.stopped_at is not None:
            require_utc(self.stopped_at, "stopped_at")
        if (self.stopped_at is None) != (self.stop_reason is None):
            raise ValueError(
                "a stopped run carries both a time and a reason, and a running one carries "
                "neither; a run that stopped for no stated reason is a run nobody can explain"
            )
        return self

    @property
    def running(self) -> bool:
        return self.stop_reason is None

    @property
    def steps_remaining(self) -> int:
        return max(0, self.max_steps - self.steps_taken)


__all__ = [
    "MAX_NOTE_LENGTH",
    "MAX_REFS",
    "BranchStatus",
    "CandidateStatus",
    "CheckpointRefs",
    "EpistemicGate",
    "EvaluationResult",
    "EvolutionBranch",
    "EvolutionRun",
    "GateFinding",
    "InvestigationCheckpoint",
    "ScoreVector",
    "StopReason",
    "TrajectoryMeasurement",
    "best_of",
    "promotes",
]
