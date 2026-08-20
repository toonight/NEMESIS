"""Investigation state: what NEMESIS is currently chasing, and why.

The Pursuit Engine is autonomous, which makes its state the thing an analyst must be able
to interrogate. Not a log of what it did — a structure that answers *why is it doing this*,
*what did it decide not to do*, and *what would change its mind*.

Three ideas carry the design.

**Branches, not a queue.** An investigation is a set of competing lines of enquiry, each
with its own hypothesis and its own budget. A flat pivot queue cannot express "this line
went nowhere" — it just runs out of work and looks finished.

**Abandonment is a recorded decision, not a silence.** When a branch is dropped, the reason
is stored. An investigation that quietly stops exploring a direction is indistinguishable
from one that explored it and found nothing, and those are very different findings.

**Budget is explicit.** Pivots cost money and time, and an autonomous engine with no budget
will happily spend both on the least informative branch available. Cost-per-pivot comes
from the connector's declared capabilities, so the engine plans over real numbers.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.core.confidence import Opinion
from nemesis.core.entities import EntityType
from nemesis.core.ids import ClaimId, EntityId, EvidenceId, InvestigationId
from nemesis.core.temporal import utcnow
from nemesis.ports.collection import PivotType


class IncidentSeed(BaseModel):
    """The observable that starts an investigation.

    Deliberately small. A seed is one entity and the circumstances in which it was seen —
    not a pre-formed theory. An investigation that begins with a conclusion tends to end
    with it.
    """

    model_config = ConfigDict(frozen=True)

    entity_type: EntityType
    entity_key: str
    observed_at: datetime
    detected_by: Annotated[str, Field(min_length=1)]
    """The sensor or analyst that produced the seed."""

    context: dict[str, str] = Field(default_factory=dict)
    supporting_evidence: tuple[EvidenceId, ...] = ()
    victim_hint: str | None = None


class BranchState(StrEnum):
    """Where a line of enquiry stands."""

    ACTIVE = "active"
    EXHAUSTED = "exhausted"
    """Every worthwhile pivot has been run. Not a failure — a completed line."""

    ABANDONED_UNINFORMATIVE = "abandoned_uninformative"
    """Pivots returned nothing that moved any hypothesis."""

    ABANDONED_LOW_SELECTIVITY = "abandoned_low_selectivity"
    """The only available pivots go through shared infrastructure and would generate
    a large, meaningless cluster."""

    ABANDONED_BUDGET = "abandoned_budget"
    ABANDONED_BY_ANALYST = "abandoned_by_analyst"
    BLOCKED_REQUIRES_EXTERNAL_DATA = "blocked_requires_external_data"
    """A real answer exists but needs a source we do not have licensed."""


class HypothesisState(StrEnum):
    OPEN = "open"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    UNDECIDABLE = "undecidable"
    """Available evidence cannot settle it. Recorded rather than left open forever, so an
    analyst can see the difference between "still working" and "cannot be answered"."""


class Hypothesis(BaseModel):
    """A proposition the investigation is trying to settle.

    Every hypothesis names what would refute it. A hypothesis with no refutation
    condition is not an investigative object, it is a belief, and it will accumulate
    supporting evidence indefinitely without ever being tested.
    """

    model_config = ConfigDict(frozen=True)

    hypothesis_id: str
    statement: Annotated[str, Field(min_length=1)]
    state: HypothesisState = HypothesisState.OPEN
    confidence: Opinion = Field(default_factory=Opinion.vacuous)

    would_be_refuted_by: Annotated[str, Field(min_length=1)]
    """The concrete observation that would kill this hypothesis."""

    would_be_confirmed_by: Annotated[str, Field(min_length=1)]

    supporting_claims: tuple[ClaimId, ...] = ()
    contradicting_claims: tuple[ClaimId, ...] = ()
    created_at: datetime = Field(default_factory=utcnow)

    @property
    def is_settled(self) -> bool:
        return self.state is not HypothesisState.OPEN


class PivotCandidate(BaseModel):
    """A pivot the engine could run, with what it expects to gain and what it will cost.

    Expected value is stated *before* the pivot runs so that the engine's choices are
    auditable after the fact. An engine that only records what it did cannot be second
    guessed on what it chose not to do — and "why didn't you look there?" is the question
    an analyst asks most often.
    """

    model_config = ConfigDict(frozen=True)

    pivot_type: PivotType
    entity_id: EntityId
    entity_type: EntityType
    entity_key: str

    addresses_hypothesis: str | None = None
    expected_information_gain: Annotated[float, Field(ge=0.0, le=1.0)]
    """How much this is expected to move an open hypothesis, before running it."""

    estimated_cost: Annotated[float, Field(ge=0.0)]
    rationale: Annotated[str, Field(min_length=1)]

    would_pivot_through_shared_infrastructure: bool = False
    """Set when the pivot targets an entity type shared by unrelated parties. Such pivots
    are not forbidden — sometimes the CDN address is the answer — but they are heavily
    discounted and must be justified."""

    @property
    def value_per_cost(self) -> float:
        """Ranking score. A free pivot with any expected gain beats a costly speculative one."""
        if self.estimated_cost <= 0:
            return self.expected_information_gain * 1000
        return self.expected_information_gain / self.estimated_cost


class ExecutedPivot(BaseModel):
    """A pivot that ran, and what came back. Kept whether or not it was useful.

    Unproductive pivots are retained deliberately. "We looked at the certificate history
    and it showed nothing" is a finding; deleting it makes the investigation look like it
    never considered the question.
    """

    model_config = ConfigDict(frozen=True)

    candidate: PivotCandidate
    executed_at: datetime
    connector: str
    succeeded: bool
    error: str | None = None
    truncated: bool = False
    claims_produced: tuple[ClaimId, ...] = ()
    evidence_produced: tuple[EvidenceId, ...] = ()
    entities_discovered: tuple[EntityId, ...] = ()
    actual_cost: float = 0.0

    @property
    def was_informative(self) -> bool:
        return self.succeeded and bool(self.claims_produced)


class InvestigationBranch(BaseModel):
    """One line of enquiry, with its own hypothesis, budget and history."""

    model_config = ConfigDict(frozen=True)

    branch_id: str
    parent_branch_id: str | None = None
    focus_entity_id: EntityId
    focus_entity_key: str
    hypothesis_id: str | None = None

    state: BranchState = BranchState.ACTIVE
    abandonment_reason: str | None = None
    depth: Annotated[int, Field(ge=0)] = 0

    executed: tuple[ExecutedPivot, ...] = ()
    budget_spent: float = 0.0
    budget_allocated: float = 0.0

    created_at: datetime = Field(default_factory=utcnow)
    closed_at: datetime | None = None

    @model_validator(mode="after")
    def _abandonment_needs_a_reason(self) -> Self:
        abandoned = self.state.value.startswith("abandoned")
        if abandoned and not self.abandonment_reason:
            raise ValueError(
                f"branch {self.branch_id} is {self.state.value} without a stated reason; "
                "an unexplained abandonment is indistinguishable from an unexplored line"
            )
        return self

    @property
    def is_open(self) -> bool:
        return self.state is BranchState.ACTIVE

    @property
    def consecutive_uninformative(self) -> int:
        """How many pivots in a row returned nothing. Drives abandonment."""
        count = 0
        for pivot in reversed(self.executed):
            if pivot.was_informative:
                break
            count += 1
        return count

    @property
    def budget_remaining(self) -> float:
        return max(0.0, self.budget_allocated - self.budget_spent)


class InvestigationState(StrEnum):
    OPEN = "open"
    AWAITING_AUTHORIZATION = "awaiting_authorization"
    DISRUPTION_EXECUTED = "disruption_executed"
    MONITORING_RESURGENCE = "monitoring_resurgence"
    """A takedown closes no case (invariant 14). This is where investigations live
    afterwards — not a terminal state."""

    CLOSED = "closed"


class Investigation(BaseModel):
    """The complete state of one pursuit.

    Immutable and replaced wholesale on each step. Mutating investigation state in place
    would make the engine's decision sequence unreconstructable, and invariant 11 requires
    that meaningful agent actions be replayable, not merely logged.
    """

    model_config = ConfigDict(frozen=True)

    investigation_id: InvestigationId
    seed: IncidentSeed
    state: InvestigationState = InvestigationState.OPEN

    branches: tuple[InvestigationBranch, ...] = ()
    hypotheses: tuple[Hypothesis, ...] = ()

    total_budget: float = 100.0
    budget_spent: float = 0.0

    started_at: datetime = Field(default_factory=utcnow)
    last_step_at: datetime | None = None
    step_count: int = 0

    notes: tuple[str, ...] = ()

    @property
    def open_branches(self) -> tuple[InvestigationBranch, ...]:
        return tuple(branch for branch in self.branches if branch.is_open)

    @property
    def open_hypotheses(self) -> tuple[Hypothesis, ...]:
        return tuple(h for h in self.hypotheses if not h.is_settled)

    @property
    def budget_remaining(self) -> float:
        return max(0.0, self.total_budget - self.budget_spent)

    @property
    def all_executed_pivots(self) -> tuple[ExecutedPivot, ...]:
        return tuple(pivot for branch in self.branches for pivot in branch.executed)

    def branch(self, branch_id: str) -> InvestigationBranch | None:
        return next((b for b in self.branches if b.branch_id == branch_id), None)

    def hypothesis(self, hypothesis_id: str) -> Hypothesis | None:
        return next((h for h in self.hypotheses if h.hypothesis_id == hypothesis_id), None)

    def with_branch(self, updated: InvestigationBranch) -> Investigation:
        """Return a copy with one branch replaced or appended."""
        existing = {b.branch_id for b in self.branches}
        branches = (
            tuple(updated if b.branch_id == updated.branch_id else b for b in self.branches)
            if updated.branch_id in existing
            else (*self.branches, updated)
        )
        return self.model_copy(update={"branches": branches})

    def with_hypothesis(self, updated: Hypothesis) -> Investigation:
        existing = {h.hypothesis_id for h in self.hypotheses}
        hypotheses = (
            tuple(
                updated if h.hypothesis_id == updated.hypothesis_id else h for h in self.hypotheses
            )
            if updated.hypothesis_id in existing
            else (*self.hypotheses, updated)
        )
        return self.model_copy(update={"hypotheses": hypotheses})

    def summary(self) -> str:
        """A line an analyst can read to know where this stands."""
        abandoned = [b for b in self.branches if b.state.value.startswith("abandoned")]
        return (
            f"{self.investigation_id}: {self.state.value}, step {self.step_count}, "
            f"{len(self.open_branches)} open branch(es), {len(abandoned)} abandoned, "
            f"{len(self.open_hypotheses)}/{len(self.hypotheses)} hypotheses unsettled, "
            f"budget {self.budget_spent:.1f}/{self.total_budget:.1f}"
        )
