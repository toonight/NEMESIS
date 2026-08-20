"""The attribution engine: five separate answers, and a refusal where one is owed.

:mod:`nemesis.attribute.dimensions` defines what an assessment must carry. This module
produces them, and the whole of it is arranged around three decisions.

**There is no aggregate, and no method that computes one.** :class:`AttributionResult`
exposes the five assessments and nothing that folds them together. Anyone who wants a
single number must write the collapse in their own module and defend their weights there.

**Human identity is gated on the *shape* of the evidence, before anything is scored.**
:func:`run_identity_gate` runs first and, when it refuses, no fusion happens at all. A
threshold — however high — is something an adversary can push a number over by
manufacturing agreement, and manufacturing agreement is cheap in exactly the channels
where names circulate. The number of independent origins, whether any of them lies outside
the adversary's reach, and whether any single statement is attested twice cannot be moved
that way. The refused assessment also declines to restate the name it refused to assert:
a refusal document is precisely the artifact that gets forwarded, and a refusal that
repeats the accusation has published it.

**Deception is a hypothesis with weight, not a caveat in prose.** A signal whose
:class:`~nemesis.core.claims.DeceptionAssessment` says an adversary could have planted it
cheaply is not weak support for the party it names — it is, on balance, evidence *against*
that party, because the cheaper a marker is to fake the more attractive faking it becomes,
and the marker exists only because somebody put it there. :func:`_orient` therefore moves
such a signal into contradicting evidence and generates an explicit "this was planted to
mislead us" alternative with its own fused opinion. The inversion is deliberately capped:
an adversary who anticipates it can plant a marker naming itself, and nothing in the
evidence distinguishes that double bluff from the ordinary case.

Every combination of opinions goes through :func:`nemesis.core.fusion.fuse`. Nothing here
multiplies a confidence by hand: the dependence grouping, the trust discounting and the
independent-origin count are the parts that are easy to get wrong, and they exist once.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, NamedTuple, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.attribute.dimensions import (
    DEFAULT_TEMPORAL_GAP_TOLERANCE,
    DIMENSION_QUESTION,
    AlternativeHypothesis,
    AttributionDimension,
    DimensionAssessment,
    EvidenceAvailability,
    IdentityGateResult,
    MissingEvidence,
    RefusalReason,
    SignalContribution,
    SourceDiversity,
    TemporalConsistency,
    assess_temporal_consistency,
)
from nemesis.core.claims import Claim, DeceptionAssessment
from nemesis.core.confidence import ConfidenceBand, Opinion, band_of, describe
from nemesis.core.fusion import DependenceHandling, SourcedOpinion, fuse
from nemesis.core.ids import ActorId, AttributionId, ClaimId, IdPrefix, new_id
from nemesis.core.proposition import PropositionClass
from nemesis.core.provenance import SourceDescriptor
from nemesis.core.temporal import utcnow


class AttributionError(ValueError):
    """The request could not be assessed without producing a meaningless answer."""


DEFAULT_BASE_RATE: dict[AttributionDimension, float] = {
    AttributionDimension.INFRASTRUCTURE: 0.10,
    AttributionDimension.CAMPAIGN: 0.15,
    AttributionDimension.ORGANIZATION: 0.05,
    AttributionDimension.PERSONA: 0.02,
    AttributionDimension.HUMAN_IDENTITY: 0.01,
}
"""Prior probability that a named candidate is the answer, before any evidence.

All five are well below 0.5, and that is the point. The prior for *"these two personas on a
large forum are one operator"* is very low; setting it to 0.5 out of apparent neutrality
builds in the assumption that any two personas are as likely the same as not, which is how
base-rate neglect produces confident false identification at scale. Human identity sits
lowest because the candidate field is every adult with a keyboard.

Calibration choices, not measurements. They should be re-set against a ground-truth corpus
if one ever exists, and until then they are stated here so a reader can disagree with them
rather than having to reverse-engineer them from an output.
"""


LOW_PLANTING_COSTS: frozenset[str] = frozenset({"trivial", "low"})
"""Planting costs at which a marker tells us more about the planter than about the named.

:attr:`~nemesis.core.claims.DeceptionAssessment.planting_cost` is free text by design; these
are the values at which the inversion in :func:`_orient` fires. A moderate or high cost is
left alone: an adversary who must burn real infrastructure to stage a false flag is making
a trade that occasionally makes the marker genuine evidence.
"""

PLANTING_BELIEF_BY_COST: dict[str, float] = {"trivial": 0.55, "low": 0.40}
"""How much belief the "it was planted" hypothesis starts with, by cost to stage.

Not above 0.55 even for a string in a file the adversary wrote: criminal toolkits do carry
genuine author markers, because operators are careless. Trust discounting is applied on top
of this by :func:`fuse`.
"""

PLANTED_EVIDENCE_DISBELIEF_CEILING = 0.40
"""Most disbelief a single planted marker may contribute against the party it names.

The cap exists because the inversion is itself predictable. An adversary who knows a
cheap marker naming X will be read as evidence against X can plant a marker naming
*itself* and earn an exoneration; nothing in a string distinguishes that from the ordinary
case. So a cheap marker moves the estimate down and never refutes.
"""

CONTRA_INDICATOR_DISCOUNT = 0.5
"""Applied when the deception assessment records observations arguing against staging.

Halved rather than cancelled: :attr:`DeceptionAssessment.contra_indicators` is a list of
strings whose strength this module cannot judge, so it softens the planting hypothesis
without being able to defeat it.
"""

DECEPTION_BASE_RATE = 0.25
"""Prior that a cheap attribution marker found in adversary-controlled material was staged.

Higher than the priors in :data:`DEFAULT_BASE_RATE` because the population is different:
these are markers found inside the tooling of an operation that is being pursued, not
arbitrary artifacts. A calibration choice, and the one in this module most likely to be
wrong.
"""

NEGLIGIBLE_CONTRIBUTION_NOTE = (
    "offered in support and moved the estimate by less than one point; present in the "
    "record, absent from the conclusion"
)

REFUSED_IDENTITY_HYPOTHESIS = (
    "No natural person is identified. An identification was offered and refused at the "
    "structural gate; it is recorded against its claim identifiers and is deliberately not "
    "restated here."
)
"""What a refused human-identity assessment reports as its hypothesis.

The caller's hypothesis string contains the name — that is what a hypothesis about a
person is. Copying it into the refusal would publish the accusation inside the document
that exists to withhold it, and refusal documents are exactly what gets forwarded onward.
"""


_REFUSAL_REMEDY: dict[RefusalReason, MissingEvidence] = {
    RefusalReason.NO_EVIDENCE: MissingEvidence(
        description=(
            "Any artifact naming the operator that the operator did not author: a payment "
            "record, a lawful-process return from a service provider, or material from a "
            "device seized under warrant."
        ),
        would_settle="Would give the identification something to rest on. There is nothing.",
        availability=EvidenceAvailability.REQUIRES_LEGAL_AUTHORITY,
    ),
    RefusalReason.SINGLE_SOURCED: MissingEvidence(
        description=(
            "A second attestation of the same identification originating outside the single "
            "origin already held — a different operator, a different collection channel, a "
            "different jurisdiction."
        ),
        would_settle=(
            "Two independent origins attesting one statement is the minimum shape this "
            "dimension will score. One origin restated is not that shape."
        ),
        availability=EvidenceAvailability.COLLECTABLE,
    ),
    RefusalReason.ONLY_ADVERSARY_INFLUENCEABLE: MissingEvidence(
        description=(
            "An attestation from a channel the adversary cannot write into: an unredacted "
            "registrant record, an exchange's KYC record for the deposit address, or a "
            "law-enforcement return."
        ),
        would_settle=(
            "Would break the circularity of an identification that exists only where the "
            "adversary is free to place it."
        ),
        availability=EvidenceAvailability.REQUIRES_LEGAL_AUTHORITY,
    ),
    RefusalReason.NO_CORROBORATION: MissingEvidence(
        description=(
            "Two origins attesting the same statement, rather than two origins attesting "
            "different statements about the same persona."
        ),
        would_settle=(
            "Distinguishes corroboration from a set of unrelated assertions that merely "
            "point the same way."
        ),
        availability=EvidenceAvailability.COLLECTABLE,
    ),
    RefusalReason.MODEL_DERIVED_SUPPORT: MissingEvidence(
        description=(
            "The underlying artifact behind each model-produced identification, so the "
            "assertion can be checked against collected material."
        ),
        would_settle=(
            "A model's output is a claim about text, not evidence about a person "
            "(invariant 1). The artifact is what would carry the identification."
        ),
        availability=EvidenceAvailability.COLLECTABLE,
    ),
}
"""What would change each refusal, stated concretely enough to become a collection task.

A refusal that does not say what it wants reads as a permanent verdict, and the next
analyst re-runs the same assessment against the same evidence expecting a different answer.
"""


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


class EvidenceDirection(StrEnum):
    """What role the caller believes a signal plays. The engine may overrule it."""

    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"


def _is_cheaply_plantable(deception: DeceptionAssessment) -> bool:
    return (
        deception.adversary_could_plant
        and deception.planting_cost.strip().casefold() in LOW_PLANTING_COSTS
    )


class AttributionEvidence(BaseModel):
    """One claim offered towards one dimension, with the source and what it is worth alone.

    The claim is carried whole rather than by identifier. Its
    :attr:`~nemesis.core.claims.Claim.deception` assessment, its derivation and its validity
    extent are all inputs to this engine, and a caller passing only an identifier would have
    to restate them — which is where they get restated wrongly.
    """

    model_config = ConfigDict(frozen=True)

    claim: Claim
    source: SourceDescriptor
    opinion: Opinion
    """What this signal alone justifies, before trust discounting and before the dimension's
    base rate is applied. Fusion, not this field, decides what it is worth in company."""

    direction: EvidenceDirection = EvidenceDirection.SUPPORTS
    label: Annotated[str, Field(min_length=1, max_length=200)]
    """Short analyst-facing name for the signal, used in reasoning and contributions."""

    @model_validator(mode="after")
    def _direction_matches_opinion(self) -> Self:
        # A declared direction that disagrees with the mass it carries is a caller bug that
        # would otherwise surface as a claim filed under the opposite heading from the one
        # it moves the estimate towards.
        if self.direction is EvidenceDirection.CONTRADICTS and self.opinion.belief > (
            self.opinion.disbelief
        ):
            raise ValueError(
                f"{self.label!r} is declared as contradicting but carries more belief than "
                "disbelief"
            )
        if self.direction is EvidenceDirection.SUPPORTS and self.opinion.disbelief > (
            self.opinion.belief
        ):
            raise ValueError(
                f"{self.label!r} is declared as supporting but carries more disbelief than belief"
            )
        return self

    @property
    def claim_id(self) -> ClaimId:
        return self.claim.claim_id

    @property
    def is_cheaply_plantable(self) -> bool:
        """Whether an adversary could have arranged for us to see this, cheaply."""
        return self.claim.deception is not None and _is_cheaply_plantable(self.claim.deception)


class DimensionInput(BaseModel):
    """Everything offered towards one dimension."""

    model_config = ConfigDict(frozen=True)

    dimension: AttributionDimension
    hypothesis: Annotated[str, Field(min_length=1, max_length=2000)]
    """The specific proposition, not the dimension's generic question."""

    evidence: tuple[AttributionEvidence, ...] = ()
    alternatives: tuple[AlternativeHypothesis, ...] = ()
    """Analyst-supplied alternatives. The engine adds its own; it never removes these."""

    missing_evidence: tuple[MissingEvidence, ...] = ()
    base_rate: Annotated[float, Field(ge=0.0, le=1.0)] | None = None
    """Prior for this proposition. Defaults to :data:`DEFAULT_BASE_RATE` for the dimension."""

    @model_validator(mode="after")
    def _one_direction_per_claim(self) -> Self:
        directions: dict[str, EvidenceDirection] = {}
        for item in self.evidence:
            previous = directions.setdefault(item.claim_id, item.direction)
            if previous is not item.direction:
                raise ValueError(
                    f"claim {item.claim_id} is offered as both supporting and contradicting "
                    f"the {self.dimension.value} hypothesis; one of the two readings is wrong"
                )
        return self

    def effective_base_rate(self) -> float:
        return DEFAULT_BASE_RATE[self.dimension] if self.base_rate is None else self.base_rate


class AttributionRequest(BaseModel):
    """What is being attributed, and what is offered towards each dimension."""

    model_config = ConfigDict(frozen=True)

    subject: Annotated[str, Field(min_length=1, max_length=512)]
    """What the attribution is about: an operation, a cluster, a case."""

    dimensions: tuple[DimensionInput, ...] = ()

    @model_validator(mode="after")
    def _one_input_per_dimension(self) -> Self:
        seen = [item.dimension for item in self.dimensions]
        duplicates = {value for value in seen if seen.count(value) > 1}
        if duplicates:
            raise AttributionError(
                f"dimension(s) {sorted(d.value for d in duplicates)} were supplied more than "
                "once; merging them here would silently choose one reading over the other"
            )
        return self

    def input_for(self, dimension: AttributionDimension) -> DimensionInput | None:
        return next((item for item in self.dimensions if item.dimension is dimension), None)


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


class AttributionResult(BaseModel):
    """The five dimensions, separately.

    Deliberately without an overall figure, an overall band, or any accessor that combines
    the assessments. A weighted mean of the five would be dominated by infrastructure — the
    dimension with the most evidence and the least to say about who anybody is — and a
    reader shown one number stops reading the five.
    """

    model_config = ConfigDict(frozen=True)

    attribution_id: AttributionId
    subject: Annotated[str, Field(min_length=1, max_length=512)]
    assessed_by: ActorId
    assessed_at: datetime
    assessments: tuple[DimensionAssessment, ...]
    warnings: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _every_dimension_exactly_once(self) -> Self:
        present = [assessment.dimension for assessment in self.assessments]
        if sorted(present) != sorted(AttributionDimension):
            raise ValueError(
                "an attribution result must carry all five dimensions exactly once; "
                f"got {sorted(value.value for value in present)}. A dimension omitted for "
                "want of evidence is a finding, not an absence."
            )
        return self

    def for_dimension(self, dimension: AttributionDimension) -> DimensionAssessment:
        return next(item for item in self.assessments if item.dimension is dimension)

    @property
    def names_a_person(self) -> bool:
        """Whether this attribution asserts a natural person's identity.

        The acceptance criterion of the GLASS ANVIL scenario is that this is False. It is
        derived from the gate result rather than tracked separately, so it cannot drift out
        of agreement with what the assessment actually says.
        """
        return not self.for_dimension(AttributionDimension.HUMAN_IDENTITY).is_refused

    def render(self) -> str:
        """Plain text for an analyst or a report. Five blocks, no total."""
        blocks = [f"ATTRIBUTION {self.attribution_id} — {self.subject}"]
        blocks.extend(f"! {warning}" for warning in self.warnings)
        blocks.extend(self.for_dimension(dimension).render() for dimension in AttributionDimension)
        return "\n\n".join(blocks)


# ---------------------------------------------------------------------------
# The human-identity gate
# ---------------------------------------------------------------------------


def run_identity_gate(evidence: Sequence[AttributionEvidence]) -> IdentityGateResult:
    """Decide whether the evidence is even the right *shape* to name a person.

    Every check below is structural: how many independent origins there are, whether any
    of them is outside a channel the adversary can write into, whether any one statement is
    attested twice, and whether a model is anywhere in the support. None of them looks at
    how strong the evidence is, and that is the design. Strength is the axis an adversary
    can move — agreement is cheap to manufacture in the channels where names circulate, and
    a threshold on strength is therefore a threshold on the adversary's budget.

    All failing reasons are collected rather than short-circuited, so the refusal states
    everything that is wrong and a caller who fixes one problem is not surprised by the next.
    """
    supporting = [item for item in evidence if item.direction is EvidenceDirection.SUPPORTS]
    reasons: list[RefusalReason] = []
    origins: set[str] = {item.source.provenance_cluster() for item in supporting}

    attestations: dict[str, set[str]] = {}
    for item in supporting:
        attestations.setdefault(item.claim.statement.canonical(), set()).add(
            item.source.provenance_cluster()
        )
    corroborated = sum(1 for keys in attestations.values() if len(keys) >= 2)

    if not supporting:
        reasons.append(RefusalReason.NO_EVIDENCE)
    else:
        if len(origins) <= 1:
            reasons.append(RefusalReason.SINGLE_SOURCED)
        if all(item.source.is_adversary_influenceable for item in supporting):
            reasons.append(RefusalReason.ONLY_ADVERSARY_INFLUENCEABLE)
        if not corroborated:
            reasons.append(RefusalReason.NO_CORROBORATION)
        if any(item.claim.is_model_derived for item in supporting):
            reasons.append(RefusalReason.MODEL_DERIVED_SUPPORT)

    if reasons:
        return IdentityGateResult(
            passed=False,
            reasons=tuple(reasons),
            explanation=_refusal_explanation(reasons, len(supporting), len(origins), corroborated),
            # The offered claims are kept here and out of supporting_claims. A downstream
            # reader who finds them under "supporting" will present them as grounds for a
            # name, which is the failure this whole dimension exists to prevent.
            refused_claims=_unique(item.claim_id for item in evidence),
            independent_origin_count=len(origins),
            corroborated_statements=corroborated,
        )

    return IdentityGateResult(
        passed=True,
        reasons=(),
        explanation=(
            f"{len(supporting)} supporting signal(s) from {len(origins)} independent "
            f"origin(s), {corroborated} statement(s) attested by more than one of them, at "
            "least one origin outside a channel the adversary can write into, and no model "
            "in the support. The evidence is the right shape to be scored; that is not the "
            "same as being sufficient to name anyone."
        ),
        independent_origin_count=len(origins),
        corroborated_statements=corroborated,
    )


def _refusal_explanation(
    reasons: Sequence[RefusalReason], signals: int, origins: int, corroborated: int
) -> str:
    detail = {
        RefusalReason.NO_EVIDENCE: "nothing was offered in support",
        RefusalReason.SINGLE_SOURCED: (
            f"{signals} supporting signal(s) resolve to {origins} independent origin(s); "
            "restatement is not corroboration"
        ),
        RefusalReason.ONLY_ADVERSARY_INFLUENCEABLE: (
            "every supporting source sits in a channel an adversary can plant into, so the "
            "identification may exist only because someone wanted us to find it"
        ),
        RefusalReason.NO_CORROBORATION: (
            f"{corroborated} statement(s) are attested by two or more independent origins; "
            "origins asserting different things are not confirming each other"
        ),
        RefusalReason.MODEL_DERIVED_SUPPORT: (
            "a model or statistical method is among the supports, and model output is never "
            "evidence about a person (invariant 1)"
        ),
    }
    listed = "; ".join(detail[reason] for reason in reasons)
    return (
        "Human identity refused before scoring. "
        f"{listed}. "
        "The gate is structural and runs before fusion, so no strength of evidence reaches "
        "past it. Naming a natural person is irreversible once it leaves the building, and "
        "in a pursued operation the name on offer is as likely to have been placed for us "
        "to find as to be true."
    )


# ---------------------------------------------------------------------------
# Orientation: what a signal is actually evidence of
# ---------------------------------------------------------------------------


class _Oriented(NamedTuple):
    evidence: AttributionEvidence
    direction: EvidenceDirection
    opinion: Opinion
    was_inverted: bool


def _orient(evidence: AttributionEvidence, base_rate: float) -> _Oriented:
    """Fix a signal's direction and its mass before fusion.

    Two things happen here. The dimension's base rate replaces whatever prior the caller
    attached to the signal, because the prior belongs to the proposition and not to the
    source — leaving it per-source lets one source arrive with ``base_rate=0.99`` and carry
    a confident answer out of an opinion that contains no evidence, which is the
    whitewashing case :mod:`nemesis.core.fusion` already refuses in trust discounting.

    Then a cheaply-plantable signal offered in support is turned around. Its existence is
    explained better by someone having placed it than by the party it names having been
    careless, and treating it as support inverts the incentive: the cheaper a marker is to
    fake, the more attractive faking it becomes. The resulting disbelief is capped by
    :data:`PLANTED_EVIDENCE_DISBELIEF_CEILING`, because the inversion is itself
    anticipatable.
    """
    opinion = evidence.opinion.model_copy(update={"base_rate": base_rate})
    deception = evidence.claim.deception
    if (
        evidence.direction is EvidenceDirection.CONTRADICTS
        or deception is None
        or not _is_cheaply_plantable(deception)
    ):
        return _Oriented(evidence, evidence.direction, opinion, was_inverted=False)

    mass = min(opinion.belief, PLANTED_EVIDENCE_DISBELIEF_CEILING)
    if deception.contra_indicators:
        mass *= CONTRA_INDICATOR_DISCOUNT
    inverted = Opinion(belief=0.0, disbelief=mass, uncertainty=1.0 - mass, base_rate=base_rate)
    return _Oriented(evidence, EvidenceDirection.CONTRADICTS, inverted, was_inverted=True)


DIMENSION_PROPOSITION: dict[AttributionDimension, PropositionClass] = {
    AttributionDimension.INFRASTRUCTURE: PropositionClass.SHARED_ORIGIN,
    AttributionDimension.CAMPAIGN: PropositionClass.SHARED_ORIGIN,
    AttributionDimension.PERSONA: PropositionClass.SHARED_ORIGIN,
    AttributionDimension.ORGANIZATION: PropositionClass.ACTOR_ATTRIBUTION,
    AttributionDimension.HUMAN_IDENTITY: PropositionClass.ACTOR_ATTRIBUTION,
}
"""Which robustness margin each dimension answers to.

Infrastructure, campaign and persona are all claims that artifacts share a controller.
Organization and human identity name a party, which is the claim that ends in a takedown
request or a referral. No caller picks a class by hand; the dimension decides.
"""


def proposition_of(dimension: AttributionDimension) -> PropositionClass:
    return DIMENSION_PROPOSITION[dimension]


def _planting_alternative(oriented: _Oriented, hypothesis: str) -> AlternativeHypothesis:
    """The explicit "this was planted to mislead us" hypothesis, with a fused opinion.

    Scored rather than merely listed. An alternative recorded without a number is an
    alternative nobody will weigh against the one the report leads with.
    """
    deception = oriented.evidence.claim.deception
    if deception is None:  # pragma: no cover - _orient only inverts assessed claims
        raise AttributionError("a planting alternative requires a deception assessment")

    belief = PLANTING_BELIEF_BY_COST[deception.planting_cost.strip().casefold()]
    if deception.contra_indicators:
        belief *= CONTRA_INDICATOR_DISCOUNT

    # Fused through the same machinery as everything else so the source's reliability
    # discounts the planting hypothesis exactly as it discounts what the source claims.
    fusion = fuse(
        (
            SourcedOpinion(
                fact_key=oriented.evidence.claim.statement.canonical(),
                source=oriented.evidence.source,
                opinion=Opinion(
                    belief=belief,
                    disbelief=0.0,
                    uncertainty=1.0 - belief,
                    base_rate=DECEPTION_BASE_RATE,
                ),
                supporting_claims=(oriented.evidence.claim_id,),
                label=oriented.evidence.label,
            ),
        ),
        # OBSERVATION, deliberately. A planting hypothesis is single-source by construction
        # — it is the assertion that THIS signal was staged — so a robustness margin would
        # remove its only support and report every deception alternative as baseless.
        # Invariant 13 would go inert, which is the opposite of what the margin is for.
        proposition=PropositionClass.OBSERVATION,
    )

    beneficiaries = ", ".join(deception.benefits_from_belief) or "not stated"
    contra = ", ".join(deception.contra_indicators) or "none recorded"
    return AlternativeHypothesis(
        name=f"Planted to mislead: {oriented.evidence.label}"[:200],
        description=(
            f"The signal {oriented.evidence.label!r} was placed for us to find rather than "
            f"left behind. Cost to stage: {deception.planting_cost}. Who gains if we believe "
            f"it: {beneficiaries}. Observations against staging: {contra}. On this reading "
            f"the signal is evidence about whoever placed it, not about {hypothesis!r}."
        ),
        opinion=fusion.opinion,
        band=band_of(fusion.opinion),
        supporting_claims=(oriented.evidence.claim_id,),
        contradicting_claims=(),
        argument_against=(
            "Cheap to stage is not the same as staged. Nothing here shows who inserted the "
            "marker, and criminal tooling does carry genuine author traces because operators "
            "are careless. The inversion is also anticipatable: an adversary who expects a "
            "marker naming X to be read as evidence against X can plant a marker naming "
            "itself and earn an exoneration. This alternative is therefore retained and "
            "weighed, and the signal is capped rather than treated as a refutation."
        ),
        is_deception_hypothesis=True,
    )


def _staged_set_alternative(hypothesis: str, signal_count: int) -> AlternativeHypothesis:
    """Raised when every contributing source sits in a channel the adversary can write into.

    Left vacuous on purpose. There is no measurement of it to report — that is exactly the
    problem with an evidence set the adversary could have composed — and inventing a number
    here would make the hypothesis look assessed when it has only been noticed.
    """
    opinion = Opinion.vacuous(base_rate=DECEPTION_BASE_RATE)
    return AlternativeHypothesis(
        name="Staged evidence set",
        description=(
            f"All {signal_count} contributing signal(s) reach us through channels an "
            f"adversary can write into, so the picture supporting {hypothesis!r} may have "
            "been composed for us rather than observed."
        ),
        opinion=opinion,
        band=band_of(opinion),
        supporting_claims=(),
        contradicting_claims=(),
        argument_against=(
            "No positive indication of staging was found; an adversary-influenceable channel "
            "is where most real intelligence about criminal operations comes from, and "
            "refusing it wholesale would leave the dimension permanently unassessable. "
            "Recorded as an unmeasured alternative rather than scored."
        ),
        is_deception_hypothesis=True,
    )


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _dependence_shape(signals: int, origins: int) -> DependenceHandling:
    """Describe the shape of what was offered, when no fusion was run.

    Used only on the refused path, where reporting a handling produced by a fusion that
    never happened would be a lie about how the answer was reached.
    """
    if signals == 0:
        return DependenceHandling.NO_SOURCES
    if origins <= 1:
        return (
            DependenceHandling.SINGLE_SOURCE
            if signals == 1
            else DependenceHandling.DEPENDENT_COLLAPSED
        )
    return DependenceHandling.INDEPENDENT_ACCUMULATED


class AttributionEngine:
    """Produces a :class:`AttributionResult` from offered evidence.

    Stateless apart from who is doing the assessing and how sparse collection is assumed to
    be. Nothing here reads storage, and nothing here is permitted to collect: the attribution
    plane sees only what an investigation hands it, which is what makes an assessment
    replayable from its inputs.
    """

    def __init__(
        self,
        *,
        assessed_by: ActorId,
        temporal_tolerance: timedelta = DEFAULT_TEMPORAL_GAP_TOLERANCE,
    ) -> None:
        self._assessed_by = assessed_by
        self._temporal_tolerance = temporal_tolerance

    def assess(
        self, request: AttributionRequest, *, assessed_at: datetime | None = None
    ) -> AttributionResult:
        """Assess all five dimensions separately.

        A dimension with no input is still assessed and still reported: silence about a
        dimension reads as agreement with whatever the reader already believed, and the
        honest answer — "nobody looked" — is a finding an analyst can act on.
        """
        moment = assessed_at if assessed_at is not None else utcnow()

        assessments: list[DimensionAssessment] = []
        inverted_total = 0
        for dimension in AttributionDimension:
            item = request.input_for(dimension) or DimensionInput(
                dimension=dimension,
                hypothesis=(
                    f"Not assessed: nothing was offered on the {dimension.value} dimension "
                    f"for {request.subject}."
                ),
            )
            assessment, inverted = self._assess_dimension(item)
            assessments.append(assessment)
            inverted_total += inverted

        warnings: list[str] = []
        human = next(
            item for item in assessments if item.dimension is AttributionDimension.HUMAN_IDENTITY
        )
        if human.is_refused:
            warnings.append(
                "No natural person is named by this attribution: the human-identity "
                "dimension was refused at the structural gate."
            )
        if inverted_total:
            warnings.append(
                f"{inverted_total} signal(s) offered in support were recorded as "
                "contradicting evidence because an adversary could have planted them "
                "cheaply. See the deception alternatives on the affected dimensions."
            )

        return AttributionResult(
            attribution_id=new_id(IdPrefix.ATTRIBUTION),
            subject=request.subject,
            assessed_by=self._assessed_by,
            assessed_at=moment,
            assessments=tuple(assessments),
            warnings=tuple(warnings),
        )

    # -- one dimension --------------------------------------------------------

    def _assess_dimension(self, item: DimensionInput) -> tuple[DimensionAssessment, int]:
        base_rate = item.effective_base_rate()

        gate: IdentityGateResult | None = None
        if item.dimension is AttributionDimension.HUMAN_IDENTITY:
            # Before anything is scored. The ordering is the control, not a convenience.
            gate = run_identity_gate(item.evidence)
            if not gate.passed:
                return self._refused_assessment(item, gate, base_rate), 0

        oriented = tuple(_orient(evidence, base_rate) for evidence in item.evidence)
        sourced = tuple(
            SourcedOpinion(
                fact_key=entry.evidence.claim.statement.canonical(),
                source=entry.evidence.source,
                opinion=entry.opinion,
                supporting_claims=(entry.evidence.claim_id,),
                label=entry.evidence.label,
            )
            for entry in oriented
        )
        fusion = fuse(sourced, proposition=proposition_of(item.dimension))

        supporting = _unique(
            entry.evidence.claim_id
            for entry in oriented
            if entry.direction is EvidenceDirection.SUPPORTS
        )
        contradicting = _unique(
            entry.evidence.claim_id
            for entry in oriented
            if entry.direction is EvidenceDirection.CONTRADICTS
        )
        overlap = set(supporting) & set(contradicting)
        if overlap:  # pragma: no cover - DimensionInput rejects the input that causes it
            raise AttributionError(
                f"claim(s) {sorted(overlap)} ended up on both sides of the "
                f"{item.dimension.value} assessment"
            )

        contributions = self._contributions(
            oriented, sourced, fusion.opinion, base_rate, item.dimension
        )
        temporal = assess_temporal_consistency(
            [entry.evidence.claim.valid_extent for entry in oriented],
            tolerance=self._temporal_tolerance,
        )

        inverted = tuple(entry for entry in oriented if entry.was_inverted)
        alternatives = list(item.alternatives)
        alternatives.extend(_planting_alternative(entry, item.hypothesis) for entry in inverted)
        if oriented and fusion.adversary_influenceable_sources == fusion.total_sources:
            alternatives.append(_staged_set_alternative(item.hypothesis, fusion.total_sources))

        warnings = list(fusion.warnings)
        for entry in inverted:
            warnings.append(
                f"{entry.evidence.label!r} was offered in support and is recorded as "
                "contradicting evidence: it is cheap for an adversary to plant."
            )
        warnings.extend(
            f"{contribution.label!r} {NEGLIGIBLE_CONTRIBUTION_NOTE}."
            for contribution in contributions
            if contribution.is_negligible
        )

        assessment = DimensionAssessment(
            dimension=item.dimension,
            hypothesis=item.hypothesis,
            opinion=fusion.opinion,
            band=band_of(fusion.opinion),
            evidential_opinion=fusion.evidential_opinion,
            margin_outcome=fusion.margin_outcome.value,
            removed_fact=fusion.removed_fact,
            supporting_claims=supporting,
            contradicting_claims=contradicting,
            alternatives=tuple(alternatives),
            missing_evidence=item.missing_evidence,
            source_diversity=SourceDiversity.from_fusion(fusion),
            temporal_consistency=temporal,
            reasoning=self._reasoning(item, fusion.opinion, base_rate, contributions, temporal),
            signal_contributions=contributions,
            identity_gate=gate,
            warnings=tuple(warnings),
        )
        return assessment, len(inverted)

    def _refused_assessment(
        self, item: DimensionInput, gate: IdentityGateResult, base_rate: float
    ) -> DimensionAssessment:
        """Build the assessment for a refused human identity, without fusing anything.

        No opinion is computed from the offered evidence, no signal contributions are
        reported, and no label is echoed. The offered material is referenced by claim
        identifier only — hashes carry no name — so this document can be forwarded without
        forwarding the accusation.
        """
        origins = {
            evidence.source.provenance_cluster()
            for evidence in item.evidence
            if evidence.direction is EvidenceDirection.SUPPORTS
        }
        diversity = SourceDiversity(
            total_signals=len(item.evidence),
            independent_source_count=len(origins),
            adversary_influenceable_sources=sum(
                1 for evidence in item.evidence if evidence.source.is_adversary_influenceable
            ),
            dependence_handling=_dependence_shape(len(item.evidence), len(origins)),
        )
        remedies = tuple(_REFUSAL_REMEDY[reason] for reason in gate.reasons)

        return DimensionAssessment(
            dimension=item.dimension,
            hypothesis=REFUSED_IDENTITY_HYPOTHESIS,
            opinion=Opinion.vacuous(base_rate=base_rate),
            band=ConfidenceBand.INSUFFICIENT_BASIS,
            supporting_claims=(),
            contradicting_claims=(),
            alternatives=item.alternatives,
            missing_evidence=item.missing_evidence + remedies,
            source_diversity=diversity,
            temporal_consistency=assess_temporal_consistency(
                [evidence.claim.valid_extent for evidence in item.evidence],
                tolerance=self._temporal_tolerance,
            ),
            reasoning=gate.explanation,
            signal_contributions=(),
            identity_gate=gate,
            warnings=(
                "Insufficient basis is not a low probability. It is a refusal to estimate, "
                "and it must not be reported as a hedged identification.",
            ),
        )

    def _contributions(
        self,
        oriented: Sequence[_Oriented],
        sourced: Sequence[SourcedOpinion],
        fused: Opinion,
        base_rate: float,
        dimension: AttributionDimension,
    ) -> tuple[SignalContribution, ...]:
        """Leave-one-out: what each signal was actually worth in the company it kept.

        Not a declared weight. Fusion is not a weighted sum, and a signal that shares an
        origin with a stronger one contributes almost nothing however impressive it looks
        alone. This is what lets a report say "the fingerprint carried this, the alias added
        nothing" instead of listing four signals as though they were four reasons.
        """
        contributions: list[SignalContribution] = []
        for index, entry in enumerate(oriented):
            remaining = tuple(sourced[:index]) + tuple(sourced[index + 1 :])
            # With nothing left, the comparison is against the prior rather than against
            # fuse(()), whose default base rate of 0.5 would report a movement that is an
            # artifact of the empty case.
            without = (
                fuse(remaining, proposition=proposition_of(dimension)).opinion
                if remaining
                else Opinion.vacuous(base_rate=base_rate)
            )
            contributions.append(
                SignalContribution(
                    label=entry.evidence.label,
                    claim_id=entry.evidence.claim_id,
                    delta_projected=round(
                        fused.projected_probability - without.projected_probability, 4
                    ),
                )
            )
        return tuple(contributions)

    def _reasoning(
        self,
        item: DimensionInput,
        opinion: Opinion,
        base_rate: float,
        contributions: Sequence[SignalContribution],
        temporal: TemporalConsistency,
    ) -> str:
        """Prose generated from the same values as the rest of the assessment.

        Never written by a model. A narrative produced independently of the numbers drifts
        away from them, and the narrative is what gets quoted.
        """
        lines = [
            f"{DIMENSION_QUESTION[item.dimension]} Assessed: {item.hypothesis}",
            f"Confidence: {describe(opinion)}, against a base rate of {base_rate:.0%}.",
        ]
        if not item.evidence:
            lines.append(
                "No evidence was offered on this dimension. The figure above is the prior, "
                "not a finding: nobody looked."
            )
            return "\n".join(lines)

        driver = max(contributions, key=lambda entry: entry.delta_projected, default=None)
        if driver is not None and driver.delta_projected > 0.0:
            lines.append(
                f"The estimate is carried by {driver.label!r} "
                f"({driver.delta_projected:+.3f} on the point estimate when removed)."
            )
        elif driver is not None:
            # Saying an assessment is "carried by" a signal that lowered it would read as
            # support for a proposition the evidence argues against.
            lines.append(
                "No signal raised the estimate. The largest movement is "
                f"{driver.label!r} at {driver.delta_projected:+.3f}."
            )
        negligible = [entry.label for entry in contributions if entry.is_negligible]
        if negligible:
            lines.append(
                f"Contributed less than one point each: {', '.join(repr(n) for n in negligible)}."
            )
        if not temporal.is_coherent:
            lines.append(
                "The dated evidence does not form one connected stretch of time; see the "
                "discontinuities recorded on this assessment."
            )
        return "\n".join(lines)
