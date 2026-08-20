"""The five attribution dimensions, and what an assessment of one must carry.

Attribution is not one question. "Which infrastructure did this actor control" and "what
is the operator's name" differ by orders of magnitude in what the evidence can support,
and an engine that answers both with a single number has thrown away the only distinction
that matters. Invariant 4 is explicit about it: attribution confidence is multi-dimensional
*by construction*.

So there is no aggregate here, and there is deliberately no method that produces one. A
weighted mean of the five would be dominated by whichever dimension happened to be
best-evidenced, which in practice is infrastructure — the dimension that says nothing about
who anyone is. Anyone who wants one number must write the collapse themselves, in their own
module, and own the choice of weights. Making that awkward is the point.

Each assessment carries, alongside the fused opinion:

- **contradicting evidence**, as a required field. Optional contradiction is contradiction
  that gets dropped: the caller that forgets it produces a clean-looking assessment, and
  nothing in the type system objects.
- **alternative hypotheses**, each retained with its own opinion and an argument against
  it. Deleting a refuted alternative erases the record that it was considered, which is
  precisely what an opposing expert will ask about.
- **missing evidence**, stated concretely enough to go and collect.
- **source diversity**, taken from the fusion result rather than recounted here, because
  feed count is not source count and only fusion knows the difference.
- **temporal consistency**, because a set of individually credible facts that cannot all
  have been true at once is a signal about the evidence, not about the adversary.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.core.confidence import ConfidenceBand, Opinion, band_of
from nemesis.core.fusion import DependenceHandling, FusionResult
from nemesis.core.ids import ClaimId
from nemesis.core.temporal import TemporalExtent


class AttributionDimension(StrEnum):
    """What is being attributed. Each is assessed and reported separately."""

    INFRASTRUCTURE = "infrastructure"
    """Which hosts, domains, certificates and accounts were under common control."""

    CAMPAIGN = "campaign"
    """Whether a set of activity is one operation: one toolset, one tempo, one target set."""

    ORGANIZATION = "organization"
    """Whether an organized group stands behind the operation, and which one."""

    PERSONA = "persona"
    """Whether marketplace and forum identities resolve to one operator."""

    HUMAN_IDENTITY = "human_identity"
    """Which natural person is behind the persona. Structurally gated; see
    :class:`IdentityGateResult`."""


DIMENSION_QUESTION: dict[AttributionDimension, str] = {
    AttributionDimension.INFRASTRUCTURE: "Was this infrastructure under common control?",
    AttributionDimension.CAMPAIGN: "Is this activity one campaign?",
    AttributionDimension.ORGANIZATION: "Which organization stands behind it?",
    AttributionDimension.PERSONA: "Do these personas resolve to one operator?",
    AttributionDimension.HUMAN_IDENTITY: "Which natural person is the operator?",
}
"""The proposition each dimension answers, in words an analyst reads before a number.

Kept as data so a report cannot silently relabel a dimension into a stronger claim than
the one that was actually assessed.
"""


class EvidenceAvailability(StrEnum):
    """Whether the missing evidence could in fact be obtained.

    Uses the boundary labels from CLAUDE.md rather than a free-text status, so "we did not
    look" and "we are not permitted to look" stay distinguishable in an export.
    """

    COLLECTABLE = "collectable"
    REQUIRES_EXTERNAL_DATA = "requires_external_data"
    REQUIRES_LEGAL_AUTHORITY = "requires_legal_authority"
    UNOBTAINABLE = "unobtainable"


class MissingEvidence(BaseModel):
    """Something that would settle the question, named concretely.

    "More corroboration" is not an entry here. The test is whether a reader could turn the
    description into a collection task or a legal request without asking what was meant.
    """

    model_config = ConfigDict(frozen=True)

    description: Annotated[str, Field(min_length=1, max_length=1000)]
    """The artifact or record itself: "the registrar's unredacted registrant record for
    the four domains", not "better registration data"."""

    would_settle: Annotated[str, Field(min_length=1, max_length=1000)]
    """What obtaining it would resolve, and in which direction."""

    availability: EvidenceAvailability


class AlternativeHypothesis(BaseModel):
    """An explanation other than the one being assessed, kept and argued against.

    The argument against it is a required field. An alternative recorded without one is an
    alternative nobody examined, and it will read to a later reviewer as though it had been
    dismissed on grounds that were never written down.
    """

    model_config = ConfigDict(frozen=True)

    name: Annotated[str, Field(min_length=1, max_length=200)]
    description: Annotated[str, Field(min_length=1, max_length=2000)]

    opinion: Opinion
    band: ConfidenceBand

    evidential_opinion: Opinion | None = None
    """What the evidence gave before the robustness margin removed a plantable fact.

    Carried so an analyst can see the size of the reduction and argue with it. Reporting
    only the margined figure would hide how much support was deliberately set aside;
    reporting only this one would be the defect the margin exists to fix."""

    margin_outcome: str | None = None
    removed_fact: str | None = None

    supporting_claims: tuple[ClaimId, ...]
    contradicting_claims: tuple[ClaimId, ...]

    argument_against: Annotated[str, Field(min_length=1, max_length=4000)]
    """Why this alternative is not the working conclusion. Never empty, never "refuted"."""

    is_deception_hypothesis: bool = False
    """True for "we were meant to believe this" hypotheses generated by the deception gate.
    Flagged so a reader can see that the engine raised it rather than an analyst."""

    @model_validator(mode="after")
    def _band_matches_opinion(self) -> Self:
        if self.band is not band_of(self.opinion):
            raise ValueError(
                f"band {self.band.value!r} does not follow from the opinion "
                f"(band_of gives {band_of(self.opinion).value!r})"
            )
        return self


class SourceDiversity(BaseModel):
    """How many genuinely independent origins stand behind an assessment.

    Copied from the fusion result rather than recomputed, because independence is resolved
    during fusion — resellers and mirrors are collapsed there — and a second count taken
    from the raw signal list would disagree with the number the opinion was actually
    derived from.
    """

    model_config = ConfigDict(frozen=True)

    total_signals: int
    independent_source_count: int
    adversary_influenceable_sources: int
    collapsed_groups: tuple[tuple[str, ...], ...] = ()
    dependence_handling: DependenceHandling = DependenceHandling.NO_SOURCES
    max_conflict: float = 0.0

    @classmethod
    def from_fusion(cls, result: FusionResult) -> SourceDiversity:
        return cls(
            total_signals=result.total_sources,
            independent_source_count=result.independent_source_count,
            adversary_influenceable_sources=result.adversary_influenceable_sources,
            collapsed_groups=result.collapsed_groups,
            dependence_handling=result.dependence_handling,
            max_conflict=result.max_conflict,
        )

    @property
    def is_single_sourced(self) -> bool:
        return self.independent_source_count <= 1

    @property
    def is_entirely_adversary_influenceable(self) -> bool:
        """Whether every contributing source sits in a channel an adversary can plant into."""
        return self.total_signals > 0 and self.adversary_influenceable_sources == self.total_signals


DEFAULT_TEMPORAL_GAP_TOLERANCE = timedelta(days=7)
"""How long a hole in the evidence may be before it is reported as a discontinuity.

This encodes how sparsely we collect, not how the adversary behaved. Passive DNS, CT logs
and forum scrapes all sample; a week with no sighting between two sightings is the normal
texture of the data, not a break in the operation. A tolerance of zero would flag every
evidence set as incoherent, and a check that fires always is a check nobody reads. The
value is a calibration choice and should be re-set against observed collection cadence.
"""


class TemporalConsistency(BaseModel):
    """Whether the evidence describes a timeline that could have happened.

    Not a confidence input. It answers a different question: do these facts fit together in
    time? A cluster whose registration record postdates the phishing it supposedly enabled
    is not weak evidence, it is evidence that something in the chain is wrong — a parsing
    error, a timezone bug, or a fabricated record.
    """

    model_config = ConfigDict(frozen=True)

    is_coherent: bool
    extents_assessed: int
    earliest: datetime | None = None
    latest: datetime | None = None
    discontinuities: tuple[str, ...] = ()
    tolerance_days: float = DEFAULT_TEMPORAL_GAP_TOLERANCE.total_seconds() / 86400.0

    @property
    def known_span_days(self) -> float | None:
        if self.earliest is None or self.latest is None:
            return None
        return (self.latest - self.earliest).total_seconds() / 86400.0


def assess_temporal_consistency(
    extents: Sequence[TemporalExtent],
    *,
    tolerance: timedelta = DEFAULT_TEMPORAL_GAP_TOLERANCE,
) -> TemporalConsistency:
    """Check that a set of observations forms one connected stretch of time.

    Uses only the ``known`` bounds. The ``possible`` bounds are usually open on both sides,
    and a check run against them would find every evidence set coherent — which is true and
    useless. The defensible interval is the one that was actually observed.

    An empty set is reported as *not* coherent, with the reason stated. Reporting "no dated
    evidence" as coherence would let a dimension with nothing behind it pass a check the
    well-evidenced dimensions have to earn.
    """
    if not extents:
        return TemporalConsistency(
            is_coherent=False,
            extents_assessed=0,
            discontinuities=("No dated evidence, so no timeline could be checked.",),
            tolerance_days=tolerance.total_seconds() / 86400.0,
        )

    ordered = sorted(extents, key=lambda extent: extent.known_from)
    discontinuities: list[str] = []
    reach = ordered[0].known_until

    for extent in ordered[1:]:
        gap = extent.known_from - reach
        if gap > tolerance:
            discontinuities.append(
                f"{gap.days} day gap: evidence ends {reach.date().isoformat()} and does not "
                f"resume until {extent.known_from.date().isoformat()}"
            )
        reach = max(reach, extent.known_until)

    return TemporalConsistency(
        is_coherent=not discontinuities,
        extents_assessed=len(ordered),
        earliest=ordered[0].known_from,
        latest=max(extent.known_until for extent in ordered),
        discontinuities=tuple(discontinuities),
        tolerance_days=tolerance.total_seconds() / 86400.0,
    )


class SignalContribution(BaseModel):
    """How much one signal moved the assessment, measured by removing it.

    Leave-one-out rather than a declared weight: fusion is not a weighted sum, and a signal
    that is dependent on another contributes almost nothing however strong it looks in
    isolation. This is what lets the engine say "the fingerprint carried this, the alias
    added nothing" instead of listing four signals as though they were four reasons.
    """

    model_config = ConfigDict(frozen=True)

    label: str
    claim_id: ClaimId
    delta_projected: float
    """Projected probability with this signal, minus the projected probability without it.
    Positive means the signal raised the estimate."""

    @property
    def is_negligible(self) -> bool:
        """Below one percentage point of movement — present in the record, absent from the
        conclusion."""
        return abs(self.delta_projected) < 0.01


class RefusalReason(StrEnum):
    """Why a human-identity attribution was refused before any scoring took place."""

    NO_EVIDENCE = "no_evidence"
    SINGLE_SOURCED = "single_sourced"
    ONLY_ADVERSARY_INFLUENCEABLE = "only_adversary_influenceable"
    NO_CORROBORATION = "no_corroboration"
    """No single statement is attested by two independent origins. Two origins asserting
    two different things is not corroboration, and reads as such only if nobody checks."""

    MODEL_DERIVED_SUPPORT = "model_derived_support"
    """An LLM or statistical model is among the supports. Invariant 1: naming a person on
    a model's say-so is the failure this platform is built to make impossible."""


class IdentityGateResult(BaseModel):
    """The outcome of the structural gate on :attr:`AttributionDimension.HUMAN_IDENTITY`.

    The gate runs *before* fusion, so no score can reach past it. That ordering is the
    control: a threshold, however high, is something an adversary can push a number over by
    manufacturing agreement, and agreement is cheap in the channels where names circulate.
    A gate on the *shape* of the evidence — how many independent origins, whether any of
    them are outside the adversary's reach, whether anything is corroborated — cannot be
    cleared that way.

    What is at stake is not analytic tidiness. Naming a natural person is the single most
    damaging output this platform can produce: it is irreversible once it leaves the
    building, it lands on someone who may be entirely innocent, and in the GLASS ANVIL
    scenario the name is planted precisely because the adversary expects it to be repeated.
    """

    model_config = ConfigDict(frozen=True)

    passed: bool
    reasons: tuple[RefusalReason, ...]
    explanation: Annotated[str, Field(min_length=1, max_length=4000)]

    refused_claims: tuple[ClaimId, ...] = ()
    """Claims that were offered in support and not used. Recorded so the refusal is
    auditable, and kept out of ``supporting_claims`` so no downstream reader can present
    them as grounds for a name."""

    independent_origin_count: int = 0
    corroborated_statements: int = 0

    @model_validator(mode="after")
    def _reasons_match_outcome(self) -> Self:
        if self.passed and self.reasons:
            raise ValueError("a passed gate cannot carry refusal reasons")
        if not self.passed and not self.reasons:
            raise ValueError("a refusal must name at least one reason")
        return self


class DimensionAssessment(BaseModel):
    """One dimension's answer, with everything needed to argue with it.

    Every field below is required. Defaults were considered and rejected: a caller that
    omits contradicting evidence, alternatives or missing evidence produces an assessment
    that looks complete and is not, and the omission is invisible at the point of reading.
    """

    model_config = ConfigDict(frozen=True)

    dimension: AttributionDimension
    hypothesis: Annotated[str, Field(min_length=1, max_length=2000)]
    """The exact proposition assessed. Not the dimension's generic question — the specific
    claim about this case, so a reader knows what the band applies to."""

    opinion: Opinion
    band: ConfidenceBand

    evidential_opinion: Opinion | None = None
    """What the evidence gave before the robustness margin removed a plantable fact.

    Carried so an analyst can see the size of the reduction and argue with it. Reporting
    only the margined figure would hide how much support was deliberately set aside;
    reporting only this one would be the defect the margin exists to fix."""

    margin_outcome: str | None = None
    removed_fact: str | None = None

    supporting_claims: tuple[ClaimId, ...]
    contradicting_claims: tuple[ClaimId, ...]
    """Required, and required to be non-defaulted. A dimension that cannot express
    contradiction silently drops it, and the assessment that results is not merely
    incomplete — it is systematically biased towards whatever we already believed."""

    alternatives: tuple[AlternativeHypothesis, ...]
    missing_evidence: tuple[MissingEvidence, ...]
    source_diversity: SourceDiversity
    temporal_consistency: TemporalConsistency

    reasoning: Annotated[str, Field(min_length=1)]
    """Plain prose an analyst can read without knowing subjective logic, and can disagree
    with. Generated from the same values as the rest of the object, never written freehand
    by a model."""

    signal_contributions: tuple[SignalContribution, ...] = ()
    identity_gate: IdentityGateResult | None = None
    warnings: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _enforce_assessment_rules(self) -> Self:
        if self.band is not band_of(self.opinion):
            raise ValueError(
                f"band {self.band.value!r} does not follow from the opinion "
                f"(band_of gives {band_of(self.opinion).value!r}); a band that disagrees "
                "with its own opinion is a display bug that becomes an analytic claim"
            )

        overlap = set(self.supporting_claims) & set(self.contradicting_claims)
        if overlap:
            raise ValueError(
                f"claim(s) {sorted(overlap)} are listed as both supporting and "
                "contradicting; one of the two readings is wrong and the assessment "
                "cannot be interpreted until it is resolved"
            )

        # The gate is not optional bookkeeping: an assessment of this dimension that
        # carries no gate result is one where the gate never ran.
        if self.dimension is AttributionDimension.HUMAN_IDENTITY and self.identity_gate is None:
            raise ValueError(
                "a human_identity assessment must carry the result of the identity gate"
            )

        if self.identity_gate is not None and not self.identity_gate.passed:
            if self.band is not ConfidenceBand.INSUFFICIENT_BASIS:
                raise ValueError(
                    "a refused human-identity assessment must report insufficient_basis, "
                    "not a probability band"
                )
            if self.supporting_claims:
                raise ValueError(
                    "a refused human-identity assessment must cite no supporting claims; "
                    "the offered claims belong in the gate's refused_claims"
                )

        return self

    @property
    def is_refused(self) -> bool:
        return self.identity_gate is not None and not self.identity_gate.passed

    def render(self) -> str:
        """Plain text for an analyst or a report."""
        from nemesis.core.confidence import describe

        lines = [
            f"[{self.dimension.value.upper()}] {self.hypothesis}",
            f"  {DIMENSION_QUESTION[self.dimension]}",
            f"  Confidence: {describe(self.opinion)}",
            f"  Sources: {self.source_diversity.independent_source_count} independent of "
            f"{self.source_diversity.total_signals} signal(s); "
            f"{self.source_diversity.adversary_influenceable_sources} adversary-influenceable",
            f"  Supported by {len(self.supporting_claims)} claim(s), "
            f"contradicted by {len(self.contradicting_claims)}.",
        ]
        if not self.temporal_consistency.is_coherent:
            lines.extend(f"  ! {gap}" for gap in self.temporal_consistency.discontinuities)
        lines.extend(f"  ! {warning}" for warning in self.warnings)
        for alternative in self.alternatives:
            lines.append(
                f"  Alternative — {alternative.name}: {alternative.band.value}. "
                f"{alternative.argument_against}"
            )
        for missing in self.missing_evidence:
            lines.append(
                f"  Missing — {missing.description} ({missing.availability.value}): "
                f"{missing.would_settle}"
            )
        lines.append("  Reasoning:")
        lines.extend(f"    {line}" for line in self.reasoning.splitlines())
        return "\n".join(lines)
