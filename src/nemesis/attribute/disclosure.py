"""Redacting an attribution into something that may leave the platform.

Founder decision D1's wall, on the attribution side. :class:`ExternalAttributionProduct` is
what a provider, a regulator or an investigator receives. It is a **different type** from
the internal :class:`~nemesis.attribute.engine.AttributionResult`, and the difference is not
cosmetic: it has no field capable of holding a persona or human-identity assessment.

That is the whole construction. A guard that checks a flag can be forgotten; a field that
does not exist cannot be populated by a caller in a hurry. The redaction function is the
only way to obtain the external type, and it drops internal dimensions on the way through
rather than trusting anyone to omit them.

**Withholding is stated, never silent.** The product records how many dimensions were held
back and under what class. A recipient told nothing about persona linkage would otherwise
reasonably infer that the question was not examined — and being misled by our silence is a
worse outcome than being told that something exists which they are not being given.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.attribute.dimensions import (
    AlternativeHypothesis,
    AttributionDimension,
    DimensionAssessment,
    MissingEvidence,
    SourceDiversity,
)
from nemesis.attribute.engine import AttributionResult
from nemesis.core.confidence import ConfidenceBand, Opinion
from nemesis.core.disclosure import DisclosureClass, DisclosureViolationError, most_restrictive
from nemesis.core.ids import ActorId, AttributionId, ClaimId

DIMENSION_DISCLOSURE: dict[AttributionDimension, DisclosureClass] = {
    AttributionDimension.INFRASTRUCTURE: DisclosureClass.DELIVERABLE,
    AttributionDimension.CAMPAIGN: DisclosureClass.DELIVERABLE,
    AttributionDimension.ORGANIZATION: DisclosureClass.DELIVERABLE,
    AttributionDimension.PERSONA: DisclosureClass.INTERNAL_LEAD,
    AttributionDimension.HUMAN_IDENTITY: DisclosureClass.RESTRICTED,
}
"""Which of the five dimensions may leave the platform.

The line falls between ORGANIZATION and PERSONA, and that placement *is* founder decision
D1. Everything above it describes infrastructure and activity; everything below it describes
who somebody is.
"""

DELIVERABLE_DIMENSIONS: tuple[AttributionDimension, ...] = tuple(
    dimension
    for dimension, disclosure in DIMENSION_DISCLOSURE.items()
    if disclosure is DisclosureClass.DELIVERABLE
)


class ExternalDimension(BaseModel):
    """One deliverable dimension, as a recipient sees it.

    Carries the contradicting evidence and the alternatives, not only the conclusion. An
    external product that showed a confidence figure while dropping what argues against it
    would be a more polished lie than the internal record it came from.
    """

    model_config = ConfigDict(frozen=True)

    dimension: AttributionDimension
    hypothesis: str
    opinion: Opinion
    band: ConfidenceBand
    supporting_claims: tuple[ClaimId, ...]
    contradicting_claims: tuple[ClaimId, ...]
    alternatives: tuple[AlternativeHypothesis, ...]
    missing_evidence: tuple[MissingEvidence, ...]
    source_diversity: SourceDiversity
    reasoning: str
    warnings: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _must_be_deliverable(self) -> Self:
        disclosure = DIMENSION_DISCLOSURE[self.dimension]
        if disclosure is not DisclosureClass.DELIVERABLE:
            raise DisclosureViolationError(
                f"{self.dimension.value} is classified {disclosure.value} and cannot appear "
                "in an external product. Founder decision D1: persona and human-identity "
                "findings are internal leads, not deliverables."
            )
        return self


class WithheldDimension(BaseModel):
    """A dimension that exists internally and is deliberately not supplied.

    The recipient is told the question was assessed and that the answer is not being handed
    over. They are told neither the conclusion nor the evidence — only that the silence is
    a decision rather than an absence.
    """

    model_config = ConfigDict(frozen=True)

    dimension: AttributionDimension
    disclosure: DisclosureClass
    reason: str


class ExternalAttributionProduct(BaseModel):
    """What NEMESIS is willing to hand to somebody outside it.

    Structurally incapable of carrying a persona or human-identity assessment: there is no
    field for one, and :class:`ExternalDimension` refuses to be constructed with one.
    """

    model_config = ConfigDict(frozen=True)

    attribution_id: AttributionId
    subject: Annotated[str, Field(min_length=1, max_length=512)]
    assessed_by: ActorId
    assessed_at: datetime

    dimensions: tuple[ExternalDimension, ...]
    withheld: tuple[WithheldDimension, ...]

    is_simulated: bool = True
    """True while every source is a fixture. A recipient must never be left to assume that
    material described here was collected from the real world."""

    caveats: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _no_internal_dimension_slipped_through(self) -> Self:
        # Belt and braces. ExternalDimension already refuses, but this catches a future
        # constructor that builds the tuple by some other route.
        for item in self.dimensions:
            if DIMENSION_DISCLOSURE[item.dimension] is not DisclosureClass.DELIVERABLE:
                raise DisclosureViolationError(
                    f"{item.dimension.value} reached an external product"
                )
        return self

    @property
    def disclosure(self) -> DisclosureClass:
        return most_restrictive(*(DIMENSION_DISCLOSURE[item.dimension] for item in self.dimensions))

    @property
    def names_a_person(self) -> bool:
        """Always False, by construction. Kept so a caller can assert it rather than
        assume it, and so the assertion has something to read."""
        return False

    def render(self) -> str:
        lines = [
            f"ATTRIBUTION PRODUCT {self.attribution_id}",
            f"Subject: {self.subject}",
            f"Assessed: {self.assessed_at.isoformat()}",
        ]
        if self.is_simulated:
            lines.append(
                "SIMULATED: every source behind this product is synthetic. Nothing here "
                "was collected from a real system and none of it is evidence."
            )
        lines.append("")
        for item in self.dimensions:
            lines.append(f"[{item.dimension.value.upper()}] {item.band.value}")
            lines.append(f"  {item.hypothesis}")
            lines.append(
                f"  supporting {len(item.supporting_claims)}, "
                f"contradicting {len(item.contradicting_claims)}, "
                f"independent origins {item.source_diversity.independent_source_count}"
            )
            lines.extend(f"  ! {warning}" for warning in item.warnings)
        if self.withheld:
            lines.append("")
            lines.append("WITHHELD — assessed internally, deliberately not supplied:")
            lines.extend(
                f"  - {item.dimension.value} ({item.disclosure.value}): {item.reason}"
                for item in self.withheld
            )
        lines.extend(f"! {caveat}" for caveat in self.caveats)
        return "\n".join(lines)


_WITHHOLDING_REASON: dict[DisclosureClass, str] = {
    DisclosureClass.INTERNAL_LEAD: (
        "Assessed as an internal investigative lead. It directs where NEMESIS looks next "
        "and is not a conclusion anybody outside this platform should act on."
    ),
    DisclosureClass.RESTRICTED: (
        "Held under data-protection and handling obligations. NEMESIS does not supply "
        "identity findings, and the absence of one here is not evidence that a person was "
        "or was not identified."
    ),
}


def redact_for_disclosure(
    result: AttributionResult, *, is_simulated: bool = True
) -> ExternalAttributionProduct:
    """Turn an internal attribution into the product a recipient may be given.

    The only route to an :class:`ExternalAttributionProduct`. Internal dimensions are
    dropped here and recorded as withheld; nothing downstream has to remember to omit them,
    because nothing downstream is handed them.
    """
    deliverable: list[ExternalDimension] = []
    withheld: list[WithheldDimension] = []

    for assessment in result.assessments:
        disclosure = DIMENSION_DISCLOSURE[assessment.dimension]
        if disclosure is DisclosureClass.DELIVERABLE:
            deliverable.append(_to_external(assessment))
        else:
            withheld.append(
                WithheldDimension(
                    dimension=assessment.dimension,
                    disclosure=disclosure,
                    reason=_WITHHOLDING_REASON[disclosure],
                )
            )

    caveats = list(result.warnings)
    caveats.append(
        "This product carries infrastructure, campaign and organizational findings only. "
        "NEMESIS attributes activity to operations and organizations; it does not supply "
        "findings about the identity of individuals."
    )
    if is_simulated:
        caveats.append(
            "No figure here has been calibrated against a known-correct answer. The "
            "confidences are internally consistent and externally unvalidated."
        )

    return ExternalAttributionProduct(
        attribution_id=result.attribution_id,
        subject=result.subject,
        assessed_by=result.assessed_by,
        assessed_at=result.assessed_at,
        dimensions=tuple(deliverable),
        withheld=tuple(withheld),
        is_simulated=is_simulated,
        caveats=tuple(caveats),
    )


def _to_external(assessment: DimensionAssessment) -> ExternalDimension:
    return ExternalDimension(
        dimension=assessment.dimension,
        hypothesis=assessment.hypothesis,
        opinion=assessment.opinion,
        band=assessment.band,
        supporting_claims=assessment.supporting_claims,
        contradicting_claims=assessment.contradicting_claims,
        alternatives=assessment.alternatives,
        missing_evidence=assessment.missing_evidence,
        source_diversity=assessment.source_diversity,
        reasoning=assessment.reasoning,
        warnings=assessment.warnings,
    )
