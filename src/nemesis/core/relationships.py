"""Relationships: the edges of the Global Adversary Graph.

Every edge is temporal, provenance-bearing and confidence-scored. None of those is
optional, because an edge without them is an assertion nobody can check — and invariant 12
requires that NEMESIS be able to explain, on demand, why it connected two entities.

The idea this module is built around is **selectivity**, and it is the difference between
infrastructure analysis that works and infrastructure analysis that generates confident
nonsense.

"These two domains share an IP address" is not one fact. It is two completely different
facts depending on a number nobody usually records:

- the IP hosts 2 domains  → strong evidence of common control
- the IP hosts 40,000 domains (shared hosting, a CDN) → evidence of nothing at all

Same relation type, same observation, opposite analytic value. So a pivot here carries the
size of the population it selects from, and confidence is derived from that rather than
from the relation type. An analyst who pivots through a Cloudflare address gets a link
whose own confidence says it is worthless, instead of a link that looks like all the others.
"""

from __future__ import annotations

import math
from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.core.confidence import Opinion
from nemesis.core.entities import SHARED_INFRASTRUCTURE_TYPES, EntityType
from nemesis.core.ids import ClaimId, EdgeId, EntityId
from nemesis.core.temporal import TemporalExtent


class RelationType(StrEnum):
    """What connects two entities."""

    # Network / hosting
    RESOLVES_TO = "resolves_to"
    HOSTED_ON = "hosted_on"
    ANNOUNCED_BY = "announced_by"
    REGISTERED_THROUGH = "registered_through"
    SUBDOMAIN_OF = "subdomain_of"
    REDIRECTS_TO = "redirects_to"

    # Cryptographic material
    PRESENTS_CERTIFICATE = "presents_certificate"
    SIGNED_BY = "signed_by"
    SHARES_KEY = "shares_key"

    # Code
    VARIANT_OF = "variant_of"
    BELONGS_TO_FAMILY = "belongs_to_family"
    SHARES_CODE_WITH = "shares_code_with"
    BUILT_WITH = "built_with"

    # Operations
    COMMUNICATES_WITH = "communicates_with"
    COMMANDS = "commands"
    DELIVERED_BY = "delivered_by"
    TARGETED = "targeted"
    PART_OF_CAMPAIGN = "part_of_campaign"
    USES_TTP = "uses_ttp"

    # Control and identity — the consequential ones
    CONTROLS = "controls"
    OPERATED_BY = "operated_by"
    AUTHORED_BY = "authored_by"
    SAME_OPERATOR_AS = "same_operator_as"
    ALIAS_OF = "alias_of"
    ASSOCIATED_WITH = "associated_with"

    # Ecosystem
    POSTS_ON = "posts_on"
    SELLS_ON = "sells_on"
    VOUCHED_FOR = "vouched_for"
    TRANSACTS_WITH = "transacts_with"
    CLUSTERED_WITH = "clustered_with"

    # Analytic
    CO_OCCURS_WITH = "co_occurs_with"
    SUCCEEDED_BY = "succeeded_by"
    """Resurgence: the later infrastructure that replaced this one after disruption."""


IDENTITY_ASSERTING_RELATIONS: frozenset[RelationType] = frozenset(
    {
        RelationType.SAME_OPERATOR_AS,
        RelationType.ALIAS_OF,
        RelationType.OPERATED_BY,
        RelationType.AUTHORED_BY,
        RelationType.CONTROLS,
    }
)
"""Relations that assert something about *who*, not merely about *what*.

These are the edges that end up in an attribution, a takedown request or a referral. They
carry a higher evidentiary bar and are the ones an adversary most wants us to draw wrongly.
"""


class PivotMethod(StrEnum):
    """The analytic technique that produced an edge.

    Recorded because "why do you believe these are connected?" must be answerable with a
    method, not a score. It is also how a whole class of links gets re-evaluated at once
    when a technique turns out to be weaker than believed.
    """

    DIRECT_OBSERVATION = "direct_observation"
    SHARED_ATTRIBUTE = "shared_attribute"
    TEMPORAL_CORRELATION = "temporal_correlation"
    INFRASTRUCTURE_REUSE = "infrastructure_reuse"
    CRYPTOGRAPHIC_IDENTITY = "cryptographic_identity"
    CODE_SIMILARITY = "code_similarity"
    LINGUISTIC_SIMILARITY = "linguistic_similarity"
    BEHAVIORAL_PATTERN = "behavioral_pattern"
    TRANSACTION_GRAPH = "transaction_graph"
    ANALYST_ASSERTION = "analyst_assertion"
    EXTERNAL_REPORTING = "external_reporting"


METHOD_RELIABILITY_CEILING: dict[PivotMethod, float] = {
    PivotMethod.CRYPTOGRAPHIC_IDENTITY: 1.00,
    PivotMethod.DIRECT_OBSERVATION: 1.00,
    PivotMethod.SHARED_ATTRIBUTE: 0.95,
    PivotMethod.INFRASTRUCTURE_REUSE: 0.85,
    PivotMethod.ANALYST_ASSERTION: 0.70,
    PivotMethod.CODE_SIMILARITY: 0.60,
    PivotMethod.TRANSACTION_GRAPH: 0.60,
    PivotMethod.TEMPORAL_CORRELATION: 0.50,
    PivotMethod.EXTERNAL_REPORTING: 0.50,
    PivotMethod.BEHAVIORAL_PATTERN: 0.45,
    PivotMethod.LINGUISTIC_SIMILARITY: 0.30,
}
"""How much an edge can ever be worth, given the technique that found it.

Selectivity and method reliability are different questions, and conflating them is a
mistake worth naming. Selectivity asks *how many other things share this attribute*.
Method reliability asks *how often does this technique link things that are not related*.
An attribute can be perfectly discriminating while the method that matched it is fallible.

The case that forced this: multi-input cryptocurrency clustering linking exactly two
addresses scores 0.95 on selectivity — a population of two is maximally narrow — yet the
heuristic has documented failure rates against CoinJoin and mixers. Selectivity alone would
have made a fallible inference look like a near-certainty.

The ceilings that matter most:

- **Cryptographic identity, 1.00.** A private key is not shared by accident.
- **Transaction graph, 0.60.** Common-input-ownership is a heuristic, not a proof, and
  privacy tooling defeats it by design.
- **Code similarity, 0.60.** Binary authorship attribution has a substantial critical
  literature; shared code is at least as often theft, reuse or a common library.
- **Linguistic similarity, 0.30.** Capped hardest, and never decisive alone. Adversarial
  stylometry shows deliberate obfuscation degrades authorship attribution severely, and
  open-world accuracy sits far below the closed-world figures usually quoted.

These are **calibration choices, not measurements**. They are stated here so they can be
argued with rather than discovered in a debugger, and they must be re-set against observed
outcomes once resolved cases exist. See ADR-0002.
"""


class PivotSelectivity(BaseModel):
    """How discriminating the shared attribute actually is.

    ``population_size`` is the number of entities sharing this attribute. It is the field
    that turns "shares an IP" into information. Where a connector cannot supply it, that
    must be recorded as unknown rather than assumed small — assuming a pivot is selective
    when nobody counted is how shared-hosting artifacts become adversary clusters.
    """

    model_config = ConfigDict(frozen=True)

    attribute: Annotated[str, Field(min_length=1)]
    """What is shared: the IP, the certificate hash, the PGP fingerprint, the phrase."""

    population_size: int | None = Field(
        default=None,
        ge=1,
        description="How many entities share this attribute, including the two linked. "
        "None means nobody counted — treated as uninformative, never as selective.",
    )

    population_measured_against: str | None = Field(
        default=None,
        description="The corpus the count came from, e.g. 'passive DNS, 2026-08 snapshot'. "
        "A count with no stated denominator is not a count.",
    )

    is_globally_unique: bool = Field(
        default=False,
        description="True only for attributes that identify by construction: a full PGP "
        "fingerprint, a private-key-derived signature. Never assert it for an IP, a "
        "user-agent, or a phrase.",
    )

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.is_globally_unique and (self.population_size or 2) > 2:
            raise ValueError(
                "an attribute claimed globally unique cannot be shared by more than the "
                "two entities being linked"
            )
        if self.population_size is not None and self.population_measured_against is None:
            raise ValueError(
                "population_size requires population_measured_against: a count without a "
                "stated corpus and date cannot be interpreted or challenged"
            )
        return self

    @property
    def is_informative(self) -> bool:
        """Whether this pivot narrows the field enough to mean anything."""
        if self.is_globally_unique:
            return True
        if self.population_size is None:
            return False
        return self.population_size <= 50

    def evidential_weight(self) -> float:
        """Weight in [0, 1] derived from how much the attribute narrows the field.

        Weight is ``1 / log2(population)``, clamped to 0.95 and floored at a population
        of 2: sharing an attribute with one other entity is strong (0.95), with 12 it is
        moderate (0.28), with 40,000 it is noise (0.07). An uncounted population yields
        0.0 rather than a guess.

        The shape is a **modelling choice, not a measurement**. It is monotone in the
        right direction and stated explicitly so it can be argued with; it is not derived
        from observed base rates, and it must be recalibrated once real case outcomes
        exist. See ADR-0002.
        """
        if self.is_globally_unique:
            return 1.0
        if self.population_size is None:
            return 0.0
        if self.population_size <= 2:
            return 0.95
        return min(0.95, 1.0 / math.log2(self.population_size))


class Relationship(BaseModel):
    """A temporal, provenance-bearing, confidence-scored edge.

    Construction rules that are enforced rather than advised:

    - An identity-asserting relation must cite supporting claims. Asserting that two
      personas are the same operator without saying why is exactly the output this
      platform exists to make impossible.
    - A pivot through shared infrastructure (a CDN address, a registrar, an exchange)
      must carry an explicit justification, because by default such a pivot means nothing.
    """

    model_config = ConfigDict(frozen=True)

    edge_id: EdgeId
    source_id: EntityId
    target_id: EntityId
    source_type: EntityType
    target_type: EntityType
    relation: RelationType

    extent: TemporalExtent
    """When the relationship held, with honest bounds."""

    confidence: Opinion
    pivot_method: PivotMethod
    selectivity: PivotSelectivity | None = None

    supporting_claims: tuple[ClaimId, ...] = ()
    contradicting_claims: tuple[ClaimId, ...] = ()

    shared_infrastructure_justification: str | None = Field(
        default=None,
        description="Required when pivoting through an entity type that is shared by "
        "unrelated parties by default. Must say why this instance is different.",
    )

    is_synthetic: bool = False

    @model_validator(mode="after")
    def _enforce_edge_rules(self) -> Self:
        if self.source_id == self.target_id:
            raise ValueError("an entity cannot be related to itself")

        if self.relation in IDENTITY_ASSERTING_RELATIONS and not self.supporting_claims:
            raise ValueError(
                f"{self.relation.value} asserts identity or control and must cite "
                "supporting claims (invariant 12: every edge must be explainable)"
            )

        pivots_through_shared = (
            self.source_type in SHARED_INFRASTRUCTURE_TYPES
            or self.target_type in SHARED_INFRASTRUCTURE_TYPES
        )
        needs_justification = pivots_through_shared and self.pivot_method in {
            PivotMethod.SHARED_ATTRIBUTE,
            PivotMethod.INFRASTRUCTURE_REUSE,
        }
        if needs_justification and not self.shared_infrastructure_justification:
            shared = (
                self.source_type
                if self.source_type in SHARED_INFRASTRUCTURE_TYPES
                else self.target_type
            )
            raise ValueError(
                f"pivoting through {shared.value} requires an explicit justification: "
                "this entity type is shared by unrelated parties, so co-location on it "
                "is not by itself evidence of a relationship"
            )

        if self.selectivity is not None and self.pivot_method is PivotMethod.DIRECT_OBSERVATION:
            raise ValueError(
                "a directly observed relationship has no selectivity: nothing was inferred "
                "from a shared attribute"
            )

        return self

    def evidential_weight(self) -> float:
        """How much this edge can carry, given both the pivot and the technique.

        The lesser of what the shared attribute discriminates and what the method can be
        trusted to establish. A perfectly selective attribute matched by a fallible
        technique is still a fallible link.
        """
        ceiling = METHOD_RELIABILITY_CEILING[self.pivot_method]
        if self.selectivity is None:
            return ceiling
        return min(self.selectivity.evidential_weight(), ceiling)

    @property
    def is_method_capped(self) -> bool:
        """Whether the technique, not the attribute, is what limits this edge.

        Surfaced because the two call for different responses: a weak attribute needs a
        better pivot, a weak method needs corroboration by a different kind of evidence.
        """
        if self.selectivity is None:
            return False
        return METHOD_RELIABILITY_CEILING[self.pivot_method] < self.selectivity.evidential_weight()

    @property
    def asserts_identity(self) -> bool:
        return self.relation in IDENTITY_ASSERTING_RELATIONS

    @property
    def is_contradicted(self) -> bool:
        return bool(self.contradicting_claims)

    def explain(self) -> Explanation:
        """Why NEMESIS believes this edge exists. Invariant 12."""
        reasons: list[str] = []
        caveats: list[str] = []

        reasons.append(f"Established by {self.pivot_method.value.replace('_', ' ')}.")

        if self.selectivity is not None:
            sel = self.selectivity
            if sel.is_globally_unique:
                reasons.append(f"The shared attribute ({sel.attribute}) is unique by construction.")
            elif sel.population_size is None:
                caveats.append(
                    f"The shared attribute ({sel.attribute}) was never counted, so its "
                    "discriminating power is unknown and this link carries no weight."
                )
            else:
                reasons.append(
                    f"{sel.population_size} entities share {sel.attribute} "
                    f"(measured against {sel.population_measured_against})."
                )
                if not sel.is_informative:
                    caveats.append(
                        f"{sel.population_size} entities share this attribute — too many "
                        "for co-location to indicate a relationship."
                    )

        if self.shared_infrastructure_justification:
            reasons.append(self.shared_infrastructure_justification)

        if self.is_method_capped:
            ceiling = METHOD_RELIABILITY_CEILING[self.pivot_method]
            caveats.append(
                f"The attribute is discriminating, but {self.pivot_method.value.replace('_', ' ')} "
                f"is only reliable to {ceiling:.0%}; this link needs corroboration by a "
                "different kind of evidence, not a better pivot of the same kind."
            )

        if self.confidence.is_vacuous:
            caveats.append("No evidence has been gathered for or against this relationship.")
        if self.confidence.indecisiveness > 0.5 and not self.confidence.is_vacuous:
            caveats.append(
                "Supporting and contradicting evidence are close to balanced for this edge."
            )
        if self.contradicting_claims:
            caveats.append(
                f"{len(self.contradicting_claims)} claim(s) contradict this relationship."
            )
        if self.is_synthetic:
            caveats.append("SIMULATED: this edge originates from a synthetic connector.")
        if self.extent.is_open_ended:
            caveats.append("The relationship may still hold; no end has been observed.")

        return Explanation(
            edge_id=self.edge_id,
            summary=(
                f"{self.source_id} --[{self.relation.value}]--> {self.target_id}, "
                f"observed {self.extent.known_from.date()} to {self.extent.known_until.date()}"
            ),
            reasons=tuple(reasons),
            caveats=tuple(caveats),
            supporting_claims=self.supporting_claims,
            contradicting_claims=self.contradicting_claims,
            confidence=self.confidence,
        )


class Explanation(BaseModel):
    """A machine-readable and human-readable answer to "why are these connected?".

    Returned by :meth:`Relationship.explain`. Caveats are a first-class field rather than
    prose buried in a summary, so a UI can surface them and an export cannot drop them.
    """

    model_config = ConfigDict(frozen=True)

    edge_id: EdgeId
    summary: str
    reasons: tuple[str, ...]
    caveats: tuple[str, ...]
    supporting_claims: tuple[ClaimId, ...]
    contradicting_claims: tuple[ClaimId, ...]
    confidence: Opinion

    def render(self) -> str:
        """Plain text for an analyst or a report."""
        from nemesis.core.confidence import describe

        lines = [self.summary, f"Confidence: {describe(self.confidence)}"]
        if self.reasons:
            lines.append("Because:")
            lines.extend(f"  - {reason}" for reason in self.reasons)
        if self.caveats:
            lines.append("But:")
            lines.extend(f"  ! {caveat}" for caveat in self.caveats)
        lines.append(
            f"Supported by {len(self.supporting_claims)} claim(s), "
            f"contradicted by {len(self.contradicting_claims)}."
        )
        return "\n".join(lines)
