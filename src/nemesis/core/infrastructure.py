"""Whose infrastructure this is — kept separate from what it was seen doing.

Observing an adversary use a piece of infrastructure tells you nothing about whose it is.
That sentence is the whole module. A phishing redirector is very often a small company's
neglected WordPress install; the company is not the adversary, its host is not a takedown
target, and a platform that cannot say so will eventually take down a victim and call it a
result.

So four questions are asked separately and never merged:

===========================  ============================================================
``LEGAL_OWNERSHIP``          Whose asset is it, as a matter of record and law?
``CURRENT_CONTROL``          Who is operating it right now?
``OBSERVED_USE``             What was it seen doing?
``ATTRIBUTED_RESPONSIBILITY`` Who is answerable for that?
===========================  ============================================================

They are four objects rather than four fields on one, because the failure this module exists
to prevent has already happened once in this codebase:
:class:`~nemesis.disrupt.options.OwnershipEvidence` is named for ownership and, in its only
production construction, is derived from the attribution dimension whose question is common
*control*. A single object with four optional fields gets filled in by whoever happens to hold
one of them, and the distinction dies quietly. Four objects make the omission visible.

**Why this lives in ``core``.** The enforcement point is the Effects plane, and
``.importlinter`` forbids ``nemesis.effects`` and ``nemesis.authz`` from importing
``nemesis.attribute`` or ``nemesis.disrupt`` — those four are sibling layers. That separation
is not an obstacle to work around: it is *what makes invariant 17 true* ("attribution is not
authorization"). ``core`` is the one layer every plane may import, and this module holds no
I/O, exactly like :mod:`nemesis.core.fusion` and :mod:`nemesis.core.retention`, which are the
precedent for substantial pure decision logic living here.

**What this module deliberately does not do.** It does not decide anything from the graph. It
is a vocabulary, a set of construction rules, and a table. The derivation of a role from
evidence happens above; the *enforcement* of a role at execution happens below, against a role
bound into a signed capability. Splitting it that way is what lets the check run at a boundary
that is structurally forbidden from computing the answer itself.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Final, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.core.authorization import OperationClass
from nemesis.core.claims import Claim, DerivationKind
from nemesis.core.confidence import ConfidenceBand, Opinion, band_of, describe
from nemesis.core.entities import Entity, EntityType
from nemesis.core.ids import ClaimId, EntityId
from nemesis.core.relationships import Relationship, RelationType
from nemesis.core.temporal import TemporalExtent, require_utc


class InfrastructureRole(StrEnum):
    """What a piece of infrastructure *is*, in the only sense that bears on acting against it.

    Not a threat score and not a verdict about the traffic. A node can be flagrantly malicious
    in every observation and still be a hospital's web server.
    """

    UNKNOWN = "unknown"
    """Nobody has established whose this is.

    A first-class answer and frequently the correct one. Forcing every node into a definitive
    class is how a classifier becomes a rubber stamp: the pressure is always toward the class
    that permits the action someone already wants to take."""

    ACTOR_OWNED = "actor_owned"
    """The adversary holds it as a matter of record — registered, paid for, theirs.

    Requires a ``LEGAL_OWNERSHIP`` facet. Control evidence cannot promote a node to this."""

    ACTOR_CONTROLLED = "actor_controlled"
    """The adversary operates it, whoever owns it.

    Requires a ``CURRENT_CONTROL`` facet. This is the honest classification for most adversary
    infrastructure: bulletproof hosting is rented, not owned, and the distinction matters to
    whoever receives the takedown request."""

    COMPROMISED_LEGITIMATE = "compromised_legitimate"
    """An innocent party's asset the adversary has taken over.

    The §6 case. Requires *both* a ``LEGAL_OWNERSHIP`` facet naming someone and a
    ``CURRENT_CONTROL`` facet: calling a host "compromised legitimate" is a claim about who
    owns it, and it must not be sayable on control evidence alone. Never a disruption target —
    the answer is remediation, notification, and evidence preservation."""

    ABUSED_LEGITIMATE_SERVICE = "abused_legitimate_service"
    """A real service being used as intended, by someone using it for harm.

    A paste site, a CDN, a link shortener, a code host. Requires ``LEGAL_OWNERSHIP``. The
    service is not the adversary; the account on it may be."""

    SHARED_INFRASTRUCTURE = "shared_infrastructure"
    """Carries unrelated parties alongside the adversary.

    Distinct from :data:`~nemesis.core.entities.SHARED_INFRASTRUCTURE_TYPES`, which is a
    property of an entity *type* and therefore cannot tell a two-tenant host from a
    forty-thousand-tenant one. This is a property of the instance, with evidence behind it."""

    VICTIM_INFRASTRUCTURE = "victim_infrastructure"
    """A target of the attack rather than a means of it. Requires ``LEGAL_OWNERSHIP``."""


class ControlFacet(StrEnum):
    """The four independent questions. Answering one answers none of the others."""

    LEGAL_OWNERSHIP = "legal_ownership"
    CURRENT_CONTROL = "current_control"
    OBSERVED_USE = "observed_use"
    ATTRIBUTED_RESPONSIBILITY = "attributed_responsibility"


FACET_CONFIDENCE_FLOOR: Final = 0.55
"""Below this projected probability a facet is too thin to act on.

Deliberately the same value, and the same argument, as
:data:`nemesis.disrupt.options.OWNERSHIP_CONFIDENCE_FLOOR`: acting against a target that is not
the adversary's is the one error that is not recoverable, so "likely" is not good enough. Kept
as a separate constant rather than imported because ``core`` may not import ``disrupt``; the
duplication is the import contract's price and is asserted equal by a test.
"""


ACTOR_HELD_ROLES: Final[frozenset[InfrastructureRole]] = frozenset(
    {InfrastructureRole.ACTOR_OWNED, InfrastructureRole.ACTOR_CONTROLLED}
)
"""The only roles that make a node the adversary's to take away."""


class FacetAssessment(BaseModel):
    """One of the four questions, answered with evidence and scored.

    The shape is :class:`~nemesis.disrupt.options.OwnershipEvidence` generalised and moved
    where the enforcement point can reach it: an :class:`Opinion` rather than a float, the
    number of *independent origins* counted separately from the confidence, and a named basis
    a reviewer can attack. Confidence and corroboration are two different questions, and one
    confident source and three corroborating ones can project the same probability — only the
    second is safe to act on.
    """

    model_config = ConfigDict(frozen=True)

    facet: ControlFacet
    holder: str = ""
    """Natural key of whoever holds this facet — the owner, the controller, the user. Empty
    when the facet is established but the holder is not: "somebody other than the registrant
    controls this" is a real and useful finding."""

    opinion: Opinion
    independent_source_count: Annotated[int, Field(ge=0)]
    """Distinct origins after resolving resellers and mirrors — the fusion sense of the word,
    not the feed count."""

    basis: Annotated[str, Field(min_length=1)]
    """What establishes it: a registrant record, a shared unique key, an observed session.
    Named so a reviewer can attack it rather than a score they can only accept."""

    supporting_claims: tuple[ClaimId, ...] = ()
    extent: TemporalExtent
    """When this held. Control is temporary and ownership usually is not, which is exactly the
    kind of difference a single undated field would hide."""

    @classmethod
    def from_claims(
        cls,
        *,
        facet: ControlFacet,
        holder: str,
        opinion: Opinion,
        independent_source_count: int,
        basis: str,
        claims: Sequence[Claim],
        extent: TemporalExtent,
    ) -> FacetAssessment:
        """Build a facet from claims, refusing any that a model authored.

        Invariant 1 applied to the surface that decides whether an effect may run. A pilot can
        already state a belief — the mediator stores it as a ``HYPOTHESIS`` derived from
        ``MODEL_ASSERTION``, attributed to the model, unable to outrank what it cites. Nothing
        stopped that claim being handed to an ownership facet, where it would have become the
        basis of a takedown against a target a model decided was the adversary's.

        Refuses on *any* model-derived claim rather than discounting the set, because the
        failure is categorical: an assertion about who owns a server is exactly the kind of
        thing a model produces fluently and cannot know. The tainted input must not be
        laundered by the company it keeps.

        The ``supporting_claims`` field remains assignable directly for callers reconstructing
        a stored assessment; this is the constructor for *deriving* one, and it is the one
        producers are expected to use.
        """
        model_derived = [claim.claim_id for claim in claims if claim.is_model_derived]
        if model_derived:
            raise ValueError(
                f"claim(s) {', '.join(sorted(model_derived))} are model-derived and cannot "
                f"establish {facet.value}: a model assertion is a hypothesis about the world, "
                "never a record of it (invariant 1). Whoever actually checked who owns this "
                "records it outside the model"
            )
        return cls(
            facet=facet,
            holder=holder,
            opinion=opinion,
            independent_source_count=independent_source_count,
            basis=basis,
            supporting_claims=tuple(claim.claim_id for claim in claims),
            extent=extent,
        )

    @property
    def is_single_sourced(self) -> bool:
        return self.independent_source_count <= 1

    @property
    def band(self) -> ConfidenceBand:
        return band_of(self.opinion)

    @property
    def is_weak(self) -> bool:
        """Too thin to act on. A disjunction of safeguards, not an averaged score."""
        return (
            self.is_single_sourced
            or self.band is ConfidenceBand.INSUFFICIENT_BASIS
            or self.opinion.projected_probability < FACET_CONFIDENCE_FLOOR
        )

    def describe(self) -> str:
        reasons: list[str] = []
        if self.is_single_sourced:
            reasons.append(f"single-sourced ({self.independent_source_count} independent origin)")
        if self.band is ConfidenceBand.INSUFFICIENT_BASIS:
            reasons.append("insufficient basis to estimate")
        elif self.opinion.projected_probability < FACET_CONFIDENCE_FLOOR:
            reasons.append(
                f"below the floor ({self.opinion.projected_probability:.0%} < "
                f"{FACET_CONFIDENCE_FLOOR:.0%})"
            )
        detail = "; ".join(reasons) if reasons else describe(self.opinion)
        holder = self.holder or "an unidentified party"
        return f"{self.facet.value}: {holder} — {self.basis} — {detail}"


REQUIRED_FACETS: Final[Mapping[InfrastructureRole, frozenset[ControlFacet]]] = {
    InfrastructureRole.UNKNOWN: frozenset(),
    InfrastructureRole.ACTOR_OWNED: frozenset({ControlFacet.LEGAL_OWNERSHIP}),
    InfrastructureRole.ACTOR_CONTROLLED: frozenset({ControlFacet.CURRENT_CONTROL}),
    InfrastructureRole.COMPROMISED_LEGITIMATE: frozenset(
        {ControlFacet.LEGAL_OWNERSHIP, ControlFacet.CURRENT_CONTROL}
    ),
    InfrastructureRole.ABUSED_LEGITIMATE_SERVICE: frozenset({ControlFacet.LEGAL_OWNERSHIP}),
    InfrastructureRole.SHARED_INFRASTRUCTURE: frozenset(),
    InfrastructureRole.VICTIM_INFRASTRUCTURE: frozenset({ControlFacet.LEGAL_OWNERSHIP}),
}
"""Which facets a role may not be asserted without.

This table is the mission's ``MALICIOUS_USE != ATTACKER_OWNED`` written as a construction rule.
``OBSERVED_USE`` appears in no row on purpose: no amount of observed malicious use, however
confident, is on its own sufficient to classify a node as the adversary's.
"""


class RoleAssessment(BaseModel):
    """What a node is, why we think so, and how sure we are.

    Frozen: an assessment is a judgement made at a point in time against the evidence then
    available. Re-assessing produces a new one rather than editing the old, so a capability
    approved against a classification can be shown to have been approved against *that*
    classification.
    """

    model_config = ConfigDict(frozen=True)

    entity_id: EntityId
    natural_key: Annotated[str, Field(min_length=1)]
    role: InfrastructureRole
    opinion: Opinion
    """Confidence in the *role*, distinct from confidence in any one facet. A node can have
    strong ownership evidence and still be hard to classify."""

    facets: tuple[FacetAssessment, ...] = ()
    assessed_at: datetime
    reasoning: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _enforce_classification_rules(self) -> Self:
        require_utc(self.assessed_at, "assessed_at")

        seen: set[ControlFacet] = set()
        for item in self.facets:
            if item.facet in seen:
                raise ValueError(
                    f"{item.facet.value} is asserted more than once; each of the four "
                    "questions is answered exactly once or not at all"
                )
            seen.add(item.facet)

        if self.role is InfrastructureRole.UNKNOWN:
            return self

        # The bar is asymmetric, and deliberately so: a role that *permits* an effect must be
        # supported, and a role that *forbids* one need not be. Over-applying
        # SHARED_INFRASTRUCTURE costs a refusal; under-applying it costs a third party their
        # server. SHARED_INFRASTRUCTURE in particular is established by the node's type rather
        # than by any facet, and manufacturing a synthetic facet to satisfy a uniform rule would
        # be inventing an ownership finding nobody made — the exact sin this module exists to
        # prevent, committed to satisfy a validator.
        if self.role in ACTOR_HELD_ROLES:
            if not self.facets:
                raise ValueError(
                    f"role {self.role.value} rests on at least one facet; a classification "
                    "supported by nothing is a guess wearing a label"
                )
            if self.opinion.is_vacuous:
                raise ValueError(
                    f"role {self.role.value} cannot rest on a vacuous opinion: nobody having "
                    "looked is not a classification, however confident the label sounds"
                )
        missing = sorted(f.value for f in REQUIRED_FACETS[self.role] - seen)
        if missing:
            raise ValueError(
                f"role {self.role.value} requires {', '.join(missing)}; observing what a node "
                "was used for establishes neither who owns it nor who controls it "
                "(MALICIOUS_USE != ATTACKER_OWNED)"
            )
        return self

    # -- derived --------------------------------------------------------------

    @property
    def is_established(self) -> bool:
        """Whether anybody has actually classified this node."""
        return self.role is not InfrastructureRole.UNKNOWN

    def facet_for(self, which: ControlFacet) -> FacetAssessment | None:
        return next((item for item in self.facets if item.facet is which), None)

    def owner(self) -> str | None:
        found = self.facet_for(ControlFacet.LEGAL_OWNERSHIP)
        return found.holder if found and found.holder else None

    def controller(self) -> str | None:
        found = self.facet_for(ControlFacet.CURRENT_CONTROL)
        return found.holder if found and found.holder else None

    @property
    def has_weak_facet(self) -> bool:
        """Whether any facet this role rests on is too thin to act on."""
        required = REQUIRED_FACETS[self.role]
        return any(item.is_weak for item in self.facets if item.facet in required)

    @staticmethod
    def projected_role(role: InfrastructureRole) -> str:
        """The role as it appears in an entity attribute and a bound capability."""
        return role.value

    def render(self) -> str:
        lines = [f"{self.natural_key}: {self.role.value} — {describe(self.opinion)}"]
        lines.extend(f"  {item.describe()}" for item in self.facets)
        lines.extend(f"  ! {reason}" for reason in self.reasoning)
        return "\n".join(lines)


ROLE_ATTRIBUTE: Final = "infrastructure_role"
"""The entity attribute the role projects onto, and the bound-capability key.

A narrow, deterministic, lossy projection of the assessment. The assessment — with its
opinions and its cited claims — is the canonical state; this is the index that exists so the
enforcement point, which sees only ``dict[str, str]``, can see the answer at all.
"""


def role_attributes(assessment: RoleAssessment) -> dict[str, str]:
    """Project an assessment onto the entity attributes the effects boundary can observe.

    ``UNKNOWN`` projects to a *present* attribute reading ``"unknown"`` rather than to no
    attribute, because those are different facts and the boundary treats them differently: an
    absent attribute means nobody looked and is refused as unobserved; ``unknown`` means
    somebody looked and could not tell.
    """
    return {ROLE_ATTRIBUTE: RoleAssessment.projected_role(assessment.role)}


# -- the eligibility table --------------------------------------------------------

OBSERVE_AND_PRESERVE_OPERATIONS: Final[frozenset[OperationClass]] = frozenset(
    {OperationClass.SIMULATION, OperationClass.EVIDENCE_EXPORT}
)
"""Operations that touch nobody and may run against any target, including an unclassified one.

§6 puts evidence preservation before everything else for a reason: failing closed here would
destroy the record while we worked out whose host it is. Neither of these can harm the target
or a third party — one is a rehearsal, the other writes a bundle into our own vault.
"""

THIRD_PARTY_ENGAGEMENT_OPERATIONS: Final[frozenset[OperationClass]] = frozenset(
    {
        OperationClass.PROVIDER_NOTIFICATION,
        OperationClass.EXCHANGE_NOTIFICATION,
        OperationClass.LAW_ENFORCEMENT_REFERRAL,
        OperationClass.JUDICIAL_SEIZURE_PACKAGE,
    }
)
"""Operations that tell somebody something. Permitted against any *established* role.

Telling a hosting provider that one of their customers has been compromised is the correct
response to ``COMPROMISED_LEGITIMATE`` — it is the §6 answer, not a disruption. What is refused
is engaging a third party about a target nobody has classified: a notification naming a host we
cannot characterise is a statement we cannot stand behind.
"""

DISRUPTIVE_OPERATIONS: Final[frozenset[OperationClass]] = frozenset(
    {
        OperationClass.TAKEDOWN_REQUEST_DRAFT,
        OperationClass.REGISTRAR_SUSPENSION,
        OperationClass.HOSTING_TERMINATION,
        OperationClass.ACCOUNT_SUSPENSION,
        OperationClass.ASSET_FREEZE_REQUEST,
        OperationClass.DOMAIN_SEIZURE,
        OperationClass.SINKHOLE,
    }
)
"""Operations that take something away. Permitted only where the adversary owns or controls it.

``ACCOUNT_SUSPENSION`` belongs here rather than with third-party engagement because the target
of the operation is the adversary's *account*, which is actor-controlled, even when the service
hosting it is a legitimate one.
"""


def _check_every_operation_is_tiered() -> None:
    """Import-time totality check, in the house style of ``authorization._check_risk_table``.

    A new ``OperationClass`` member must be placed in a tier deliberately. Without this, a new
    member would fall through :func:`eligible_roles` to the safe default and be silently
    unusable — which is fail-closed, but silently, and a control nobody can satisfy stops
    protecting anything the day somebody removes it to make a demo work.
    """
    tiers = (
        OBSERVE_AND_PRESERVE_OPERATIONS,
        THIRD_PARTY_ENGAGEMENT_OPERATIONS,
        DISRUPTIVE_OPERATIONS,
    )
    union: set[OperationClass] = set()
    for tier in tiers:
        overlap = union & tier
        if overlap:
            raise RuntimeError(
                f"operation class(es) {sorted(o.value for o in overlap)} appear in two "
                "eligibility tiers"
            )
        union |= tier
    unplaced = set(OperationClass) - union
    if unplaced:
        raise RuntimeError(
            f"operation class(es) {sorted(o.value for o in unplaced)} are in no eligibility "
            "tier; place them deliberately in nemesis.core.infrastructure"
        )


_check_every_operation_is_tiered()


ESTABLISHED_ROLES: Final[frozenset[InfrastructureRole]] = frozenset(
    role for role in InfrastructureRole if role is not InfrastructureRole.UNKNOWN
)


def eligible_roles(operation: OperationClass) -> frozenset[InfrastructureRole]:
    """Which target roles this operation class may ever run against.

    Fails closed on an unrecognised operation: the empty set, not everything.
    """
    if operation in OBSERVE_AND_PRESERVE_OPERATIONS:
        return frozenset(InfrastructureRole)
    if operation in THIRD_PARTY_ENGAGEMENT_OPERATIONS:
        return ESTABLISHED_ROLES
    if operation in DISRUPTIVE_OPERATIONS:
        return ACTOR_HELD_ROLES
    return frozenset()


def is_role_eligible(operation: OperationClass, role: InfrastructureRole) -> bool:
    """Whether this operation class may run against a target in this role.

    The deterministic half of the §5 gate — the half that can run at the enforcement boundary,
    where the only thing available is a role string carried inside a signature. The other half,
    which weighs facet strength, collateral and authority, runs at approval time where that
    knowledge exists; the approver's signature over the bound role is the attestation that it
    ran.
    """
    return role in eligible_roles(operation)


__all__ = [
    "ACTOR_HELD_ROLES",
    "DISRUPTIVE_OPERATIONS",
    "ESTABLISHED_ROLES",
    "FACET_CONFIDENCE_FLOOR",
    "OBSERVE_AND_PRESERVE_OPERATIONS",
    "REQUIRED_FACETS",
    "ROLE_ATTRIBUTE",
    "THIRD_PARTY_ENGAGEMENT_OPERATIONS",
    "ControlFacet",
    "FacetAssessment",
    "InfrastructureRole",
    "RoleAssessment",
    "eligible_roles",
    "is_role_eligible",
    "role_attributes",
]


# -- deriving a standing from what the graph holds --------------------------------

OWNERSHIP_PREDICATE: Final = "legally_owned_by"
"""The claim predicate that asserts legal ownership of a node.

A **claim predicate and deliberately not a** :class:`~nemesis.core.relationships.RelationType`.
An ownership edge would be traversable, and therefore citable as the premise of a pivot — the
same argument that keeps attribution off the graph (``ClaimKind.ATTRIBUTION`` sits at epistemic
strength 1 so nothing stronger derives from it). Ownership is a statement about the world made
by somebody who looked at a register; it is not a path between two nodes to be walked.

Nothing collects it today. The project's own RDAP fixture returns
``entities.registrant: "REDACTED FOR PRIVACY"``, which is what a real GDPR-era lookup returns,
so this predicate is expected to arrive from an analyst submission or an authoritative record —
:data:`ADMISSIBLE_OWNERSHIP_DERIVATIONS` is what it must carry to count.
"""

ADMISSIBLE_OWNERSHIP_DERIVATIONS: Final[frozenset[DerivationKind]] = frozenset(
    {
        DerivationKind.AUTHORITATIVE_RECORD,
        DerivationKind.HUMAN_ANALYST,
        DerivationKind.DIRECT_COLLECTION,
    }
)
"""What an ownership claim must be derived from to move a node's standing.

Excludes ``MODEL_ASSERTION`` and ``STATISTICAL_MODEL`` (invariant 1), and excludes
``EXTERNAL_REPORT``: a vendor blog saying whose a server is, is an assertion about a register
its author did not read either.

Note which way this cuts. Refusing a model's guess about an owner leaves the node
``ACTOR_CONTROLLED`` rather than ``COMPROMISED_LEGITIMATE`` — the *more* permissive outcome. The
rule is not the platform protecting itself; it is the platform declining to launder a guess
into a fact in either direction.
"""

ADVERSARY_ENTITY_TYPES: Final[frozenset[EntityType]] = frozenset(
    {EntityType.THREAT_ACTOR, EntityType.PERSONA, EntityType.ALIAS}
)
"""Node types that mean *the adversary* rather than merely *a party*.

``EntityCategory.ACTOR`` cannot do this job: it contains ``ORGANIZATION`` alongside
``THREAT_ACTOR``, so a company controlling its own web server would read as adversary control.
The distinction is the difference between a finding and a normal Tuesday.
"""

CONTROL_RELATIONS: Final[frozenset[RelationType]] = frozenset(
    {RelationType.CONTROLS, RelationType.OPERATED_BY}
)
"""Edges that assert who operates a node. Both are in ``IDENTITY_ASSERTING_RELATIONS``, so
neither can be constructed without citing supporting claims."""

USE_RELATIONS: Final[frozenset[RelationType]] = frozenset(
    {
        RelationType.COMMUNICATES_WITH,
        RelationType.COMMANDS,
        RelationType.DELIVERED_BY,
        RelationType.REDIRECTS_TO,
        RelationType.TARGETED,
    }
)
"""Edges that record what a node was seen doing. Establish ``OBSERVED_USE`` and nothing else."""


def _widen(left: TemporalExtent, right: TemporalExtent) -> TemporalExtent:
    """The union of two observation windows, as a core-local helper.

    ``nemesis.graph.memory.widen_extent`` does this already, and ``core`` may not import
    ``graph``. Duplicating four lines is the import contract's price; the alternative is a core
    module reaching up into a plane above it, which is the thing the contract exists to stop.
    """
    return TemporalExtent(
        known_from=min(left.known_from, right.known_from),
        known_until=max(left.known_until, right.known_until),
    )


def _independent_origins(claim_ids: Sequence[str], claims: Sequence[Claim]) -> int:
    """Distinct asserters behind a set of claims.

    An honest ceiling rather than a measurement, and the difference matters. The fusion sense
    of independence is the *provenance cluster*
    (:meth:`~nemesis.core.provenance.SourceDescriptor.provenance_cluster`), which lives on the
    evidence a claim cites, not on the claim — and this function is pure and holds no vault. Two
    feeds that both copied one blog have two asserters and one origin, so this over-states
    independence in exactly the case invariant-16 machinery exists to catch.

    It is used only to populate ``independent_source_count``, which a human approver reads
    through :meth:`FacetAssessment.describe`. The standing *gate* does not consult it — an
    over-count therefore cannot widen what an effect may do, only what a reviewer is told, and
    the basis string says what was counted so they can discount it.
    """
    wanted = set(claim_ids)
    return len({claim.asserted_by for claim in claims if claim.claim_id in wanted})


def _facet_from_edges(
    facet: ControlFacet,
    edges: Sequence[Relationship],
    claims: Sequence[Claim],
    *,
    holder: str,
    what: str,
) -> FacetAssessment | None:
    if not edges:
        return None
    strongest = max(edges, key=lambda e: e.confidence.projected_probability)
    cited = tuple(dict.fromkeys(cid for edge in edges for cid in edge.supporting_claims))
    origins = _independent_origins(cited, claims)
    extent = edges[0].extent
    for edge in edges[1:]:
        extent = _widen(extent, edge.extent)
    return FacetAssessment(
        facet=facet,
        holder=holder,
        opinion=strongest.confidence,
        independent_source_count=origins,
        basis=f"{what} ({len(edges)} edge(s), {origins} distinct asserter(s))",
        supporting_claims=tuple(cited),
        extent=extent,
    )


def _other_end(edge: Relationship, entity_id: str) -> tuple[str, EntityType] | None:
    if edge.source_id == entity_id:
        return edge.target_id, edge.target_type
    if edge.target_id == entity_id:
        return edge.source_id, edge.source_type
    return None


def derive_standing(
    entity: Entity,
    *,
    relationships: Sequence[Relationship],
    claims: Sequence[Claim],
    assessed_at: datetime,
) -> RoleAssessment:
    """Work out whose a node is from the edges and claims that touch it.

    Deterministic and total: every input produces an assessment, and ``UNKNOWN`` is what most
    inputs produce. That is the intended shape. Observed use — traffic to a C2, a redirect
    chain, delivery of a payload — populates ``OBSERVED_USE`` and moves the role not at all,
    because it is the node being *used* and says nothing about whose it is.

    The rules, in order, and each one is a refusal before it is a classification:

    1. A node whose *type* is shared by unrelated parties is ``SHARED_INFRASTRUCTURE``, and this
       outranks everything below. Adversary traffic through a registrar is not a reason to act
       against the registrar. (Type-level and therefore crude: it cannot tell a two-tenant host
       from a forty-thousand-tenant one, and it does not catch a shared IP or CDN domain at all,
       which :class:`~nemesis.core.relationships.PivotSelectivity` handles instead.)
    2. A ``VICTIM`` node is ``VICTIM_INFRASTRUCTURE``.
    3. An admissible owner who is the adversary, plus adversary control, is ``ACTOR_OWNED``.
    4. An admissible owner who is *not* the adversary, plus adversary control, is
       ``COMPROMISED_LEGITIMATE`` — the §6 case, and the one that cannot be reached from
       collection alone because registrant data is redacted.
    5. An admissible non-adversary owner with adversary *use* but no adversary control is
       ``ABUSED_LEGITIMATE_SERVICE``.
    6. Adversary control with no established owner is ``ACTOR_CONTROLLED`` — the honest answer
       for most adversary infrastructure, which is rented rather than owned.
    7. Everything else is ``UNKNOWN``.

    Control asserted by an ``ORGANIZATION`` moves nothing: a company operating its own server is
    not a finding, and ``EntityCategory.ACTOR`` cannot make that distinction because it holds
    both. See :data:`ADVERSARY_ENTITY_TYPES`.
    """
    control_edges: list[Relationship] = []
    use_edges: list[Relationship] = []
    controller: str | None = None
    controller_is_adversary = False

    for edge in relationships:
        end = _other_end(edge, entity.entity_id)
        if end is None:
            continue
        other_id, other_type = end
        if edge.relation in CONTROL_RELATIONS and other_type in ADVERSARY_ENTITY_TYPES:
            control_edges.append(edge)
            controller = f"{other_type.value}:{other_id}"
            controller_is_adversary = True
        elif edge.relation in USE_RELATIONS:
            use_edges.append(edge)

    owner: str | None = None
    owner_claims: list[Claim] = []
    subject = f"{entity.entity_type.value}:{entity.natural_key}"
    for claim in claims:
        if claim.statement.predicate != OWNERSHIP_PREDICATE:
            continue
        if claim.statement.subject != subject:
            continue
        if claim.derivation not in ADMISSIBLE_OWNERSHIP_DERIVATIONS:
            continue
        owner = claim.statement.obj
        owner_claims.append(claim)

    facets: list[FacetAssessment] = []
    if owner is None and entity.entity_type is EntityType.VICTIM:
        # The node *is* the harmed party, so the type itself answers the ownership question and
        # no separate claim is needed. Synthesised rather than left absent because the
        # alternative is UNKNOWN, and UNKNOWN blocks third-party engagement — the platform would
        # identify a victim and then be unable to notify anyone about them, which is the harm
        # this classification exists to prevent rather than a cautious version of preventing it.
        owner = f"{entity.entity_type.value}:{entity.natural_key}"
        facets.append(
            FacetAssessment(
                facet=ControlFacet.LEGAL_OWNERSHIP,
                holder=owner,
                opinion=Opinion(belief=0.9, disbelief=0.0, uncertainty=0.1),
                independent_source_count=2,
                basis="the node is itself a victim entity; its type is the ownership answer",
                extent=entity.extent,
            )
        )
    elif owner is not None and owner_claims:
        facets.append(
            FacetAssessment(
                facet=ControlFacet.LEGAL_OWNERSHIP,
                holder=owner,
                # An admissible ownership claim is a record, not an inference: belief is high
                # and the residual uncertainty is that registers go stale, not that the reader
                # might have misread one.
                opinion=Opinion(belief=0.85, disbelief=0.0, uncertainty=0.15),
                independent_source_count=_independent_origins(
                    tuple(c.claim_id for c in owner_claims), owner_claims
                ),
                basis=(
                    f"{len(owner_claims)} admissible ownership claim(s) "
                    f"({len({c.asserted_by for c in owner_claims})} distinct asserter(s))"
                ),
                supporting_claims=tuple(c.claim_id for c in owner_claims),
                extent=entity.extent,
            )
        )
    control = _facet_from_edges(
        ControlFacet.CURRENT_CONTROL,
        control_edges,
        claims,
        holder=controller or "",
        what="adversary control asserted by a claim-citing edge",
    )
    if control is not None:
        facets.append(control)
    use = _facet_from_edges(
        ControlFacet.OBSERVED_USE,
        use_edges,
        claims,
        holder="",
        what="observed operational use, which establishes nothing about whose this is",
    )
    if use is not None:
        facets.append(use)

    owner_is_adversary = owner is not None and owner.split(":", 1)[0] in {
        t.value for t in ADVERSARY_ENTITY_TYPES
    }

    role = InfrastructureRole.UNKNOWN
    reasoning: list[str] = []
    if entity.is_shared_infrastructure:
        role = InfrastructureRole.SHARED_INFRASTRUCTURE
        reasoning.append(
            f"{entity.entity_type.value} is shared by unrelated parties by default; use of it "
            "by the adversary is not a reason to act against it"
        )
    elif entity.entity_type is EntityType.VICTIM:
        role = InfrastructureRole.VICTIM_INFRASTRUCTURE
    elif owner is not None and controller_is_adversary and owner_is_adversary:
        role = InfrastructureRole.ACTOR_OWNED
    elif owner is not None and controller_is_adversary:
        role = InfrastructureRole.COMPROMISED_LEGITIMATE
        reasoning.append(
            f"the adversary operates it, {owner} owns it; the answer is remediation and "
            "notification, never a takedown"
        )
    elif owner is not None and use_edges and not owner_is_adversary:
        role = InfrastructureRole.ABUSED_LEGITIMATE_SERVICE
    elif controller_is_adversary:
        role = InfrastructureRole.ACTOR_CONTROLLED
        reasoning.append(
            "control is established and ownership is not; registrant data is routinely "
            "redacted, so this is the strongest honest classification"
        )
    else:
        reasoning.append(
            "nothing establishes who owns or controls this node; observed use is not evidence "
            "of either"
        )

    # A role other than UNKNOWN needs a non-vacuous opinion and its required facets. Where the
    # evidence does not reach that bar the honest output is UNKNOWN rather than a weak
    # classification, because a weak classification is what the gate would act on.
    required = REQUIRED_FACETS[role]
    present = {item.facet for item in facets}
    if role is not InfrastructureRole.UNKNOWN and not required <= present:
        reasoning.append(
            f"downgraded to unknown: {role.value} requires "
            f"{', '.join(sorted(f.value for f in required - present))}"
        )
        role = InfrastructureRole.UNKNOWN

    if role is InfrastructureRole.UNKNOWN:
        opinion = Opinion.vacuous()
    else:
        opinion = max(
            (item.opinion for item in facets if item.facet in required),
            key=lambda o: o.projected_probability,
            default=Opinion(belief=0.6, disbelief=0.1, uncertainty=0.3),
        )

    return RoleAssessment(
        entity_id=entity.entity_id,
        natural_key=entity.natural_key,
        role=role,
        opinion=opinion,
        facets=tuple(facets),
        assessed_at=assessed_at,
        reasoning=tuple(reasoning),
    )
