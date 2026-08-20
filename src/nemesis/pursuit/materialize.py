"""Turning what a connector said into nodes and edges.

A connector returns claims, not graph structure — deliberately, so that the collection
plane never decides what the graph believes. Materialization is that decision, and it lives
here, on the pursuit side of the boundary.

The convention: a claim's subject and object are written ``<entity_type>:<natural_key>``,
and its predicate names a :class:`RelationType`. Everything needed to judge the resulting
edge — the population the pivot selected from, the corpus it was counted against — travels
in the statement's qualifiers.

The strictness below is the point. A claim whose predicate does not map to a known relation
is skipped and reported, never coerced into ``ASSOCIATED_WITH``. A generic catch-all edge
is worse than a missing one: it looks like a finding, joins the cluster, and nobody can
later say what it was supposed to mean.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from nemesis.core.claims import Claim, ClaimKind
from nemesis.core.confidence import Opinion
from nemesis.core.entities import (
    SHARED_INFRASTRUCTURE_TYPES,
    Entity,
    EntityType,
    NormalizationError,
    normalize_identifier,
)
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.relationships import (
    METHOD_RELIABILITY_CEILING,
    PivotMethod,
    PivotSelectivity,
    Relationship,
    RelationType,
)

QUALIFIER_POPULATION = "population_size"
QUALIFIER_CORPUS = "population_measured_against"
QUALIFIER_ATTRIBUTE = "shared_attribute"
QUALIFIER_UNIQUE = "globally_unique"
QUALIFIER_METHOD = "pivot_method"
QUALIFIER_JUSTIFICATION = "shared_infrastructure_justification"


class MaterializationResult(BaseModel):
    """What could be built from a set of claims, and what could not.

    ``skipped`` is not an error channel. Claims that do not map are expected, and an
    engine that silently discards them would hide a connector drifting away from the
    convention — which is exactly how a graph fills with edges nobody intended.
    """

    model_config = ConfigDict(frozen=True)

    entities: tuple[Entity, ...] = ()
    relationships: tuple[Relationship, ...] = ()
    skipped: tuple[str, ...] = ()


class EntityReference(BaseModel):
    model_config = ConfigDict(frozen=True)

    entity_type: EntityType
    natural_key: str
    observed_form: str


def parse_reference(token: str) -> EntityReference | None:
    """Parse ``<entity_type>:<natural_key>``, or return None if it is not one.

    IPv6 addresses contain colons, so the split is on the *first* colon only, and the
    prefix must be a known entity type. ``2001:db8::1`` therefore does not parse as an
    entity of type ``2001``.
    """
    prefix, separator, remainder = token.partition(":")
    if not separator or not remainder:
        return None
    try:
        entity_type = EntityType(prefix)
    except ValueError:
        return None
    try:
        natural_key = normalize_identifier(entity_type, remainder)
    except NormalizationError:
        return None
    return EntityReference(
        entity_type=entity_type, natural_key=natural_key, observed_form=remainder
    )


def _selectivity_from(claim: Claim) -> PivotSelectivity | None:
    qualifiers = claim.statement.qualifiers
    attribute = qualifiers.get(QUALIFIER_ATTRIBUTE)
    if attribute is None:
        return None

    raw_population = qualifiers.get(QUALIFIER_POPULATION)
    population: int | None = None
    if raw_population is not None:
        try:
            population = int(raw_population)
        except ValueError:
            population = None

    corpus = qualifiers.get(QUALIFIER_CORPUS)
    # A population with no stated corpus cannot be interpreted, so it is discarded rather
    # than kept as a number that looks meaningful. PivotSelectivity refuses it anyway.
    if population is not None and corpus is None:
        population = None

    return PivotSelectivity(
        attribute=attribute,
        population_size=population,
        population_measured_against=corpus if population is not None else None,
        is_globally_unique=qualifiers.get(QUALIFIER_UNIQUE) == "true",
    )


def _confidence_from(
    claim: Claim, selectivity: PivotSelectivity | None, method: PivotMethod
) -> Opinion:
    """Derive an edge's confidence from the pivot AND the technique that found it.

    Two independent limits, and the lesser wins. Selectivity says how many other things
    share the attribute; the method ceiling says how often the technique links things that
    are not related. A multi-input wallet-clustering match on exactly two addresses is
    maximally selective and still a heuristic that mixers defeat.

    An uncounted population yields a vacuous opinion rather than a default, because nobody
    having measured is not the same as the measurement being favourable.
    """
    ceiling = METHOD_RELIABILITY_CEILING[method]

    if selectivity is None:
        supporting = 6.0 if claim.kind in {ClaimKind.OBSERVATION, ClaimKind.FACT} else 1.0
        return Opinion.from_evidence(
            supporting=supporting * ceiling, contradicting=0.0, base_rate=0.1
        )

    weight = min(selectivity.evidential_weight(), ceiling)
    if weight <= 0.0:
        return Opinion.vacuous(base_rate=0.1)
    return Opinion.from_evidence(supporting=weight * 10.0, contradicting=0.0, base_rate=0.1)


def materialize(claims: tuple[Claim, ...], *, is_synthetic: bool) -> MaterializationResult:
    """Build entities and relationships from connector output."""
    entities: dict[tuple[EntityType, str], Entity] = {}
    relationships: list[Relationship] = []
    skipped: list[str] = []

    def entity_for(reference: EntityReference) -> Entity:
        key = (reference.entity_type, reference.natural_key)
        if key not in entities:
            entities[key] = Entity.create(
                entity_id=new_id(IdPrefix.ENTITY),
                entity_type=reference.entity_type,
                observed_form=reference.observed_form,
                extent=claim.valid_extent,
                is_synthetic=is_synthetic,
            )
        return entities[key]

    for claim in claims:
        source = parse_reference(claim.statement.subject)
        target = parse_reference(claim.statement.obj)
        if source is None or target is None:
            skipped.append(
                f"{claim.claim_id}: subject or object is not '<entity_type>:<key>' "
                f"({claim.statement.subject!r} -> {claim.statement.obj!r})"
            )
            continue

        try:
            relation = RelationType(claim.statement.predicate)
        except ValueError:
            skipped.append(
                f"{claim.claim_id}: predicate {claim.statement.predicate!r} is not a known "
                "relation; not coerced into a generic edge"
            )
            continue

        source_entity = entity_for(source)
        target_entity = entity_for(target)
        if source_entity.entity_id == target_entity.entity_id:
            skipped.append(f"{claim.claim_id}: subject and object are the same entity")
            continue

        try:
            selectivity = _selectivity_from(claim)
        except ValueError as exc:
            # Qualifiers arrive from the collection plane, where content is hostile by
            # default (invariant 5). A contradictory set — "globally unique" alongside a
            # population of forty thousand — must cost one claim, not the whole pivot:
            # letting it propagate would discard every other claim in the same batch and
            # abort the investigation step that collected them.
            skipped.append(f"{claim.claim_id}: selectivity qualifiers are not coherent: {exc}")
            continue

        raw_method = claim.statement.qualifiers.get(QUALIFIER_METHOD)
        try:
            method = (
                PivotMethod(raw_method)
                if raw_method
                else (
                    PivotMethod.DIRECT_OBSERVATION
                    if selectivity is None
                    else PivotMethod.SHARED_ATTRIBUTE
                )
            )
        except ValueError:
            method = PivotMethod.SHARED_ATTRIBUTE

        # PivotSelectivity is meaningless for a directly observed relationship, and the
        # Relationship model rejects the combination.
        if method is PivotMethod.DIRECT_OBSERVATION:
            selectivity = None

        justification = claim.statement.qualifiers.get(QUALIFIER_JUSTIFICATION)
        pivots_through_shared = (
            source.entity_type in SHARED_INFRASTRUCTURE_TYPES
            or target.entity_type in SHARED_INFRASTRUCTURE_TYPES
        )
        if (
            pivots_through_shared
            and method in {PivotMethod.SHARED_ATTRIBUTE, PivotMethod.INFRASTRUCTURE_REUSE}
            and not justification
        ):
            justification = (
                "No justification supplied by the connector. This pivot crosses an entity "
                "type shared by unrelated parties and carries no weight on its own."
            )

        try:
            relationships.append(
                Relationship(
                    edge_id=new_id(IdPrefix.EDGE),
                    source_id=source_entity.entity_id,
                    target_id=target_entity.entity_id,
                    source_type=source.entity_type,
                    target_type=target.entity_type,
                    relation=relation,
                    extent=claim.valid_extent,
                    confidence=_confidence_from(claim, selectivity, method),
                    pivot_method=method,
                    selectivity=selectivity,
                    supporting_claims=(claim.claim_id,),
                    shared_infrastructure_justification=justification,
                    is_synthetic=is_synthetic,
                )
            )
        except ValueError as exc:
            # The edge violated a construction rule — an identity assertion with no
            # supporting claims, say. Surfaced, never quietly dropped.
            skipped.append(f"{claim.claim_id}: rejected by Relationship: {exc}")

    return MaterializationResult(
        entities=tuple(entities.values()),
        relationships=tuple(relationships),
        skipped=tuple(skipped),
    )
