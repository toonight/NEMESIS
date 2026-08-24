"""Writing a node's standing onto the graph, so the effects boundary can see it.

The gate in :mod:`nemesis.effects.registry` reads a classification out of
``TargetFingerprint.bound_attributes`` and compares it against what the mediator observed on the
entity. Until this module existed nothing wrote that attribute — and in fact **nothing wrote any
entity attribute at all**: both production callers of ``Entity.create``
(``pursuit/engine.py``, ``pursuit/materialize.py``) build entities with none, and no API or CLI
route mutates them. So every attribute-based control depended on whoever happened to seed the
graph, which in practice meant a demo fixture.

This is the smallest thing that closes that: after a pivot lands new claims and edges, reassess
the nodes it touched and record the answer.

**What is recorded is a projection, not the assessment.** The :class:`RoleAssessment` — with its
four facets, their opinions and their cited claims — is what a human reads and what a reviewer
attacks. The entity attribute is one lowercase string, written so that a boundary holding only
``dict[str, str]`` can act on it. Losing the reasoning on the way to the enforcement point is
the price of the enforcement point not being allowed to reason.

**Re-assessment is safe by construction, and the reason is worth stating.**
``merge_attributes`` makes the incoming value current and displaces the previous one to
``infrastructure_role@prior1``, so the gate always reads the latest answer while the history
stays recoverable. A capability that was signed against the old classification stops matching
its target fingerprint the moment the answer changes — nobody has to remember to revoke it. That
is the whole argument for binding the role into the signature rather than checking it at
approval and hoping it stays true.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from nemesis.core.claims import Claim
from nemesis.core.entities import Entity
from nemesis.core.infrastructure import (
    ROLE_ATTRIBUTE,
    InfrastructureRole,
    RoleAssessment,
    derive_standing,
    role_attributes,
)
from nemesis.ports.storage import GraphQuery, GraphStore


async def assess_entity_standing(
    graph: GraphStore,
    entity: Entity,
    *,
    claims: Sequence[Claim],
    assessed_at: datetime,
) -> RoleAssessment:
    """Derive one node's standing from its immediate neighbourhood and the claims in hand.

    Depth 1 on purpose. Whose a node is, is answered by the edges that touch it — who controls
    it, what it was seen doing — and not by what sits two hops away. Widening the window would
    let a distant adversary association drag an uninvolved node's classification toward
    "theirs", which is the failure this whole subsystem exists to prevent, arriving by the back
    door of a graph traversal.
    """
    subgraph = await graph.neighbourhood(GraphQuery(entity_id=entity.entity_id, max_depth=1))
    return derive_standing(
        entity,
        relationships=subgraph.relationships,
        claims=claims,
        assessed_at=assessed_at,
    )


async def record_standing(graph: GraphStore, assessment: RoleAssessment) -> Entity | None:
    """Write the projected role onto the entity. Returns the stored node, or None if it is gone.

    Writes ``UNKNOWN`` as explicitly as any other answer. An absent attribute and an attribute
    reading ``unknown`` are different facts and the boundary treats them differently: absent
    means nobody looked and is refused as unobserved, ``unknown`` means somebody looked and
    could not tell. Skipping the write for UNKNOWN would collapse the two and turn "we
    assessed this and could not classify it" into "nobody has been here".
    """
    current = await graph.get_entity(assessment.entity_id)
    if current is None:
        return None
    return await graph.upsert_entity(
        current.model_copy(
            update={"attributes": dict(current.attributes) | role_attributes(assessment)}
        )
    )


async def reassess_standing(
    graph: GraphStore,
    entity_ids: Sequence[str],
    *,
    claims: Sequence[Claim],
    assessed_at: datetime,
) -> dict[str, InfrastructureRole]:
    """Reassess and record every node a pivot touched. Returns what each was classified as.

    Ordinary control flow, not best-effort: a node that cannot be read is skipped and reported
    by omission rather than being silently recorded as unclassified. The caller records the
    tally in the audit trail, so a run where classification stopped happening is visible as a
    changed count rather than as nothing at all.
    """
    results: dict[str, InfrastructureRole] = {}
    for entity_id in dict.fromkeys(entity_ids):
        entity = await graph.get_entity(entity_id)
        if entity is None:
            continue
        assessment = await assess_entity_standing(
            graph, entity, claims=claims, assessed_at=assessed_at
        )
        await record_standing(graph, assessment)
        results[entity_id] = assessment.role
    return results


__all__ = [
    "ROLE_ATTRIBUTE",
    "assess_entity_standing",
    "reassess_standing",
    "record_standing",
]
