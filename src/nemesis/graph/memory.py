"""In-memory implementations of the graph and claim stores.

`IMPLEMENTED`. No persistence, no I/O, no network. This is the reference implementation
of the storage ports: it is what the invariant tests and the vertical slice run against,
and it is the specification a persistent backend must reproduce.

Four behaviours here are the reason this module is not a dictionary with helper functions:

**Merging, not inserting.** An entity's identity is ``(type, natural_key)``. Writing the
same real-world thing twice must produce one node, because entity duplication turns three
weak links into an apparent cluster and an apparent cluster looks like a finding.

**Widening, not overwriting.** Intelligence arrives out of order. Learning in December
about a domain's March activity has to extend the known extent backwards; overwriting it
would erase the very interval that justified the pivot.

**Refusing to cross shared infrastructure.** A two-hop traversal through a CDN address
reaches most of the internet. The traversal stops at such nodes and *reports* where it
stopped, so an analyst sees a deliberate boundary rather than an unexplained absence.

**Filtering at traversal time, not at the end.** A weak edge two hops behind a strong one
must not be laundered into the result by association: if the engine would not have crossed
it, nothing behind it exists as far as the query is concerned.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from datetime import datetime

from nemesis.core.claims import Claim
from nemesis.core.entities import Entity, EntityType, NormalizationError, normalize_identifier
from nemesis.core.relationships import Explanation, Relationship
from nemesis.core.temporal import RecordVersion, TemporalExtent, utcnow
from nemesis.ports.storage import GraphQuery, Subgraph

ATTRIBUTE_CONFLICT_MARKER = "@prior"
"""Suffix marking an attribute value that a later observation displaced.

A key ``registrar`` whose value changed keeps the newest value under ``registrar`` and the
displaced ones under ``registrar@prior1``, ``registrar@prior2``, ... Both are retained
because a *changed* attribute is one of the few signals that an adversary reconfigured
something, and a merge that silently picks a winner destroys it.
"""

_MAX_EXPLAINED_PATHS = 64
"""Cap on simple paths enumerated by :meth:`InMemoryGraphStore.explain_connection`.

Path enumeration is exponential in a dense graph. The cap bounds the work; the caller sees
the shortest paths first, which are the ones an explanation is actually about.
"""


# --------------------------------------------------------------------------------------
# Merge semantics — pure functions, so they can be reasoned about and tested alone.
# --------------------------------------------------------------------------------------


def widen_extent(existing: TemporalExtent, incoming: TemporalExtent) -> TemporalExtent:
    """The narrowest extent consistent with both observations.

    The known window is the union of the two known windows: each side was directly
    observed, so both intervals are defensible and the merge must keep them.

    An unbounded possible bound (``None``) is *wider* than any timestamp, so it absorbs a
    bounded one. Doing it the other way round — taking the bounded value because it is
    "more informative" — manufactures a start or end date that no source established.
    """
    possible_from: datetime | None = None
    if existing.possible_from is not None and incoming.possible_from is not None:
        possible_from = min(existing.possible_from, incoming.possible_from)

    possible_until: datetime | None = None
    if existing.possible_until is not None and incoming.possible_until is not None:
        possible_until = max(existing.possible_until, incoming.possible_until)

    return TemporalExtent(
        known_from=min(existing.known_from, incoming.known_from),
        known_until=max(existing.known_until, incoming.known_until),
        possible_from=possible_from,
        possible_until=possible_until,
    )


def _split_attribute_key(key: str) -> tuple[str, int | None]:
    base, marker, suffix = key.rpartition(ATTRIBUTE_CONFLICT_MARKER)
    if not marker or not base or not suffix.isdigit():
        return key, None
    return base, int(suffix)


def attribute_values(attributes: Mapping[str, str], key: str) -> tuple[str, ...]:
    """Every value ever recorded for ``key``: the current one first, then displaced ones.

    Read attributes through this rather than by direct subscript whenever a conflict would
    change an analytic conclusion. ``attributes[key]`` alone answers "what do we believe
    now", which is a different and weaker question than "what have we seen".
    """
    values: list[str] = []
    if key in attributes:
        values.append(attributes[key])
    displaced: list[tuple[int, str]] = []
    for attribute_key, value in attributes.items():
        base, index = _split_attribute_key(attribute_key)
        if base == key and index is not None:
            displaced.append((index, value))
    values.extend(value for _, value in sorted(displaced))
    return tuple(values)


def _grouped(attributes: Mapping[str, str]) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for attribute_key in attributes:
        base, _ = _split_attribute_key(attribute_key)
        if base not in groups:
            groups[base] = list(attribute_values(attributes, base))
    return groups


def merge_attributes(existing: Mapping[str, str], incoming: Mapping[str, str]) -> dict[str, str]:
    """Union two attribute maps, retaining conflicting values instead of resolving them.

    The incoming value becomes current — the graph holds what we believe now — and every
    distinct value seen before is kept under a ``@priorN`` key. The operation is
    idempotent and its output is bounded by the number of *distinct* values, so a source
    that flaps between two answers does not grow the record without limit.
    """
    left = _grouped(existing)
    right = _grouped(incoming)
    merged: dict[str, str] = {}
    for base in [*left, *(key for key in right if key not in left)]:
        known = left.get(base, [])
        fresh = right.get(base, [])
        union = list(dict.fromkeys([*known, *fresh]))
        if not union:
            continue
        current = fresh[0] if fresh else known[0]
        merged[base] = current
        for index, value in enumerate((v for v in union if v != current), start=1):
            merged[f"{base}{ATTRIBUTE_CONFLICT_MARKER}{index}"] = value
    return merged


def merge_entities(existing: Entity, incoming: Entity) -> Entity:
    """Fold a newly observed entity into the one already held for that natural key.

    The stored ``entity_id`` and ``observed_form`` win: references already recorded against
    them must keep resolving, and the stored observed form is the one the natural key was
    validated against.

    ``is_synthetic`` is a logical OR and can only ever be set. A synthetic node that loses
    the flag because a later connector forgot to set it corrupts every confidence figure
    downstream of it, and nothing in the graph would show that it happened.
    """
    if existing.identity() != incoming.identity():
        raise ValueError(
            f"refusing to merge {incoming.identity()} into {existing.identity()}: "
            "entities with different natural keys are different things"
        )
    return existing.model_copy(
        update={
            "extent": widen_extent(existing.extent, incoming.extent),
            "attributes": merge_attributes(existing.attributes, incoming.attributes),
            "labels": tuple(dict.fromkeys([*existing.labels, *incoming.labels])),
            "display_name": existing.display_name or incoming.display_name,
            "is_synthetic": existing.is_synthetic or incoming.is_synthetic,
        }
    )


def _edge_holds(extent: TemporalExtent, as_of: datetime | None, now: datetime) -> bool:
    """Whether an edge is in scope for a query instant.

    With ``as_of`` set the test is the *known* window: reconstructing March means returning
    what was demonstrably true in March, not everything March cannot rule out. With
    ``as_of`` unset the question is "what plausibly holds now", which is the possible
    window — an open-ended relationship has not been observed to end.
    """
    if as_of is None:
        return extent.possibly_held_at(now)
    return extent.certainly_held_at(as_of)


# --------------------------------------------------------------------------------------
# Graph store
# --------------------------------------------------------------------------------------


class InMemoryGraphStore:
    """The Global Adversary Graph, held in process memory.

    Satisfies :class:`nemesis.ports.storage.GraphStore`. Methods are ``async`` because the
    port declares them so; nothing here awaits anything, and nothing here performs I/O.

    Not thread-safe and not concurrency-safe: two coroutines interleaving inside
    :meth:`upsert_entity` would each read the pre-merge entity and the second write would
    drop the first merge. Callers must serialize writes.
    """

    def __init__(self) -> None:
        self._entities: dict[str, Entity] = {}
        self._by_identity: dict[tuple[EntityType, str], str] = {}
        self._canonical: dict[str, str] = {}
        self._relationships: dict[str, Relationship] = {}
        self._incident: dict[str, list[str]] = {}

    # -- writes ---------------------------------------------------------------

    async def upsert_entity(self, entity: Entity) -> Entity:
        """Insert, or merge into the entity already held for this ``(type, natural_key)``."""
        identity = entity.identity()
        existing_id = self._by_identity.get(identity)
        bound_to = self._canonical.get(entity.entity_id)

        if bound_to is not None and bound_to != existing_id:
            # Reusing an identifier for a different thing would re-point every edge already
            # recorded against it at the wrong node — a silent rewrite of the graph.
            raise ValueError(
                f"{entity.entity_id} is already bound to "
                f"{self._entities[bound_to].identity()}, cannot rebind it to {identity}"
            )

        if existing_id is None:
            self._entities[entity.entity_id] = entity
            self._by_identity[identity] = entity.entity_id
            self._canonical[entity.entity_id] = entity.entity_id
            self._incident.setdefault(entity.entity_id, [])
            return entity

        merged = merge_entities(self._entities[existing_id], entity)
        self._entities[existing_id] = merged
        if entity.entity_id != existing_id:
            # Every identifier this thing was ever known by keeps resolving, so an edge
            # recorded against a pre-merge id is not orphaned by the merge.
            self._canonical[entity.entity_id] = existing_id
            self._incident.setdefault(existing_id, []).extend(
                self._incident.pop(entity.entity_id, [])
            )
        return merged

    async def erase_entity(self, entity_id: str) -> bool:
        """Remove a node and every edge touching it. Returns whether anything was there.

        Erasure is the one graph mutation that *loses* information, so it is deliberate about
        what it takes with it. Leaving the edges would leave dangling references to a node the
        platform has undertaken to forget, and a traversal would still show its shape — which
        is the same disclosure wearing a different form.

        Every identifier the thing was ever known by is unbound too. A merge registers
        pre-merge ids in the alias map so old edges keep resolving; leaving those behind after
        erasure would let a later upsert re-bind to a canonical id that no longer exists.
        """
        canonical = self._canonical.get(entity_id, entity_id)
        entity = self._entities.get(canonical)
        if entity is None:
            return False

        def _touches(edge: Relationship) -> bool:
            return canonical in (
                self._canonical.get(edge.source_id, edge.source_id),
                self._canonical.get(edge.target_id, edge.target_id),
            )

        doomed = {edge_id for edge_id, edge in self._relationships.items() if _touches(edge)}
        for edge_id in doomed:
            self._relationships.pop(edge_id, None)
        self._incident.pop(canonical, None)
        for other, edge_ids in self._incident.items():
            self._incident[other] = [eid for eid in edge_ids if eid not in doomed]
        self._entities.pop(canonical, None)
        self._by_identity.pop(entity.identity(), None)
        for alias, target in list(self._canonical.items()):
            if target == canonical:
                self._canonical.pop(alias, None)
        return True

    async def add_relationship(self, relationship: Relationship) -> Relationship:
        """Record an edge between two entities that already exist.

        Both endpoints must be present. The port does not require this; the alternative is
        an edge whose endpoint types the traversal cannot check, which would let a pivot
        through shared infrastructure escape the control that exists to stop it. A dangling
        edge is also invisible in results, and a silently smaller subgraph is worse than a
        loud rejection at write time.
        """
        source = self._canonical.get(relationship.source_id)
        target = self._canonical.get(relationship.target_id)
        missing = [
            endpoint
            for endpoint, resolved in (
                (relationship.source_id, source),
                (relationship.target_id, target),
            )
            if resolved is None
        ]
        if missing or source is None or target is None:
            raise ValueError(
                f"relationship {relationship.edge_id} references unknown entities "
                f"{missing}: upsert both endpoints before relating them"
            )

        self._relationships[relationship.edge_id] = relationship
        # A set, because a merge can collapse both endpoints onto one node; the edge must
        # then be indexed once, not twice.
        for endpoint in {source, target}:
            edges = self._incident.setdefault(endpoint, [])
            if relationship.edge_id not in edges:
                edges.append(relationship.edge_id)
        return relationship

    # -- reads ----------------------------------------------------------------

    async def get_entity(self, entity_id: str) -> Entity | None:
        canonical = self._canonical.get(entity_id)
        return None if canonical is None else self._entities[canonical]

    async def find_entity(self, entity_type: EntityType, natural_key: str) -> Entity | None:
        entity_id = self._by_identity.get((entity_type, natural_key))
        if entity_id is None:
            try:
                normalized = normalize_identifier(entity_type, natural_key)
            except NormalizationError:
                return None
            entity_id = self._by_identity.get((entity_type, normalized))
        return None if entity_id is None else self._entities[entity_id]

    async def entity_count(self) -> int:
        return len(self._entities)

    async def relationship_count(self) -> int:
        """Not part of the port; used by tests and by the CLI's status output."""
        return len(self._relationships)

    def entities(self) -> tuple[Entity, ...]:
        """Every node held, in insertion order. Not part of the port.

        Exists so a property that must hold of the *whole* graph — every node flagged
        synthetic, say — can be asserted over the store rather than over whichever nodes a
        traversal happened to reach. A sample cannot fail on the node nobody queried.
        """
        return tuple(self._entities.values())

    def relationships(self) -> tuple[Relationship, ...]:
        """Every edge held, in insertion order. Not part of the port. See :meth:`entities`."""
        return tuple(self._relationships.values())

    # -- traversal ------------------------------------------------------------

    async def neighbourhood(self, query: GraphQuery) -> Subgraph:
        """Breadth-first expansion honouring valid time, confidence and the shared-
        infrastructure boundary.

        Every filter is applied *before* an edge is crossed. That ordering is the whole
        point: a filter applied to the finished result would still have let the traversal
        walk through a rejected edge and collect whatever lay behind it.
        """
        if query.as_of is not None and query.as_of.tzinfo is None:
            raise ValueError("GraphQuery.as_of must be timezone-aware")

        seed_id = self._canonical.get(query.entity_id)
        if seed_id is None:
            return Subgraph(entities=(), relationships=(), explanations=())

        # One clock read for the whole traversal: judging early edges against a different
        # instant from late ones makes a query non-reproducible.
        now = utcnow()

        entities: dict[str, Entity] = {seed_id: self._entities[seed_id]}
        edges: dict[str, Relationship] = {}
        excluded: list[str] = []
        visited: set[str] = {seed_id}
        frontier: list[str] = [seed_id]

        for _depth in range(1, max(query.max_depth, 0) + 1):
            next_frontier: list[str] = []
            for current_id in frontier:
                for edge_id in self._incident.get(current_id, []):
                    edge = self._relationships[edge_id]
                    if not self._edge_passes(edge, query, now):
                        continue
                    other_id = self._other_end(edge, current_id)
                    if other_id is None:
                        continue
                    other = self._entities[other_id]
                    if query.entity_types is not None and other.entity_type not in (
                        query.entity_types
                    ):
                        continue

                    edges[edge_id] = edge
                    entities.setdefault(other_id, other)

                    if other_id in visited:
                        continue
                    visited.add(other_id)

                    if query.exclude_shared_infrastructure and other.is_shared_infrastructure:
                        # Included as a leaf — the analyst should see that the CDN address
                        # or the registrar is there — but never expanded through. Recorded
                        # so the boundary is visible rather than looking like an absence.
                        excluded.append(other_id)
                        continue
                    next_frontier.append(other_id)
            frontier = next_frontier
            if not frontier:
                break

        return Subgraph(
            entities=tuple(entities[key] for key in sorted(entities)),
            relationships=tuple(edges[key] for key in sorted(edges)),
            explanations=tuple(edges[key].explain() for key in sorted(edges)),
            # Nodes still on the frontier when the budget ran out would have been expanded.
            truncated_at_depth=max(query.max_depth, 0) if frontier else None,
            excluded_shared_infrastructure=tuple(excluded),
        )

    async def explain_connection(
        self, source_id: str, target_id: str, *, max_depth: int = 4
    ) -> tuple[Explanation, ...]:
        """Every edge on the paths between two entities, shortest paths first.

        The chain, never a verdict. No confidence threshold and no shared-infrastructure
        refusal is applied here: the caller named both endpoints and is entitled to see
        exactly what connects them, including that it is six weak hops through a CDN. Each
        :class:`~nemesis.core.relationships.Explanation` carries its own caveats, so a weak
        link announces itself rather than being quietly withheld.
        """
        source = self._canonical.get(source_id)
        target = self._canonical.get(target_id)
        if source is None or target is None or source == target:
            return ()

        ordered: list[str] = []
        for path in sorted(self._simple_paths(source, target, max_depth), key=len):
            for edge_id in path:
                if edge_id not in ordered:
                    ordered.append(edge_id)
        return tuple(self._relationships[edge_id].explain() for edge_id in ordered)

    # -- internals ------------------------------------------------------------

    def _edge_passes(self, edge: Relationship, query: GraphQuery, now: datetime) -> bool:
        if query.relation_types is not None and edge.relation not in query.relation_types:
            return False
        if edge.confidence.projected_probability < query.min_confidence:
            return False
        return _edge_holds(edge.extent, query.as_of, now)

    def _other_end(self, edge: Relationship, from_id: str) -> str | None:
        """The far endpoint of an edge, in canonical ids.

        Returns ``None`` when both endpoints resolve to the same node. That happens after a
        merge discovers two nodes were one thing all along, which turns the edge into a
        self-loop that cannot extend a path.
        """
        source = self._canonical[edge.source_id]
        target = self._canonical[edge.target_id]
        if source == target:
            return None
        return target if source == from_id else source

    def _simple_paths(self, start: str, goal: str, max_depth: int) -> list[tuple[str, ...]]:
        """Enumerate node-disjoint paths of at most ``max_depth`` edges.

        The per-path visited set is what makes this terminate on a cyclic graph: a poisoned
        or merely circular neighbourhood would otherwise be walked forever.
        """
        paths: list[tuple[str, ...]] = []
        stack: list[tuple[str, tuple[str, ...], frozenset[str]]] = [(start, (), frozenset({start}))]
        while stack and len(paths) < _MAX_EXPLAINED_PATHS:
            node, walked, seen = stack.pop()
            if len(walked) >= max_depth:
                continue
            for edge_id in sorted(self._incident.get(node, [])):
                if edge_id in walked:
                    continue
                other = self._other_end(self._relationships[edge_id], node)
                if other is None:
                    continue
                if other == goal:
                    paths.append((*walked, edge_id))
                    continue
                if other in seen:
                    continue
                stack.append((other, (*walked, edge_id), seen | {other}))
        return paths


# --------------------------------------------------------------------------------------
# Claim store
# --------------------------------------------------------------------------------------


class InMemoryClaimStore:
    """Append-only claim store, held in process memory.

    Satisfies :class:`nemesis.ports.storage.ClaimStore`. Nothing is ever removed: a
    correction supersedes its predecessor and both versions remain readable, which is what
    lets the belief state at any past moment be reconstructed and what makes a poisoning
    attempt leave a trace instead of overwriting one.
    """

    def __init__(self) -> None:
        self._claims: dict[str, Claim] = {}
        self._replaced_by: dict[str, str] = {}
        self._reasons: dict[str, str] = {}
        self._named_as_contradictor: dict[str, set[str]] = {}

    async def record(self, claim: Claim) -> Claim:
        """Store a claim. Re-recording an existing claim id is a no-op.

        Claim ids are content addresses, so an identical assertion derived identically from
        identical inputs is the same claim. Storing it twice would let one source look like
        two agreeing ones the moment anything counts corroboration.
        """
        stored = self._claims.get(claim.claim_id)
        if stored is not None:
            return stored
        self._claims[claim.claim_id] = claim
        self._index_contradictions(claim)
        return claim

    async def get(self, claim_id: str) -> Claim | None:
        """The current version of a claim, following supersessions forward.

        Asking for a superseded id yields its replacement — the graph answers "what do we
        believe about this now". The exact stored version is still readable through
        :meth:`get_version`.
        """
        return self._current(claim_id)

    def get_version(self, claim_id: str) -> Claim | None:
        """The exact version stored under this id, superseded or not. Not part of the port.

        This is the read an audit or a challenge needs: what did the record say before it
        was corrected, and when was it marked as corrected.
        """
        return self._claims.get(claim_id)

    def claims(self) -> tuple[Claim, ...]:
        """Every stored version, superseded ones included. Not part of the port.

        Ordered by first storage. Like :meth:`InMemoryGraphStore.entities`, it exists so a
        property required of every claim can be checked against all of them rather than
        against the ones a caller remembered to keep a reference to.
        """
        return tuple(self._claims.values())

    def supersession_reason(self, claim_id: str) -> str | None:
        """Why this claim was superseded. Not part of the port.

        :class:`~nemesis.core.temporal.RecordVersion` records *that* a claim was superseded
        but has no field for why, and the core model is frozen. A correction with no stated
        reason is indistinguishable from tampering, so the reason is held here.
        """
        return self._reasons.get(claim_id)

    async def supersede(self, claim_id: str, replacement: Claim, *, reason: str) -> Claim:
        """Replace a claim without deleting it. Both versions stay readable."""
        if not reason.strip():
            raise ValueError("a supersession must state why; an unexplained edit is tampering")

        original = self._claims.get(claim_id)
        if original is None:
            raise KeyError(f"cannot supersede unknown claim {claim_id}")
        if claim_id in self._replaced_by:
            raise ValueError(
                f"{claim_id} was already superseded by {self._replaced_by[claim_id]}; "
                "supersede the current version or history forks into two readings"
            )
        if replacement.claim_id == claim_id:
            raise ValueError(
                "a claim cannot supersede itself: claim ids are content addresses, so "
                "identical ids mean nothing changed"
            )
        if replacement.claim_id in self._replaced_by:
            raise ValueError(
                f"{replacement.claim_id} has itself been superseded; reinstating it would "
                "make the supersession chain cyclic and the current version undefined"
            )

        superseded_at = max(utcnow(), original.version.recorded_at)
        self._claims[claim_id] = original.model_copy(
            update={
                "version": RecordVersion(
                    recorded_at=original.version.recorded_at,
                    superseded_at=superseded_at,
                    supersedes=original.version.supersedes,
                    revision=original.version.revision,
                )
            }
        )
        stored = replacement.model_copy(
            update={
                "version": RecordVersion(
                    recorded_at=superseded_at,
                    supersedes=claim_id,
                    revision=original.version.revision + 1,
                )
            }
        )
        self._claims[replacement.claim_id] = stored
        self._index_contradictions(stored)
        self._replaced_by[claim_id] = replacement.claim_id
        self._reasons[claim_id] = reason
        return stored

    async def supporting(self, claim_id: str) -> tuple[Claim, ...]:
        """The claims this one rests on, one level up.

        Resolves the exact cited versions. An input that is not in the store is omitted:
        that is a broken provenance chain, and a caller checking invariant 3 must compare
        this against ``claim.derived_from_claims`` rather than assume the lengths match.
        """
        claim = self._claims.get(claim_id)
        if claim is None:
            return ()
        parents: list[Claim] = []
        for parent_id in claim.derived_from_claims:
            parent = self._claims.get(parent_id)
            if parent is not None:
                parents.append(parent)
        return tuple(parents)

    async def derivation_chain(self, claim_id: str) -> tuple[Claim, ...]:
        """The claim and its full transitive derivation, breadth-first from the claim.

        Walks the *cited* versions rather than their current replacements: a derivation
        records what was actually reasoned from, and following supersessions here would
        rewrite the history it exists to preserve.

        The visited set is load-bearing, not an optimization. Content addressing makes a
        genuine cycle impossible — a claim's id depends on its inputs' ids — but the store
        holds whatever it is handed, and an injected cycle must terminate the walk rather
        than exhaust the stack.
        """
        start = self._claims.get(claim_id)
        if start is None:
            return ()
        ordered: list[Claim] = []
        seen: set[str] = {start.claim_id}
        queue: deque[Claim] = deque([start])
        while queue:
            claim = queue.popleft()
            ordered.append(claim)
            for parent_id in claim.derived_from_claims:
                if parent_id in seen:
                    continue
                seen.add(parent_id)
                parent = self._claims.get(parent_id)
                if parent is not None:
                    queue.append(parent)
        return tuple(ordered)

    async def contradicting(self, claim_id: str) -> tuple[Claim, ...]:
        """Every claim in a contradiction relationship with this one, in both directions.

        A contradiction is recorded on one side only, whichever was written second. Reading
        it from one end alone would make the same conflict visible or invisible depending
        on which claim an analyst happened to open.
        """
        found: dict[str, Claim] = {}
        claim = self._claims.get(claim_id)
        if claim is not None:
            for other_id in claim.contradicted_by_claims:
                other = self._claims.get(other_id)
                if other is not None:
                    found[other.claim_id] = other
        for other_id in self._named_as_contradictor.get(claim_id, set()):
            other = self._claims.get(other_id)
            if other is not None:
                found[other.claim_id] = other
        return tuple(found[key] for key in sorted(found))

    # -- internals ------------------------------------------------------------

    def _index_contradictions(self, claim: Claim) -> None:
        for contradictor_id in claim.contradicted_by_claims:
            self._named_as_contradictor.setdefault(contradictor_id, set()).add(claim.claim_id)

    def _current(self, claim_id: str) -> Claim | None:
        current = claim_id
        seen: set[str] = {current}
        while current in self._replaced_by:
            current = self._replaced_by[current]
            if current in seen:
                # supersede() refuses to create one; if a cycle exists anyway the store was
                # tampered with, and looping forever would hide that.
                raise ValueError(f"supersession chain from {claim_id} is cyclic at {current}")
            seen.add(current)
        return self._claims.get(current)
