"""Storage ports: the graph, the claim store, the evidence vault, the audit trail.

Four stores with deliberately different guarantees, because they are trusted differently:

- The **graph** is mutable and revisable. It holds what we currently believe.
- The **claim store** is append-only. Beliefs are superseded, never edited, so the belief
  state at any past moment can be reconstructed.
- The **evidence vault** is append-only *and* tamper-evident. Its operator is in the
  threat model.
- The **audit trail** is append-only, tamper-evident, and records actions rather than
  facts.

Merging any two of these would be simpler and would destroy the property that makes the
stricter one worth having.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from nemesis.core.authorization import AuthorizationDecision
from nemesis.core.claims import Claim
from nemesis.core.entities import Entity, EntityType
from nemesis.core.evidence import EvidenceObject
from nemesis.core.ids import AuditId, ClaimId, EntityId, EvidenceId
from nemesis.core.relationships import Explanation, Relationship, RelationType


class GraphQuery(BaseModel):
    """A temporal neighbourhood query.

    ``as_of`` is what makes this a temporal graph rather than a graph with timestamps on
    it. Asking "what did this cluster look like in March?" must return March's answer, not
    today's answer filtered — those differ whenever an edge was added retroactively, which
    in intelligence work is most of the time.
    """

    model_config = ConfigDict(frozen=True)

    entity_id: EntityId
    max_depth: int = 2
    as_of: datetime | None = None
    """Valid-time instant. None means "whatever holds now"."""

    relation_types: frozenset[RelationType] | None = None
    entity_types: frozenset[EntityType] | None = None

    min_confidence: float = 0.0
    """Filter on projected probability. Applied at traversal time, so a weak edge cannot
    be laundered by being two hops away from a strong one."""

    exclude_shared_infrastructure: bool = True
    """Skip traversal through entity types shared by unrelated parties. On by default:
    a traversal that hops through a CDN address reaches most of the internet in two steps
    and returns a cluster that means nothing.
    """


class Subgraph(BaseModel):
    """A query result: the entities, edges, and why each edge is there."""

    model_config = ConfigDict(frozen=True)

    entities: tuple[Entity, ...]
    relationships: tuple[Relationship, ...]
    explanations: tuple[Explanation, ...]
    truncated_at_depth: int | None = None
    excluded_shared_infrastructure: tuple[EntityId, ...] = ()
    """Entities the traversal deliberately refused to cross. Reported rather than silently
    dropped — an analyst must be able to see that the graph stopped somewhere on purpose."""


@runtime_checkable
class GraphStore(Protocol):
    """The Global Adversary Graph."""

    async def upsert_entity(self, entity: Entity) -> Entity:
        """Insert, or merge into an existing entity with the same (type, natural key).

        Merging rather than inserting is what keeps one real-world thing as one node.
        Implementations must merge temporal extents rather than overwrite them: learning
        about a domain's March activity in December must widen its known extent, not
        replace it.
        """
        ...

    async def get_entity(self, entity_id: EntityId) -> Entity | None: ...

    async def find_entity(self, entity_type: EntityType, natural_key: str) -> Entity | None: ...

    async def add_relationship(self, relationship: Relationship) -> Relationship: ...

    async def neighbourhood(self, query: GraphQuery) -> Subgraph: ...

    async def explain_connection(
        self, source_id: EntityId, target_id: EntityId, *, max_depth: int = 4
    ) -> tuple[Explanation, ...]:
        """Every edge on the paths connecting two entities. Invariant 12.

        Returns the chain, not a verdict. If NEMESIS connected two entities through six
        hops of weak correlation, the analyst sees six weak links rather than a
        confident-looking conclusion.
        """
        ...

    async def erase_entity(self, entity_id: EntityId) -> bool:
        """Forget a node and every edge touching it. Returns whether anything was there.

        The only graph mutation that loses information, and it exists because retention is an
        obligation rather than a preference: a human-identity lead past its period must stop
        being held, and "held" includes being reachable through a traversal.

        An implementation with a mutation journal must record the erasure as its own entry.
        Otherwise the upsert that created the node is still on disk and the next replay
        resurrects exactly what was undertaken to be forgotten.
        """
        ...

    async def entity_count(self) -> int: ...


@runtime_checkable
class ClaimStore(Protocol):
    """Append-only store of claims."""

    async def record(self, claim: Claim) -> Claim:
        """Store a claim. Recording an existing claim id is a no-op, not a duplicate."""
        ...

    async def get(self, claim_id: ClaimId) -> Claim | None: ...

    async def supersede(self, claim_id: ClaimId, replacement: Claim, *, reason: str) -> Claim:
        """Replace a claim without deleting it. Both remain readable."""
        ...

    async def supporting(self, claim_id: ClaimId) -> tuple[Claim, ...]:
        """The claims this one rests on, one level up the derivation chain."""
        ...

    async def derivation_chain(self, claim_id: ClaimId) -> tuple[Claim, ...]:
        """The full transitive derivation, terminating at evidence-backed claims."""
        ...

    async def contradicting(self, claim_id: ClaimId) -> tuple[Claim, ...]: ...


class VaultIntegrityReport(BaseModel):
    """The result of verifying the vault against tampering."""

    model_config = ConfigDict(frozen=True)

    checked_at: datetime
    objects_checked: int
    hash_chain_intact: bool
    artifacts_verified: int
    artifacts_missing: tuple[EvidenceId, ...] = ()
    artifacts_corrupted: tuple[EvidenceId, ...] = ()
    externally_anchored: int = 0

    @property
    def is_intact(self) -> bool:
        return (
            self.hash_chain_intact and not self.artifacts_missing and not self.artifacts_corrupted
        )

    @property
    def is_defensible_against_insider(self) -> bool:
        """Whether integrity holds against someone who controls the store.

        An intact internal hash chain proves nothing against an operator who can recompute
        it. Only externally held anchors close that gap, so a vault with zero anchors is
        reported as undefensible however clean its own bookkeeping looks.
        """
        return self.is_intact and self.externally_anchored > 0


@runtime_checkable
class EvidenceVault(Protocol):
    """Append-only, tamper-evident evidence storage."""

    async def seal(self, evidence: EvidenceObject, artifact: bytes) -> EvidenceObject:
        """Store an artifact and its metadata, extending the hash chain.

        Must reject an artifact whose bytes do not hash to the object's ``content_hash``,
        and must reject re-sealing an existing evidence id with different bytes — that is
        either a hash collision or someone substituting evidence, and both must fail loudly.
        """
        ...

    async def get(self, evidence_id: EvidenceId) -> EvidenceObject | None: ...

    async def retrieve_artifact(
        self, evidence_id: EvidenceId, *, accessed_by: str, reason: str
    ) -> bytes:
        """Return the sealed bytes, recording the access.

        Access is itself recorded: who read what, when, and why. In a chain-of-custody
        context an unrecorded read is a gap someone will ask about.
        """
        ...

    async def verify_integrity(self) -> VaultIntegrityReport: ...

    async def head(self) -> str:
        """The current root hash of the vault, suitable for external anchoring."""
        ...


class AuditEvent(BaseModel):
    """One recorded action. Replayable, not merely readable."""

    model_config = ConfigDict(frozen=True)

    audit_id: AuditId
    occurred_at: datetime
    actor: str
    actor_kind: str
    """human | agent | rule | system. An action with no attributable actor is a defect."""

    action: str
    subject: str
    outcome: str

    inputs: dict[str, str] = {}
    """Enough to re-run the action and get the same result. This is what separates an
    audit trail from a log: a log tells you something happened, a replayable trail lets
    you check whether it should have."""

    authorization_decision: AuthorizationDecision | None = None
    """Present for any action that consulted a capability, permitted or denied. Denials
    are recorded with equal weight — a pattern of denied attempts is a security signal."""

    previous_hash: str | None = None
    entry_hash: str | None = None


@runtime_checkable
class PublicationRecorder(Protocol):
    """Write to the audit trail, and read nothing back.

    A deliberate narrowing of :class:`AuditSink`, and the narrowing is the whole reason it
    exists. The collaboration plane must record what it published — invariant 11 does not
    have an exception for the outward-facing plane — but it is the plane whose whole job is
    to talk to a backend NEMESIS does not control. Handing it an ``AuditSink`` would hand it
    ``query``, and a compromised collaboration path could then read the platform's history
    of every action rather than only the events it was given to publish.

    Structural typing makes this free: :class:`AuditSink` and
    :class:`~nemesis.audit.trail.AppendOnlyAuditTrail` both already satisfy it, so a caller
    passes the trail it already has and the plane sees one method. No adapter, no second
    implementation, and nothing to keep in step.
    """

    async def record(self, event: AuditEvent) -> AuditEvent: ...


@runtime_checkable
class AuditSink(Protocol):
    """Append-only, tamper-evident record of what the platform and its operators did."""

    async def record(self, event: AuditEvent) -> AuditEvent: ...

    async def query(
        self,
        *,
        actor: str | None = None,
        action: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> Sequence[AuditEvent]: ...

    async def verify_chain(self) -> bool: ...
