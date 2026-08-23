"""The three things the Evolution plane may read, and nothing else.

Each Protocol here is a **narrowing** of a port that already exists in
:mod:`nemesis.ports.storage`, and the narrowing is the control. This is the same move
:class:`~nemesis.ports.storage.PublicationRecorder` makes for the collaboration plane: structural
typing means the caller passes the store it already has, no adapter exists to keep in step, and
the plane sees one or two methods instead of a full store.

What each narrowing removes is the point:

- :class:`EntityReader` drops ``upsert_entity``, ``add_relationship`` and ``erase_entity``. The
  Evolution plane reads the graph to *score* what happened; a plane that could write it could
  manufacture the improvement it is measuring, which is the Goodhart failure this whole design is
  arranged against.
- :class:`ClaimReader` drops ``record`` and ``supersede``. A checkpoint cites claims. It does not
  mint them, and it cannot retire one that contradicts a promotion it wants.
- :class:`EvidenceReader` drops ``seal`` and — the one that matters — ``retrieve_artifact``. The
  evaluator needs an evidence object's *provenance*, which is metadata, to answer "how many
  independent origins does this trajectory rest on". It never needs the bytes, so it is not given
  a method that returns them. Sealed material stays in the vault with its access record intact.

None of these is a substitute for the import contract. ``evolution-holds-no-platform-handles``
forbids this package from importing :mod:`nemesis.graph`, :mod:`nemesis.evidence`,
:mod:`nemesis.authz`, :mod:`nemesis.effects`, :mod:`nemesis.collect` or
:mod:`nemesis.pursuit.engine` at all, so a future author cannot reach past a Protocol by
importing the implementation behind it. The Protocols bound what a *caller* hands over; the
contract bounds what this package can name.

Status: `IMPLEMENTED`.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from nemesis.core.claims import Claim
from nemesis.core.entities import Entity
from nemesis.core.evidence import EvidenceObject
from nemesis.core.ids import ClaimId, EntityId, EvidenceId
from nemesis.ports.storage import GraphQuery, Subgraph


@runtime_checkable
class EntityReader(Protocol):
    """Read-only view of the graph. Satisfied by any :class:`~nemesis.ports.storage.GraphStore`."""

    async def get_entity(self, entity_id: EntityId) -> Entity | None: ...

    async def neighbourhood(self, query: GraphQuery) -> Subgraph:
        """Bounded traversal, used to count how *discriminating* the new edges are.

        The evaluator asks for one shallow neighbourhood per evaluation and reads only
        :attr:`~nemesis.core.relationships.Relationship.selectivity`. Reusing the traversal rather
        than counting edges some other way is deliberate: the existing store already refuses to
        expand through shared infrastructure and already reports where it stopped, and a second
        implementation of that judgement would be a second place for it to be wrong.
        """
        ...


@runtime_checkable
class ClaimReader(Protocol):
    """Read-only view of the claim store."""

    async def get(self, claim_id: ClaimId) -> Claim | None: ...


@runtime_checkable
class EvidenceReader(Protocol):
    """Read-only view of evidence **metadata**. Deliberately without ``retrieve_artifact``.

    :class:`~nemesis.evidence.vault.FileSystemEvidenceVault` satisfies this already, so a caller
    passes the vault it has and this plane sees one method.
    """

    async def get(self, evidence_id: EvidenceId) -> EvidenceObject | None: ...


__all__ = ["ClaimReader", "EntityReader", "EvidenceReader"]
