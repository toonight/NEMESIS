"""Durability for the graph and the claim store, without a second implementation of either.

The investigation itself has lived in dictionaries. The evidence vault and the audit trail
have always persisted; the graph and the claims did not, so a restart lost what the platform
believed and why — including the supersession history that answers "what did we think in
March?", which is the whole point of keeping beliefs append-only.

**Why a journal rather than a schema.** The obvious move is a SQLite table per entity type
and a SQL rewrite of the traversal. The traversal is the subtlest code in this repository:
bitemporal filtering, a confidence floor applied *at* traversal time so a weak edge cannot be
laundered by distance, and shared-infrastructure exclusion so a hop through a CDN address
does not return most of the internet. A second implementation of that is a second set of
answers to the same question, and the two would diverge silently — which is exactly the class
of defect the last several reviews kept finding.

So this persists the *mutations* and replays them, and the traversal stays the one that is
already tested. Every write appends one line; opening replays the file. What that buys is
durability and restart recovery. What it does not buy is scale or query performance, and the
label says `IMPLEMENTED (durable)` rather than anything about a production datastore: replay
is linear in history, and a deployment that outgrows that needs a real database and the SQL
rewrite this defers.

**Failing closed.** A journal line that does not parse, or that replays into a rejected
state, aborts the load. A store that silently skipped a line it could not read would come up
believing something *narrower* than what was recorded, and would look perfectly healthy doing
it — a graph missing one edge answers "why do you think these are connected?" with a smaller
answer and no error, which is worse than refusing to start.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

from pydantic import ValidationError

from nemesis.core.claims import Claim
from nemesis.core.entities import Entity
from nemesis.core.relationships import Relationship
from nemesis.graph.memory import InMemoryClaimStore, InMemoryGraphStore

GRAPH_JOURNAL: Final = "graph.jsonl"
CLAIM_JOURNAL: Final = "claims.jsonl"

OP_ENTITY: Final = "entity"
OP_RELATIONSHIP: Final = "relationship"
OP_CLAIM: Final = "claim"
OP_SUPERSEDE: Final = "supersede"
OP_ERASE: Final = "erase"
"""Erasure, journalled as its own operation.

Without it the journal is a resurrection machine: the upsert that created a node is still on
disk, so the next replay brings back exactly what a retention policy undertook to forget. The
same reasoning that made supersession its own op — replay must reproduce the decision, not
only the data."""


class JournalError(RuntimeError):
    """The journal could not be read, or replayed into a state the model accepts."""


def _append(path: Path, op: str, payload: dict[str, Any]) -> None:
    """One line per mutation, flushed before returning.

    Written before the in-memory store is updated by the callers below, so a crash between
    the two loses nothing: replay is idempotent for upserts and the claim store rejects a
    duplicate record on its own terms.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"op": op, "payload": payload}, sort_keys=True) + "\n")
        handle.flush()


def _lines(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError as exc:
            raise JournalError(
                f"{path}:{number} is not readable JSON ({exc}). Refusing to start on a "
                "partial history: a store that skipped this line would come up believing "
                "something narrower than what was recorded, and would look healthy doing it."
            ) from exc
        records.append(record)
    return records


class JournalBackedGraphStore(InMemoryGraphStore):
    """The graph, with every mutation written down and replayed on open.

    Subclasses rather than wraps, so the traversal, the temporal filtering and the
    explanation machinery are the ones already under test. The only additions are an append
    on write and a replay on open.

    Replay goes through the **public** API — the same `upsert_entity` and `add_relationship`
    a live write uses — rather than repopulating internals. Two reasons, and the second is
    the one that matters: reaching into a base class's dictionaries means a rename breaks
    persistence silently, and replaying through the front door means a journal that would
    produce an invalid graph is refused by the same validators that would have refused it
    live. A store cannot come up in a state it could never have reached.
    """

    def __init__(self, root: Path | str) -> None:
        super().__init__()
        self._path = Path(root) / GRAPH_JOURNAL
        self._replaying = False

    @classmethod
    async def open(cls, root: Path | str) -> JournalBackedGraphStore:
        """Construct and replay. Async because replay uses the same writes a caller would."""
        store = cls(root)
        store._replaying = True
        try:
            for number, record in enumerate(_lines(store._path), start=1):
                try:
                    if record["op"] == OP_ENTITY:
                        await store.upsert_entity(Entity.model_validate(record["payload"]))
                    elif record["op"] == OP_RELATIONSHIP:
                        await store.add_relationship(Relationship.model_validate(record["payload"]))
                    elif record["op"] == OP_ERASE:
                        await store.erase_entity(str(record["payload"]["entity_id"]))
                    else:
                        raise JournalError(f"{store._path}:{number}: unknown op {record['op']!r}")
                except (ValidationError, KeyError, ValueError) as exc:
                    raise JournalError(
                        f"{store._path}:{number} does not replay into a valid record: {exc}"
                    ) from exc
        finally:
            store._replaying = False
        return store

    @property
    def journal_path(self) -> Path:
        return self._path

    async def upsert_entity(self, entity: Entity) -> Entity:
        stored = await super().upsert_entity(entity)
        if not self._replaying:
            # The ARGUMENT, not the merged result — and the first version of this line said
            # the opposite, confidently, in a comment. `upsert_entity` merges a new record
            # into an existing one under the existing id, and registers the pre-merge id in
            # an alias map so that an edge recorded against it is not orphaned. That map is
            # built by the *sequence of calls*, so a journal of merged results replays a
            # graph where those aliases never existed — and every edge naming a pre-merge id
            # fails to replay. A mutation journal records the call, not the outcome.
            _append(self._path, OP_ENTITY, entity.model_dump(mode="json"))
        return stored

    async def erase_entity(self, entity_id: str) -> bool:
        """Erase, and journal the erasure so a replay does not bring it back."""
        erased = await super().erase_entity(entity_id)
        if erased and not self._replaying:
            _append(self._path, OP_ERASE, {"entity_id": entity_id})
        return erased

    async def add_relationship(self, relationship: Relationship) -> Relationship:
        stored = await super().add_relationship(relationship)
        if not self._replaying:
            _append(self._path, OP_RELATIONSHIP, stored.model_dump(mode="json"))
        return stored


class JournalBackedClaimStore(InMemoryClaimStore):
    """The claim store, append-only on disk as well as in memory.

    Supersession is journalled as its own operation rather than as a rewritten claim, because
    "this belief replaced that one, for this reason" is the fact the store exists to keep. A
    journal recording only current versions would answer "what do we believe now?" and lose
    "what did we believe in March, and why did that change?".
    """

    def __init__(self, root: Path | str) -> None:
        super().__init__()
        self._path = Path(root) / CLAIM_JOURNAL
        self._replaying = False

    @classmethod
    async def open(cls, root: Path | str) -> JournalBackedClaimStore:
        store = cls(root)
        store._replaying = True
        try:
            for number, record in enumerate(_lines(store._path), start=1):
                try:
                    if record["op"] == OP_CLAIM:
                        await store.record(Claim.model_validate(record["payload"]))
                    elif record["op"] == OP_SUPERSEDE:
                        await store.supersede(
                            record["payload"]["claim_id"],
                            Claim.model_validate(record["payload"]["replacement"]),
                            reason=record["payload"]["reason"],
                        )
                    else:
                        raise JournalError(f"{store._path}:{number}: unknown op {record['op']!r}")
                except (ValidationError, KeyError, ValueError) as exc:
                    raise JournalError(
                        f"{store._path}:{number} does not replay into a valid record: {exc}"
                    ) from exc
        finally:
            store._replaying = False
        return store

    @property
    def journal_path(self) -> Path:
        return self._path

    async def record(self, claim: Claim) -> Claim:
        stored = await super().record(claim)
        if not self._replaying:
            _append(self._path, OP_CLAIM, stored.model_dump(mode="json"))
        return stored

    async def supersede(self, claim_id: str, replacement: Claim, *, reason: str) -> Claim:
        stored = await super().supersede(claim_id, replacement, reason=reason)
        if not self._replaying:
            _append(
                self._path,
                OP_SUPERSEDE,
                {
                    "claim_id": claim_id,
                    "replacement": stored.model_dump(mode="json"),
                    "reason": reason,
                },
            )
        return stored
