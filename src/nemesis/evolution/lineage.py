"""The trajectory: everything the run tried, hash-chained, and the promoted line through it.

Two objects that are routinely confused and must not be:

**The active lineage** is the chain of promoted checkpoints — the state a resume restores and the
state the next briefing is built from. A candidate that was evaluated and rejected is not in it.

**The complete audit trajectory** is every entry ever appended, promotions and rejections alike.
A rejected candidate does not leave it, and that is the whole reason this store is append-only
rather than a pointer to "the best checkpoint so far". Three separate things depend on it:

- *Not repeating work.* The most valuable thing a long-horizon run knows is which directions are
  spent, and that knowledge lives entirely in the attempts that failed.
- *Explaining the run.* "Why did you not look there?" is the question an analyst asks most often
  — the reasoning :class:`~nemesis.pursuit.investigation.Investigation` already gives for keeping
  abandoned branches — and it is unanswerable from a store that keeps only what worked.
- *Invariant 11.* An agent action that is reversed is still an agent action. A trajectory that
  silently dropped rejected candidates would be a log of successes, which is the shape of record
  that makes an autonomous system unauditable.

**Why it chains.** Deleting a rejected attempt is the obvious way to make a run look better than
it was, and — worse — the way to make an exhausted direction look fresh so it gets retried at
cost. A signature over each entry would not catch a deletion, so entries carry their predecessor's
hash, exactly as :class:`~nemesis.authz.envelope.SpendRecord` does for consumption. A missing
entry breaks every link after it.

The chain's honest limit is the one this repository states everywhere else: deleting the *newest*
entry is undetected, because nothing follows the tail. :meth:`LineageStore.entries` is therefore
not a defence against an operator; it is a defence against a run rewriting its own history, and
against the accident where a store that drops rows looks identical to one that never had them.

Status: `IMPLEMENTED` in memory and durably. No external anchor, so the same insider gap the
evidence vault reports applies here.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Iterator, Mapping
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Final, Protocol, Self, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from nemesis.core.authorization import GENESIS_HASH
from nemesis.core.ids import EvolutionRunId
from nemesis.core.temporal import require_utc
from nemesis.evolution.models import InvestigationCheckpoint

LINEAGE_JOURNAL: Final = "lineage.jsonl"

MAX_DETAIL_LENGTH: Final = 1000


class LineageError(RuntimeError):
    """The lineage could not be read, or an append would have contradicted what is on disk."""


class LineageEventKind(StrEnum):
    """What happened. Closed, because a trajectory whose vocabulary grows by accident is one
    nobody can query."""

    RUN_STARTED = "run_started"
    RUN_RESUMED = "run_resumed"
    STEP_ATTEMPTED = "step_attempted"
    """One variation step ran: the pilot drove a bounded segment through the mediator."""

    CANDIDATE_INVALID = "candidate_invalid"
    """A hard gate failed. Never promotable, whatever it appeared to gain."""

    CANDIDATE_REJECTED = "candidate_rejected"
    """Valid, and did not beat the incumbent. Kept precisely because it did not."""

    CHECKPOINT_PROMOTED = "checkpoint_promoted"
    BRANCH_OPENED = "branch_opened"
    BRANCH_CLOSED = "branch_closed"
    PLATEAU_DETECTED = "plateau_detected"
    SUPERVISOR_CONSULTED = "supervisor_consulted"
    DIRECTIVE_ISSUED = "directive_issued"
    DIRECTIVE_APPLIED = "directive_applied"
    HINT_ACCEPTED = "hint_accepted"
    """A research suggestion from a channel entered memory as untrusted data."""

    HINT_QUARANTINED = "hint_quarantined"
    """A suggestion that read as an instruction. Kept, classified, and never projected."""

    MEMORY_EVICTED = "memory_evicted"
    RUN_STOPPED = "run_stopped"


class LineageEntry(BaseModel):
    """One appended fact about the trajectory, chained to its predecessor.

    ``sequence`` and ``previous_hash`` are constructed by the store, never by a caller, for the
    reason :class:`~nemesis.authz.envelope.SpendLedger` gives: both are only knowable inside
    whatever serializes concurrent writers, and a caller that built them would have read the
    count before taking the lock.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    sequence: Annotated[int, Field(ge=0)]
    run_id: EvolutionRunId
    kind: LineageEventKind
    occurred_at: datetime
    detail: Annotated[str, Field(max_length=MAX_DETAIL_LENGTH)] = ""
    facts: Mapping[str, str] = Field(default_factory=dict)
    """Machine-readable measurements. Strings, like an
    :class:`~nemesis.ports.storage.AuditEvent`'s inputs, because this is a record read by people
    and by queries rather than a place to park a structure."""

    checkpoint: InvestigationCheckpoint | None = None
    """The candidate this entry is about, when it is about one. Carried whole rather than by
    reference: a reference into a mutable store would let a resumed run read a checkpoint that has
    since changed, and a checkpoint is supposed to be the state *at that point*."""

    previous_hash: str = GENESIS_HASH

    @model_validator(mode="after")
    def _require_utc(self) -> Self:
        require_utc(self.occurred_at, "occurred_at")
        return self

    def chain_hash(self) -> str:
        """This link's hash, over its own contents and its predecessor's.

        Encoded with :func:`_encode` rather than
        :func:`~nemesis.core.canonical.canonical_bytes`, and the difference is the whole integrity
        claim. ``canonical_bytes`` **sorts arrays** — which is right for a payload whose lists are
        sets, and wrong for this one, where a checkpoint carries ordered tuples of evidence,
        entity and claim references. An adversarial review demonstrated it: reordering a
        checkpoint's ``evidence_refs`` produced a byte-identical digest, so a journal could be
        edited without breaking the chain. The collaboration plane learned the same lesson about
        ``derive_event_id`` and states it in the same words: sorting them would make two different
        objects share an identifier.
        """
        return hashlib.sha256(_encode(self.model_dump(mode="json"))).hexdigest()


def _encode(payload: Mapping[str, object]) -> bytes:
    """Deterministic JSON that preserves array order. Keys sorted, arrays left alone."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")


def verify_lineage_chain(entries: tuple[LineageEntry, ...]) -> bool:
    """Whether the trajectory is intact: nothing removed, reordered or edited.

    Written once and shared by every implementation, so the in-memory and durable stores cannot
    disagree about what an intact chain is.
    """
    expected = GENESIS_HASH
    for position, entry in enumerate(entries):
        if entry.sequence != position or entry.previous_hash != expected:
            return False
        expected = entry.chain_hash()
    return True


def active_lineage(entries: tuple[LineageEntry, ...]) -> tuple[InvestigationCheckpoint, ...]:
    """The promoted line through the trajectory, oldest first.

    Reconstructed by following ``parent_checkpoint_id`` back from the newest promotion rather than
    by filtering on the kind, because a promoted checkpoint whose parent was later superseded is
    not on the active line even though it was promoted once. Filtering would return a set of
    winners; this returns a *chain*, which is what a resume needs.
    """
    promoted = {
        entry.checkpoint.checkpoint_id: entry.checkpoint
        for entry in entries
        if entry.kind is LineageEventKind.CHECKPOINT_PROMOTED and entry.checkpoint is not None
    }
    head = next(
        (
            entry.checkpoint
            for entry in reversed(entries)
            if entry.kind is LineageEventKind.CHECKPOINT_PROMOTED and entry.checkpoint is not None
        ),
        None,
    )
    chain: list[InvestigationCheckpoint] = []
    seen: set[str] = set()
    while head is not None and head.checkpoint_id not in seen:
        seen.add(head.checkpoint_id)
        chain.append(head)
        parent = head.parent_checkpoint_id
        head = promoted.get(parent) if parent else None
    return tuple(reversed(chain))


@runtime_checkable
class LineageStore(Protocol):
    """Where a trajectory is kept. A port, so it can be made durable.

    ``append`` takes the *content* of an entry and returns the entry the store built, for the
    reason :class:`~nemesis.authz.envelope.SpendLedger.debit` does the same: the sequence number
    and the predecessor hash belong to whatever serializes writers.
    """

    def append(
        self,
        *,
        run_id: str,
        kind: LineageEventKind,
        occurred_at: datetime,
        detail: str = "",
        facts: Mapping[str, str] | None = None,
        checkpoint: InvestigationCheckpoint | None = None,
    ) -> LineageEntry: ...

    def entries(self, run_id: str) -> tuple[LineageEntry, ...]:
        """Every entry for one run, in order. Promotions and rejections alike."""
        ...

    def runs(self) -> tuple[str, ...]: ...


class InMemoryLineageStore:
    """The default store. Correct within one process, and forgetful across a restart.

    Named so the limitation is visible at the call site, exactly as
    :class:`~nemesis.authz.envelope.InMemorySpendLedger` is. A run that must survive a restart
    wants :class:`FileLineageStore`; a unit test does not.
    """

    def __init__(self) -> None:
        self._entries: dict[str, list[LineageEntry]] = {}
        self._lock = threading.Lock()

    def append(
        self,
        *,
        run_id: str,
        kind: LineageEventKind,
        occurred_at: datetime,
        detail: str = "",
        facts: Mapping[str, str] | None = None,
        checkpoint: InvestigationCheckpoint | None = None,
    ) -> LineageEntry:
        with self._lock:
            chain = self._entries.setdefault(run_id, [])
            entry = LineageEntry(
                sequence=len(chain),
                run_id=run_id,
                kind=kind,
                occurred_at=occurred_at,
                detail=detail[:MAX_DETAIL_LENGTH],
                facts=dict(facts or {}),
                checkpoint=checkpoint,
                previous_hash=chain[-1].chain_hash() if chain else GENESIS_HASH,
            )
            chain.append(entry)
            return entry

    def entries(self, run_id: str) -> tuple[LineageEntry, ...]:
        return tuple(self._entries.get(run_id, ()))

    def runs(self) -> tuple[str, ...]:
        return tuple(sorted(self._entries))


class FileLineageStore(InMemoryLineageStore):
    """Append-only JSONL, fsynced, replayed through the public API on open.

    Subclasses rather than wraps, for the reason :class:`~nemesis.graph.journal.
    JournalBackedGraphStore` gives: the chaining under test stays the one that runs, and a replay
    that would produce an invalid chain is refused by the same validator that would have refused
    it live.

    Durability ordering is the repository's: bytes reach the file and are fsynced **before** the
    in-memory chain advances. A store whose memory ran ahead of its file would hand a resumed run
    a predecessor hash that no entry on disk produces.

    Single-process, and honest about it. A second writer would interleave lines and both would
    believe they were last. Anything that runs a fleet wants the same treatment
    :class:`~nemesis.authz.store.SqliteAuthorizationStore` gives the spend ledger, which is not
    built here.
    """

    def __init__(self, root: Path | str) -> None:
        """Load whatever is already on disk. Constructing one is opening one.

        The first version left the constructor empty and put loading in :meth:`open`, which meant
        ``FileLineageStore(root)`` on an existing journal started its sequence at zero and appended
        — producing a file with two entries numbered 0, a chain that no longer verifies, and a
        trajectory nobody can resume from. An adversarial review reproduced it in four lines, and
        the shape of the mistake is a familiar one: a door that looks like the door and skips what
        the real door does.

        So there is one behaviour and :meth:`open` is a named alias for it. Refusing to load in the
        constructor and raising instead was the alternative; loading is better, because the class
        is then correct however it is reached.
        """
        super().__init__()
        self._path = Path(root) / LINEAGE_JOURNAL
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._entries = self._load()

    @property
    def journal_path(self) -> Path:
        return self._path

    @classmethod
    def open(cls, root: Path | str) -> FileLineageStore:
        """The named door. Identical to the constructor, which also loads."""
        return cls(root)

    def _load(self) -> dict[str, list[LineageEntry]]:
        """Read the trajectory, refusing anything it cannot reconstruct exactly.

        Fail-closed on a malformed line, an unknown field or a broken chain — including a **torn
        tail**, the partial line a crash between ``write`` and ``fsync`` leaves behind. A store that
        skipped a line it could not parse would silently resurrect a spent direction as an
        unexplored one, which is the failure this whole module exists to prevent, and the audit
        trail refuses on the same grounds.

        The cost is stated rather than hidden: a torn tail makes **every** run in the file
        unreadable and there is no repair path in code. That is deliberate — repairing a
        tamper-evident record automatically is indistinguishable from tampering with it — so the
        error names the line and the operator truncates it as a documented act.
        """
        if not self._path.exists():
            return {}
        loaded: dict[str, list[LineageEntry]] = {}
        for number, line in enumerate(self._read_lines(), start=1):
            try:
                entry = LineageEntry.model_validate_json(line)
            except ValidationError as invalid:
                raise LineageError(
                    f"{self._path}:{number}: unreadable lineage entry. If this is the last line, "
                    "it is a torn tail from a crash mid-append; truncating it is a deliberate "
                    "operator act, not something this store will do for you"
                ) from invalid
            loaded.setdefault(entry.run_id, []).append(entry)
        for run_id, chain in loaded.items():
            if not verify_lineage_chain(tuple(chain)):
                raise LineageError(
                    f"{self._path}: the trajectory for {run_id} does not verify — an entry has "
                    "been removed, reordered or edited. A run cannot be resumed from a history "
                    "that does not reconstruct"
                )
        return loaded

    def append(
        self,
        *,
        run_id: str,
        kind: LineageEventKind,
        occurred_at: datetime,
        detail: str = "",
        facts: Mapping[str, str] | None = None,
        checkpoint: InvestigationCheckpoint | None = None,
    ) -> LineageEntry:
        with self._lock:
            chain = self._entries.setdefault(run_id, [])
            entry = LineageEntry(
                sequence=len(chain),
                run_id=run_id,
                kind=kind,
                occurred_at=occurred_at,
                detail=detail[:MAX_DETAIL_LENGTH],
                facts=dict(facts or {}),
                checkpoint=checkpoint,
                previous_hash=chain[-1].chain_hash() if chain else GENESIS_HASH,
            )
            self._write(entry)
            chain.append(entry)
            return entry

    def verify(self) -> bool:
        """Whether every run in this store reconstructs."""
        return all(verify_lineage_chain(self.entries(run)) for run in self.runs())

    def _read_lines(self) -> Iterator[str]:
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped:
                    yield stripped

    def _write(self, entry: LineageEntry) -> None:
        fresh = not self._path.exists()
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    entry.model_dump(mode="json"),
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                + "\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        if fresh:
            # The directory entry too, on first creation. Without it the first line can survive
            # in an unreachable inode — the detail the audit trail documents and most callers omit.
            directory = os.open(self._path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)


__all__ = [
    "LINEAGE_JOURNAL",
    "FileLineageStore",
    "InMemoryLineageStore",
    "LineageEntry",
    "LineageError",
    "LineageEventKind",
    "LineageStore",
    "active_lineage",
    "verify_lineage_chain",
]
