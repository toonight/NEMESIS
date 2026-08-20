"""Authorization state that survives a restart, and a revocation that crosses a process.

Everything the gateway knows has lived in dictionaries: requests, decisions, issued
capabilities, revocations. That was defensible while issuance and execution shared one
process and one lifetime. Neither is true any more — ADR-0007 moved the Effects plane into a
child process — and one of those dictionaries is a security control.

**Revocation is the reason this module exists.** A capability is signed, offline-verifiable
and deliberately unaffected by being withdrawn, so the *only* thing standing between a
revoked grant and its use is the oracle's answer. An oracle that lives in one process's
memory answers for that process and nobody else, and forgets everything on restart. Four
reviews recorded it as residual risk in the same words: revocation is the one control that
already fails open across a split deployment.

SQLite rather than a service: it is in the standard library, it is ACID, one file is one
deployment's state, and cross-process visibility is what it is for. The choice that matters
is not the engine but the failure direction — every path here raises rather than returning a
comfortable answer, because :class:`~nemesis.ports.authorization.RevocationOracle` says an
implementation that cannot answer must raise, and the Effects plane turns that into a refusal.

**What this does not do.** It does not authenticate revocation. Anyone who can write to the
file can withdraw any capability, which is a denial-of-service on lawful action and is
recorded as an open gap in the threat model. Persisting the list does not change that; it
only means the list is now somewhere an attacker could find it rather than somewhere it
evaporates.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager, suppress
from datetime import datetime
from pathlib import Path
from typing import Final

from pydantic import ValidationError

from nemesis.authz.envelope import SpendRecord
from nemesis.authz.gateway import ApprovalRequest
from nemesis.core.authorization import (
    GENESIS_HASH,
    Approval,
    AuthorizationCapability,
    OperationClass,
    Revocation,
)
from nemesis.core.ids import CapabilityId
from nemesis.core.temporal import utcnow
from nemesis.ports.authorization import CapabilityVerifier, ChainTip

SCHEMA_VERSION: Final = 4

_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

-- Append-only, because it is hash-chained. `sequence` is the primary key and
-- `capability_id` is deliberately *not* unique: withdrawing the same capability twice adds a
-- second link rather than editing the first. An earlier schema keyed on `capability_id` and
-- re-revoked by UPDATE, which is the contradiction this layout removes — a chain of hashes
-- over rows that can be rewritten proves nothing about rows that can be rewritten.
CREATE TABLE IF NOT EXISTS revocations (
    sequence        INTEGER PRIMARY KEY,
    capability_id   TEXT NOT NULL,
    revoked_at      TEXT NOT NULL,
    revoked_by      TEXT NOT NULL,
    reason          TEXT NOT NULL,
    chain_hash      TEXT NOT NULL,
    record          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS revocations_by_capability
    ON revocations (capability_id, revoked_at);

CREATE TABLE IF NOT EXISTS requests (
    capability_id   TEXT PRIMARY KEY,
    case_id         TEXT NOT NULL,
    requested_at    TEXT NOT NULL,
    record          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
    capability_id   TEXT NOT NULL,
    approver        TEXT NOT NULL,
    decided_at      TEXT NOT NULL,
    record          TEXT NOT NULL,
    PRIMARY KEY (capability_id, approver)
);

CREATE TABLE IF NOT EXISTS capabilities (
    capability_id   TEXT PRIMARY KEY,
    issued_at       TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    record          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS envelope_budgets (
    capability_id   TEXT PRIMARY KEY,
    budget          INTEGER NOT NULL,
    registered_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS envelope_spends (
    capability_id       TEXT NOT NULL,
    sequence            INTEGER NOT NULL,
    operation           TEXT NOT NULL,
    target_fingerprint  TEXT NOT NULL,
    requested_by        TEXT NOT NULL,
    spent_at            TEXT NOT NULL,
    previous_hash       TEXT NOT NULL,
    chain_hash          TEXT NOT NULL,
    record              TEXT NOT NULL,
    PRIMARY KEY (capability_id, sequence)
);
"""


class ChainPositionTakenError(RuntimeError):
    """Another writer took this position in the revocation chain first.

    Its own type because the caller's correct response is specific — re-read the tip, sign
    again — and a caller catching "the store is unavailable" must not swallow it and conclude
    the withdrawal was recorded.
    """


class AuthorizationStoreError(RuntimeError):
    """The store could not answer. Never swallowed, never turned into a default."""


class EnvelopeWidenedError(AuthorizationStoreError):
    """Someone tried to reopen a spent autonomy envelope with a bigger budget.

    Its own type because it is not an outage: it is the control firing. A caller catching
    "the store is unavailable" must not accidentally swallow "an authority was widened".
    """


@contextmanager
def _connect(path: Path, *, timeout: float) -> Iterator[sqlite3.Connection]:
    """One connection per operation, opened and closed.

    Deliberately not a long-lived handle. A connection held across a fork — which is what an
    isolating executor does constantly — is a connection two processes can corrupt, and the
    cost of opening a SQLite file is not worth a class of bug that appears under load.
    """
    connection = sqlite3.connect(path, timeout=timeout, isolation_level=None)
    try:
        # The returned value is checked, not assumed. `PRAGMA journal_mode` reports the mode
        # in force and returns the OLD one when the change is refused — on a network share, a
        # read-only directory, or an open connection in another mode — rather than raising. A
        # store that believed it was in WAL while journalling would have the concurrency
        # guarantees of neither, and nothing would have said so.
        mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
        if mode is None or str(mode[0]).lower() != "wal":
            raise sqlite3.DatabaseError(
                f"could not switch {path} to WAL (mode is {mode[0] if mode else 'unknown'}); "
                "refusing to use a store whose concurrency behaviour is not the one this code "
                "reasons about"
            )
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        yield connection
    finally:
        # Closing a connection to a file that turned out not to be a database raises, and
        # raising here would replace the caller's real error — "the store could not be
        # consulted" — with a confusing one from the cleanup path, or surface later as an
        # exception from `__del__` that belongs to nobody.
        with suppress(sqlite3.Error):
            connection.close()


class SqliteAuthorizationStore:
    """Durable authorization state, shared by whatever opens the same file.

    Implements :class:`~nemesis.ports.authorization.RevocationOracle`, so it can be handed
    straight to the Effects plane as the thing to ask — and it is a public key's worth of
    authority: it answers questions and issues nothing.
    """

    __slots__ = ("_path", "_timeout")

    def __init__(self, path: Path | str, *, timeout: float = 5.0) -> None:
        """``timeout`` is how long to wait for a writer's lock before giving up.

        Giving up raises. A busy store is a store that has not answered, and an oracle that
        answered "not revoked" because it was busy would be worse than one that was never
        consulted.
        """
        self._path = Path(path)
        self._timeout = timeout
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fresh = not self._path.exists() or self._path.stat().st_size == 0
            with _connect(self._path, timeout=timeout) as connection:
                if fresh:
                    connection.executescript(_SCHEMA)
                # Created on first initialisation only. Running `CREATE TABLE IF NOT EXISTS`
                # on every open silently *repaired* a store whose revocations table had been
                # renamed away: the next `is_revoked` answered "not revoked" for everything,
                # with no error and no trace. Within the documented "we do not authenticate
                # revocation" gap, and still the wrong direction — tampering must look like
                # tampering, not like an empty list.
                stored = connection.execute("SELECT version FROM schema_version").fetchone()
                if stored is None:
                    connection.execute(
                        "INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,)
                    )
                elif stored[0] != SCHEMA_VERSION:
                    raise AuthorizationStoreError(
                        f"{self._path} carries schema version {stored[0]}, this build expects "
                        f"{SCHEMA_VERSION}; refusing to read authorization state written by a "
                        "different understanding of what these rows mean"
                    )
        except sqlite3.Error as exc:
            raise AuthorizationStoreError(f"could not open {self._path}: {exc}") from exc

    @property
    def path(self) -> Path:
        return self._path

    # -- revocation, which is the part that must never fail open ----------------

    def is_revoked(self, capability_id: CapabilityId) -> bool:
        """The question the Effects plane asks immediately before acting.

        Raises on any failure at all — unreadable file, lock timeout, corrupt row. The
        caller's contract is to treat that as a refusal, and
        :func:`nemesis.effects.registry.preflight` does.
        """
        try:
            with (
                _connect(self._path, timeout=self._timeout) as connection,
                closing(
                    connection.execute(
                        "SELECT 1 FROM revocations WHERE capability_id = ?", (capability_id,)
                    )
                ) as cursor,
            ):
                return cursor.fetchone() is not None
        except sqlite3.Error as exc:
            raise AuthorizationStoreError(
                f"the revocation store could not be consulted ({type(exc).__name__}: {exc}); "
                "an unreachable oracle is not an oracle reporting no revocation"
            ) from exc

    def record(self, revocation: Revocation) -> Revocation:
        """Append a withdrawal. The earliest one governs, and the earliest one is returned.

        **Appends; never edits.** Re-revoking the same capability adds a link rather than
        rewriting the one already there, and which withdrawal *governs* is then decided when
        the store is read: the earliest, always.

        This used to be an `ON CONFLICT ... DO UPDATE` guarded by
        `WHERE excluded.revoked_at < revocations.revoked_at`, which read as a neat way to make
        earliest-wins atomic. It had two problems, and the second is the one that matters.

        The visible one: the update refreshed `revoked_at`, `revoked_by`, `reason` and
        `record` and left `sequence` and `chain_hash` behind, so the stored JSON described one
        position in the chain while its own columns described another. `verify_chain` then
        reported deletions — permanently, and on a store from which nothing had been deleted.

        The real one: a hash chain over rows that can be rewritten is not a hash chain. The
        chain exists to make a *removal* visible, and every link's hash covers the link before
        it; editing any row invalidates every row after it, so the operation the old SQL made
        convenient was precisely the one the structure exists to forbid. Invariant 10 says
        append-only, and now the table is.

        Re-revoking with a *later* time still changes nothing that governs — the earliest link
        keeps winning — so the property the old `WHERE` clause protected is preserved, by
        reading rather than by writing. A second withdrawal can no longer narrow the window in
        which the first applied, because it cannot touch the first at all.
        """
        try:
            with _connect(self._path, timeout=self._timeout) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    connection.execute(
                        """
                        INSERT INTO revocations
                            (sequence, capability_id, revoked_at, revoked_by, reason,
                             chain_hash, record)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            revocation.sequence,
                            revocation.capability_id,
                            revocation.revoked_at.isoformat(),
                            revocation.revoked_by,
                            revocation.reason,
                            revocation.chain_hash(),
                            revocation.model_dump_json(),
                        ),
                    )
                except sqlite3.IntegrityError as clash:
                    connection.execute("ROLLBACK")
                    if clash.sqlite_errorcode != sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
                        # Not a position collision. Reporting it as one would tell the caller
                        # to re-read the tip and sign again — advice that loops forever on a
                        # constraint no retry can satisfy.
                        raise AuthorizationStoreError(
                            f"the revocation was refused by a constraint that retrying cannot "
                            f"satisfy: {clash}"
                        ) from clash
                    # Two writers read the same `tip()` and both signed a link for the same
                    # position. The primary key refuses the second, loudly, which is the
                    # outcome to want: a signature covers the sequence, so the position cannot
                    # be reassigned after the fact, and two links silently claiming one
                    # position is exactly the corruption the chain exists to expose. The
                    # caller re-reads the tip and signs again.
                    raise ChainPositionTakenError(
                        f"position {revocation.sequence} in the revocation chain is already "
                        "occupied; another writer took it between reading the tip and "
                        "recording. Re-read the tip and sign the withdrawal again — the "
                        "position is part of what was signed and cannot be renumbered here"
                    ) from clash
                connection.execute("COMMIT")
                return self._revocation(connection, revocation.capability_id) or revocation
        except sqlite3.Error as exc:
            raise AuthorizationStoreError(f"could not record a revocation: {exc}") from exc

    def tip(self) -> ChainTip:
        """Where the next revocation attaches.

        **Not taken under the write lock**, and it cannot be: the caller reads the tip, builds
        a revocation, *signs* it — the signature covers the sequence — and only then records.
        No lock is held across that. This docstring used to claim otherwise, which was the
        more dangerous half of the bug, because a reader would have stopped looking for the
        race.

        What actually forbids two links at one position is the primary key: the second writer
        is refused with :class:`ChainPositionTakenError` and re-signs against a fresh tip.
        Enforced by the store rather than by a promise about timing.
        """
        try:
            with (
                _connect(self._path, timeout=self._timeout) as connection,
                closing(
                    connection.execute(
                        "SELECT sequence, chain_hash FROM revocations "
                        "ORDER BY sequence DESC LIMIT 1"
                    )
                ) as cursor,
            ):
                row = cursor.fetchone()
        except sqlite3.Error as exc:
            raise AuthorizationStoreError(f"could not read the revocation chain: {exc}") from exc
        return ChainTip(0, GENESIS_HASH) if row is None else ChainTip(row[0] + 1, row[1])

    def verify_chain(self, verifier: CapabilityVerifier) -> tuple[str, ...]:
        """Check every signature and every link. Returns the defects, empty when sound.

        Two separate questions asked together because they fail together in practice: a
        revocation nobody signed is one somebody inserted, and a broken link is one somebody
        removed. A store that checked only signatures would certify a chain with a hole in it.
        """
        defects: list[str] = []
        previous = GENESIS_HASH
        for position, revocation in enumerate(self.revocations()):
            if revocation.sequence != position:
                defects.append(
                    f"revocation {position}: sequence is {revocation.sequence}; a withdrawal "
                    "was removed or reordered"
                )
            if revocation.previous_hash != previous:
                defects.append(
                    f"revocation {position} ({revocation.capability_id}): does not follow the "
                    "one before it — a withdrawal was deleted from this store"
                )
            if revocation.signature is None or not verifier.verify(
                revocation.signing_payload(), revocation.signature
            ):
                defects.append(
                    f"revocation {position} ({revocation.capability_id}): not signed by the "
                    "issuing authority — somebody who is not the gateway wrote this row"
                )
            previous = revocation.chain_hash()
        return tuple(defects)

    def revocation(self, capability_id: CapabilityId) -> Revocation | None:
        """The withdrawal itself, for a reader who needs the reason and not just the fact."""
        try:
            with _connect(self._path, timeout=self._timeout) as connection:
                return self._revocation(connection, capability_id)
        except sqlite3.Error as exc:
            raise AuthorizationStoreError(f"could not read a revocation: {exc}") from exc

    def revocations(self) -> tuple[Revocation, ...]:
        try:
            with (
                _connect(self._path, timeout=self._timeout) as connection,
                closing(
                    # Chain order, which is append order. Ordering by `revoked_at` — as this
                    # did — meant a re-revocation with an earlier time silently *reordered*
                    # the chain, and every sequence after it stopped matching its position.
                    connection.execute("SELECT record FROM revocations ORDER BY sequence")
                ) as cursor,
            ):
                return tuple(self._parse(Revocation, row[0]) for row in cursor.fetchall())
        except sqlite3.Error as exc:
            raise AuthorizationStoreError(f"could not list revocations: {exc}") from exc

    # -- the approval chain, so a restart does not lose what was decided --------

    def save_request(self, request: ApprovalRequest) -> None:
        self._upsert(
            "INSERT OR REPLACE INTO requests (capability_id, case_id, requested_at, record) "
            "VALUES (?, ?, ?, ?)",
            (
                request.capability_id,
                request.case_id,
                request.requested_at.isoformat(),
                request.model_dump_json(),
            ),
        )

    def save_decision(self, capability_id: CapabilityId, approval: Approval) -> None:
        """One row per (capability, approver), which is dual control expressed as a key.

        A second decision from the same person replaces their first rather than counting
        twice — the gateway already refuses that, and a storage layer that could represent
        it would be a storage layer a future gateway bug could exploit.
        """
        self._upsert(
            "INSERT OR REPLACE INTO decisions (capability_id, approver, decided_at, record) "
            "VALUES (?, ?, ?, ?)",
            (
                capability_id,
                approval.approver,
                approval.decided_at.isoformat(),
                approval.model_dump_json(),
            ),
        )

    def save_capability(self, capability: AuthorizationCapability) -> None:
        self._upsert(
            "INSERT OR REPLACE INTO capabilities (capability_id, issued_at, expires_at, record) "
            "VALUES (?, ?, ?, ?)",
            (
                capability.capability_id,
                capability.issued_at.isoformat(),
                capability.expires_at.isoformat(),
                capability.model_dump_json(),
            ),
        )

    def requests(self) -> tuple[ApprovalRequest, ...]:
        return tuple(
            self._parse(ApprovalRequest, record)
            for record in self._all("SELECT record FROM requests ORDER BY requested_at")
        )

    def decisions(self, capability_id: CapabilityId) -> tuple[Approval, ...]:
        return tuple(
            self._parse(Approval, record)
            for record in self._all(
                "SELECT record FROM decisions WHERE capability_id = ? ORDER BY decided_at",
                (capability_id,),
            )
        )

    def capabilities(self) -> tuple[AuthorizationCapability, ...]:
        return tuple(
            self._parse(AuthorizationCapability, record)
            for record in self._all("SELECT record FROM capabilities ORDER BY issued_at")
        )

    # -- the autonomy envelope's spend ledger, which must be atomic -------------

    def register(self, capability_id: CapabilityId, budget: int) -> int:
        """Record an envelope's ceiling, and refuse to widen one already in circulation.

        This is what stops a restart from becoming a fresh budget. Reopening the same
        capability with a larger number is the whole attack — an operator or a compromised
        orchestrator restarts the process with ``max_autonomous_effects=999`` and the spent
        envelope is full again — so a larger budget raises rather than being believed. A
        *smaller* one is a narrowing and is honoured, because nothing that only ever reduces
        authority needs to be refused.
        """
        try:
            with _connect(self._path, timeout=self._timeout) as connection:
                connection.execute("BEGIN IMMEDIATE")
                with closing(
                    connection.execute(
                        "SELECT budget FROM envelope_budgets WHERE capability_id = ?",
                        (capability_id,),
                    )
                ) as cursor:
                    row = cursor.fetchone()
                if row is not None and budget > row[0]:
                    connection.execute("ROLLBACK")
                    raise EnvelopeWidenedError(
                        f"{capability_id} was registered with a budget of {row[0]}; reopening "
                        f"it with {budget} would widen an authority already in circulation. An "
                        "envelope narrows; it never grows back"
                    )
                effective = budget if row is None else min(row[0], budget)
                connection.execute(
                    "INSERT INTO envelope_budgets (capability_id, budget, registered_at) "
                    "VALUES (?, ?, ?) "
                    "ON CONFLICT(capability_id) DO UPDATE SET budget = excluded.budget",
                    (capability_id, effective, utcnow().isoformat()),
                )
                connection.execute("COMMIT")
                return effective
        except sqlite3.Error as exc:
            raise AuthorizationStoreError(
                f"could not register an autonomy envelope: {exc}"
            ) from exc

    def debit(
        self,
        *,
        capability_id: CapabilityId,
        operation: OperationClass,
        target_fingerprint: str,
        requested_by: str,
        spent_at: datetime,
    ) -> SpendRecord | None:
        """Spend one autonomous effect, atomically, or return ``None`` when the budget is gone.

        The count and the append happen inside one ``BEGIN IMMEDIATE`` transaction, which is
        the point of this implementation rather than a detail of it. Durability is the visible
        half of making a budget real; **atomicity is the half that matters**. Two processes —
        or two coroutines in a fleet sharing one file — that each read "three spent of four"
        and then each append would both act, and the ceiling would have bounded nothing. Here
        the second one waits for the write lock and reads four.

        Returns ``None`` rather than raising on exhaustion, because that is an expected outcome
        the mediator records as a refusal. A store that *cannot answer* still raises: an
        unreachable ledger is not a ledger reporting room to spend.
        """
        try:
            with _connect(self._path, timeout=self._timeout) as connection:
                connection.execute("BEGIN IMMEDIATE")
                with closing(
                    connection.execute(
                        "SELECT budget FROM envelope_budgets WHERE capability_id = ?",
                        (capability_id,),
                    )
                ) as cursor:
                    budget_row = cursor.fetchone()
                budget = 0 if budget_row is None else int(budget_row[0])

                with closing(
                    connection.execute(
                        "SELECT sequence, chain_hash FROM envelope_spends "
                        "WHERE capability_id = ? ORDER BY sequence DESC LIMIT 1",
                        (capability_id,),
                    )
                ) as cursor:
                    tip = cursor.fetchone()
                next_sequence = 0 if tip is None else int(tip[0]) + 1
                previous_hash = GENESIS_HASH if tip is None else str(tip[1])

                if next_sequence >= budget:
                    connection.execute("ROLLBACK")
                    return None

                record = SpendRecord(
                    sequence=next_sequence,
                    capability_id=capability_id,
                    operation=operation,
                    target_fingerprint=target_fingerprint,
                    requested_by=requested_by,
                    spent_at=spent_at,
                    previous_hash=previous_hash,
                )
                connection.execute(
                    "INSERT INTO envelope_spends (capability_id, sequence, operation, "
                    "target_fingerprint, requested_by, spent_at, previous_hash, chain_hash, "
                    "record) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        capability_id,
                        record.sequence,
                        record.operation.value,
                        record.target_fingerprint,
                        record.requested_by,
                        record.spent_at.isoformat(),
                        record.previous_hash,
                        record.chain_hash(),
                        record.model_dump_json(),
                    ),
                )
                connection.execute("COMMIT")
                return record
        except sqlite3.Error as exc:
            raise AuthorizationStoreError(
                f"the autonomy envelope's ledger could not be written ({type(exc).__name__}: "
                f"{exc}); an unreachable ledger is not a ledger reporting room to spend"
            ) from exc

    def spends(self, capability_id: CapabilityId) -> tuple[SpendRecord, ...]:
        """Every debit against one envelope, in order.

        Ordered by ``sequence`` rather than by timestamp: the sequence is what the chain binds,
        and two spends inside the same clock tick must still come back in the order they were
        written.
        """
        return tuple(
            self._parse(SpendRecord, record)
            for record in self._all(
                "SELECT record FROM envelope_spends WHERE capability_id = ? ORDER BY sequence",
                (capability_id,),
            )
        )

    def budget_of(self, capability_id: CapabilityId) -> int | None:
        """The registered ceiling, or ``None`` if this envelope was never opened here."""
        rows = self._all(
            "SELECT budget FROM envelope_budgets WHERE capability_id = ?", (capability_id,)
        )
        return int(rows[0]) if rows else None

    # -- helpers ---------------------------------------------------------------

    def _revocation(
        self, connection: sqlite3.Connection, capability_id: CapabilityId
    ) -> Revocation | None:
        with closing(
            connection.execute(
                # Earliest wins, decided here rather than by editing rows. `sequence` breaks
                # a tie so the answer is deterministic when two links share an instant.
                "SELECT record FROM revocations WHERE capability_id = ? "
                "ORDER BY revoked_at ASC, sequence ASC LIMIT 1",
                (capability_id,),
            )
        ) as cursor:
            row = cursor.fetchone()
        return None if row is None else self._parse(Revocation, row[0])

    def _upsert(self, statement: str, parameters: tuple[object, ...]) -> None:
        try:
            with _connect(self._path, timeout=self._timeout) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(statement, parameters)
                connection.execute("COMMIT")
        except sqlite3.Error as exc:
            raise AuthorizationStoreError(f"could not write authorization state: {exc}") from exc

    def _all(self, statement: str, parameters: tuple[object, ...] = ()) -> tuple[str, ...]:
        try:
            with (
                _connect(self._path, timeout=self._timeout) as connection,
                closing(connection.execute(statement, parameters)) as cursor,
            ):
                return tuple(row[0] for row in cursor.fetchall())
        except sqlite3.Error as exc:
            raise AuthorizationStoreError(f"could not read authorization state: {exc}") from exc

    @staticmethod
    def _parse[T](model: type[T], record: str) -> T:
        """Rebuild through the model's validators, never by trusting the row.

        The same rule as ADR-0006: what bytes say is decided by parsing them. A row edited
        on disk is exactly the "object handed to you alongside the signature" case, one
        storage layer down — and for a capability, the signature is re-checked downstream
        against these very bytes, so a tampered row fails there too.
        """
        try:
            return model.model_validate_json(record)  # type: ignore[attr-defined, no-any-return]
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            raise AuthorizationStoreError(
                f"a stored {model.__name__} row is not a valid {model.__name__}: {exc}"
            ) from exc


def isoformat(moment: datetime) -> str:
    """Exported so a reader can see that ordering in this store is lexicographic on ISO-8601.

    Which is only true for timezone-aware, UTC-normalised timestamps — every timestamp in
    this codebase is, enforced by :mod:`nemesis.core.temporal`.
    """
    return moment.isoformat()
