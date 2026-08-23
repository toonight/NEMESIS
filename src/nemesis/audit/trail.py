"""An append-only, hash-chained audit trail backed by a JSONL file.

Invariant 11 asks for *replayable*, not *logged*. The distinction is the whole design:
a log says "agent-7 pivoted on 198.51.100.23"; a replayable trail says which connector at
which version was asked what, so the pivot can be re-run and the answer compared. Only the
second lets anyone establish, months later, whether a link that ended up in an attribution
was justified at the time or was an artifact of a connector build nobody kept.

That is why the recording helpers below take the replay inputs as *required* keyword
arguments. An optional ``connector_version`` is a field that is empty in exactly the
records an investigation later depends on.

Three properties the file carries, and what each one actually buys:

**Attribution.** Every entry names an actor and one of four actor kinds. An action with no
attributable actor is refused at :meth:`AppendOnlyAuditTrail.record`, including the
plausible-looking placeholders ("system", "unknown", "user"), because an unattributable
entry is indistinguishable from an entry someone declined to sign.

**Chaining.** Each entry hashes its own canonical encoding together with its predecessor's
hash. Insertion, deletion, reordering and modification all break the chain, and they break
it differently — :meth:`AppendOnlyAuditTrail.verify` reports which and where. A chain that
only catches in-place modification is the common useless variant: it is defeated by an
editor that simply drops a line.

**Durability.** A write that fails raises. The in-memory head advances only after the bytes
are on disk, because a head that ran ahead of the file would chain the next entry onto a
hash nobody can verify, quietly forking the trail at the exact moment it was under stress.

What this does *not* buy, stated because the vault module states the same thing and the
threat model is the same: an internal hash chain is defeated by anyone who can rewrite the
whole file, since they can recompute it. It detects corruption, careless editing and
partial tampering. Only an external anchor over :meth:`AppendOnlyAuditTrail.head` closes
the gap against an operator, and tail truncation that happens before this process ever
opened the file cannot be seen at all from the file alone.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, NamedTuple

from pydantic import BaseModel, ConfigDict, ValidationError

from nemesis.core.authorization import AuthorizationDecision
from nemesis.core.identity import ActorKind as ActorKind
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.relationships import PivotMethod, RelationType
from nemesis.core.temporal import utcnow
from nemesis.ports.effects import EffectRequest, EffectResult
from nemesis.ports.storage import AuditEvent

HASH_PREFIX: Final = "sha256:"

MAX_RENDERED_RESULTS: Final = 8
"""How many result identifiers an outcome string spells out before summarising.

The demo scenario's control case is a CDN address hosting 41,700 domains. Inlining that
result set would make the entry unreadable and the trail enormous, so the rendering keeps a
digest of the full sorted set — exactly comparable on replay — plus a readable head.
"""

_UNATTRIBUTABLE_ACTORS: Final = frozenset(
    {
        "",
        "-",
        "?",
        "n/a",
        "na",
        "none",
        "null",
        "nobody",
        "someone",
        "unknown",
        "anonymous",
        "user",
        "system",
        "agent",
        "rule",
        "human",
    }
)
"""Actor strings that name nobody.

A system action is still attributable: the actor is the component
("pursuit-scheduler", "resurgence-watcher"), not the word "system". Accepting the generic
token would let a whole class of actions accumulate under one meaningless name, which is
the same failure as not recording an actor at all — only harder to notice.
"""


class AuditWriteError(RuntimeError):
    """An event could not be appended, or could not be proven to have been appended.

    Raised rather than swallowed: a caller that believes it recorded an authorization
    denial when it did not is worse off than a caller that crashed, because the first one
    keeps going and produces an investigation with a hole in it.
    """


class UnattributedActionError(ValueError):
    """An action was submitted with no attributable actor or an unknown actor kind."""


class ChainVerification(BaseModel):
    """Where the chain broke, if it did.

    :meth:`AppendOnlyAuditTrail.verify_chain` returns the port's bare ``bool``. That bool
    is useless to whoever has to act on it, so the underlying check reports the index and
    the failure mode as well.
    """

    model_config = ConfigDict(frozen=True)

    intact: bool
    entries_checked: int
    broken_at: int | None = None
    """Zero-based index of the first entry that failed, or None."""

    reason: str | None = None


def outcome_token(outcome: str) -> str:
    """The leading, machine-comparable word of an outcome string.

    Outcomes follow ``"<token> <detail>"``: the token is a stable value an operator can
    filter on ("denied", "discovered", "simulated"), the detail is free text. Keeping the
    convention in one function stops it from being re-derived, differently, at each call
    site.
    """
    return outcome.split(" ", 1)[0]


def render_result_set(values: Iterable[str]) -> str:
    """Render a set of discovered identifiers as a deterministic, bounded outcome string.

    Sorted and de-duplicated before hashing: a pivot returning the same four domains in a
    different order is the same result, and a replay that reported a spurious difference
    would train people to ignore the comparison.
    """
    ordered = sorted(set(values))
    digest = hashlib.sha256("\n".join(ordered).encode("utf-8")).hexdigest()
    head = ",".join(ordered[:MAX_RENDERED_RESULTS])
    elision = ",..." if len(ordered) > MAX_RENDERED_RESULTS else ""
    return f"discovered {len(ordered)} {HASH_PREFIX}{digest} [{head}{elision}]"


def make_event(
    *,
    actor: str,
    actor_kind: ActorKind,
    action: str,
    subject: str,
    outcome: str,
    inputs: Mapping[str, str] | None = None,
    authorization_decision: AuthorizationDecision | None = None,
    occurred_at: datetime | None = None,
) -> AuditEvent:
    """Mint an unsealed audit event.

    ``actor_kind`` is typed as the enum here so the common construction path cannot produce
    an unclassifiable actor; :meth:`AppendOnlyAuditTrail.record` re-checks it because the
    port accepts events built by anyone.
    """
    return AuditEvent(
        audit_id=new_id(IdPrefix.AUDIT),
        occurred_at=occurred_at or utcnow(),
        actor=actor,
        actor_kind=actor_kind.value,
        action=action,
        subject=subject,
        outcome=outcome,
        inputs=dict(inputs or {}),
        authorization_decision=authorization_decision,
    )


class AppendOnlyAuditTrail:
    """A hash-chained audit trail persisted as one JSON object per line.

    Satisfies :class:`nemesis.ports.storage.AuditSink`. Single-writer by construction: two
    processes appending to one file would both chain onto the same head and fork the trail.
    A concurrent writer is detected — the file size no longer matches what this instance
    last wrote — and refused rather than merged, because merging two forks silently would
    produce a trail that verifies and is still wrong.
    """

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        # The critical section performs synchronous file I/O and contains no await, so a
        # plain mutex is correct here. asyncio.Lock would additionally bind the trail to
        # whichever event loop touched it first, which a long-lived sink must not be.
        self._lock = threading.Lock()

        scan = _scan(self._path)
        self._head: str | None = scan.head
        self._count = len(scan.events)
        self._known_ids = {event.audit_id for event in scan.events}
        self._expected_size = scan.size
        self._unreadable_from_line = scan.malformed_line

    @property
    def path(self) -> Path:
        return self._path

    # -- AuditSink ------------------------------------------------------------

    async def record(self, event: AuditEvent) -> AuditEvent:
        """Seal an event into the chain and append it. Returns the sealed event.

        Async because the port declares it so; the implementation is synchronous, and
        deliberately so — an audit write that returns before the bytes are durable is a
        write that can be lost between the action and the record of it.
        """
        _require_attributable_actor(event)
        _require_aware(event.occurred_at, "occurred_at")
        if event.previous_hash is not None or event.entry_hash is not None:
            # The chain links are assigned here. A caller supplying them is either
            # confused or choosing its own position in the chain; both must fail loudly.
            raise AuditWriteError(
                f"{event.audit_id} arrives with chain hashes already set; the trail assigns "
                "previous_hash and entry_hash and never accepts them from a caller"
            )

        with self._lock:
            if self._unreadable_from_line is not None:
                raise AuditWriteError(
                    f"{self._path} is unreadable from line {self._unreadable_from_line}; "
                    "refusing to extend a chain whose tail cannot be verified"
                )
            if event.audit_id in self._known_ids:
                raise AuditWriteError(
                    f"{event.audit_id} is already in the trail; re-recording an audit id "
                    "would make the identifier ambiguous as a reference"
                )

            current_size = self._path.stat().st_size if self._path.exists() else 0
            if current_size != self._expected_size:
                raise AuditWriteError(
                    f"{self._path} changed on disk (expected {self._expected_size} bytes, "
                    f"found {current_size}); another writer or an editor has touched the "
                    "trail and appending now would fork the chain"
                )

            sealed = event.model_copy(update={"previous_hash": self._head})
            sealed = sealed.model_copy(update={"entry_hash": _entry_hash(sealed)})

            try:
                new_size = _append_line(self._path, _encode(sealed))
            except OSError as exc:
                raise AuditWriteError(
                    f"failed to append {event.audit_id} to {self._path}: {exc}"
                ) from exc

            # State advances only after the bytes are durable. The reverse order would let
            # a failed write leave the next entry chained onto a hash absent from the file.
            self._head = sealed.entry_hash
            self._count += 1
            self._known_ids.add(sealed.audit_id)
            self._expected_size = new_size

        return sealed

    async def query(
        self,
        *,
        actor: str | None = None,
        action: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        outcome: str | None = None,
        limit: int = 100,
    ) -> Sequence[AuditEvent]:
        """Filter the trail by actor, action, outcome token and time window.

        The window is half-open, ``since <= occurred_at < until``, so adjacent windows
        partition the trail instead of double-counting the events on the boundary.

        When more entries match than ``limit``, the **most recent** are returned, in
        chronological order. Truncating from the other end would hide the newest activity,
        which is the opposite of what anyone querying an audit trail wants.
        """
        if limit < 0:
            raise ValueError("limit must not be negative")
        if since is not None:
            _require_aware(since, "since")
        if until is not None:
            _require_aware(until, "until")

        matches = [
            event
            for event in _scan(self._path).events
            if (actor is None or event.actor == actor)
            and (action is None or event.action == action)
            and (outcome is None or outcome_token(event.outcome) == outcome)
            and (since is None or event.occurred_at >= since)
            and (until is None or event.occurred_at < until)
        ]
        return tuple(matches[-limit:]) if limit else ()

    async def verify_chain(self) -> bool:
        """Whether the trail on disk is intact. See :meth:`verify` for what broke."""
        return (await self.verify()).intact

    # -- beyond the port ------------------------------------------------------

    async def verify(self) -> ChainVerification:
        """Re-read the file and check every link, reporting the first failure.

        Four failure modes, which is the point of checking in this order:

        - an entry whose recomputed hash differs from its stored one was **modified**;
        - an entry whose ``previous_hash`` does not match its predecessor's hash sits after
          an **insertion**, an interior **deletion**, or a **reordering**;
        - a file shorter than what this instance wrote had its **tail removed** — the one
          case the links alone cannot catch, since a truncated chain is still internally
          consistent.
        """
        scan = _scan(self._path)
        if scan.malformed_line is not None:
            return ChainVerification(
                intact=False,
                entries_checked=len(scan.events),
                broken_at=len(scan.events),
                reason=f"line {scan.malformed_line} is not a readable audit entry",
            )

        previous: str | None = None
        for index, event in enumerate(scan.events):
            if event.entry_hash is None:
                return ChainVerification(
                    intact=False,
                    entries_checked=index,
                    broken_at=index,
                    reason=f"entry {index} carries no entry_hash and was never sealed",
                )
            if event.previous_hash != previous:
                return ChainVerification(
                    intact=False,
                    entries_checked=index,
                    broken_at=index,
                    reason=(
                        f"entry {index} does not follow entry {index - 1}: an entry was "
                        "inserted, removed or reordered"
                    ),
                )
            if _entry_hash(event) != event.entry_hash:
                return ChainVerification(
                    intact=False,
                    entries_checked=index,
                    broken_at=index,
                    reason=f"entry {index} was modified after it was sealed",
                )
            previous = event.entry_hash

        # Tail truncation leaves a chain that links perfectly and is missing the end of the
        # story. Only a head remembered outside the file exposes it.
        if self._count > 0:
            if len(scan.events) < self._count:
                return ChainVerification(
                    intact=False,
                    entries_checked=len(scan.events),
                    broken_at=len(scan.events),
                    reason=(
                        f"the trail holds {len(scan.events)} entries but {self._count} were "
                        "written: entries were removed from the end"
                    ),
                )
            if scan.events[self._count - 1].entry_hash != self._head:
                return ChainVerification(
                    intact=False,
                    entries_checked=len(scan.events),
                    broken_at=self._count - 1,
                    reason=(
                        "the entry at the last position this instance wrote no longer "
                        "carries the head it was given: the trail was rewritten"
                    ),
                )

        return ChainVerification(intact=True, entries_checked=len(scan.events))

    async def head(self) -> str | None:
        """The current chain head, suitable for external anchoring. None if empty.

        Publishing this to somewhere we cannot quietly rewrite is what makes the chain
        worth anything against an operator who controls the file (invariant 10's reasoning,
        applied to actions rather than artifacts).
        """
        return self._head

    async def entry_count(self) -> int:
        return self._count

    # -- recording helpers ----------------------------------------------------

    async def record_pivot(
        self,
        *,
        actor: str,
        actor_kind: ActorKind,
        connector: str,
        connector_version: str,
        method: PivotMethod,
        relation: RelationType,
        from_entity: str,
        query_parameters: Mapping[str, str],
        discovered: Iterable[str],
        occurred_at: datetime | None = None,
    ) -> AuditEvent:
        """Record one pursuit pivot, with enough to re-run it.

        ``connector_version`` is required for the same reason
        :class:`~nemesis.core.provenance.CollectionMethod` requires it: a pivot re-run
        against a different connector build is a different pivot, and if the version is not
        in the record then a replay that disagrees proves nothing.
        """
        inputs = {
            "connector": connector,
            "connector_version": connector_version,
            "method": method.value,
            "relation": relation.value,
            "from_entity": from_entity,
        }
        # Connector parameters are namespaced so a parameter named "connector" cannot
        # shadow the replay metadata — a collision here would silently rewrite the record
        # of which tool was run.
        inputs.update({f"param.{key}": value for key, value in query_parameters.items()})

        return await self.record(
            make_event(
                actor=actor,
                actor_kind=actor_kind,
                action="pursuit.pivot",
                subject=from_entity,
                outcome=render_result_set(discovered),
                inputs=inputs,
                occurred_at=occurred_at,
            )
        )

    async def record_authorization(
        self,
        *,
        actor: str,
        actor_kind: ActorKind,
        decision: AuthorizationDecision,
        subject: str,
        inputs: Mapping[str, str] | None = None,
        occurred_at: datetime | None = None,
    ) -> AuditEvent:
        """Record an authorization decision, permitted or denied.

        There is no branch here on ``decision.permitted``. A trail that records only the
        successes hides the pattern an investigator most wants: repeated denied attempts
        against the same target, which is what an agent probing its own limits, or a
        compromised caller, looks like from the outside.

        ``subject`` is the target in readable form (a domain, a wallet, a case) because a
        fingerprint is unusable as a search key by a human reading the trail later.
        """
        derived = {
            "capability_id": decision.capability_id,
            "operation": decision.operation.value,
            "target_fingerprint": decision.target_fingerprint,
            "evaluated_at": decision.evaluated_at.astimezone(UTC).isoformat(),
        }
        # Caller extras first: the facts taken from the decision itself must not be
        # overwritable by whoever is reporting it.
        merged = {**dict(inputs or {}), **derived}

        return await self.record(
            make_event(
                actor=actor,
                actor_kind=actor_kind,
                action="authorization.decision",
                subject=subject,
                outcome="permitted" if decision.permitted else "denied",
                inputs=merged,
                authorization_decision=decision,
                occurred_at=occurred_at,
            )
        )

    async def record_effect(
        self,
        *,
        actor: str,
        actor_kind: ActorKind,
        request: EffectRequest,
        result: EffectResult,
        occurred_at: datetime | None = None,
    ) -> AuditEvent:
        """Record an executed or refused effect, with the request that produced it.

        Both halves are required: the request holds the target state that was checked
        against the approved fingerprint, and without it a refusal reading
        ``refused_target_changed`` cannot be re-examined to see *what* had changed.
        """
        if request.operation_id != result.operation_id:
            raise ValueError(
                f"request {request.operation_id} and result {result.operation_id} describe "
                "different operations; recording them as one entry would make the trail lie"
            )

        inputs = {
            "operation_id": request.operation_id,
            "operation": request.operation.value,
            "adapter": result.adapter_name,
            "target_fingerprint": request.target_fingerprint,
            "target_natural_key": request.target_natural_key,
            "requested_by": request.requested_by,
            "requested_at": request.requested_at.astimezone(UTC).isoformat(),
        }
        inputs.update({f"param.{key}": value for key, value in request.parameters.items()})
        inputs.update(
            {f"target.{key}": value for key, value in request.current_target_attributes.items()}
        )

        artifacts = ",".join(result.produced_artifacts) or "none"
        outcome = (
            f"{result.outcome.value} adapter={result.adapter_name} "
            f"external_contact={str(result.external_contact_made).lower()} "
            f"artifacts={artifacts} detail={result.detail}"
        )

        return await self.record(
            make_event(
                actor=actor,
                actor_kind=actor_kind,
                action="effect.execute",
                subject=request.target_natural_key,
                outcome=outcome,
                inputs=inputs,
                authorization_decision=result.authorization,
                occurred_at=occurred_at,
            )
        )


# -- encoding and chaining ----------------------------------------------------


def _entry_hash(event: AuditEvent) -> str:
    """Hash over a canonical encoding of the event, including its predecessor's hash.

    The field list is written out rather than taken from ``model_dump`` on purpose: adding
    a field to :class:`AuditEvent` would otherwise silently invalidate every hash already
    on disk, and the trail would fail verification for a schema change rather than for
    tampering.

    ``occurred_at`` is normalised to UTC before hashing so that a timestamp written as
    ``+02:00`` and read back as ``Z`` hashes identically — otherwise a JSON round-trip
    through a different serializer would look exactly like modification.
    """
    decision = (
        event.authorization_decision.model_dump(mode="json")
        if event.authorization_decision is not None
        else None
    )
    payload = json.dumps(
        {
            "audit_id": event.audit_id,
            "occurred_at": event.occurred_at.astimezone(UTC).isoformat(),
            "actor": event.actor,
            "actor_kind": event.actor_kind,
            "action": event.action,
            "subject": event.subject,
            "outcome": event.outcome,
            "inputs": dict(sorted(event.inputs.items())),
            "authorization_decision": decision,
            "previous_hash": event.previous_hash or "",
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return f"{HASH_PREFIX}{hashlib.sha256(payload).hexdigest()}"


def _encode(event: AuditEvent) -> str:
    return json.dumps(
        event.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _append_line(path: Path, line: str) -> int:
    """Append one line durably and return the file's new size in bytes.

    Written as a single ``write`` on a file opened for append, then fsynced, so that a
    crash leaves either the whole entry or nothing where an interrupted buffered write
    would leave a half-entry that reads as tampering.
    """
    existed = path.exists()
    with path.open("ab") as handle:
        handle.write((line + "\n").encode("utf-8"))
        handle.flush()
        os.fsync(handle.fileno())
        size = handle.tell()
    if not existed:
        # fsync on the file does not commit the directory entry that names it; without
        # this, the first event of a brand-new trail can survive in an unreachable inode.
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return size


class _Scan(NamedTuple):
    events: tuple[AuditEvent, ...]
    size: int
    malformed_line: int | None
    """1-based number of the first unreadable line, or None."""

    @property
    def head(self) -> str | None:
        return self.events[-1].entry_hash if self.events else None


def _scan(path: Path) -> _Scan:
    """Read every entry, stopping at the first line that will not parse.

    A malformed line is reported rather than skipped. Skipping it would make a corrupted or
    partially-overwritten trail verify as if the missing entries had never existed, which
    is precisely the outcome tampering aims for.
    """
    if not path.exists():
        return _Scan(events=(), size=0, malformed_line=None)

    size = path.stat().st_size
    events: list[AuditEvent] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            events.append(AuditEvent.model_validate(json.loads(line)))
        except (json.JSONDecodeError, ValidationError):
            return _Scan(events=tuple(events), size=size, malformed_line=number)
    return _Scan(events=tuple(events), size=size, malformed_line=None)


# -- validation ---------------------------------------------------------------


def _require_attributable_actor(event: AuditEvent) -> None:
    if event.actor != event.actor.strip():
        # "alice " and "alice" would otherwise be two actors, and a query for either
        # would return half of what that person did.
        raise UnattributedActionError(
            f"actor {event.actor!r} carries surrounding whitespace and would split one "
            "person's activity across two names"
        )
    if event.actor.lower() in _UNATTRIBUTABLE_ACTORS:
        raise UnattributedActionError(
            f"actor {event.actor!r} names nobody; every recorded action must be attributable "
            "to a person, an agent instance or a named platform component"
        )
    if event.actor_kind not in {kind.value for kind in ActorKind}:
        raise UnattributedActionError(
            f"actor_kind {event.actor_kind!r} is not one of "
            f"{sorted(kind.value for kind in ActorKind)}"
        )


def _require_aware(moment: datetime, field: str) -> None:
    if moment.tzinfo is None:
        raise ValueError(
            f"{field} must be timezone-aware; a naive timestamp in an audit trail cannot be "
            "ordered against events recorded elsewhere"
        )
