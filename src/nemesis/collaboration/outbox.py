"""What happens to a publication when the backend is not there.

NEMESIS must keep investigating while the collaboration backend is down, and it must not
lose what it meant to say. Those are two different requirements and only the second needs
machinery: the first is satisfied by :mod:`nemesis.collaboration` being optional, and the
second by writing the intention to disk *before* attempting the send.

That ordering is the whole design. An event is durable the moment
:meth:`Outbox.enqueue` returns, and delivery is a separate, retryable step. The alternative
— publish, and enqueue only on failure — loses every event that was in flight when the
process died, which is exactly the population of events worth keeping, because a process
dying mid-investigation is the situation somebody will later want the channel to explain.

Three properties, each with a specific failure it prevents:

**Idempotent by content.** The key is
:attr:`~nemesis.collaboration.events.CollaborationEvent.event_id`, which is derived from
the content. A retry after a lost acknowledgement is recognisable as the same event by the
outbox and by the backend, so "we don't know whether it landed" resolves to one copy rather
than two. Enqueuing the same event twice is a no-op, not a duplicate row.

**Bounded, with the boundary visible.** Attempts are capped and the delay grows
exponentially. An event that exhausts its attempts moves to
:attr:`OutboxState.DEAD_LETTER` and stays on disk with the reason it failed, rather than
being dropped or retried forever. A queue that silently discards is indistinguishable from
a queue that delivered.

**Circuit-broken.** After enough consecutive failures the outbox stops trying until a
cool-down passes. Without this, a relay that is down turns every publication attempt into a
timeout, and a plane that was supposed to be optional becomes the thing that slows the
investigation down.

The store is a JSONL file with the record rewritten in place on state change — deliberately
*not* hash-chained. This is a work queue, not a record of what happened: the audit trail
already holds the tamper-evident account, and a chained queue would have to choose between
refusing to mutate a row and breaking its own chain on every retry.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterator, Sequence
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Final, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from nemesis.collaboration.base import PublicationReceipt, PublicationStatus
from nemesis.collaboration.events import CollaborationEvent
from nemesis.core.temporal import require_utc

DEFAULT_MAX_ATTEMPTS: Final = 6
DEFAULT_BASE_DELAY_SECONDS: Final = 5.0
DEFAULT_MAX_DELAY_SECONDS: Final = 900.0
DEFAULT_FAILURE_THRESHOLD: Final = 5
DEFAULT_COOLDOWN_SECONDS: Final = 60.0


class OutboxWriteError(RuntimeError):
    """The queue could not be written, so the caller must not believe it was queued.

    Raised rather than swallowed, for the same reason
    :class:`~nemesis.audit.trail.AuditWriteError` is: a caller that thinks it queued a
    publication and did not carries on and produces a channel with a hole in it, which is
    worse than a caller that stopped.
    """


class OutboxState(StrEnum):
    PENDING = "pending"
    DELIVERED = "delivered"
    ABANDONED = "abandoned"
    """The backend reached us and refused the event on its merits. Not retried: sending the
    same bytes to the same backend will be refused the same way."""

    DEAD_LETTER = "dead_letter"
    """Attempts exhausted. Kept, with the last failure's detail, because an operator has to
    be able to answer "what did we fail to say, and why"."""

    @property
    def is_terminal(self) -> bool:
        return self is not OutboxState.PENDING


class OutboxRecord(BaseModel):
    """One event and everything known about trying to deliver it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event: CollaborationEvent
    channel_key: Annotated[str, Field(min_length=1)]
    provider: Annotated[str, Field(min_length=1)]
    state: OutboxState = OutboxState.PENDING
    attempts: Annotated[int, Field(ge=0)] = 0
    enqueued_at: datetime
    next_attempt_at: datetime
    last_detail: str = ""
    backend_reference: str | None = None

    @model_validator(mode="after")
    def _require_utc(self) -> Self:
        require_utc(self.enqueued_at, "enqueued_at")
        require_utc(self.next_attempt_at, "next_attempt_at")
        return self

    @property
    def key(self) -> str:
        return self.event.event_id


class CircuitBreaker:
    """Stops calling a backend that keeps failing, and says when it will try again.

    Deliberately not a decorator or a context manager. Both hide the state, and the state is
    the thing an operator asks about: :meth:`describe` is the answer to "why has nothing
    been published for ten minutes", and a mechanism that cannot answer that gets disabled
    the first time it is suspected.
    """

    def __init__(
        self,
        *,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        cooldown_seconds: float = DEFAULT_COOLDOWN_SECONDS,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be at least 1")
        self._threshold = failure_threshold
        self._cooldown = timedelta(seconds=cooldown_seconds)
        self._consecutive_failures = 0
        self._opened_at: datetime | None = None

    def allows(self, now: datetime) -> bool:
        """Whether a call may be attempted, closing the circuit if the cool-down has passed.

        This mutates, and the name does not say so — which a review flagged, correctly, as a
        query with a side effect. It is kept because the alternative is worse: a pure
        ``allows()`` plus a separate ``tick()`` means every caller must remember to call
        both, and a caller that forgets leaves the circuit open forever with no symptom but
        silence. The transition is idempotent and monotonic — it only ever closes an expired
        circuit, never opens one — so calling it twice, or with an older ``now``, cannot
        produce a state a single call would not have produced.

        :meth:`is_open` is the pure reader for anyone who needs the state without advancing
        it.
        """
        require_utc(now, "now")
        if self._opened_at is None:
            return True
        if now - self._opened_at >= self._cooldown:
            self._opened_at = None
            self._consecutive_failures = 0
            return True
        return False

    def record_success(self) -> None:
        self._consecutive_failures = 0
        self._opened_at = None

    def record_failure(self, now: datetime) -> None:
        require_utc(now, "now")
        self._consecutive_failures += 1
        if self._consecutive_failures >= self._threshold and self._opened_at is None:
            self._opened_at = now

    @property
    def is_open(self) -> bool:
        return self._opened_at is not None

    def describe(self) -> str:
        if self._opened_at is None:
            return f"closed after {self._consecutive_failures} consecutive failure(s)"
        reopen = self._opened_at + self._cooldown
        return (
            f"open since {self._opened_at.isoformat()} after {self._consecutive_failures} "
            f"consecutive failures; retrying from {reopen.isoformat()}"
        )


class Outbox:
    """A durable, idempotent queue of publications that have not been acknowledged.

    Single-process. A lock guards the file, and the whole queue is rewritten on each
    settlement — correct and adequate at this scale, and honest about not being a database:
    two NEMESIS processes sharing one outbox path would interleave rewrites and lose
    records. A deployment that needs that needs a real queue, and should say so rather than
    discovering it.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        base_delay_seconds: float = DEFAULT_BASE_DELAY_SECONDS,
        max_delay_seconds: float = DEFAULT_MAX_DELAY_SECONDS,
        breaker: CircuitBreaker | None = None,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        self._path = Path(path)
        self._max_attempts = max_attempts
        self._base_delay = base_delay_seconds
        self._max_delay = max_delay_seconds
        self._lock = threading.Lock()
        self.breaker = breaker if breaker is not None else CircuitBreaker()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.touch(exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def enqueue(
        self,
        event: CollaborationEvent,
        *,
        channel_key: str,
        provider: str,
        now: datetime,
    ) -> OutboxRecord:
        """Make the intention durable. Idempotent on the event's content-derived id.

        Returns the existing record when the event is already queued or already delivered,
        so a caller retrying after a crash cannot enqueue a second copy of the same event.
        """
        require_utc(now, "now")
        with self._lock:
            records = self._read()
            for record in records:
                if record.key == event.event_id:
                    return record
            record = OutboxRecord(
                event=event,
                channel_key=channel_key,
                provider=provider,
                enqueued_at=now,
                next_attempt_at=now,
            )
            records.append(record)
            self._write(records)
            return record

    def due(self, now: datetime, *, limit: int = 100) -> tuple[OutboxRecord, ...]:
        """Pending records whose next attempt is due, oldest first.

        Returns nothing while the circuit is open. The caller does not need to know why —
        it publishes what it is given — and :meth:`CircuitBreaker.describe` explains it to
        whoever asks.
        """
        require_utc(now, "now")
        if not self.breaker.allows(now):
            return ()
        with self._lock:
            records = self._read()
        due = [
            record
            for record in records
            if record.state is OutboxState.PENDING and record.next_attempt_at <= now
        ]
        due.sort(key=lambda record: record.enqueued_at)
        return tuple(due[:limit])

    def settle(self, receipt: PublicationReceipt, *, now: datetime) -> OutboxRecord | None:
        """Record what a backend said about one attempt and schedule or close it.

        Returns the updated record, or ``None`` when the outbox holds no such event — which
        happens if a caller publishes without enqueuing, and is reported rather than
        silently creating a record for something that was never queued.
        """
        require_utc(now, "now")
        with self._lock:
            records = self._read()
            index = next(
                (i for i, record in enumerate(records) if record.key == receipt.event_id), None
            )
            if index is None:
                return None

            record = records[index]
            if record.state.is_terminal:
                # A settled record is settled. Without this, a late or duplicated receipt —
                # two publisher loops, a retry that raced its own acknowledgement — demoted a
                # DELIVERED record to DEAD_LETTER, and the outbox then reported an event as
                # lost that it had in fact delivered. Returning the record unchanged makes a
                # late receipt a no-op rather than a regression.
                return record

            attempts = record.attempts + 1

            if receipt.succeeded:
                self.breaker.record_success()
                updated = record.model_copy(
                    update={
                        "state": OutboxState.DELIVERED,
                        "attempts": attempts,
                        "last_detail": receipt.detail,
                        "backend_reference": receipt.backend_reference,
                    }
                )
            elif receipt.status is PublicationStatus.REFUSED_REJECTED:
                self.breaker.record_success()
                updated = record.model_copy(
                    update={
                        "state": OutboxState.ABANDONED,
                        "attempts": attempts,
                        "last_detail": receipt.detail,
                    }
                )
            else:
                self.breaker.record_failure(now)
                exhausted = attempts >= self._max_attempts
                updated = record.model_copy(
                    update={
                        "state": OutboxState.DEAD_LETTER if exhausted else OutboxState.PENDING,
                        "attempts": attempts,
                        "last_detail": receipt.detail,
                        "next_attempt_at": now + self._backoff(attempts),
                    }
                )

            records[index] = updated
            self._write(records)
            return updated

    def records(self, *, state: OutboxState | None = None) -> tuple[OutboxRecord, ...]:
        with self._lock:
            records = self._read()
        if state is None:
            return tuple(records)
        return tuple(record for record in records if record.state is state)

    def dead_letters(self) -> tuple[OutboxRecord, ...]:
        return self.records(state=OutboxState.DEAD_LETTER)

    def pending_count(self) -> int:
        return len(self.records(state=OutboxState.PENDING))

    def _backoff(self, attempts: int) -> timedelta:
        delay = min(self._base_delay * (2 ** (attempts - 1)), self._max_delay)
        return timedelta(seconds=delay)

    def _read(self) -> list[OutboxRecord]:
        records: list[OutboxRecord] = []
        for number, line in enumerate(self._iter_lines(), start=1):
            try:
                records.append(OutboxRecord.model_validate_json(line))
            except ValidationError as exc:
                raise OutboxWriteError(
                    f"{self._path}:{number} is not a readable outbox record. The queue is "
                    "refused wholesale rather than partially: skipping the line would drop "
                    "a publication nobody would ever be told about."
                ) from exc
        return records

    def _iter_lines(self) -> Iterator[str]:
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped:
                    yield stripped

    def _write(self, records: Sequence[OutboxRecord]) -> None:
        """Rewrite the queue atomically, and do not return until the bytes are on disk.

        Same discipline as the audit trail, for the same reason: an in-memory queue that has
        advanced past what the file holds will, after a crash, re-send what it already sent
        and forget what it had not.
        """
        temporary = self._path.with_suffix(self._path.suffix + ".tmp")
        payload = "".join(
            json.dumps(record.model_dump(mode="json"), separators=(",", ":"), ensure_ascii=False)
            + "\n"
            for record in records
        )
        try:
            with temporary.open("w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(self._path)
        except OSError as exc:
            raise OutboxWriteError(f"could not write the outbox at {self._path}: {exc}") from exc


__all__ = [
    "DEFAULT_BASE_DELAY_SECONDS",
    "DEFAULT_COOLDOWN_SECONDS",
    "DEFAULT_FAILURE_THRESHOLD",
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_MAX_DELAY_SECONDS",
    "CircuitBreaker",
    "Outbox",
    "OutboxRecord",
    "OutboxState",
    "OutboxWriteError",
]
