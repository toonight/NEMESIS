"""What the collaboration plane does when the backend is not there.

The invariant suite already pins what may cross the collaboration boundary and what a
message confers. This file pins the other half of the brief: NEMESIS must keep working when
the backend is down, and it must not lose what it meant to say. Those are two claims, and
only the second one needs machinery — which means the second one is the one that can be
wrong quietly.

A queue that drops a publication is indistinguishable, from the inside, from a queue that
delivered it. Nobody is paged, no log line is written, and the hole only becomes visible
months later when somebody reads the channel as an account of what happened and finds a
step missing. So every test here is written to catch a *silent* failure rather than a loud
one, and several assert on counts rather than on outcomes for exactly that reason: after an
outage the total number of records the outbox holds must still be the number that were
enqueued, whatever state they ended up in.

The failure modes each section pins:

**Durability and idempotence.** An event is durable when :meth:`Outbox.enqueue` returns,
not when a send succeeds — so a record enqueued by one process must be found by a second
:class:`Outbox` constructed over the same path, and enqueuing the same content twice must
produce one record rather than two copies of one statement in a human-readable channel.

**Settlement.** A backend that refuses on the merits and a backend that cannot be reached
are different events, and treating them alike breaks in both directions: a rejected event
retried forever, or a transient outage abandoned on the first timeout.

**Bounded retry with a visible boundary.** Delays grow and are capped, attempts are capped,
and an event that exhausts them lands in ``DEAD_LETTER`` *on disk* with the reason. The
dead-letter file is the answer to "what did we fail to say, and why"; a queue that could not
answer that would be a queue whose silence means nothing.

**Degrading gracefully.** The headline scenario at the end runs five publications through a
backend that is completely down — first refusing politely, then raising outright — and then
through the real :class:`LocalCollaborationProvider` once it recovers. It asserts that
nothing escaped, nothing was lost, the circuit opened, and the events that had already
landed during a lost-acknowledgement window deduplicated into one copy each rather than two.

One thing this file deliberately supplies itself: the pump. There is no publisher loop in
``src`` — the outbox is a queue and the caller drives it — so :func:`_pump` plays the
caller's part, and it is the pump, not the outbox, that converts a provider raising into a
``FAILED`` receipt. That division is the real contract: the provider Protocol promises not
to raise for a backend that is merely down, and the outbox promises that whatever the caller
reports, no record disappears. :func:`_pump` proves a caller can honour the first without
the outbox breaking the second.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

import pytest

from nemesis.collaboration.base import (
    ActorBinding,
    ChannelDescriptor,
    ChannelHandle,
    CollaborationProvider,
    InboundSignal,
    PublicationReceipt,
    PublicationStatus,
)
from nemesis.collaboration.events import CollaborationEvent, EpistemicStanding
from nemesis.collaboration.outbox import (
    CircuitBreaker,
    Outbox,
    OutboxRecord,
    OutboxState,
    OutboxWriteError,
)
from nemesis.collaboration.providers.local import LocalCollaborationProvider
from nemesis.core.identity import ActorKind

T0 = datetime(2026, 5, 4, 9, 30, tzinfo=UTC)
CASE = "case-2026-000123"
INVESTIGATION = "inv-2026-000123"
CHANNEL_KEY = "case-2026-000123"


# --- the fake backend ---------------------------------------------------------------


class _Mode(StrEnum):
    """The four behaviours a backend can be told to have, plus the interesting fifth."""

    SUCCEED = "succeed"
    UNAVAILABLE = "unavailable"
    REJECT = "reject"
    RAISE = "raise"

    ACK_LOST = "ack_lost"
    """The write lands and the acknowledgement does not.

    Not a fifth kind of failure — it is ``UNAVAILABLE`` from the caller's point of view, and
    that is the point. It is the only mode under which a retry can produce a second copy of
    a published statement, so it is the mode that exercises what the content-addressed
    ``event_id`` is actually for.
    """


class _ScriptedProvider:
    """A collaboration backend that behaves however the test tells it to.

    When handed a ``delegate`` it becomes a wrapper around a real provider rather than a
    simulation of one: succeeding means the delegate really writes, and recovering means the
    delegate really deduplicates. That keeps the recovery half of the headline scenario an
    assertion about shipped code instead of an assertion about this file.
    """

    def __init__(
        self, *, mode: _Mode = _Mode.SUCCEED, delegate: LocalCollaborationProvider | None = None
    ) -> None:
        self.mode = mode
        self.publish_attempts: list[str] = []
        self._delegate = delegate

    @property
    def name(self) -> str:
        return self._delegate.name if self._delegate is not None else "scripted"

    async def open_channel(self, descriptor: ChannelDescriptor) -> ChannelHandle:
        if self._delegate is not None:
            return await self._delegate.open_channel(descriptor)
        return ChannelHandle(
            key=descriptor.key,
            provider=self.name,
            backend_id=f"scripted://{descriptor.key}",
            created=True,
        )

    async def publish(
        self, channel: ChannelHandle, event: CollaborationEvent
    ) -> PublicationReceipt:
        self.publish_attempts.append(event.event_id)

        if self.mode is _Mode.RAISE:
            raise RuntimeError("the relay client library raised instead of returning a receipt")
        if self.mode is _Mode.UNAVAILABLE:
            return self._refusal(
                event,
                PublicationStatus.REFUSED_UNAVAILABLE,
                "connection refused: nothing listening",
            )
        if self.mode is _Mode.REJECT:
            return self._refusal(
                event,
                PublicationStatus.REFUSED_REJECTED,
                "invalid: this ingest does not admit that event kind",
            )

        delivered = await self._deliver(channel, event)
        if self.mode is _Mode.ACK_LOST:
            return self._refusal(
                event,
                PublicationStatus.REFUSED_UNAVAILABLE,
                "the write landed and the acknowledgement did not",
            )
        return delivered

    async def poll(
        self, channel: ChannelHandle, *, since: datetime | None = None, limit: int = 100
    ) -> Sequence[InboundSignal]:
        return ()

    async def bind_actor(self, binding: ActorBinding) -> ActorBinding:
        return binding.model_copy(update={"provider": self.name})

    async def health(self) -> bool:
        return self.mode is _Mode.SUCCEED

    async def _deliver(
        self, channel: ChannelHandle, event: CollaborationEvent
    ) -> PublicationReceipt:
        if self._delegate is not None:
            return await self._delegate.publish(channel, event)
        return PublicationReceipt(
            event_id=event.event_id,
            provider=self.name,
            status=PublicationStatus.PUBLISHED,
            backend_reference=f"scripted#{len(self.publish_attempts)}",
            published_at=T0,
        )

    def _refusal(
        self, event: CollaborationEvent, status: PublicationStatus, detail: str
    ) -> PublicationReceipt:
        return PublicationReceipt(
            event_id=event.event_id, provider=self.name, status=status, detail=detail
        )


def _pump(
    outbox: Outbox,
    provider: CollaborationProvider,
    channel: ChannelHandle,
    *,
    now: datetime,
    limit: int = 100,
) -> tuple[PublicationReceipt, ...]:
    """Publish everything currently due and settle each result. The caller's part.

    A provider that raises is converted into a ``FAILED`` receipt here rather than being
    allowed to propagate, because a publication loop that lets a backend's client library
    abort it stops draining the queue at the first bad event and never reaches the good ones
    behind it.
    """

    async def _run() -> list[PublicationReceipt]:
        receipts: list[PublicationReceipt] = []
        for record in outbox.due(now, limit=limit):
            try:
                receipt = await provider.publish(channel, record.event)
            except Exception as exc:
                receipt = PublicationReceipt(
                    event_id=record.event.event_id,
                    provider=provider.name,
                    status=PublicationStatus.FAILED,
                    detail=f"the provider raised: {exc}",
                )
            outbox.settle(receipt, now=now)
            receipts.append(receipt)
        return receipts

    return tuple(asyncio.run(_run()))


def _event(seed: str, *, occurred_at: datetime = T0) -> CollaborationEvent:
    return CollaborationEvent.for_publication(
        occurred_at=occurred_at,
        case_id=CASE,
        investigation_id=INVESTIGATION,
        correlation_id="corr-1",
        actor="nemesis-pursuit",
        actor_kind=ActorKind.RULE,
        standing=EpistemicStanding.OBSERVATION,
        event_type="threat.infrastructure.observed",
        summary=f"{seed}.example resolved to 203.0.113.7",
    )


def _receipt(
    event: CollaborationEvent,
    status: PublicationStatus,
    *,
    detail: str = "",
    backend_reference: str | None = None,
) -> PublicationReceipt:
    return PublicationReceipt(
        event_id=event.event_id,
        provider="scripted",
        status=status,
        detail=detail,
        backend_reference=backend_reference,
    )


def _outbox(tmp_path: Path, **kwargs: object) -> Outbox:
    return Outbox(tmp_path / "outbox.jsonl", **kwargs)  # type: ignore[arg-type]


def _enqueue(
    outbox: Outbox, event: CollaborationEvent, *, now: datetime = T0, provider: str = "scripted"
) -> OutboxRecord:
    return outbox.enqueue(event, channel_key=CHANNEL_KEY, provider=provider, now=now)


# --- 1. The queue is durable, and it is durable before anything is sent --------------


def test_the_fake_backend_satisfies_the_provider_protocol() -> None:
    """A guard against the guard.

    Every test below drives the real code through this fake. If the fake drifted out of
    shape — a renamed method, a changed signature — the tests would still pass while
    exercising something no real provider resembles.
    """
    assert isinstance(_ScriptedProvider(), CollaborationProvider)


def test_enqueueing_the_same_event_twice_yields_exactly_one_record(tmp_path: Path) -> None:
    """A retry after a lost acknowledgement must resolve to one copy, not two.

    The key is the content-addressed ``event_id``, so a caller that cannot tell whether its
    first enqueue survived a crash can simply enqueue again. If this deduplication failed,
    the visible damage would be a human-readable channel that says the same thing twice —
    which reads as two findings rather than one.
    """
    outbox = _outbox(tmp_path)
    event = _event("evil")

    first = _enqueue(outbox, event)
    second = _enqueue(outbox, event, now=T0 + timedelta(hours=3))

    assert first.key == second.key
    assert len(outbox.records()) == 1
    assert second.enqueued_at == T0, "the second enqueue must not overwrite the first's timing"


def test_an_enqueued_record_is_found_by_a_new_outbox_over_the_same_path(
    tmp_path: Path,
) -> None:
    """Durable means on disk, not in a list.

    Constructed fresh rather than re-read through the same object, because an in-memory
    cache would make a re-read pass while the file held nothing — and the population of
    events worth keeping is exactly the ones that were in flight when the process died.
    """
    path = tmp_path / "outbox.jsonl"
    event = _event("evil")
    Outbox(path).enqueue(event, channel_key=CHANNEL_KEY, provider="scripted", now=T0)

    reopened = Outbox(path)
    (record,) = reopened.records()

    assert record.key == event.event_id
    assert record.state is OutboxState.PENDING
    assert record.event.summary == event.summary
    assert record.channel_key == CHANNEL_KEY


def test_enqueueing_is_idempotent_across_processes_too(tmp_path: Path) -> None:
    """The crash-and-retry case, which is the one the idempotence exists for."""
    path = tmp_path / "outbox.jsonl"
    event = _event("evil")
    Outbox(path).enqueue(event, channel_key=CHANNEL_KEY, provider="scripted", now=T0)
    Outbox(path).enqueue(event, channel_key=CHANNEL_KEY, provider="scripted", now=T0)

    assert len(Outbox(path).records()) == 1


# --- 2. What is due, in which order, and how much of it -----------------------------


def test_due_returns_pending_records_oldest_first(tmp_path: Path) -> None:
    outbox = _outbox(tmp_path)
    _enqueue(outbox, _event("third"), now=T0 + timedelta(minutes=2))
    _enqueue(outbox, _event("first"), now=T0)
    _enqueue(outbox, _event("second"), now=T0 + timedelta(minutes=1))

    due = outbox.due(T0 + timedelta(hours=1))

    assert [record.enqueued_at for record in due] == [
        T0,
        T0 + timedelta(minutes=1),
        T0 + timedelta(minutes=2),
    ]


def test_due_respects_its_limit_and_takes_the_oldest(tmp_path: Path) -> None:
    """Truncating the newest end keeps a busy queue from starving its oldest entries."""
    outbox = _outbox(tmp_path)
    for minute in range(5):
        _enqueue(outbox, _event(f"host{minute}"), now=T0 + timedelta(minutes=minute))

    due = outbox.due(T0 + timedelta(hours=1), limit=2)

    assert len(due) == 2
    assert [record.enqueued_at for record in due] == [T0, T0 + timedelta(minutes=1)]


def test_a_record_whose_next_attempt_is_in_the_future_is_not_due(tmp_path: Path) -> None:
    outbox = _outbox(tmp_path)
    _enqueue(outbox, _event("evil"), now=T0 + timedelta(hours=1))

    assert outbox.due(T0) == ()
    assert len(outbox.records(state=OutboxState.PENDING)) == 1


def test_a_settled_record_is_never_due_again(tmp_path: Path) -> None:
    outbox = _outbox(tmp_path)
    event = _event("evil")
    _enqueue(outbox, event)
    outbox.settle(_receipt(event, PublicationStatus.PUBLISHED, backend_reference="ref-1"), now=T0)

    assert outbox.due(T0 + timedelta(days=7)) == ()


# --- 3. Settlement: four backend answers, four different consequences ---------------


def test_a_published_receipt_marks_the_record_delivered_and_keeps_the_reference(
    tmp_path: Path,
) -> None:
    """The backend's own identifier is retained, or nothing ties an audit entry to what a
    reader of the channel actually sees."""
    outbox = _outbox(tmp_path)
    event = _event("evil")
    _enqueue(outbox, event)

    updated = outbox.settle(
        _receipt(
            event,
            PublicationStatus.PUBLISHED,
            detail="accepted",
            backend_reference="channel.jsonl#420",
        ),
        now=T0,
    )

    assert updated is not None
    assert updated.state is OutboxState.DELIVERED
    assert updated.backend_reference == "channel.jsonl#420"
    assert updated.attempts == 1
    assert outbox.pending_count() == 0


def test_a_duplicate_receipt_also_marks_the_record_delivered(tmp_path: Path) -> None:
    """A duplicate is a success.

    It is what a content-addressed identifier is for: the retry found its own earlier copy
    already stored, which is the outcome the retry wanted. Treating it as a failure would
    retry a landed publication until its attempts ran out and then dead-letter something
    that was published correctly.
    """
    outbox = _outbox(tmp_path)
    event = _event("evil")
    _enqueue(outbox, event)

    updated = outbox.settle(
        _receipt(
            event,
            PublicationStatus.DUPLICATE,
            detail="already published; the content-addressed id matched",
            backend_reference=event.event_id,
        ),
        now=T0,
    )

    assert updated is not None
    assert updated.state is OutboxState.DELIVERED
    assert updated.state.is_terminal
    assert updated.backend_reference == event.event_id


def test_a_rejected_receipt_abandons_the_record_and_it_is_never_retried(
    tmp_path: Path,
) -> None:
    """Reached, and refused on the merits. Sending the same bytes again gets the same answer.

    Kept rather than deleted: an operator asking why a finding never appeared in the channel
    needs to find the record and the relay's reason, not an absence.
    """
    outbox = _outbox(tmp_path)
    event = _event("evil")
    _enqueue(outbox, event)

    updated = outbox.settle(
        _receipt(
            event,
            PublicationStatus.REFUSED_REJECTED,
            detail="restricted: not a member of that group",
        ),
        now=T0,
    )

    assert updated is not None
    assert updated.state is OutboxState.ABANDONED
    assert updated.last_detail == "restricted: not a member of that group"
    assert outbox.due(T0 + timedelta(days=30)) == ()
    assert len(outbox.records()) == 1


def test_an_unavailable_receipt_keeps_the_record_pending_and_defers_it(
    tmp_path: Path,
) -> None:
    """The backend was not reached. Nothing about the event is known to be wrong."""
    outbox = _outbox(tmp_path)
    event = _event("evil")
    _enqueue(outbox, event)

    updated = outbox.settle(
        _receipt(event, PublicationStatus.REFUSED_UNAVAILABLE, detail="connection refused"),
        now=T0,
    )

    assert updated is not None
    assert updated.state is OutboxState.PENDING
    assert updated.attempts == 1
    assert updated.next_attempt_at > T0
    assert outbox.due(T0) == (), "deferred means deferred, not due at the instant it failed"
    assert len(outbox.due(updated.next_attempt_at)) == 1


def test_settling_records_what_the_backend_said_even_when_it_refused(tmp_path: Path) -> None:
    """The relay's own words are kept verbatim; their prefix is how a rejection is told from
    an outage, and paraphrasing loses that."""
    outbox = _outbox(tmp_path)
    event = _event("evil")
    _enqueue(outbox, event)

    outbox.settle(
        _receipt(event, PublicationStatus.FAILED, detail="rate-limited: slow down"), now=T0
    )
    (record,) = Outbox(tmp_path / "outbox.jsonl").records()

    assert record.last_detail == "rate-limited: slow down"


# --- 4. Backoff grows and stops growing ---------------------------------------------


def test_successive_failures_produce_strictly_increasing_delays_capped_at_the_maximum(
    tmp_path: Path,
) -> None:
    """A flat retry interval turns an outage into a sustained load on the thing that is
    already failing; an uncapped one turns a two-hour outage into a two-day silence."""
    outbox = _outbox(tmp_path, max_attempts=10, base_delay_seconds=5.0, max_delay_seconds=20.0)
    event = _event("evil")
    _enqueue(outbox, event)

    delays: list[timedelta] = []
    for _ in range(5):
        updated = outbox.settle(
            _receipt(event, PublicationStatus.REFUSED_UNAVAILABLE, detail="down"), now=T0
        )
        assert updated is not None
        delays.append(updated.next_attempt_at - T0)

    cap = timedelta(seconds=20)
    assert delays[0] < delays[1] < delays[2]
    assert delays[:3] == [timedelta(seconds=5), timedelta(seconds=10), cap]
    assert all(delay == cap for delay in delays[2:])
    assert max(delays) == cap


# --- 5. The boundary is visible: dead letters stay, and stay countable ---------------


def test_exhausting_the_attempts_dead_letters_the_record_and_keeps_its_reason(
    tmp_path: Path,
) -> None:
    """A queue that silently discards is indistinguishable from a queue that delivered.

    So the record survives with the last failure's detail, and it survives *on disk*: the
    operator question this answers — "what did we fail to say, and why" — is normally asked
    of a process that has since been restarted.
    """
    outbox = _outbox(tmp_path, max_attempts=3)
    event = _event("evil")
    _enqueue(outbox, event)

    for attempt in range(3):
        updated = outbox.settle(
            _receipt(
                event,
                PublicationStatus.REFUSED_UNAVAILABLE,
                detail=f"connection refused (attempt {attempt + 1})",
            ),
            now=T0,
        )
        assert updated is not None

    (dead,) = outbox.dead_letters()
    assert dead.state is OutboxState.DEAD_LETTER
    assert dead.attempts == 3
    assert dead.last_detail == "connection refused (attempt 3)"

    (persisted,) = Outbox(tmp_path / "outbox.jsonl").dead_letters()
    assert persisted.last_detail == dead.last_detail


def test_dead_lettering_one_record_drops_none_of_the_others(tmp_path: Path) -> None:
    """The count is the assertion. Everything enqueued is still accounted for."""
    outbox = _outbox(tmp_path, max_attempts=2)
    doomed = _event("doomed")
    kept = _event("kept")
    delivered = _event("delivered")
    for event in (doomed, kept, delivered):
        _enqueue(outbox, event)

    for _ in range(2):
        outbox.settle(
            _receipt(doomed, PublicationStatus.REFUSED_UNAVAILABLE, detail="down"), now=T0
        )
    outbox.settle(
        _receipt(delivered, PublicationStatus.PUBLISHED, backend_reference="ref-1"), now=T0
    )

    assert len(outbox.records()) == 3
    assert len(outbox.dead_letters()) == 1
    assert outbox.pending_count() == 1
    assert {record.key for record in outbox.records()} == {
        doomed.event_id,
        kept.event_id,
        delivered.event_id,
    }


def test_a_dead_lettered_record_is_no_longer_due(tmp_path: Path) -> None:
    outbox = _outbox(tmp_path, max_attempts=1)
    event = _event("evil")
    _enqueue(outbox, event)
    outbox.settle(_receipt(event, PublicationStatus.FAILED, detail="down"), now=T0)

    assert outbox.due(T0 + timedelta(days=365)) == ()
    assert len(outbox.dead_letters()) == 1


# --- 6. Settling something that was never queued ------------------------------------


def test_settling_an_event_the_outbox_does_not_hold_returns_none(tmp_path: Path) -> None:
    """Reported rather than invented.

    Creating a record here would mean the outbox held an entry for a publication it had
    never been asked to make, with an ``enqueued_at`` it made up — and the durability
    guarantee is that a record's presence proves the enqueue happened before the send.
    """
    outbox = _outbox(tmp_path)
    _enqueue(outbox, _event("queued"))

    result = outbox.settle(
        _receipt(_event("never-queued"), PublicationStatus.PUBLISHED, backend_reference="r"),
        now=T0,
    )

    assert result is None
    assert len(outbox.records()) == 1


# --- 7. The circuit breaker ---------------------------------------------------------


def test_a_fresh_breaker_allows_calls() -> None:
    breaker = CircuitBreaker(failure_threshold=3, cooldown_seconds=60.0)

    assert breaker.allows(T0) is True
    assert breaker.is_open is False
    assert "closed" in breaker.describe()


def test_the_breaker_opens_after_the_threshold_of_consecutive_failures() -> None:
    breaker = CircuitBreaker(failure_threshold=3, cooldown_seconds=60.0)

    for _ in range(2):
        breaker.record_failure(T0)
    assert breaker.allows(T0) is True

    breaker.record_failure(T0)
    assert breaker.is_open is True
    assert breaker.allows(T0) is False
    assert "open since" in breaker.describe()
    assert "retrying from" in breaker.describe()


def test_the_breaker_closes_again_once_the_cooldown_has_elapsed() -> None:
    breaker = CircuitBreaker(failure_threshold=2, cooldown_seconds=60.0)
    breaker.record_failure(T0)
    breaker.record_failure(T0)

    assert breaker.allows(T0 + timedelta(seconds=59)) is False
    assert breaker.allows(T0 + timedelta(seconds=60)) is True
    assert breaker.is_open is False
    assert "closed after 0" in breaker.describe(), "the counter resets, not just the state"


def test_a_success_resets_the_failure_counter_so_failures_must_be_consecutive() -> None:
    """Intermittent failures must not accumulate into an outage that never happened."""
    breaker = CircuitBreaker(failure_threshold=3, cooldown_seconds=60.0)
    breaker.record_failure(T0)
    breaker.record_failure(T0)
    breaker.record_success()
    breaker.record_failure(T0)
    breaker.record_failure(T0)

    assert breaker.is_open is False
    assert breaker.allows(T0) is True


def test_an_open_circuit_makes_due_empty_even_when_records_are_due(tmp_path: Path) -> None:
    """The point of the breaker, asserted where it bites.

    Without this, a relay that is down turns every publication attempt into a timeout, and a
    plane that was supposed to be optional becomes the thing slowing the investigation down.
    ``due()`` returning nothing is how that back-pressure reaches the caller without the
    caller needing to know about it.
    """
    breaker = CircuitBreaker(failure_threshold=2, cooldown_seconds=60.0)
    outbox = _outbox(tmp_path, base_delay_seconds=1.0, breaker=breaker)
    first, second = _event("one"), _event("two")
    _enqueue(outbox, first)
    _enqueue(outbox, second)

    for event in (first, second):
        outbox.settle(_receipt(event, PublicationStatus.REFUSED_UNAVAILABLE, detail="down"), now=T0)
    assert outbox.breaker.is_open is True

    still_pending = outbox.records(state=OutboxState.PENDING)
    assert len(still_pending) == 2
    assert all(record.next_attempt_at <= T0 + timedelta(seconds=30) for record in still_pending)
    assert outbox.due(T0 + timedelta(seconds=30)) == ()

    assert len(outbox.due(T0 + timedelta(seconds=61))) == 2


def test_the_breaker_explains_itself_to_whoever_asks(tmp_path: Path) -> None:
    """An operator asking why nothing has been published for ten minutes needs an answer
    that is not a debugger session."""
    breaker = CircuitBreaker(failure_threshold=1, cooldown_seconds=120.0)
    outbox = _outbox(tmp_path, breaker=breaker)
    event = _event("evil")
    _enqueue(outbox, event)
    outbox.settle(_receipt(event, PublicationStatus.FAILED, detail="down"), now=T0)

    description = outbox.breaker.describe()
    assert T0.isoformat() in description
    assert (T0 + timedelta(seconds=120)).isoformat() in description


# --- 8. The headline: a backend that is completely down -----------------------------


def test_nemesis_degrades_gracefully_when_the_backend_is_unavailable(tmp_path: Path) -> None:
    """End-to-end: five publications through a dead backend, then through a live one.

    The scenario, in order:

    1. Five events are enqueued while the backend is unreachable and are published through
       a provider that refuses politely.
    2. The next round is published through a provider that raises outright, because a
       client library that aborts is a real outage shape and must not be worse than a
       refusal.
    3. The backend half-recovers: the writes land and the acknowledgements are lost, so the
       outbox still believes nothing was published.
    4. The backend recovers fully.

    What is asserted at the end is that no exception escaped, all five records were still
    accounted for at every step, the circuit opened and reopened on the cool-down, and each
    of the five statements appears exactly once in the channel — because step 3 already
    wrote them and step 4's retry deduplicated against the content-addressed id rather than
    saying everything twice.

    The recovery half runs against the real :class:`LocalCollaborationProvider`, so what is
    proved is real delivery to a real channel file, not a fake agreeing with itself.
    """
    local = LocalCollaborationProvider(tmp_path / "channels-root")
    channel = asyncio.run(
        local.open_channel(ChannelDescriptor(key=CHANNEL_KEY, display_name="Case 2026-000123"))
    )
    backend = _ScriptedProvider(mode=_Mode.UNAVAILABLE, delegate=local)
    outbox = _outbox(tmp_path)

    events = [_event(f"host{index}") for index in range(5)]
    for event in events:
        _enqueue(outbox, event, provider=backend.name)
    assert outbox.pending_count() == 5

    # 1. The backend refuses politely. Every record survives, deferred.
    receipts = _pump(outbox, backend, channel, now=T0)
    assert len(receipts) == 5
    assert all(receipt.status is PublicationStatus.REFUSED_UNAVAILABLE for receipt in receipts)
    assert outbox.pending_count() == 5
    assert local.published(CHANNEL_KEY) == ()

    # (c) The circuit opened, and it withholds work that is otherwise due.
    opened_during_the_outage = outbox.breaker.is_open
    assert opened_during_the_outage is True
    assert outbox.due(T0 + timedelta(seconds=30)) == ()

    # 2. The backend stops being polite. (a) The raise does not escape the pump.
    backend.mode = _Mode.RAISE
    t_raise = T0 + timedelta(seconds=90)
    receipts = _pump(outbox, backend, channel, now=t_raise)
    assert len(receipts) == 5
    assert all(receipt.status is PublicationStatus.FAILED for receipt in receipts)
    assert all("the provider raised" in receipt.detail for receipt in receipts)

    # (b) Nothing lost: five records, all still pending or dead-lettered, none delivered.
    records = outbox.records()
    assert len(records) == 5
    assert {record.key for record in records} == {event.event_id for event in events}
    assert all(record.state in {OutboxState.PENDING, OutboxState.DEAD_LETTER} for record in records)
    assert not outbox.records(state=OutboxState.DELIVERED)

    # 3. The writes land and the acknowledgements do not. The outbox does not know.
    backend.mode = _Mode.ACK_LOST
    t_ack_lost = t_raise + timedelta(seconds=90)
    receipts = _pump(outbox, backend, channel, now=t_ack_lost)
    assert all(receipt.status is PublicationStatus.REFUSED_UNAVAILABLE for receipt in receipts)
    assert outbox.pending_count() == 5
    assert len(local.published(CHANNEL_KEY)) == 5, "the channel already holds them"

    # 4. (d) Full recovery. The same five events deliver, and deduplicate.
    backend.mode = _Mode.SUCCEED
    t_recovered = t_ack_lost + timedelta(seconds=90)
    receipts = _pump(outbox, backend, channel, now=t_recovered)
    assert len(receipts) == 5
    assert all(receipt.status is PublicationStatus.DUPLICATE for receipt in receipts)
    assert all(receipt.succeeded for receipt in receipts)

    assert outbox.pending_count() == 0
    assert outbox.dead_letters() == ()
    assert len(outbox.records(state=OutboxState.DELIVERED)) == 5
    assert outbox.breaker.is_open is False

    published = local.published(CHANNEL_KEY)
    assert len(published) == 5
    assert [event.event_id for event in published] == [event.event_id for event in events]
    assert len({event.event_id for event in published}) == 5

    # The whole scenario survives a restart, because it was on disk throughout.
    reopened = Outbox(tmp_path / "outbox.jsonl")
    assert len(reopened.records(state=OutboxState.DELIVERED)) == 5


def test_a_rejected_event_does_not_stall_the_ones_behind_it(tmp_path: Path) -> None:
    """Degrading gracefully includes degrading partially.

    One malformed publication must not become five undelivered ones, which is what happens
    when a refusal aborts the drain loop instead of settling one record.
    """
    local = LocalCollaborationProvider(tmp_path / "channels-root")
    channel = asyncio.run(
        local.open_channel(ChannelDescriptor(key=CHANNEL_KEY, display_name="Case"))
    )
    backend = _ScriptedProvider(mode=_Mode.REJECT, delegate=local)
    outbox = _outbox(tmp_path)
    for index in range(3):
        _enqueue(outbox, _event(f"host{index}"), now=T0 + timedelta(seconds=index))

    _pump(outbox, backend, channel, now=T0 + timedelta(minutes=1))

    assert len(outbox.records(state=OutboxState.ABANDONED)) == 3
    assert outbox.pending_count() == 0
    assert outbox.breaker.is_open is False, "a rejection is not evidence the backend is down"


# --- 9. A queue that cannot be read is refused, not skipped -------------------------


def test_a_corrupted_line_refuses_the_whole_queue_rather_than_skipping_it(
    tmp_path: Path,
) -> None:
    """Skipping would drop a publication nobody would ever be told about.

    That is the precise failure this whole file is written against: a record that cannot be
    parsed is a publication NEMESIS intended to make, and reading past it produces an outbox
    that reports a clean, empty queue while an intention sits unread on disk one line above.
    The error names the file and the line so the record can be recovered by hand.
    """
    path = tmp_path / "outbox.jsonl"
    outbox = Outbox(path)
    outbox.enqueue(_event("evil"), channel_key=CHANNEL_KEY, provider="scripted", now=T0)
    path.write_text(
        path.read_text(encoding="utf-8") + '{"not":"an outbox record"}\n', encoding="utf-8"
    )

    expected = re.escape(f"{path}:2")
    with pytest.raises(OutboxWriteError, match=expected):
        Outbox(path).records()


def test_a_corrupted_line_also_stops_the_publication_loop(tmp_path: Path) -> None:
    """``due()`` must refuse too. A read path that raises and a work path that quietly
    returns nothing would leave the corruption invisible to the only caller that runs."""
    path = tmp_path / "outbox.jsonl"
    Outbox(path).enqueue(_event("evil"), channel_key=CHANNEL_KEY, provider="scripted", now=T0)
    path.write_text(path.read_text(encoding="utf-8") + "not json at all\n", encoding="utf-8")

    with pytest.raises(OutboxWriteError, match=re.escape(f"{path}:2")):
        Outbox(path).due(T0 + timedelta(hours=1))
