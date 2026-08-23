"""The one door out, and the record it leaves behind.

Everything the collaboration plane sends to a backend goes through
:class:`CollaborationPublisher`, and every one of those attempts lands in the
hash-chained audit trail — including the ones that were refused. That is invariant 11
applied to the outward-facing plane, which had no exception and had been getting one:
until this module existed, a publication was durable (the outbox) and delivered (the
provider) and *unrecorded*, so "what did NEMESIS say, to whom, and when" was answerable
only by reading a channel whose operator can delete rows.

**How the plane records without being able to read.** :mod:`nemesis.collaboration` cannot
import :mod:`nemesis.audit` — the layering forbids it and the
``collaboration-holds-no-handles`` contract names the package — and that stays true. What
it takes instead is a :class:`~nemesis.ports.storage.PublicationRecorder`: one method,
``record``, and no ``query``. A caller hands it the ``AppendOnlyAuditTrail`` it already
has, structural typing makes that free, and the plane sees a write-only surface. A
compromised collaboration path learns what it was given to publish and cannot read the
platform's history of everything else.

**Refusals are recorded, and recorded first.** A `DisclosureViolationError` — material
that must not leave, stopped at the boundary — is the single most interesting thing that
can happen here, and the version of this class that recorded only successes would have
been silent about exactly it. So the refusal is written to the trail *before* the
exception is re-raised. The audit trail's own module says denials are recorded with equal
weight because a pattern of denied attempts is a security signal; a pattern of attempts to
publish withheld material is that signal in its sharpest form.

**An audit failure is not swallowed.** If the trail refuses a write, the exception
propagates. A publisher that believed it recorded a publication and did not is worse off
than one that stopped, because it carries on and produces a channel history with a hole in
it — the same argument :class:`~nemesis.audit.trail.AuditWriteError` makes for itself. The
outbox has already made the intent durable, so an operator who hits this can see what was
in flight.

**And the pump lives here.** The outbox has always been able to hold a failed publication
and schedule its retry; nothing in ``src/`` ever drove it, so the retry loop existed only
in a test file. :meth:`CollaborationPublisher.drain` is that loop, in the one place that
can also record what each attempt did.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final

from nemesis.collaboration.approvals import ApprovalNotice, DecisionIntake, read_intents
from nemesis.collaboration.base import (
    ActorBinding,
    ChannelDescriptor,
    ChannelHandle,
    CollaborationProvider,
    PublicationReceipt,
    PublicationStatus,
)
from nemesis.collaboration.events import CollaborationEvent
from nemesis.collaboration.outbox import Outbox
from nemesis.core.disclosure import DisclosureViolationError
from nemesis.core.identity import ActorKind
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.temporal import require_utc, utcnow
from nemesis.ports.storage import AuditEvent, PublicationRecorder

ACTION_PUBLISH: Final = "collaboration.publish"
ACTION_OPEN_CHANNEL: Final = "collaboration.channel.open"
ACTION_BIND_ACTOR: Final = "collaboration.actor.bind"
ACTION_READ_SIGNALS: Final = "collaboration.signals.read"
ACTION_READ_INTENT: Final = "collaboration.decision.read"

OUTCOME_REFUSED_DISCLOSURE: Final = "refused_disclosure"
"""Distinct from every provider status on purpose.

A backend refusing an event and NEMESIS refusing to let it leave are different events with
different responses, and an auditor reading the trail must not have to infer which one
happened from a free-text detail.
"""

MAX_INPUT_LENGTH: Final = 400
"""How much of any one audit input is kept.

The same bound the pilot mediator uses. An audit record is a record of an action, not a
second copy of its content — the event itself is in the outbox and its hash is in the
record, so a reader can prove what was published without the trail holding it twice.
"""


class CollaborationPublisher:
    """Publishes, retries, reads replies, and records every one of those in the trail.

    Holds a provider, an outbox and a write-only recorder. Deliberately *not* a
    :class:`~nemesis.collaboration.base.CollaborationProvider` itself: a provider is the
    thing that talks to one backend, and wrapping one in something that satisfies the same
    Protocol would let a publisher be passed where a provider is expected and quietly
    double-record.
    """

    def __init__(
        self,
        *,
        provider: CollaborationProvider,
        outbox: Outbox,
        recorder: PublicationRecorder,
        actor: str,
        actor_kind: ActorKind = ActorKind.SYSTEM,
        clock: object = None,
    ) -> None:
        self._provider = provider
        self._outbox = outbox
        self._recorder = recorder
        self._actor = actor
        self._actor_kind = actor_kind
        self._clock = clock

    @property
    def provider_name(self) -> str:
        return self._provider.name

    @property
    def outbox(self) -> Outbox:
        return self._outbox

    async def open_channel(self, descriptor: ChannelDescriptor) -> ChannelHandle:
        """Ensure a channel exists, and record whether this call created it.

        Creating a room in a workspace is a real action with a real audience, so it is
        recorded rather than treated as setup. ``created`` distinguishes "we made one" from
        "we found one", which is the question an auditor asks when a channel turns out to
        hold more members than anybody expected.
        """
        handle = await self._provider.open_channel(descriptor)
        await self._record(
            action=ACTION_OPEN_CHANNEL,
            subject=f"{self._provider.name}:{descriptor.key}",
            outcome="created" if handle.created else "already_existed",
            inputs={
                "channel_key": descriptor.key,
                "visibility": descriptor.visibility.value,
                "case_id": descriptor.case_id or "",
                "backend_id": handle.backend_id,
            },
        )
        return handle

    async def bind_actor(self, binding: ActorBinding) -> ActorBinding:
        """Record a NEMESIS actor's presence on a backend, and audit the binding.

        The binding grants nothing — see
        :class:`~nemesis.collaboration.identities.RegisteredActor` — but an identity
        appearing in a workspace under a key is exactly the sort of thing somebody later
        wants a date for.
        """
        recorded = await self._provider.bind_actor(binding)
        await self._record(
            action=ACTION_BIND_ACTOR,
            subject=recorded.actor_id,
            outcome="bound",
            inputs={
                "display_name": recorded.display_name,
                "backend_reference": recorded.backend_reference,
                "actor_kind": recorded.actor_kind.value,
                "grants": "nothing",
            },
        )
        return recorded

    async def publish(
        self, channel: ChannelHandle, event: CollaborationEvent
    ) -> PublicationReceipt:
        """Make the intent durable, send it, settle it, and record what happened.

        The order is deliberate and is the outbox module's argument applied here: the
        intent reaches disk before anything is attempted, so a process that dies mid-send
        leaves a record of what it meant to say rather than nothing at all.

        Never raises for a backend that is merely down — that is a receipt. Raises for a
        disclosure violation, after recording it, because material that must not leave is
        not a delivery outcome to be retried.
        """
        now = self._now()
        try:
            # The enqueue is inside the handler, not before it. `OutboxRecord` validates
            # the event it is handed, so an event that must not leave is refused here
            # rather than at the provider — and the first version of this method, which
            # enqueued outside the `try`, recorded nothing at all for exactly the case the
            # record exists for.
            self._outbox.enqueue(
                event,
                channel_key=channel.key,
                channel_backend_id=channel.backend_id,
                provider=self._provider.name,
                now=now,
            )
            receipt = await self._provider.publish(channel, event)
        except DisclosureViolationError as exc:
            await self._record_publication(
                event=event,
                channel=channel,
                outcome=OUTCOME_REFUSED_DISCLOSURE,
                extra={"refusal": str(exc)[:MAX_INPUT_LENGTH]},
            )
            raise

        self._outbox.settle(receipt, now=self._now())
        await self._record_publication(
            event=event,
            channel=channel,
            outcome=receipt.status.value,
            extra={
                "backend_reference": receipt.backend_reference or "",
                "detail": receipt.detail[:MAX_INPUT_LENGTH],
            },
        )
        return receipt

    async def request_approval(
        self,
        channel: ChannelHandle,
        notice: ApprovalNotice,
        *,
        investigation_id: str,
        correlation_id: str,
        actor: str | None = None,
        actor_kind: ActorKind = ActorKind.SYSTEM,
    ) -> PublicationReceipt:
        """Publish an approval request. Authorizes nothing, and records that it did not."""
        event = notice.to_event(
            investigation_id=investigation_id,
            correlation_id=correlation_id,
            actor=actor or self._actor,
            actor_kind=actor_kind,
        )
        return await self.publish(channel, event)

    async def read_decisions(
        self,
        channel: ChannelHandle,
        notice: ApprovalNotice,
        *,
        since: datetime | None = None,
        now: datetime | None = None,
    ) -> tuple[DecisionIntake, ...]:
        """Read replies against one notice and record each reading as its own entry.

        One entry per intake rather than one per poll, because the interesting object is
        the *reading*: which key said something, whether the backend's own signature check
        passed, what a deliberately crude parser made of it, and — recorded explicitly
        rather than left to be inferred — that it authorized nothing.

        That last field is not decoration. The parser has already been wrong once in this
        module's history, reading "do not approve" as approval. When it is wrong again, the
        trail is where somebody reconstructs what the machine thought a human meant, and it
        needs the excerpt beside the verdict to do it.
        """
        moment = self._at(now)
        signals = await self._provider.poll(channel, since=since)
        await self._record(
            action=ACTION_READ_SIGNALS,
            subject=f"{self._provider.name}:{channel.key}",
            outcome=f"{len(signals)} signal(s)",
            inputs={
                "channel_key": channel.key,
                "since": since.isoformat() if since is not None else "",
                "capability_id": notice.capability_id,
            },
            occurred_at=moment,
        )

        intakes = read_intents(notice, signals, now=moment)
        for intake in intakes:
            await self._record(
                action=ACTION_READ_INTENT,
                subject=intake.capability_id,
                outcome=intake.intent.value,
                inputs={
                    "signal_id": intake.signal_id,
                    "author_reference": intake.author_reference,
                    "author_verified": str(intake.author_verified).lower(),
                    "authorizes": str(intake.authorizes).lower(),
                    "proposal_digest": notice.proposal_digest(),
                    "excerpt": intake.excerpt[:MAX_INPUT_LENGTH],
                },
                occurred_at=intake.observed_at,
            )
        return intakes

    async def drain(
        self, *, now: datetime | None = None, limit: int = 100
    ) -> tuple[PublicationReceipt, ...]:
        """Retry what the outbox says is due, and record each attempt.

        Returns the receipts of the attempts made, which is empty both when nothing is due
        and when the circuit breaker is open — two different situations that a caller
        distinguishes through :attr:`Outbox.breaker`, not through this return value. The
        breaker's :meth:`~nemesis.collaboration.outbox.CircuitBreaker.describe` is the
        answer to "why has nothing been published for ten minutes".

        A disclosure violation on a retry is recorded and **abandons that record** rather
        than propagating. An event already in the outbox has already been through this
        once; if it is now refused, re-raising from a drain loop would stop every other
        pending publication behind one poisoned entry.
        """
        moment = self._at(now)
        receipts: list[PublicationReceipt] = []
        for record in self._outbox.due(moment, limit=limit):
            handle = ChannelHandle(
                key=record.channel_key,
                provider=self._provider.name,
                backend_id=record.channel_backend_id,
            )
            try:
                receipt = await self._provider.publish(handle, record.event)
            except DisclosureViolationError as exc:
                receipt = PublicationReceipt(
                    event_id=record.event.event_id,
                    provider=self._provider.name,
                    status=PublicationStatus.REFUSED_REJECTED,
                    detail=f"refused at the disclosure boundary on retry: {exc}"[:500],
                )
                await self._record_publication(
                    event=record.event,
                    channel=handle,
                    outcome=OUTCOME_REFUSED_DISCLOSURE,
                    extra={"refusal": str(exc)[:MAX_INPUT_LENGTH], "attempt": "retry"},
                )
            else:
                await self._record_publication(
                    event=record.event,
                    channel=handle,
                    outcome=receipt.status.value,
                    extra={
                        "backend_reference": receipt.backend_reference or "",
                        "detail": receipt.detail[:MAX_INPUT_LENGTH],
                        "attempt": "retry",
                    },
                )
            self._outbox.settle(receipt, now=self._at(now))
            receipts.append(receipt)
        return tuple(receipts)

    async def _record_publication(
        self,
        *,
        event: CollaborationEvent,
        channel: ChannelHandle,
        outcome: str,
        extra: dict[str, str],
    ) -> None:
        """One entry per publication attempt, carrying what makes it checkable later.

        ``event_id`` is content-addressed and ``integrity_hash`` covers the publication
        payload, so the pair proves *which* event was published without the trail holding a
        second copy of it. The summary and the payload are deliberately absent: an audit
        record of an action is not the place to duplicate the content of that action, and
        the outbox already retains the event itself.
        """
        await self._record(
            action=ACTION_PUBLISH,
            subject=f"{self._provider.name}:{channel.key}",
            outcome=outcome,
            inputs={
                "event_id": event.event_id,
                "integrity_hash": event.integrity_hash(),
                "standing": event.standing.value,
                "classification": event.classification.value,
                "event_type": event.event_type,
                "case_id": event.case_id,
                "correlation_id": event.correlation_id,
                "published_by": event.actor,
                "references": str(len(event.references)),
                **extra,
            },
            occurred_at=event.occurred_at,
        )

    async def _record(
        self,
        *,
        action: str,
        subject: str,
        outcome: str,
        inputs: dict[str, str],
        occurred_at: datetime | None = None,
    ) -> None:
        await self._recorder.record(
            AuditEvent(
                audit_id=new_id(IdPrefix.AUDIT),
                occurred_at=occurred_at or self._now(),
                actor=self._actor,
                actor_kind=self._actor_kind.value,
                action=action,
                subject=subject[:MAX_INPUT_LENGTH],
                outcome=outcome[:MAX_INPUT_LENGTH],
                inputs={key: value[:MAX_INPUT_LENGTH] for key, value in inputs.items() if value},
            )
        )

    def _at(self, now: datetime | None) -> datetime:
        return require_utc(now, "now") if now is not None else self._now()

    def _now(self) -> datetime:
        clock = self._clock
        if clock is None:
            return utcnow()
        return require_utc(clock(), "clock")  # type: ignore[operator]


__all__ = [
    "ACTION_BIND_ACTOR",
    "ACTION_OPEN_CHANNEL",
    "ACTION_PUBLISH",
    "ACTION_READ_INTENT",
    "ACTION_READ_SIGNALS",
    "MAX_INPUT_LENGTH",
    "OUTCOME_REFUSED_DISCLOSURE",
    "CollaborationPublisher",
]
