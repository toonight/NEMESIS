"""Invariant 11 applied to the plane that talks to the outside.

"All meaningful agent and human actions are auditable. Replayable, not just logged." The
collaboration plane had no exception to that and had been getting one: a publication was
durable in the outbox and delivered by the provider and recorded nowhere, so "what did
NEMESIS say, to whom, and when" was answerable only by reading a channel whose operator
can delete rows.

These tests pin four things:

1. **Every publication attempt is recorded, including the ones that were refused.** A
   trail that holds only successes is a trail that is silent about the interesting case.
2. **The record is checkable.** Each entry carries the event's content-addressed id and
   its integrity hash, so a reader can prove which event was published without the trail
   holding a second copy of the content.
3. **The plane can write and cannot read.** It takes a
   :class:`~nemesis.ports.storage.PublicationRecorder`, not an
   :class:`~nemesis.ports.storage.AuditSink`, and still cannot import
   :mod:`nemesis.audit`.
4. **An audit failure stops the publisher.** Recording is not best-effort.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from nemesis.audit.trail import AppendOnlyAuditTrail, AuditWriteError
from nemesis.collaboration.approvals import ApprovalNotice
from nemesis.collaboration.base import (
    ChannelDescriptor,
    ChannelHandle,
    InboundSignal,
    PublicationReceipt,
    PublicationStatus,
)
from nemesis.collaboration.demonstration import run_collaboration_demonstration
from nemesis.collaboration.events import (
    CollaborationEvent,
    EpistemicStanding,
)
from nemesis.collaboration.outbox import Outbox, OutboxState
from nemesis.collaboration.providers.local import LocalCollaborationProvider
from nemesis.collaboration.publisher import (
    ACTION_OPEN_CHANNEL,
    ACTION_PUBLISH,
    ACTION_READ_INTENT,
    OUTCOME_REFUSED_DISCLOSURE,
    CollaborationPublisher,
)
from nemesis.core.authorization import OperationClass, TargetFingerprint
from nemesis.core.disclosure import DisclosureClass, DisclosureViolationError
from nemesis.core.identity import ActorKind
from nemesis.core.ids import IdPrefix, new_id
from nemesis.ports.storage import AuditEvent, AuditSink, PublicationRecorder

pytestmark = pytest.mark.invariant

T0 = datetime(2026, 5, 4, 9, 30, tzinfo=UTC)
CASE = "case-2026-000123"
PUBLISHER_ACTOR = "nemesis-collaboration-publisher"


class _Collector:
    """A recorder that keeps what it was given. Satisfies the port structurally."""

    def __init__(self) -> None:
        self.entries: list[AuditEvent] = []

    async def record(self, event: AuditEvent) -> AuditEvent:
        self.entries.append(event)
        return event


class _RefusingRecorder:
    """A trail that will not accept a write."""

    async def record(self, event: AuditEvent) -> AuditEvent:
        raise AuditWriteError("the trail is unreadable from line 4")


def _event(**overrides: object) -> CollaborationEvent:
    fields: dict[str, object] = {
        "occurred_at": T0,
        "case_id": CASE,
        "investigation_id": "inv-1",
        "correlation_id": "corr-1",
        "actor": "nemesis-pursuit",
        "actor_kind": ActorKind.RULE,
        "standing": EpistemicStanding.OBSERVATION,
        "event_type": "threat.infrastructure.observed",
        "summary": "evil.example resolved to 203.0.113.7",
    }
    fields.update(overrides)
    return CollaborationEvent.for_publication(**fields)  # type: ignore[arg-type]


def _publisher(
    tmp_path: Path, recorder: PublicationRecorder
) -> tuple[CollaborationPublisher, LocalCollaborationProvider]:
    provider = LocalCollaborationProvider(tmp_path / "collab", clock=lambda: T0)
    publisher = CollaborationPublisher(
        provider=provider,
        outbox=Outbox(tmp_path / "outbox.jsonl"),
        recorder=recorder,
        actor=PUBLISHER_ACTOR,
        clock=lambda: T0,
    )
    return publisher, provider


def _open(publisher: CollaborationPublisher, key: str = "ops") -> ChannelHandle:
    return asyncio.run(publisher.open_channel(ChannelDescriptor(key=key, display_name="Ops")))


# --- 1. Every attempt is recorded, refusals included -------------------------------


def test_a_successful_publication_is_recorded(tmp_path: Path) -> None:
    collector = _Collector()
    publisher, _ = _publisher(tmp_path, collector)
    channel = _open(publisher)

    event = _event()
    receipt = asyncio.run(publisher.publish(channel, event))
    assert receipt.status is PublicationStatus.PUBLISHED

    entries = [e for e in collector.entries if e.action == ACTION_PUBLISH]
    assert len(entries) == 1
    assert entries[0].outcome == "published"
    assert entries[0].inputs["event_id"] == event.event_id


def test_a_refused_publication_is_recorded_before_the_refusal_propagates(
    tmp_path: Path,
) -> None:
    """The single most interesting thing that can happen here, and the easiest to lose.

    A publisher that recorded only successes would be silent about exactly the event an
    operator most needs to see: an attempt to put withheld material into a channel. The
    entry is written *before* the exception is re-raised, so the record survives a caller
    that does not catch it.
    """
    collector = _Collector()
    publisher, provider = _publisher(tmp_path, collector)
    channel = _open(publisher)

    withheld = _event().model_copy(update={"classification": DisclosureClass.RESTRICTED})
    with pytest.raises(DisclosureViolationError):
        asyncio.run(publisher.publish(channel, withheld))

    entries = [e for e in collector.entries if e.action == ACTION_PUBLISH]
    assert len(entries) == 1
    assert entries[0].outcome == OUTCOME_REFUSED_DISCLOSURE
    assert "refusal" in entries[0].inputs
    assert provider.published("ops") == ()


def test_an_unreachable_backend_is_recorded_rather_than_lost(tmp_path: Path) -> None:
    """A backend being down is an ordinary Tuesday, and still an auditable event."""
    collector = _Collector()
    publisher, _ = _publisher(tmp_path, collector)
    # A handle pointing at a channel that was never opened: the local provider refuses it.
    unopened = ChannelHandle(
        key="ghost", provider="local", backend_id=str(tmp_path / "nowhere.jsonl")
    )
    receipt = asyncio.run(publisher.publish(unopened, _event()))

    assert not receipt.succeeded
    entries = [e for e in collector.entries if e.action == ACTION_PUBLISH]
    assert len(entries) == 1
    assert entries[0].outcome == receipt.status.value


def test_opening_a_channel_is_recorded_and_says_whether_it_was_created(
    tmp_path: Path,
) -> None:
    collector = _Collector()
    publisher, _ = _publisher(tmp_path, collector)
    _open(publisher)
    _open(publisher)

    outcomes = [e.outcome for e in collector.entries if e.action == ACTION_OPEN_CHANNEL]
    assert outcomes == ["created", "already_existed"]


def test_reading_a_reply_records_that_it_authorized_nothing(tmp_path: Path) -> None:
    """The reading is the auditable object, and its worth is recorded beside it.

    The parser has already been wrong once in this plane's history — it read "do not
    approve" as approval. When it is wrong again, the trail is where somebody reconstructs
    what the machine thought a human meant, so it carries the excerpt beside the verdict
    and states outright that nothing was authorized.
    """
    collector = _Collector()
    publisher, provider = _publisher(
        tmp_path,
        collector,
    )
    channel = _open(publisher, "approvals")

    notice = ApprovalNotice(
        capability_id=new_id(IdPrefix.CAPABILITY),
        case_id=CASE,
        requested_by="nemesis-pilot",
        requested_by_kind=ActorKind.AGENT,
        operation=OperationClass.PROVIDER_NOTIFICATION,
        targets=(
            TargetFingerprint.create(
                entity_id=new_id(IdPrefix.ENTITY),
                entity_type="domain",
                natural_key="evil.example",
                bound_attributes={},
            ),
        ),
        rationale="four independent sources",
        proposed_at=T0,
        responses_close_at=T0 + timedelta(hours=4),
    )
    provider.deliver_inbound(
        "approvals",
        InboundSignal(
            signal_id="sig-1",
            provider="local",
            channel_key="approvals",
            received_at=T0 + timedelta(minutes=5),
            author_reference="npub-analyst",
            author_verified=True,
            body=f"APPROVE {notice.proposal_digest()}",
        ),
    )

    intakes = asyncio.run(
        publisher.read_decisions(channel, notice, since=T0, now=T0 + timedelta(minutes=10))
    )
    assert len(intakes) == 1

    (entry,) = [e for e in collector.entries if e.action == ACTION_READ_INTENT]
    assert entry.outcome == "appears_to_approve"
    assert entry.inputs["authorizes"] == "false"
    assert entry.inputs["author_verified"] == "true"
    assert notice.proposal_digest() in entry.inputs["proposal_digest"]
    assert entry.inputs["excerpt"].startswith("APPROVE")


# --- 2. The record is checkable ----------------------------------------------------


def test_a_publication_entry_proves_which_event_was_published(tmp_path: Path) -> None:
    """Replayable, not merely logged.

    The entry carries the content-addressed id and the integrity hash. Given the event, a
    reader can recompute both and show that this entry is about that event — without the
    trail holding a second copy of the content.
    """
    collector = _Collector()
    publisher, _ = _publisher(tmp_path, collector)
    channel = _open(publisher)
    event = _event()
    asyncio.run(publisher.publish(channel, event))

    (entry,) = [e for e in collector.entries if e.action == ACTION_PUBLISH]
    assert entry.inputs["event_id"] == event.event_id
    assert entry.inputs["integrity_hash"] == event.integrity_hash()
    assert entry.inputs["standing"] == event.standing.value
    assert entry.inputs["classification"] == DisclosureClass.DELIVERABLE.value


def test_a_publication_entry_does_not_duplicate_the_content(tmp_path: Path) -> None:
    """An audit record of an action is not a second copy of it.

    The summary is what a channel displays and what the outbox retains; putting it in the
    trail too would mean an operator practising retention on the vault and the channel
    while a third copy accumulated in a file nothing prunes.
    """
    collector = _Collector()
    publisher, _ = _publisher(tmp_path, collector)
    channel = _open(publisher)
    marker = "a distinctive summary nobody else would write"
    asyncio.run(publisher.publish(channel, _event(summary=marker)))

    (entry,) = [e for e in collector.entries if e.action == ACTION_PUBLISH]
    assert marker not in " ".join(entry.inputs.values())


def test_the_demonstration_records_one_entry_per_publication(tmp_path: Path) -> None:
    """Counted against the publications, not asserted in a docstring."""
    trail = AppendOnlyAuditTrail(tmp_path / "audit.jsonl")
    result = asyncio.run(run_collaboration_demonstration(workspace=tmp_path, recorder=trail))

    assert len(result.publication_entries) == len(result.receipts)
    assert result.audit_entries, "the demonstration recorded nothing"
    assert asyncio.run(trail.verify_chain()) is True


def test_the_demonstration_writes_a_chain_that_survives_reopening(tmp_path: Path) -> None:
    """The bytes are on disk, and a fresh reader verifies them."""
    trail = AppendOnlyAuditTrail(tmp_path / "audit.jsonl")
    asyncio.run(run_collaboration_demonstration(workspace=tmp_path, recorder=trail))

    reopened = AppendOnlyAuditTrail(tmp_path / "audit.jsonl")
    assert asyncio.run(reopened.verify_chain()) is True
    assert asyncio.run(reopened.verify()).intact


def test_tampering_with_a_publication_entry_breaks_the_chain(tmp_path: Path) -> None:
    """The property the whole exercise is for, demonstrated by actually tampering."""
    path = tmp_path / "audit.jsonl"
    trail = AppendOnlyAuditTrail(path)
    asyncio.run(run_collaboration_demonstration(workspace=tmp_path, recorder=trail))
    assert asyncio.run(AppendOnlyAuditTrail(path).verify()).intact

    lines = path.read_text(encoding="utf-8").splitlines()
    edited = [
        line.replace('"outcome":"published"', '"outcome":"refused_rejected"', 1)
        if '"outcome":"published"' in line
        else line
        for line in lines
    ]
    assert edited != lines, "the tamper did not change anything"
    path.write_text("\n".join(edited) + "\n", encoding="utf-8")

    assert asyncio.run(AppendOnlyAuditTrail(path).verify()).intact is False


# --- 3. The plane can write and cannot read ----------------------------------------


def test_the_publisher_takes_a_write_only_recorder(tmp_path: Path) -> None:
    """A publisher handed a full sink would be able to read the platform's history.

    `PublicationRecorder` has exactly one member. This asserts the Protocol itself rather
    than the annotation, because an annotation is a claim and a Protocol's member set is
    the thing that decides what a holder can call.
    """
    members = {
        name
        for name in dir(PublicationRecorder)
        if not name.startswith("_") and callable(getattr(PublicationRecorder, name, None))
    }
    assert members == {"record"}

    sink_members = {
        name
        for name in dir(AuditSink)
        if not name.startswith("_") and callable(getattr(AuditSink, name, None))
    }
    assert "query" in sink_members
    assert "query" not in members


def test_an_audit_sink_satisfies_the_recorder_without_an_adapter() -> None:
    """Structural typing is what makes the narrowing free."""
    assert isinstance(AppendOnlyAuditTrail, type)
    assert hasattr(AppendOnlyAuditTrail, "record")
    signature = inspect.signature(AppendOnlyAuditTrail.record)
    assert list(signature.parameters) == ["self", "event"]


def test_the_publisher_holds_no_reference_into_the_audit_plane(tmp_path: Path) -> None:
    """The contract forbids the import; this checks the loaded module graph too."""
    import nemesis.collaboration.publisher as module

    for value in vars(module).values():
        name = getattr(value, "__name__", "")
        assert not name.startswith("nemesis.audit"), f"{name} is reachable from the publisher"


# --- 4. Recording is not best-effort ------------------------------------------------


def test_an_audit_write_failure_stops_the_publisher(tmp_path: Path) -> None:
    """A publisher that believed it recorded a publication and did not is worse off.

    It carries on and produces a channel history with a hole in it — the same argument
    `AuditWriteError` makes for itself. The outbox has already made the intent durable, so
    an operator who hits this can still see what was in flight.
    """
    publisher, _ = _publisher(tmp_path, _RefusingRecorder())
    with pytest.raises(AuditWriteError):
        asyncio.run(publisher.open_channel(ChannelDescriptor(key="ops", display_name="Ops")))


def test_the_intent_survives_an_audit_failure_because_the_outbox_wrote_first(
    tmp_path: Path,
) -> None:
    """Durability before delivery, and before recording."""
    outbox = Outbox(tmp_path / "outbox.jsonl")
    provider = LocalCollaborationProvider(tmp_path / "collab", clock=lambda: T0)
    publisher = CollaborationPublisher(
        provider=provider,
        outbox=outbox,
        recorder=_RefusingRecorder(),
        actor=PUBLISHER_ACTOR,
        clock=lambda: T0,
    )
    channel = ChannelHandle(
        key="ops", provider="local", backend_id=str(tmp_path / "collab" / "nowhere.jsonl")
    )
    event = _event()
    with pytest.raises(AuditWriteError):
        asyncio.run(publisher.publish(channel, event))

    reopened = Outbox(tmp_path / "outbox.jsonl")
    keys = [record.key for record in reopened.records()]
    assert event.event_id in keys


def test_a_retry_through_drain_is_recorded_too(tmp_path: Path) -> None:
    """The pump is in `src/` now, and it records what each attempt did."""
    collector = _Collector()
    outbox = Outbox(tmp_path / "outbox.jsonl")
    provider = LocalCollaborationProvider(tmp_path / "collab", clock=lambda: T0)
    publisher = CollaborationPublisher(
        provider=provider,
        outbox=outbox,
        recorder=collector,
        actor=PUBLISHER_ACTOR,
        clock=lambda: T0,
    )
    channel = _open(publisher)

    event = _event()
    outbox.enqueue(
        event,
        channel_key=channel.key,
        channel_backend_id=channel.backend_id,
        provider="local",
        now=T0,
    )
    before = len([e for e in collector.entries if e.action == ACTION_PUBLISH])

    receipts: Sequence[PublicationReceipt] = asyncio.run(publisher.drain(now=T0))
    assert len(receipts) == 1

    entries = [e for e in collector.entries if e.action == ACTION_PUBLISH]
    assert len(entries) == before + 1
    assert entries[-1].inputs["attempt"] == "retry"

    (record,) = [r for r in outbox.records() if r.key == event.event_id]
    assert record.state is OutboxState.DELIVERED
