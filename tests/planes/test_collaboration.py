"""The collaboration plane doing its ordinary job, correctly, on an ordinary day.

``tests/invariants/test_collaboration_boundary.py`` pins the things that must never happen:
that nothing above ``DELIVERABLE`` is publishable, that a signed message is not an
authorization, that inbound text stays data, that the plane holds no socket. Those are the
walls. This file is about everything the plane does *between* them, because a wall around a
mechanism that does not work is still a system that does not work.

Four failure modes shape what is tested here, each one quiet enough to survive a review.

**An identifier that is not actually deterministic.** The whole retry story rests on two
publications of one event content-addressing to one id: the outbox deduplicates on it, the
backend deduplicates on it, and a reader deduplicates on it. Timezone normalisation is where
that quietly breaks — the same instant written ``+02:00`` and written ``Z`` are the same
event, and a naive ISO rendering would give them two identifiers and therefore two copies in
a channel. So the equality is asserted directly, in both directions: same content is the same
id, and every published field changing the content changes the id.

**A provider that behaves plausibly instead of correctly.** The local provider is the mode
every test in this repository runs in, which makes its fidelity load-bearing rather than
convenient: if publishing to a channel nobody opened crashed here, or a retry appended a
second line here, the suite would be validating an implementation nobody deploys. Its
idempotence, its refusals, its ordering and its ``since``/``limit`` semantics are pinned as
the behaviour the seam actually promises.

**A Protocol nothing is checked against.** :class:`CollaborationProvider` is
``runtime_checkable``, and both shipped implementations are duck-typed onto it — neither
inherits from it, so nothing but an explicit check notices the day a method is renamed on one
side only.

**An approval notice that reads correctly and cannot be answered.** The published summary is
the entire user interface of the authorization flow: a reader who cannot see the digest and
the close time cannot reply in a way that parses, and a request nobody can answer correctly
is a request that gets answered incorrectly. That the projection carries both, at
``RECOMMENDATION`` standing and never higher, with the capability named first, is tested as
behaviour rather than assumed from the docstring.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from nemesis.collaboration.approvals import ApprovalNotice
from nemesis.collaboration.base import (
    ChannelDescriptor,
    ChannelHandle,
    CollaborationProvider,
    InboundSignal,
    PublicationReceipt,
    PublicationStatus,
)
from nemesis.collaboration.events import (
    MAX_PAYLOAD_ENTRIES,
    MAX_PAYLOAD_VALUE_LENGTH,
    MAX_REFERENCES,
    MAX_SUMMARY_LENGTH,
    CollaborationEvent,
    EpistemicStanding,
    Reference,
    ReferenceScheme,
)
from nemesis.collaboration.identities import (
    STANDING_ACTORS,
    ActorRegistry,
    DuplicateBindingError,
    platform_actor_id,
)
from nemesis.collaboration.providers.buzz.provider import BuzzCollaborationProvider
from nemesis.collaboration.providers.local import LocalCollaborationProvider
from nemesis.collaboration.providers.registry import (
    DEFAULT_PROVIDER,
    PROVIDERS,
    UnknownCollaborationProviderError,
    build_provider,
)
from nemesis.core.authorization import AuthorizationDecision, OperationClass, TargetFingerprint
from nemesis.core.identity import ActorKind
from nemesis.core.ids import IdPrefix, new_id

T0 = datetime(2026, 5, 4, 9, 30, tzinfo=UTC)
CASE = "case-2026-000123"
INVESTIGATION = "inv-2026-000123"
CHANNEL = "case-2026-000123"


def _event(**overrides: object) -> CollaborationEvent:
    fields: dict[str, object] = {
        "occurred_at": T0,
        "case_id": CASE,
        "investigation_id": INVESTIGATION,
        "correlation_id": "corr-1",
        "actor": "nemesis-pursuit",
        "actor_kind": ActorKind.RULE,
        "standing": EpistemicStanding.OBSERVATION,
        "event_type": "threat.infrastructure.observed",
        "summary": "evil.example resolved to 203.0.113.7",
    }
    fields.update(overrides)
    return CollaborationEvent.for_publication(**fields)  # type: ignore[arg-type]


def _reference(locator: str = "evd_sha256-" + "ab" * 32) -> Reference:
    return Reference(scheme=ReferenceScheme.EVIDENCE, case_id=CASE, locator=locator)


def _target(natural_key: str = "evil.example") -> TargetFingerprint:
    return TargetFingerprint.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type="domain",
        natural_key=natural_key,
        bound_attributes={"registrar": "example-registrar"},
    )


def _notice(**overrides: object) -> ApprovalNotice:
    fields: dict[str, object] = {
        "capability_id": new_id(IdPrefix.CAPABILITY),
        "case_id": CASE,
        "requested_by": "nemesis-pilot",
        "requested_by_kind": ActorKind.AGENT,
        "operation": OperationClass.PROVIDER_NOTIFICATION,
        "targets": (_target(),),
        "rationale": "Four independent sources place this domain in the campaign.",
        "proposed_at": T0,
        "responses_close_at": T0 + timedelta(hours=4),
    }
    fields.update(overrides)
    return ApprovalNotice(**fields)


def _signal(signal_id: str, minutes: int, body: str = "noted") -> InboundSignal:
    return InboundSignal(
        signal_id=signal_id,
        provider="unset",
        channel_key="unset",
        received_at=T0 + timedelta(minutes=minutes),
        author_reference="npub-analyst",
        body=body,
    )


def _opened(root: Path, key: str = CHANNEL) -> tuple[LocalCollaborationProvider, ChannelHandle]:
    provider = LocalCollaborationProvider(root)
    handle = asyncio.run(provider.open_channel(ChannelDescriptor(key=key, display_name="Case 123")))
    return provider, handle


# --- 1. The identifier is the deduplication story, so it is tested as one ----------


def test_two_events_built_from_the_same_inputs_are_the_same_event() -> None:
    """What makes a retry safe. Nothing else in the pipeline provides this property."""
    assert _event().event_id == _event().event_id
    assert _event().integrity_hash() == _event().integrity_hash()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("occurred_at", T0 + timedelta(seconds=1)),
        ("case_id", "case-2026-000999"),
        ("investigation_id", "inv-2026-000999"),
        ("correlation_id", "corr-2"),
        ("actor", "nemesis-pilot"),
        ("actor_kind", ActorKind.AGENT),
        ("standing", EpistemicStanding.INFERENCE),
        ("event_type", "threat.infrastructure.retired"),
        ("summary", "evil.example resolved to 203.0.113.8"),
        ("payload", {"resolver": "203.0.113.53"}),
        ("references", (_reference(),)),
        ("confidence", 0.4),
        ("uncertainty_note", "one source, not corroborated"),
    ],
)
def test_changing_any_published_field_changes_the_identifier(field: str, value: object) -> None:
    """Every field the id claims to cover, checked one at a time.

    A field accidentally dropped from :meth:`CollaborationEvent.publication_payload` would
    make two genuinely different events collide on one identifier, and the second would be
    silently discarded as a duplicate by the outbox and by the backend alike.
    """
    assert _event(**{field: value}).event_id != _event().event_id


def test_the_reference_order_is_part_of_the_identity() -> None:
    """Sorting them would make two different published statements share one id.

    An approval request naming an evidence bundle first and its target second is not the
    same statement as one naming them the other way round.
    """
    first, second = _reference("evd_sha256-" + "ab" * 32), _reference("evd_sha256-" + "cd" * 32)
    assert (
        _event(references=(first, second)).event_id != _event(references=(second, first)).event_id
    )


def test_an_event_id_that_does_not_match_its_content_is_refused() -> None:
    """The tampered-envelope case: content rewritten, identifier left alone.

    The check lives in a model validator rather than in the factory, so it also runs when an
    event is rehydrated from a channel file or a wire payload — which is the path a modified
    stored event would actually arrive by.
    """
    body = _event().model_dump()
    body["summary"] = "evil.example was never seen at all"
    with pytest.raises(ValueError, match="does not match its content"):
        CollaborationEvent(**body)


def test_the_same_instant_written_in_two_timezones_is_one_event() -> None:
    """The bug this normalisation exists to prevent, stated as an equality.

    ``09:30Z`` and ``11:30+02:00`` are the same moment. Without normalisation the ISO
    rendering differs, the content address differs, and one event is published twice with a
    deduplication check that matches neither copy.
    """
    berlin = _event(occurred_at=datetime(2026, 5, 4, 11, 30, tzinfo=timezone(timedelta(hours=2))))
    assert berlin.event_id == _event().event_id
    assert berlin.occurred_at == T0
    assert berlin.occurred_at.utcoffset() == timedelta(0)


def test_a_naive_occurred_at_is_refused_rather_than_assumed_to_be_utc() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        _event(occurred_at=T0.replace(tzinfo=None))


def test_the_integrity_hash_follows_the_content_and_not_the_clock() -> None:
    """Stable for one content, different for another. It is a checksum, not a nonce."""
    assert _event().integrity_hash().startswith("sha256:")
    assert _event().integrity_hash() != _event(summary="something else entirely").integrity_hash()


# --- 2. The published bounds, and the messages they fail with ----------------------


def test_a_payload_with_more_entries_than_the_bound_is_refused() -> None:
    payload = {f"key-{index}": "value" for index in range(MAX_PAYLOAD_ENTRIES + 1)}
    with pytest.raises(ValueError, match=f"at most {MAX_PAYLOAD_ENTRIES}"):
        _event(payload=payload)


def test_an_oversized_payload_value_names_the_key_and_says_what_to_do_instead() -> None:
    """A bound that does not say how to comply is a bound people work around.

    The message names the offending key and points at the alternative — publish a reference
    — because the wrong fix here is to truncate the material into the channel.
    """
    with pytest.raises(ValueError, match=r"payload\['blob'\].*Publish a reference"):
        _event(payload={"blob": "x" * (MAX_PAYLOAD_VALUE_LENGTH + 1)})


def test_more_references_than_the_bound_are_refused() -> None:
    references = tuple(
        Reference(scheme=ReferenceScheme.CLAIM, case_id=CASE, locator=f"claim-{index}")
        for index in range(MAX_REFERENCES + 1)
    )
    with pytest.raises(ValueError, match=f"at most {MAX_REFERENCES}"):
        _event(references=references)


def test_a_summary_longer_than_the_bound_is_refused() -> None:
    with pytest.raises(ValueError, match="at most 2000 characters"):
        _event(summary="x" * (MAX_SUMMARY_LENGTH + 1))


def test_an_event_sitting_exactly_on_every_bound_is_publishable() -> None:
    """The off-by-one direction nobody checks.

    A bound implemented as ``>=`` instead of ``>`` refuses the largest legitimate event, and
    the failure appears only for the one publication that happens to be at the limit.
    """
    event = _event(
        summary="x" * MAX_SUMMARY_LENGTH,
        payload={
            f"key-{index}": "v" * MAX_PAYLOAD_VALUE_LENGTH for index in range(MAX_PAYLOAD_ENTRIES)
        },
        references=tuple(
            Reference(scheme=ReferenceScheme.CLAIM, case_id=CASE, locator=f"claim-{index}")
            for index in range(MAX_REFERENCES)
        ),
    )
    assert len(event.payload) == MAX_PAYLOAD_ENTRIES
    assert len(event.references) == MAX_REFERENCES
    assert len(event.summary) == MAX_SUMMARY_LENGTH


# --- 3. The local provider: the mode every other test in this repository runs in ---


def test_opening_a_channel_twice_creates_it_once_and_reports_which_call_did(
    tmp_path: Path,
) -> None:
    """``created`` is reported rather than swallowed so an audit entry can say which
    happened: making a room and finding one are different facts about a deployment."""
    provider = LocalCollaborationProvider(tmp_path)
    descriptor = ChannelDescriptor(key=CHANNEL, display_name="Case 123")

    first = asyncio.run(provider.open_channel(descriptor))
    second = asyncio.run(provider.open_channel(descriptor))

    assert first.created is True
    assert second.created is False
    assert first.backend_id == second.backend_id
    assert first.provider == "local"


def test_publishing_to_a_channel_nobody_opened_is_a_refusal_not_an_exception(
    tmp_path: Path,
) -> None:
    """The seam promises a receipt for every expected failure.

    A crash here would push callers into wrapping every publication in a try/except, which
    ends as a bare one; and creating the channel as a side effect of a write would mean a
    typo in a key silently opens a room nobody meant to exist.
    """
    provider = LocalCollaborationProvider(tmp_path)
    ghost = ChannelHandle(
        key="never-opened",
        provider="local",
        backend_id=str(tmp_path / "channels" / "never-opened.jsonl"),
    )

    receipt = asyncio.run(provider.publish(ghost, _event()))

    assert receipt.status is PublicationStatus.REFUSED_REJECTED
    assert receipt.status.is_settled is True
    assert receipt.succeeded is False
    assert "never-opened" in receipt.detail
    assert not (tmp_path / "channels" / "never-opened.jsonl").exists()


def test_publishing_one_event_twice_is_a_duplicate_and_writes_a_single_line(
    tmp_path: Path,
) -> None:
    """The retry path, end to end.

    ``DUPLICATE`` is a success — it is what a content-addressed identifier is for — and the
    assertion that matters is the one about the file: a retry that appended a second line
    would give every reader of the channel two of everything after any lost acknowledgement.
    """
    provider, handle = _opened(tmp_path)
    event = _event()

    first = asyncio.run(provider.publish(handle, event))
    second = asyncio.run(provider.publish(handle, event))

    assert first.status is PublicationStatus.PUBLISHED
    assert second.status is PublicationStatus.DUPLICATE
    assert second.succeeded is True
    assert Path(handle.backend_id).read_text(encoding="utf-8").count("\n") == 1
    assert len(provider.published(CHANNEL)) == 1


def test_a_published_receipt_carries_the_backends_own_reference(tmp_path: Path) -> None:
    """Without it, "we published it" is an assertion the platform makes about itself."""
    provider, handle = _opened(tmp_path)
    receipt = asyncio.run(provider.publish(handle, _event()))

    assert receipt.backend_reference is not None
    assert receipt.backend_reference.startswith(Path(handle.backend_id).name)
    assert receipt.published_at is not None
    assert receipt.published_at.utcoffset() == timedelta(0)
    assert receipt.provider == "local"


def test_a_published_receipt_without_a_backend_reference_cannot_be_built() -> None:
    """The rule is on the model, so no provider can report a success it cannot evidence."""
    with pytest.raises(ValueError, match="must carry the backend's own reference"):
        PublicationReceipt(
            event_id=_event().event_id,
            provider="local",
            status=PublicationStatus.PUBLISHED,
        )


def test_published_round_trips_every_event_in_the_order_it_was_published(
    tmp_path: Path,
) -> None:
    """A channel read as a timeline is only a timeline if the mirror preserves order."""
    provider, handle = _opened(tmp_path)
    events = [_event(correlation_id=f"corr-{index}") for index in range(3)]
    for event in events:
        asyncio.run(provider.publish(handle, event))

    recovered = provider.published(CHANNEL)

    assert [event.event_id for event in recovered] == [event.event_id for event in events]
    assert recovered[0] == events[0]
    assert recovered[1].integrity_hash() == events[1].integrity_hash()


def test_published_is_empty_for_a_channel_that_was_never_opened(tmp_path: Path) -> None:
    assert LocalCollaborationProvider(tmp_path).published("no-such-channel") == ()


def test_poll_returns_delivered_signals_oldest_first_whatever_order_they_arrived(
    tmp_path: Path,
) -> None:
    """Sorted on read rather than trusted from the file.

    A backend delivers what it has when it has it; a caller reading a channel to reconstruct
    a conversation needs time order, and inferring it from arrival order is how a late
    delivery rewrites the history of a decision.
    """
    provider, handle = _opened(tmp_path)
    for signal_id, minutes in (("sig-late", 30), ("sig-early", 10), ("sig-middle", 20)):
        provider.deliver_inbound(CHANNEL, _signal(signal_id, minutes))

    signals = asyncio.run(provider.poll(handle))

    assert [signal.signal_id for signal in signals] == ["sig-early", "sig-middle", "sig-late"]
    assert {signal.provider for signal in signals} == {"local"}
    assert {signal.channel_key for signal in signals} == {CHANNEL}


def test_poll_since_excludes_the_watermark_itself_so_a_loop_cannot_re_read_one_signal(
    tmp_path: Path,
) -> None:
    """``since`` is exclusive on purpose: a caller loops by passing back the last
    ``received_at`` it saw, and an inclusive bound would re-deliver that signal forever."""
    provider, handle = _opened(tmp_path)
    for signal_id, minutes in (("sig-early", 10), ("sig-middle", 20), ("sig-late", 30)):
        provider.deliver_inbound(CHANNEL, _signal(signal_id, minutes))

    signals = asyncio.run(provider.poll(handle, since=T0 + timedelta(minutes=20)))

    assert [signal.signal_id for signal in signals] == ["sig-late"]


def test_poll_limit_returns_the_oldest_signals_rather_than_an_arbitrary_slice(
    tmp_path: Path,
) -> None:
    """A limit that dropped the oldest would silently skip the reply a caller is waiting
    for, and the next poll — advancing its watermark past it — would never see it."""
    provider, handle = _opened(tmp_path)
    for signal_id, minutes in (("sig-late", 30), ("sig-early", 10), ("sig-middle", 20)):
        provider.deliver_inbound(CHANNEL, _signal(signal_id, minutes))

    signals = asyncio.run(provider.poll(handle, limit=2))

    assert [signal.signal_id for signal in signals] == ["sig-early", "sig-middle"]


def test_polling_a_channel_nothing_was_delivered_to_returns_nothing(tmp_path: Path) -> None:
    provider, handle = _opened(tmp_path)
    assert asyncio.run(provider.poll(handle)) == ()


def test_poll_refuses_a_naive_since_rather_than_guessing_its_timezone(tmp_path: Path) -> None:
    provider, handle = _opened(tmp_path)
    with pytest.raises(ValueError, match="timezone-aware"):
        asyncio.run(provider.poll(handle, since=T0.replace(tzinfo=None)))


def test_health_is_true_while_the_storage_root_is_there(tmp_path: Path) -> None:
    provider = LocalCollaborationProvider(tmp_path / "collab")
    assert asyncio.run(provider.health()) is True


def test_a_channel_key_that_climbs_out_of_the_root_is_refused_at_both_doors(
    tmp_path: Path,
) -> None:
    """The key reaches a filesystem path, so a traversal in it would write outside the root.

    Both doors are checked. :class:`ChannelDescriptor` constrains the pattern, but
    :meth:`LocalCollaborationProvider.published` and ``deliver_inbound`` take a bare string,
    and a validator that only runs on one of two doors is not a validator.
    """
    provider = LocalCollaborationProvider(tmp_path / "root")

    with pytest.raises(ValueError, match="String should match pattern"):
        ChannelDescriptor(key="../escape", display_name="Escape")

    with pytest.raises(ValueError, match="not safe as a path component"):
        provider.published("../escape")

    with pytest.raises(ValueError, match="not safe as a path component"):
        provider.deliver_inbound("../escape", _signal("sig-1", 5))

    assert not (tmp_path / "escape.jsonl").exists()
    assert list((tmp_path / "root" / "inbox").iterdir()) == []


# --- 4. Both shipped providers are checked against the seam they claim to satisfy --


@pytest.mark.parametrize(
    "provider",
    [
        pytest.param(LocalCollaborationProvider, id="local"),
        pytest.param(BuzzCollaborationProvider, id="buzz"),
    ],
)
def test_every_shipped_provider_satisfies_the_collaboration_protocol(
    provider: type[object], tmp_path: Path
) -> None:
    """Neither implementation inherits from the Protocol, so nothing but this notices.

    A method renamed on one side only would leave the other silently unsubstitutable, and
    the discovery would happen at the call site of whichever provider a deployment chose.
    """
    instance = (
        LocalCollaborationProvider(tmp_path)
        if provider is LocalCollaborationProvider
        else BuzzCollaborationProvider()
    )
    assert isinstance(instance, CollaborationProvider)
    assert isinstance(instance.name, str)


# --- 5. The registry resolves by name and is closed to runtime additions ----------


def test_building_the_local_provider_roots_it_where_it_was_told(tmp_path: Path) -> None:
    provider = build_provider("local", root=tmp_path / "collab")
    assert isinstance(provider, LocalCollaborationProvider)
    assert provider.root == tmp_path / "collab"
    assert provider.name == "local"


def test_the_local_provider_cannot_be_built_without_somewhere_to_write() -> None:
    with pytest.raises(ValueError, match="needs a root directory"):
        build_provider("local")


def test_the_buzz_name_resolves_to_the_buzz_provider(tmp_path: Path) -> None:
    provider = build_provider("buzz", root=tmp_path)
    assert isinstance(provider, BuzzCollaborationProvider)
    assert provider.name == "buzz"


def test_an_unknown_provider_name_is_refused_and_the_message_lists_what_exists() -> None:
    """Failing closed, with the typo's neighbours in the message.

    A deployment that configured ``buzzz`` and silently fell back to the local provider
    would write to a directory while its logs said it was publishing to a relay, and nothing
    would ever tell it otherwise.
    """
    with pytest.raises(UnknownCollaborationProviderError) as raised:
        build_provider("buzzz")

    message = str(raised.value)
    assert "buzzz" in message
    for name in PROVIDERS:
        assert name in message


def test_the_default_provider_is_the_one_that_reaches_no_network() -> None:
    assert DEFAULT_PROVIDER == "local"
    assert DEFAULT_PROVIDER in PROVIDERS


def test_the_provider_table_cannot_be_added_to_at_runtime() -> None:
    """An import graph is not an authorization decision.

    A registry with a ``register()`` function lets whatever happened to be imported decide
    which backends NEMESIS will talk to. This one is built at import; adding a backend is a
    commit.
    """
    with pytest.raises(TypeError):
        PROVIDERS["rogue"] = "a backend nobody reviewed"  # type: ignore[index]

    assert "rogue" not in PROVIDERS


# --- 6. Projecting an approval request into something a human can answer ----------


def test_an_approval_notice_projects_at_recommendation_standing_and_no_higher() -> None:
    """A proposal is not a decision and not a finding.

    ``RECOMMENDATION`` is the standing that authorizes nothing by existing; publishing the
    same request as an ``INFERENCE`` or a ``DECISION`` would make a question look like an
    outcome to every reader of the channel.
    """
    event = _notice().to_event(
        investigation_id=INVESTIGATION,
        correlation_id="corr-1",
        actor="nemesis-authorization",
    )
    assert event.standing is EpistemicStanding.RECOMMENDATION
    assert event.event_type == "authorization.approval.requested"


def test_the_published_summary_tells_a_reader_exactly_what_to_type_back() -> None:
    """The summary is the whole user interface of the approval flow.

    A reader who cannot see the digest cannot produce a reply that parses as anything but
    ``UNCLEAR``, and a request nobody can answer correctly is a request that gets answered
    incorrectly.
    """
    notice = _notice()
    event = notice.to_event(
        investigation_id=INVESTIGATION,
        correlation_id="corr-1",
        actor="nemesis-authorization",
    )

    assert notice.proposal_digest() in event.summary
    assert notice.responses_close_at.isoformat() in event.summary
    assert "not an authorization" in event.summary
    assert event.payload["proposal_digest"] == notice.proposal_digest()
    assert event.occurred_at == notice.proposed_at


def test_the_capability_is_the_first_reference_and_the_evidence_follows_it() -> None:
    """Order carries meaning here and is covered by the identifier.

    A reader scanning the references sees what is being decided before what supports it, and
    the capability locator is the identifier the proposal, the decision and the eventual
    grant all share.
    """
    notice = _notice(evidence_references=(_reference(),))
    event = notice.to_event(
        investigation_id=INVESTIGATION,
        correlation_id="corr-1",
        actor="nemesis-authorization",
    )

    assert event.references[0].scheme is ReferenceScheme.CAPABILITY
    assert event.references[0].locator == notice.capability_id
    assert event.references[1].scheme is ReferenceScheme.EVIDENCE
    assert len(event.references) == 2


def test_a_denied_policy_decision_is_published_beside_the_request_rather_than_hidden() -> None:
    """Asking a person to approve what the policy already refuses is worth showing."""
    target = _target()
    capability_id = new_id(IdPrefix.CAPABILITY)
    notice = _notice(
        capability_id=capability_id,
        targets=(target,),
        policy_decision=AuthorizationDecision(
            permitted=False,
            capability_id=capability_id,
            operation=OperationClass.PROVIDER_NOTIFICATION,
            target_fingerprint=target.fingerprint,
            evaluated_at=T0,
            denial_reasons=("the capability had expired",),
        ),
    )
    event = notice.to_event(
        investigation_id=INVESTIGATION,
        correlation_id="corr-1",
        actor="nemesis-authorization",
    )

    assert event.payload["policy_decision"] == "denied"
    assert event.payload["policy_denial_reasons"] == "the capability had expired"


def test_a_policy_decision_about_a_different_operation_is_refused_at_construction() -> None:
    """Publishing a verdict beside an operation it never evaluated misrepresents the check.

    Refused when the notice is built, not when it is published, so there is no object in
    existence for a second publication path to pick up.
    """
    target = _target()
    capability_id = new_id(IdPrefix.CAPABILITY)
    with pytest.raises(ValueError, match="but the notice proposes"):
        _notice(
            capability_id=capability_id,
            operation=OperationClass.PROVIDER_NOTIFICATION,
            targets=(target,),
            policy_decision=AuthorizationDecision(
                permitted=True,
                capability_id=capability_id,
                operation=OperationClass.DOMAIN_SEIZURE,
                target_fingerprint=target.fingerprint,
                evaluated_at=T0,
            ),
        )


def test_a_policy_decision_about_a_different_target_is_refused_at_construction() -> None:
    """Target substitution, in the field a reader is least likely to re-check."""
    capability_id = new_id(IdPrefix.CAPABILITY)
    with pytest.raises(ValueError, match="not among the notice's targets"):
        _notice(
            capability_id=capability_id,
            targets=(_target("evil.example"),),
            policy_decision=AuthorizationDecision(
                permitted=True,
                capability_id=capability_id,
                operation=OperationClass.PROVIDER_NOTIFICATION,
                target_fingerprint=_target("innocent.example").fingerprint,
                evaluated_at=T0,
            ),
        )


@pytest.mark.parametrize("offset", [timedelta(0), timedelta(seconds=-1)])
def test_a_proposal_that_is_closed_when_it_opens_is_refused(offset: timedelta) -> None:
    """A window that never opens is a silent refusal wearing the shape of a question."""
    with pytest.raises(ValueError, match="must be after proposed_at"):
        _notice(responses_close_at=T0 + offset)


# --- 7. Actor identity: stable, distinct, and bound exactly once ------------------


def test_the_standing_roster_is_populated_and_no_two_actors_share_an_identifier() -> None:
    """The roster is keyed by ``actor_id``, so a collision would silently shrink it.

    Two actors deriving one id would not raise — one would simply replace the other, and the
    channel would attribute a component's messages to a component that never wrote them.
    """
    actors = tuple(STANDING_ACTORS.values())
    assert len(actors) >= 1
    assert len({actor.actor_id for actor in actors}) == len(actors)
    assert len({actor.display_name for actor in actors}) == len(actors)
    assert all(key == actor.actor_id for key, actor in STANDING_ACTORS.items())


def test_a_platform_actor_id_is_the_same_on_every_call_and_differs_per_component() -> None:
    """A component that minted a fresh id per construction would appear in a channel as a
    new participant on every restart, and a week of history would read as a crowd."""
    assert platform_actor_id("pilot-seat") == platform_actor_id("pilot-seat")
    assert platform_actor_id("pilot-seat") != platform_actor_id("pursuit-scheduler")
    assert platform_actor_id("pilot-seat").startswith(f"{IdPrefix.ACTOR.value}_")
    assert platform_actor_id("pilot-seat") in STANDING_ACTORS


def test_enrolling_an_unchanged_binding_twice_returns_the_one_binding() -> None:
    """Re-enrolment on restart is the normal case and must not be an error."""
    registry = ActorRegistry("local")
    actor = STANDING_ACTORS[platform_actor_id("pilot-seat")]

    first = registry.enrol(actor, "npub-pilot")
    second = registry.enrol(actor, "npub-pilot")

    assert first == second
    assert len(registry) == 1
    assert registry.backend_reference_for(actor.actor_id) == "npub-pilot"
    assert registry.actor_for_backend("npub-pilot") == actor.actor_id


def test_rebinding_an_actor_to_a_second_key_is_refused_rather_than_overwritten() -> None:
    """Last-writer-wins here would make a week of channel history read as two participants
    who are one, which is the same failure the audit trail refuses for human names."""
    registry = ActorRegistry("local")
    actor = STANDING_ACTORS[platform_actor_id("pilot-seat")]
    registry.enrol(actor, "npub-pilot")

    with pytest.raises(DuplicateBindingError, match="already bound"):
        registry.enrol(actor, "npub-pilot-rotated")

    assert registry.backend_reference_for(actor.actor_id) == "npub-pilot"
    assert registry.actor_for_backend("npub-pilot-rotated") is None
