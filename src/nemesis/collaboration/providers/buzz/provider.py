"""Buzz as a collaboration provider: the whole conversation, none of the authority.

This is a full implementation of
:class:`~nemesis.collaboration.base.CollaborationProvider` against a Buzz relay's real wire
protocol — NIP-01 events, NIP-29 groups, the relay's ``OK`` message vocabulary. What it
cannot do is reach a network, because the transport and the signer are injected Protocols
that NEMESIS ships no implementation of. See
:mod:`nemesis.collaboration.providers.buzz.transport` for why, and ADR-0010 for the
decision.

Three behaviours here are the load-bearing ones, and each exists because of something
measured in the relay's source rather than assumed:

**Every inbound event is re-verified as far as we can verify it.** The relay verifies
signatures at ingest and stores the row with a hardcoded ``verified: true``; nothing
re-checks on the read path, and no trigger prevents a direct ``UPDATE`` of ``content``,
``tags`` or ``sig``. So a stored event is only as trustworthy as the relay's database.
:meth:`BuzzCollaborationProvider.poll` therefore recomputes each event's id from its own
fields — which catches any modification of content or tags — and sets
:attr:`~nemesis.collaboration.base.InboundSignal.author_verified` to ``False`` unless a
signature check actually ran. It reports what it checked, never what it hopes.

**A refusal is classified by the relay's own message prefix.** ``duplicate:`` is a success,
``restricted:`` and ``invalid:`` are non-retryable rejections, ``auth-required:`` is a
credential problem, and anything else is a retryable failure. Collapsing those into "it
didn't work" would make the outbox retry a malformed event forever and give up on a
transient one.

**Nothing here decides anything.** The provider publishes an approval notice and returns
signals. It has no path to :mod:`nemesis.authz` — the layering forbids the import and a
contract names the package — so the strongest thing it can produce is
:class:`~nemesis.collaboration.approvals.DecisionIntake`, whose ``authorizes`` property is
``False`` by construction.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from datetime import datetime
from typing import Final

from nemesis.collaboration.base import (
    ActorBinding,
    ChannelDescriptor,
    ChannelHandle,
    ChannelVisibility,
    InboundSignal,
    ProviderConfigurationError,
    PublicationReceipt,
    PublicationStatus,
    SignalKind,
)
from nemesis.collaboration.events import CollaborationEvent
from nemesis.collaboration.providers.buzz import wire
from nemesis.collaboration.providers.buzz.transport import (
    BuzzTransport,
    EventSigner,
    PublishOutcome,
    SignerNotWiredError,
    TransportNotWiredError,
    UnwiredBuzzTransport,
    UnwiredEventSigner,
)
from nemesis.core.temporal import require_utc, utcnow

PROVIDER_NAME: Final = "buzz"

_DUPLICATE_PREFIXES: Final = ("duplicate:",)
_REJECTION_PREFIXES: Final = ("invalid:", "restricted:", "blocked:", "error:", "rate-limited:")
_AUTH_PREFIXES: Final = ("auth-required:",)


class BuzzCollaborationProvider:
    """Speaks a Buzz relay's protocol. Reaches a relay only if handed the means to.

    ``relay_url`` has no default and no environment fallback. An endpoint that a deployment
    picks up from an unset variable is an endpoint nobody chose, and invariant 15 requires
    that no endpoint ships. Construction without one is legal — the format is testable
    without an address — but any operation that would need it refuses by name.
    """

    def __init__(
        self,
        *,
        relay_url: str | None = None,
        transport: BuzzTransport | None = None,
        signer: EventSigner | None = None,
        clock: object = None,
    ) -> None:
        self._relay_url = relay_url
        self._transport: BuzzTransport = transport or UnwiredBuzzTransport(relay_url)
        self._signer: EventSigner = signer or UnwiredEventSigner()
        self._transport_was_injected = transport is not None
        self._signer_was_injected = signer is not None
        self._clock = clock

    @property
    def name(self) -> str:
        return PROVIDER_NAME

    @property
    def relay_url(self) -> str | None:
        return self._relay_url

    @property
    def is_wired(self) -> bool:
        """Whether this provider could actually reach a relay.

        Reported so a deployment can *assert* its own posture rather than infer it from
        whether messages appear. A demonstration that prints "publishing to Buzz" while
        holding an unwired transport is the class of self-describing untruth this repository
        keeps finding in itself."""
        return self._transport_was_injected and self._signer_was_injected

    async def open_channel(self, descriptor: ChannelDescriptor) -> ChannelHandle:
        self._require_relay_url("open_channel")
        unsigned = wire.build_create_group(
            pubkey=self._public_key(),
            created_at=self._timestamp(),
            channel_key=descriptor.key,
            display_name=descriptor.display_name,
            purpose=descriptor.purpose,
            private=descriptor.visibility is ChannelVisibility.RESTRICTED,
        )
        outcome = await self._send(unsigned)
        duplicate = _classify(outcome) is PublicationStatus.DUPLICATE
        if not outcome.accepted and not duplicate:
            raise ProviderConfigurationError(
                f"the relay refused to create channel {descriptor.key!r}: {outcome.message!r}. "
                "A channel that does not exist cannot be published to, so this is raised "
                "rather than returned as a handle nothing would work through"
            )
        return ChannelHandle(
            key=descriptor.key,
            provider=PROVIDER_NAME,
            backend_id=wire.channel_uuid(descriptor.key),
            created=outcome.accepted and not duplicate,
        )

    async def publish(
        self, channel: ChannelHandle, event: CollaborationEvent
    ) -> PublicationReceipt:
        try:
            self._require_relay_url("publish")
            # ADR-0006 at this boundary: act on the object reconstructed from the bytes,
            # never on the one handed to us. `model_copy(update=...)` and
            # `model_construct()` both skip validators, so an event that never passed the
            # classification wall can exist in memory — it must not reach a relay.
            event = CollaborationEvent.model_validate(event.model_dump(mode="json"))
            unsigned = wire.build_collaboration_event(
                pubkey=self._public_key(),
                created_at=self._timestamp(),
                channel_key=channel.key,
                event=event,
            )
            outcome = await self._send(unsigned)
        except (TransportNotWiredError, SignerNotWiredError, ProviderConfigurationError):
            raise
        except ValueError as exc:
            return PublicationReceipt(
                event_id=event.event_id,
                provider=PROVIDER_NAME,
                status=PublicationStatus.REFUSED_REJECTED,
                detail=f"the event could not be put on the wire: {exc}",
            )
        except Exception as exc:
            return PublicationReceipt(
                event_id=event.event_id,
                provider=PROVIDER_NAME,
                status=PublicationStatus.REFUSED_UNAVAILABLE,
                detail=f"{type(exc).__name__}: {exc}",
            )

        status = _classify(outcome)
        stored = status in {PublicationStatus.PUBLISHED, PublicationStatus.DUPLICATE}
        return PublicationReceipt(
            event_id=event.event_id,
            provider=PROVIDER_NAME,
            status=status,
            detail=outcome.message,
            backend_reference=outcome.event_id if stored else None,
            published_at=self._now() if status is PublicationStatus.PUBLISHED else None,
        )

    async def poll(
        self, channel: ChannelHandle, *, since: datetime | None = None, limit: int = 100
    ) -> Sequence[InboundSignal]:
        if since is not None:
            require_utc(since, "since")
        query = wire.channel_message_filter(
            channel_key=channel.key,
            since=int(since.timestamp()) if since is not None else None,
            limit=limit,
        )
        try:
            result = await self._transport.query([query])
        except TransportNotWiredError:
            raise
        except Exception:
            return ()

        signals: list[InboundSignal] = []
        for raw in result.events:
            signals.append(self._to_signal(channel.key, raw))
        return tuple(signals)

    async def bind_actor(self, binding: ActorBinding) -> ActorBinding:
        """Publish the actor's profile so the workspace can render it, and record the binding.

        Publishing a ``kind:0`` is the whole of "registering an agent" on this backend —
        there is no registration RPC. A failure to publish is not fatal: the binding is still
        what NEMESIS uses to attribute its own messages, and a workspace that shows a bare
        public key instead of a name is legible, if ugly."""
        recorded = binding.model_copy(update={"provider": PROVIDER_NAME})
        if not self.is_wired or self._relay_url is None:
            return recorded
        unsigned = wire.build_profile(
            pubkey=self._public_key(),
            created_at=self._timestamp(),
            display_name=binding.display_name,
            about=binding.role_description,
        )
        try:
            await self._send(unsigned)
        except Exception:
            return recorded
        return recorded

    async def health(self) -> bool:
        try:
            return await self._transport.health()
        except Exception:
            return False

    def auth_event(self, *, challenge: str) -> wire.NostrEvent:
        """Build and sign the NIP-42 answer to a relay's challenge.

        Exposed because the handshake belongs to whoever owns the socket — a transport
        implementation — while the event's construction belongs here, where it is tested.
        The relay pushes its challenge as the first frame and cancels the connection after
        five seconds, so a transport calls this and sends the result immediately."""
        self._require_relay_url("auth_event")
        assert self._relay_url is not None
        unsigned = wire.build_auth(
            pubkey=self._public_key(),
            created_at=self._timestamp(),
            challenge=challenge,
            relay_url=self._relay_url,
        )
        return unsigned.sealed(self._signer.sign(unsigned.signing_digest()))

    async def _send(self, unsigned: wire.UnsignedEvent) -> PublishOutcome:
        signed = unsigned.sealed(self._signer.sign(unsigned.signing_digest()))
        return await self._transport.publish(signed.to_wire())

    def _to_signal(self, channel_key: str, raw: object) -> InboundSignal:
        """Turn one raw wire object into a signal, recording what could not be established.

        A malformed event becomes an ``UNPARSEABLE`` signal rather than an exception or a
        discarded row: something arrived on this channel and NEMESIS could not read it,
        which is a fact about the channel worth keeping. ``author_verified`` is ``False``
        for it, as it is for anything whose id does not recompute.
        """
        received_at = self._now()
        try:
            event = wire.NostrEvent.model_validate(raw)
        except Exception as exc:
            digest = _stable_reference(raw)
            return InboundSignal(
                signal_id=f"unparseable:{digest}",
                provider=PROVIDER_NAME,
                channel_key=channel_key,
                received_at=received_at,
                author_reference="unknown",
                author_verified=False,
                kind=SignalKind.UNPARSEABLE,
                body="",
                metadata={"error": f"{type(exc).__name__}: {exc}"[:500]},
            )

        # `NostrEvent` already recomputed the id and refused a mismatch, so reaching here
        # means content and tags are intact relative to the id. It does NOT mean the
        # signature was checked: verifying BIP-340 needs the same curve implementation
        # NEMESIS does not ship, so `author_verified` stays False and says so.
        envelope = wire.parse_collaboration_event(event)
        metadata: dict[str, str] = {
            "kind": str(event.kind),
            "created_at": str(event.created_at),
            "id_recomputed": "true",
            "signature_checked": "false",
        }
        if envelope is not None:
            metadata["nemesis_event_id"] = envelope.event_id
            metadata["nemesis_standing"] = envelope.standing.value

        return InboundSignal(
            signal_id=event.id,
            provider=PROVIDER_NAME,
            channel_key=channel_key,
            received_at=received_at,
            author_reference=event.pubkey,
            author_verified=False,
            # A message that parses as a NEMESIS envelope is still a MESSAGE. Labelling it
            # DECISION_INTENT was wrong twice over: the enum's own documentation says that
            # member means the text looked like agreement or refusal, and an envelope is a
            # projection NEMESIS published — most likely our own event read back, or a
            # replay of it. Deciding what a reply means is `ApprovalNotice.intent_from`'s
            # job, and a provider must not pre-empt it.
            kind=SignalKind.MESSAGE,
            body=event.content[:8000],
            in_reply_to=event.tag_value("e"),
            metadata=metadata,
        )

    def _public_key(self) -> str:
        return self._signer.public_key_hex

    def _timestamp(self) -> int:
        return int(self._now().timestamp())

    def _now(self) -> datetime:
        clock = self._clock
        if clock is None:
            return utcnow()
        return require_utc(clock(), "clock")  # type: ignore[operator]

    def _require_relay_url(self, operation: str) -> None:
        if self._relay_url:
            return
        raise ProviderConfigurationError(
            f"{operation} needs a relay URL and none was configured. NEMESIS ships no default "
            "endpoint: invariant 15 requires that the MVP contact nothing it was not "
            "explicitly pointed at, so the address is an operator's deliberate act rather "
            "than an environment variable that happened to be set"
        )


def _classify(outcome: PublishOutcome) -> PublicationStatus:
    """Read the relay's own ``OK`` message, because its prefix carries the distinction.

    A duplicate is a success — it is what a content-derived identifier is for, and a retry
    that lands there has done its job. A ``restricted:`` or ``invalid:`` is the relay
    refusing these bytes and will refuse them identically next time, so retrying is
    pointless. ``auth-required:`` is a credential problem an operator has to fix. Anything
    else is treated as retryable, which is the safe default: retrying a permanent failure
    costs attempts and ends in a dead letter that names the reason; giving up on a transient
    one loses the event.
    """
    message = outcome.message.strip().lower()
    # The duplicate check comes FIRST, before `accepted`. NIP-01 says a relay acknowledging
    # an event it already holds answers `OK <id> true` with a `duplicate:` message — it is a
    # success, so `accepted` is true. Reading `accepted` first labelled that PUBLISHED and
    # stamped a fresh `published_at`, so a retry after a lost acknowledgement reported a
    # first publication at the wrong time. The prefix is the only thing that distinguishes
    # the two, and it is on the success path as well as the failure path.
    if message.startswith(_DUPLICATE_PREFIXES):
        return PublicationStatus.DUPLICATE
    if outcome.accepted:
        return PublicationStatus.PUBLISHED
    if message.startswith(_AUTH_PREFIXES):
        return PublicationStatus.REFUSED_UNAUTHENTICATED
    if message.startswith(_REJECTION_PREFIXES):
        return PublicationStatus.REFUSED_REJECTED
    return PublicationStatus.FAILED


def _stable_reference(raw: object) -> str:
    try:
        payload = json.dumps(raw, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        payload = repr(raw)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


__all__ = ["PROVIDER_NAME", "BuzzCollaborationProvider"]
