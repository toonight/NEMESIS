"""The seam a collaboration backend plugs into, and the four things it may never do.

NEMESIS does not need a collaboration backend to work. The demonstration runs, the pilot
flies, the gateway authorizes and the vault seals with nothing on the other side of this
interface — which is the property that makes a provider optional rather than a dependency
wearing an interface as a disguise.
:class:`~nemesis.collaboration.providers.local.LocalCollaborationProvider` is the default
and reaches no network at all.

The Protocol is deliberately narrow, and what is *absent* from it is the design:

**No ``authorize``.** A provider publishes an approval request and reports what came back.
It cannot approve anything, because there is no verb for it. A human's agreement arrives as
an :class:`InboundSignal` — untrusted data, like everything else crossing a boundary — and
becomes an :class:`~nemesis.core.authorization.Approval` only by passing through
:class:`~nemesis.authz.gateway.AuthorizationGateway` with a verified identity assertion.
The provider cannot reach that gateway: :mod:`nemesis.collaboration` sits below
:mod:`nemesis.authz` in the layering and an ``import-linter`` contract names the package.
This is the brief's *signature ≠ authorization* rule made structural rather than
documented.

**No ``read_evidence``, no ``query_graph``, no ``execute``.** A provider holds no platform
handle. It is handed a :class:`~nemesis.collaboration.events.CollaborationEvent` that was
already projected and redacted, and it returns bytes-level receipts. A compromised provider
— a hostile relay, a stolen agent key, a backdoored client library — learns exactly what
was published to it and nothing more.

**No exceptions on the expected failures.** ``publish`` returns a
:class:`PublicationReceipt` whose :attr:`PublicationReceipt.status` names what happened.
A backend being down is an ordinary Tuesday, and a caller that must wrap every publication
in a try/except eventually wraps it in a bare one. Only programmer errors raise.

**No standing connection implied.** Every method takes what it needs per call. A provider
that caches a session, a credential or a channel roster across calls has reconstructed the
ambient authority the effects plane is forbidden — see :mod:`nemesis.ports.effects`, whose
adapters carry the same rule for the same reason.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Protocol, Self, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.collaboration.events import CollaborationEvent
from nemesis.core.identity import ActorKind
from nemesis.core.temporal import require_utc


class ProviderConfigurationError(RuntimeError):
    """A provider was asked to act and had not been given what it needs to act.

    A programmer error, so it raises rather than becoming a receipt: a provider with no
    transport that quietly reported "unavailable" would be indistinguishable from a relay
    that is down, and the deployment would look like it was publishing when nothing had
    ever been wired.
    """


class PublicationStatus(StrEnum):
    """What a backend did with an event. Every value is recorded, refusals included."""

    PUBLISHED = "published"
    PENDING = "pending"
    """Accepted locally and not yet acknowledged by the backend. The outbox owns it."""

    DUPLICATE = "duplicate"
    """The backend already holds this ``event_id``. A success, not an error — it is what a
    content-addressed identifier is for, and a retry that lands here has done its job."""

    REFUSED_UNAVAILABLE = "refused_unavailable"
    """The backend could not be reached, or refused the connection. Retryable."""

    REFUSED_REJECTED = "refused_rejected"
    """The backend was reached and declined the event: unknown channel, missing membership,
    an event kind its ingest does not admit. Not retryable without a change."""

    REFUSED_UNAUTHENTICATED = "refused_unauthenticated"
    """The backend would not accept this identity. Distinct from ``REJECTED`` because it is
    a credential problem rather than a content problem, and an operator reading a log needs
    to tell a misconfigured key from a malformed publication."""

    FAILED = "failed"
    """Something else went wrong. Retryable, and the detail says what."""

    @property
    def is_settled(self) -> bool:
        """Whether the outbox may stop retrying this event."""
        return self in {
            PublicationStatus.PUBLISHED,
            PublicationStatus.DUPLICATE,
            PublicationStatus.REFUSED_REJECTED,
        }

    @property
    def is_retryable(self) -> bool:
        return self in {
            PublicationStatus.REFUSED_UNAVAILABLE,
            PublicationStatus.REFUSED_UNAUTHENTICATED,
            PublicationStatus.FAILED,
        }


class PublicationReceipt(BaseModel):
    """What a backend said about one publication.

    ``backend_reference`` is the backend's own identifier for the stored object — a Nostr
    event id, a message id, a file offset. Recorded so a NEMESIS audit entry can be tied to
    the thing an outside reader sees, which is the only way to answer "is what the channel
    shows what we published" without trusting the channel.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: Annotated[str, Field(min_length=1)]
    provider: Annotated[str, Field(min_length=1)]
    status: PublicationStatus
    detail: str = ""
    backend_reference: str | None = None
    published_at: Annotated[datetime, Field()] | None = None

    @model_validator(mode="after")
    def _require_utc_and_evidence_of_success(self) -> Self:
        if self.published_at is not None:
            require_utc(self.published_at, "published_at")
        if self.status is PublicationStatus.PUBLISHED and self.backend_reference is None:
            raise ValueError(
                "a PUBLISHED receipt must carry the backend's own reference for the stored "
                "object. Without one nothing ties the audit entry to what a reader sees, and "
                "'we published it' becomes an assertion the platform makes about itself"
            )
        return self

    @property
    def succeeded(self) -> bool:
        return self.status in {PublicationStatus.PUBLISHED, PublicationStatus.DUPLICATE}


class ChannelVisibility(StrEnum):
    """Who may read a channel, as the backend understands it.

    Named after what the backend enforces rather than after what we would like it to mean.
    ``RESTRICTED`` is *not* a confidentiality guarantee: every backend examined enforces it
    with a server-side access list over plaintext storage, so it keeps out other members of
    the workspace and does not keep out the operator. NEMESIS therefore publishes references
    rather than material into channels of either visibility, and the distinction here is
    about blast radius, not secrecy.
    """

    OPEN = "open"
    RESTRICTED = "restricted"


class ChannelDescriptor(BaseModel):
    """A request to have a channel exist. Idempotent by ``key``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    key: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._-]*$")]
    """A stable, caller-chosen name. Lowercase and punctuation-restricted so the same key
    survives a backend that normalises names, and so two callers asking for the same channel
    get one channel rather than two that differ by a capital letter."""

    display_name: Annotated[str, Field(min_length=1, max_length=200)]
    purpose: Annotated[str, Field(max_length=500)] = ""
    visibility: ChannelVisibility = ChannelVisibility.RESTRICTED
    """Restricted by default. A channel that has to be opened deliberately is the one an
    operator thinks about once; a channel that defaults to open is the one nobody thinks
    about at all."""

    case_id: str | None = None
    """Set when the channel belongs to one case. ``None`` for standing channels.

    The brief warns about uncontrolled channel proliferation and it is a real failure mode:
    a channel per case, per agent and per stage produces a workspace nobody can follow. The
    intended topology is a small number of standing channels with ``case_id`` and
    ``correlation_id`` carried *inside* the events, and a case channel opened only when a
    case genuinely needs its own room."""


class ChannelHandle(BaseModel):
    """What a backend calls a channel once it exists."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    key: Annotated[str, Field(min_length=1)]
    provider: Annotated[str, Field(min_length=1)]
    backend_id: Annotated[str, Field(min_length=1)]
    created: bool = False
    """True when this call created it, False when it already existed. Reported rather than
    swallowed so an audit entry can distinguish "we made a room" from "we found one"."""


class SignalKind(StrEnum):
    """What an inbound signal appears to be.

    "Appears to be" is exact. This is a parse of untrusted content, not a finding. A
    :attr:`DECISION_INTENT` means a human's message looked like agreement or refusal — it
    does not mean anything was decided, and nothing downstream may treat it as if it had
    been. See :mod:`nemesis.collaboration.approvals`.
    """

    MESSAGE = "message"
    DECISION_INTENT = "decision_intent"
    REACTION = "reaction"
    MEMBERSHIP = "membership"
    UNPARSEABLE = "unparseable"
    """Received, could not be understood, and kept anyway. A signal a backend delivered and
    NEMESIS could not parse is a fact about the channel worth recording; discarding it
    silently is how a malformed-message flood becomes invisible."""


class InboundSignal(BaseModel):
    """Something a human or a foreign agent put into a channel.

    A separate type from :class:`~nemesis.collaboration.events.CollaborationEvent` on
    purpose, and the separation is the control. An outbound event is a projection of
    something NEMESIS established. An inbound signal is adversary-reachable text that
    happens to have arrived over an authenticated socket — invariant 5 applies to it in
    full, and it is never an instruction.

    :attr:`author_verified` records whether the *backend's* cryptographic check on the
    author passed. It is worth exactly what a signature is worth: it establishes who
    produced these bytes and says nothing whatever about whether they are true or whether
    the author may cause anything to happen.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    signal_id: Annotated[str, Field(min_length=1)]
    provider: Annotated[str, Field(min_length=1)]
    channel_key: Annotated[str, Field(min_length=1)]
    received_at: Annotated[datetime, Field()]

    author_reference: Annotated[str, Field(min_length=1)]
    """The backend's identifier for the author — a public key, a user id. Deliberately not
    an :class:`~nemesis.core.identity.Principal`: mapping a backend identity to a NEMESIS
    identity is a decision the authorization plane makes against a registry, not something a
    provider asserts."""

    author_verified: bool = False
    kind: SignalKind = SignalKind.MESSAGE
    body: Annotated[str, Field(max_length=8000)] = ""
    references: tuple[str, ...] = ()
    """Reference strings as they appeared in the message, unresolved. Parsed, never
    followed: a locator that arrived from a channel names something the sender wanted read,
    which is not the same as something NEMESIS should read."""

    in_reply_to: str | None = None
    metadata: Mapping[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _require_utc(self) -> Self:
        require_utc(self.received_at, "received_at")
        return self


class ActorBinding(BaseModel):
    """A NEMESIS actor's presence on a collaboration backend.

    One direction only, and that is the point. It records that ``actor_id`` publishes as
    ``backend_reference``, so a reader can tell which NEMESIS component wrote a message.
    It confers nothing: the binding does not grant the backend identity any NEMESIS role,
    any capability, or any standing, and there is no field here that could. Authorization
    flows from :class:`~nemesis.core.identity.Principal` and
    :class:`~nemesis.core.authorization.AuthorizationCapability`, both of which are
    unreachable from this plane.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    actor_id: Annotated[str, Field(min_length=1, max_length=200)]
    actor_kind: ActorKind
    display_name: Annotated[str, Field(min_length=1, max_length=200)]
    provider: Annotated[str, Field(min_length=1)]
    backend_reference: Annotated[str, Field(min_length=1)]
    role_description: Annotated[str, Field(max_length=500)] = ""
    """Prose for humans reading the channel: "records evidence", "proposes disruption
    options". Not a :class:`~nemesis.core.identity.Role`, and not consulted by any check."""


@runtime_checkable
class CollaborationProvider(Protocol):
    """A backend NEMESIS can talk to humans through.

    Every method is async because the two shipped implementations are I/O-shaped even when
    one of them touches only a file, and a Protocol that is sync in the local case and async
    in the remote one is a Protocol nothing can be substituted into.
    """

    @property
    def name(self) -> str:
        """Recorded in every receipt and every audit entry this provider causes."""
        ...

    async def open_channel(self, descriptor: ChannelDescriptor) -> ChannelHandle:
        """Ensure a channel exists and return what the backend calls it.

        Idempotent on :attr:`ChannelDescriptor.key`. Raises
        :class:`ProviderConfigurationError` when the provider was never wired; returns a
        handle otherwise, because a channel that already exists is the normal case.
        """
        ...

    async def publish(
        self, channel: ChannelHandle, event: CollaborationEvent
    ) -> PublicationReceipt:
        """Send one projected event. Never raises for a backend that is merely down."""
        ...

    async def poll(
        self, channel: ChannelHandle, *, since: datetime | None = None, limit: int = 100
    ) -> Sequence[InboundSignal]:
        """Read what arrived. Returns an empty sequence when the backend is unreachable.

        Polling rather than a subscription callback, deliberately. A push subscription
        inverts control — the backend decides when NEMESIS runs code — and a persistent
        socket held open by a plane that is not the collection plane is a standing network
        reach this architecture does not grant. A caller that wants a stream loops.
        """
        ...

    async def bind_actor(self, binding: ActorBinding) -> ActorBinding:
        """Register a NEMESIS actor's backend presence. Returns what was recorded."""
        ...

    async def health(self) -> bool:
        """Whether the backend is reachable. Never raises."""
        ...


__all__ = [
    "ActorBinding",
    "ChannelDescriptor",
    "ChannelHandle",
    "ChannelVisibility",
    "CollaborationProvider",
    "InboundSignal",
    "ProviderConfigurationError",
    "PublicationReceipt",
    "PublicationStatus",
    "SignalKind",
]
