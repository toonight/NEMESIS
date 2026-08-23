"""The two things NEMESIS deliberately does not ship: a socket and a signing key.

Both are Protocols here with no working implementation in the tree, and that is the
architecture rather than an unfinished corner. The same decision was taken for the pilot
provider seats (ADR-0009), for the same two reasons.

**Invariant 15.** The MVP's only sanctioned egress is an allowlisted URL fetch from the
collection plane, marked ``NEMESIS-EGRESS-ALLOWED``, off by default with no endpoint
shipped. ``scripts/check_prohibited.py`` enforces that mechanically: it fails the build on
an import of any of thirty-odd network modules — ``httpx``, ``websockets``, ``socket`` and
the rest — from anywhere outside :mod:`nemesis.collect`. A collaboration plane holding a
WebSocket client would either violate that check or require weakening it, and weakening a
security control to make a feature fit is the move this repository exists to refuse. So the
plane holds no transport, and the check needs no exception.

**BIP-340.** Buzz verifies every event with Schnorr signatures over secp256k1. NEMESIS's
``cryptography`` dependency provides Ed25519 and secp256k1 ECDSA and does not provide
BIP-340; the options were a new binary dependency in a project with three runtime
dependencies, or a curve implementation vendored into a security-sensitive tree. Neither is
NEMESIS's to decide on an operator's behalf, and both are worse than the third option: take
the signer as an interface, hand it a 32-byte digest, and let the deployment supply the
implementation it already trusts. This also keeps the private key outside the plane
entirely, which is the same discipline
:class:`~nemesis.authz.keys.CapabilitySigningKey` applies to the capability key.

What this costs, stated plainly:
:class:`~nemesis.collaboration.providers.buzz.provider.BuzzCollaborationProvider` cannot
reach a relay as shipped. Every byte it would send is constructed, validated and
tested; nothing sends them. Enabling that is an operator action with a documented recipe
(``docs/development/buzz-local-setup.md``), not a configuration flag someone can leave on by
accident.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Annotated, Final, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class TransportNotWiredError(RuntimeError):
    """Something tried to reach a relay through a transport NEMESIS does not ship.

    Raised rather than returned as a failed receipt, because this is not a relay being down
    — it is a deployment that believes it is publishing and is not. A quiet
    ``REFUSED_UNAVAILABLE`` here would be indistinguishable from an outage, and the
    difference is the whole point.
    """


class SignerNotWiredError(RuntimeError):
    """Something tried to sign a Nostr event with no signer configured."""


class RelayQueryResult(BaseModel):
    """What a transport returns for one query: raw wire objects, unvalidated.

    ``Mapping[str, object]`` rather than
    :class:`~nemesis.collaboration.providers.buzz.wire.NostrEvent` on purpose. A transport
    is the untrusted edge; validating there would mean a transport implementation decides
    what a well-formed event is. Parsing happens on the NEMESIS side of the boundary, where
    a malformed event becomes a recorded refusal instead of an exception in someone's HTTP
    client.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    events: tuple[Mapping[str, object], ...] = ()
    reached_end: bool = True
    """Whether the relay signalled EOSE, i.e. the stored set was fully delivered. ``False``
    means the answer was truncated and a caller must not read absence as absence."""

    detail: str = ""


class PublishOutcome(BaseModel):
    """What a relay said about one published event."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    accepted: bool
    event_id: Annotated[str, Field(min_length=1)]
    message: str = ""
    """The relay's own ``OK`` message. Carried verbatim: its prefix (``duplicate:``,
    ``restricted:``, ``invalid:``, ``auth-required:``) is how the provider tells a duplicate
    from a refusal from a credential problem, and paraphrasing it loses that."""


@runtime_checkable
class EventSigner(Protocol):
    """Produces BIP-340 Schnorr signatures over secp256k1, for one identity.

    The digest is 32 bytes and is the event id — already computed by
    :meth:`~nemesis.collaboration.providers.buzz.wire.UnsignedEvent.signing_digest`, so an
    implementation never needs to know NIP-01's serialization rules and cannot get them
    wrong. It signs bytes and returns hex.
    """

    @property
    def public_key_hex(self) -> str:
        """The x-only public key, 64 lowercase hex characters."""
        ...

    def sign(self, digest: bytes) -> str:
        """Sign a 32-byte digest, returning 128 lowercase hex characters."""
        ...


@runtime_checkable
class BuzzTransport(Protocol):
    """Carries bytes to and from one relay. The only thing in this design that touches a
    network, and NEMESIS ships no implementation of it."""

    async def publish(self, event: Mapping[str, object]) -> PublishOutcome:
        """Send one signed event and return what the relay said."""
        ...

    async def query(self, filters: Sequence[Mapping[str, object]]) -> RelayQueryResult:
        """Run one or more NIP-01 filters and return the stored events they matched."""
        ...

    async def health(self) -> bool:
        """Whether the relay is reachable. Must not raise."""
        ...


class UnwiredBuzzTransport:
    """The transport that ships: one that refuses, loudly, with the reason.

    Present so that
    :class:`~nemesis.collaboration.providers.buzz.provider.BuzzCollaborationProvider` has a
    default that is a refusal rather than a ``None`` somebody has to remember to
    check, and so that the failure names the decision instead of surfacing as an
    ``AttributeError`` on a missing attribute.
    """

    def __init__(self, relay_url: str | None = None) -> None:
        self._relay_url = relay_url

    async def publish(self, event: Mapping[str, object]) -> PublishOutcome:
        raise TransportNotWiredError(_UNWIRED_TRANSPORT_MESSAGE)

    async def query(self, filters: Sequence[Mapping[str, object]]) -> RelayQueryResult:
        raise TransportNotWiredError(_UNWIRED_TRANSPORT_MESSAGE)

    async def health(self) -> bool:
        """``False``, without raising. A transport that cannot reach anything is not
        healthy, and :meth:`CollaborationProvider.health` promises not to raise."""
        return False


class UnwiredEventSigner:
    """The signer that ships: one that refuses, with the dependency decision explained."""

    @property
    def public_key_hex(self) -> str:
        raise SignerNotWiredError(_UNWIRED_SIGNER_MESSAGE)

    def sign(self, digest: bytes) -> str:
        raise SignerNotWiredError(_UNWIRED_SIGNER_MESSAGE)


_UNWIRED_TRANSPORT_MESSAGE: Final = (
    "no Buzz transport is wired. NEMESIS ships none: invariant 15 confines network "
    "capability to the collection plane behind an explicit egress marker, and "
    "scripts/check_prohibited.py fails the build on a network import anywhere else. "
    "Supply an object satisfying nemesis.collaboration.providers.buzz.transport.BuzzTransport "
    "and pass it to BuzzCollaborationProvider(transport=...). "
    "See docs/development/buzz-local-setup.md and ADR-0010."
)

_UNWIRED_SIGNER_MESSAGE: Final = (
    "no Nostr event signer is wired. Buzz verifies BIP-340 Schnorr signatures over "
    "secp256k1, which NEMESIS's `cryptography` dependency does not provide; NEMESIS "
    "deliberately neither adds a binary dependency nor vendors a curve implementation. "
    "Supply an object satisfying nemesis.collaboration.providers.buzz.transport.EventSigner "
    "and pass it to BuzzCollaborationProvider(signer=...). "
    "See docs/development/buzz-local-setup.md and ADR-0010."
)


__all__ = [
    "BuzzTransport",
    "EventSigner",
    "PublishOutcome",
    "RelayQueryResult",
    "SignerNotWiredError",
    "TransportNotWiredError",
    "UnwiredBuzzTransport",
    "UnwiredEventSigner",
]
