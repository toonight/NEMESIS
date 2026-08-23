"""The Buzz wire format, implemented from the relay's source rather than from its docs.

Buzz is a Nostr relay speaking NIP-01 over a WebSocket, with NIP-29 relay-based groups for
channels and mandatory NIP-42 authentication. Everything in this module is pure: it builds
and hashes structures, and it performs no I/O. That separation is what lets the whole
format be tested in CI with no relay, no network and no credential.

Four constraints from the relay's implementation shape everything here, and each one would
be a silent failure if missed:

**Unknown event kinds are refused at ingest.** The relay maps every persistent kind to a
required scope and returns ``restricted: unknown event kind`` for anything absent from that
map. NEMESIS therefore cannot mint a ``kind:41337`` for "collaboration event" — it would be
rejected by every stock relay. So a NEMESIS event travels as an ordinary NIP-29 group
message, kind 9, whose ``content`` is the canonical NEMESIS envelope as JSON and whose tags
carry the routing. See :data:`KIND_GROUP_MESSAGE` and :func:`build_collaboration_event`.

**The event id is a hash of an ordered array, and order is significant.** The id covers
``[0, pubkey, created_at, kind, tags, content]``. :func:`event_id` therefore uses a local
encoder and explicitly *not*
:func:`~nemesis.core.canonical.canonical_bytes`, which sorts arrays — sorting the tag list
would produce an id the relay recomputes differently and rejects as invalid.

**Signatures are BIP-340 Schnorr over secp256k1, not Ed25519.** NEMESIS's existing
``cryptography`` dependency provides Ed25519 and secp256k1 ECDSA and does *not* provide
BIP-340. Rather than add a binary dependency or vendor a curve implementation into a
security-sensitive tree, this module computes the 32-byte digest a signature must cover and
hands it to an injected :class:`~nemesis.collaboration.providers.buzz.transport.EventSigner`.
NEMESIS ships no implementation of that Protocol. The consequence is deliberate and stated
in ADR-0010: the format is complete and tested; the ability to sign is something an operator
supplies.

**Content is capped at 256 KiB at ingest, under a 512 KiB frame cap that is the only one
advertised.** A well-behaved client can therefore build a frame the relay accepts carrying
an event it rejects. :data:`MAX_CONTENT_BYTES` is checked here so the refusal happens
locally, with a useful message, rather than as an opaque ``OK false`` from the relay.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from typing import Annotated, Final, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.collaboration.events import CollaborationEvent

KIND_PROFILE: Final = 0
"""NIP-01 metadata. How an actor's display name and description reach the workspace."""

KIND_GROUP_MESSAGE: Final = 9
"""NIP-29 group chat message. The carrier for every NEMESIS collaboration event.

Chosen because it is in the relay's ingest allowlist, is what every NIP-29 client renders,
and is subject to the relay's channel-membership check on the write path — so a NEMESIS
event published to a restricted channel is refused for a non-member before it is stored.
"""

KIND_ADD_USER: Final = 9000
"""NIP-29 put-user. Adds a participant to a group."""

KIND_CREATE_GROUP: Final = 9007
"""NIP-29 create-group. Carries the client-chosen channel UUID in its ``h`` tag."""

KIND_AUTH: Final = 22242
"""NIP-42 authentication. Never stored by the relay, and never submitted as an EVENT."""

MAX_CONTENT_BYTES: Final = 256 * 1024
MAX_TAG_VALUE_BYTES: Final = 1024

NEMESIS_TAG_NAMESPACE: Final = "nemesis"
"""Prefix for every NEMESIS-specific tag, so a mixed workspace can tell our events apart.

Tags are not allowlisted by the relay the way kinds are, so custom tags are admitted — but
a bare ``case`` tag would collide with anything else a workspace decides to use. The values
are also indexed only if single-letter, so these are for readers and for our own filtering
after retrieval, never for a server-side ``#`` filter.
"""

CHANNEL_NAMESPACE: Final = uuid.UUID("6f9d3a1e-6f6f-5c0a-9a5c-1f5d2c3b4a59")
"""Namespace for deriving a channel's UUID from its NEMESIS key.

UUIDv5 rather than a fresh UUIDv4, so ``open_channel`` is idempotent across processes and
restarts: two NEMESIS instances asked for ``case-2026-000123`` derive the same UUID, the
relay's ``ON CONFLICT DO NOTHING`` recognises the second create as a duplicate, and the
workspace does not accumulate a channel per deployment. The namespace value is arbitrary
and fixed; changing it renames every channel.
"""


class NostrEvent(BaseModel):
    """A signed Nostr event, in the exact shape the relay stores and returns.

    Frozen. ``id`` and ``sig`` are lowercase hex of the sizes the relay's parser requires,
    validated here so a malformed event is refused before it reaches a socket rather than
    producing an opaque rejection.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    pubkey: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    created_at: Annotated[int, Field(ge=0)]
    kind: Annotated[int, Field(ge=0, le=65535)]
    tags: tuple[tuple[str, ...], ...]
    content: str
    sig: Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]

    @model_validator(mode="after")
    def _check_id_matches_content(self) -> Self:
        expected = event_id(
            pubkey=self.pubkey,
            created_at=self.created_at,
            kind=self.kind,
            tags=self.tags,
            content=self.content,
        )
        if self.id != expected:
            raise ValueError(
                f"event id {self.id!r} does not match its content, which derives {expected!r}. "
                "The relay recomputes the id and rejects a mismatch, so refusing here turns "
                "an opaque remote rejection into a local error naming the field"
            )
        if len(self.content.encode("utf-8")) > MAX_CONTENT_BYTES:
            raise ValueError(
                f"content is {len(self.content.encode('utf-8'))} bytes; the relay caps event "
                f"content at {MAX_CONTENT_BYTES}"
            )
        return self

    def tag_value(self, name: str) -> str | None:
        """The first value of the first tag with this name, or ``None``."""
        for tag in self.tags:
            if len(tag) >= 2 and tag[0] == name:
                return tag[1]
        return None

    def to_wire(self) -> Mapping[str, object]:
        return {
            "id": self.id,
            "pubkey": self.pubkey,
            "created_at": self.created_at,
            "kind": self.kind,
            "tags": [list(tag) for tag in self.tags],
            "content": self.content,
            "sig": self.sig,
        }


class UnsignedEvent(BaseModel):
    """Everything but the signature. What :func:`signing_digest` covers."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    pubkey: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    created_at: Annotated[int, Field(ge=0)]
    kind: Annotated[int, Field(ge=0, le=65535)]
    tags: tuple[tuple[str, ...], ...] = ()
    content: str = ""

    @model_validator(mode="after")
    def _check_bounds(self) -> Self:
        if len(self.content.encode("utf-8")) > MAX_CONTENT_BYTES:
            raise ValueError(
                f"content is {len(self.content.encode('utf-8'))} bytes; the relay caps event "
                f"content at {MAX_CONTENT_BYTES}"
            )
        for tag in self.tags:
            if not tag:
                raise ValueError("an empty tag has no name and cannot be interpreted")
            for element in tag:
                if len(element.encode("utf-8")) > MAX_TAG_VALUE_BYTES:
                    raise ValueError(
                        f"tag element in {tag[0]!r} exceeds {MAX_TAG_VALUE_BYTES} bytes; put "
                        "long material in the content or, better, publish a reference to it"
                    )
        return self

    @property
    def event_id(self) -> str:
        return event_id(
            pubkey=self.pubkey,
            created_at=self.created_at,
            kind=self.kind,
            tags=self.tags,
            content=self.content,
        )

    def signing_digest(self) -> bytes:
        """The 32 bytes a BIP-340 signature must cover: the event id, as raw bytes."""
        return bytes.fromhex(self.event_id)

    def sealed(self, signature_hex: str) -> NostrEvent:
        """Attach a signature and produce the event that goes on the wire."""
        return NostrEvent(
            id=self.event_id,
            pubkey=self.pubkey,
            created_at=self.created_at,
            kind=self.kind,
            tags=self.tags,
            content=self.content,
            sig=signature_hex,
        )


def event_id(
    *,
    pubkey: str,
    created_at: int,
    kind: int,
    tags: Sequence[Sequence[str]],
    content: str,
) -> str:
    """The NIP-01 event id: SHA-256 over the ordered serialization array.

    ``[0, pubkey, created_at, kind, tags, content]``, compact, UTF-8, no whitespace. Tag
    order is preserved because the relay preserves it and recomputes this hash; sorting
    would yield an id it rejects.
    """
    serialized = json.dumps(
        [0, pubkey, created_at, kind, [list(tag) for tag in tags], content],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def channel_uuid(channel_key: str) -> str:
    """The stable NIP-29 group id for a NEMESIS channel key."""
    return str(uuid.uuid5(CHANNEL_NAMESPACE, channel_key))


def build_create_group(
    *,
    pubkey: str,
    created_at: int,
    channel_key: str,
    display_name: str,
    purpose: str,
    private: bool,
) -> UnsignedEvent:
    """A NIP-29 kind:9007 that creates a channel, or is refused as a duplicate.

    The relay pre-creates the row with ``ON CONFLICT DO NOTHING`` and bootstraps the signer
    as owner. Because :func:`channel_uuid` is derived rather than random, a second call for
    the same key is recognisably the same channel.
    """
    tags: list[tuple[str, ...]] = [
        ("h", channel_uuid(channel_key)),
        ("name", display_name),
        ("visibility", "private" if private else "open"),
        ("channel_type", "stream"),
        (f"{NEMESIS_TAG_NAMESPACE}-channel-key", channel_key),
    ]
    if purpose:
        tags.append(("about", purpose))
    return UnsignedEvent(
        pubkey=pubkey, created_at=created_at, kind=KIND_CREATE_GROUP, tags=tuple(tags)
    )


def build_add_user(
    *, pubkey: str, created_at: int, channel_key: str, member_pubkey: str, role: str = "member"
) -> UnsignedEvent:
    """A NIP-29 kind:9000 adding a participant to a channel."""
    return UnsignedEvent(
        pubkey=pubkey,
        created_at=created_at,
        kind=KIND_ADD_USER,
        tags=(
            ("h", channel_uuid(channel_key)),
            ("p", member_pubkey),
            ("role", role),
        ),
    )


def build_profile(*, pubkey: str, created_at: int, display_name: str, about: str) -> UnsignedEvent:
    """A NIP-01 kind:0 profile, so an actor is legible to humans in the workspace.

    ``about`` describes what the component does. It is documentation, and the docstring of
    :class:`~nemesis.collaboration.identities.RegisteredActor` explains why it is not a
    permission.
    """
    content = json.dumps(
        {"name": display_name, "display_name": display_name, "about": about},
        separators=(",", ":"),
        ensure_ascii=False,
        sort_keys=True,
    )
    return UnsignedEvent(pubkey=pubkey, created_at=created_at, kind=KIND_PROFILE, content=content)


def build_auth(*, pubkey: str, created_at: int, challenge: str, relay_url: str) -> UnsignedEvent:
    """A NIP-42 kind:22242 answering the relay's challenge.

    The relay pushes ``["AUTH", <challenge>]`` as the first frame and cancels the connection
    if it is not answered within five seconds; it also requires ``created_at`` within ±60
    seconds of its own clock and the ``relay`` tag to normalise equal to its configured URL.
    All three are the caller's problem to satisfy — this function only builds the event —
    and :func:`normalize_relay_url` implements the relay's own normalisation so the tag
    matches.
    """
    return UnsignedEvent(
        pubkey=pubkey,
        created_at=created_at,
        kind=KIND_AUTH,
        tags=(("relay", normalize_relay_url(relay_url)), ("challenge", challenge)),
    )


def build_collaboration_event(
    *, pubkey: str, created_at: int, channel_key: str, event: CollaborationEvent
) -> UnsignedEvent:
    """Carry one NEMESIS event as a NIP-29 group message.

    The envelope goes in ``content`` as JSON so a NIP-29 client shows *something* and a
    NEMESIS reader gets the typed object back. Tags carry what a reader or a filter needs
    without parsing the body: the channel, the NEMESIS event id (for deduplication), the
    epistemic standing, the case and the correlation id.

    The content is the envelope, not the investigation. Everything in it passed
    :class:`~nemesis.collaboration.events.CollaborationEvent`'s classification wall and
    internal-marker scan before it could exist, and references point at material rather than
    carrying it.
    """
    body = json.dumps(
        {
            "nemesis": {
                "version": 1,
                "event": event.model_dump(mode="json"),
                "integrity_hash": event.integrity_hash(),
            }
        },
        separators=(",", ":"),
        ensure_ascii=False,
        sort_keys=True,
    )
    tags: tuple[tuple[str, ...], ...] = (
        ("h", channel_uuid(channel_key)),
        (f"{NEMESIS_TAG_NAMESPACE}-event-id", event.event_id),
        (f"{NEMESIS_TAG_NAMESPACE}-standing", event.standing.value),
        (f"{NEMESIS_TAG_NAMESPACE}-case", event.case_id),
        (f"{NEMESIS_TAG_NAMESPACE}-correlation", event.correlation_id),
        (f"{NEMESIS_TAG_NAMESPACE}-type", event.event_type),
    )
    return UnsignedEvent(
        pubkey=pubkey,
        created_at=created_at,
        kind=KIND_GROUP_MESSAGE,
        tags=tags,
        content=body,
    )


def channel_message_filter(
    *, channel_key: str, since: int | None = None, limit: int = 100
) -> Mapping[str, object]:
    """A NIP-01 REQ filter for one channel's messages.

    ``#h`` rather than a bare kind filter: the relay keeps channel-scoped and global
    delivery strictly separate, so a kinds-only subscription receives none of a channel's
    traffic.
    """
    query: dict[str, object] = {
        "kinds": [KIND_GROUP_MESSAGE],
        "#h": [channel_uuid(channel_key)],
        "limit": limit,
    }
    if since is not None:
        query["since"] = since
    return query


def parse_collaboration_event(nostr_event: NostrEvent) -> CollaborationEvent | None:
    """Recover a NEMESIS envelope from a group message, or ``None`` if it is not one.

    ``None`` rather than an exception: most messages in a shared channel are people talking,
    and a parser that raised on ordinary chat would make polling a channel a stream of
    handled exceptions. A message that *claims* to carry an envelope and does not parse also
    returns ``None`` — it is not a NEMESIS event, whatever it says about itself.

    Recovering an envelope does **not** make it trustworthy. It came from a channel, which
    means invariant 5 applies: the object is well-formed data, not an assertion NEMESIS has
    any reason to believe, and nothing downstream may treat a parsed envelope as a record
    NEMESIS produced. The only thing that makes a returned envelope *ours* is that its
    ``event_id`` matches one we published, which the caller can check against the outbox.
    """
    if nostr_event.kind != KIND_GROUP_MESSAGE:
        return None
    try:
        body = json.loads(nostr_event.content)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(body, dict):
        return None
    wrapper = body.get("nemesis")
    if not isinstance(wrapper, dict) or wrapper.get("version") != 1:
        return None
    try:
        return CollaborationEvent.model_validate(wrapper.get("event"))
    except Exception:
        return None


def normalize_relay_url(url: str) -> str:
    """Normalise a relay URL the way the relay does before comparing it.

    The relay folds ``localhost`` and ``::1`` to ``127.0.0.1`` and strips a trailing slash
    before comparing the NIP-42 ``relay`` tag. A client that does not do the same sends a
    tag that looks correct to a human and fails the comparison, surfacing as the generic
    ``auth-required: verification failed``.
    """
    trimmed = url.rstrip("/")
    for host in ("localhost", "[::1]", "::1"):
        trimmed = trimmed.replace(f"//{host}:", "//127.0.0.1:").replace(f"//{host}", "//127.0.0.1")
    return trimmed


__all__ = [
    "CHANNEL_NAMESPACE",
    "KIND_ADD_USER",
    "KIND_AUTH",
    "KIND_CREATE_GROUP",
    "KIND_GROUP_MESSAGE",
    "KIND_PROFILE",
    "MAX_CONTENT_BYTES",
    "MAX_TAG_VALUE_BYTES",
    "NEMESIS_TAG_NAMESPACE",
    "NostrEvent",
    "UnsignedEvent",
    "build_add_user",
    "build_auth",
    "build_collaboration_event",
    "build_create_group",
    "build_profile",
    "channel_message_filter",
    "channel_uuid",
    "event_id",
    "normalize_relay_url",
    "parse_collaboration_event",
]
