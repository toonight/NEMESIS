"""Typed, prefixed identifiers for every first-class NEMESIS object.

Two identifier strategies coexist, deliberately:

*Time-ordered* identifiers (UUIDv7, RFC 9562) for objects whose identity is their
existence: an investigation, an entity, an actor. They sort by creation time, which
matters for a system where temporal ordering is analytically meaningful.

*Content-addressed* identifiers (SHA-256) for objects whose identity IS their content:
evidence artifacts and claims. Two collectors that independently observe the same
artifact must produce the same evidence identifier, or deduplication silently inflates
corroboration — the single most dangerous failure mode in evidence fusion, because it
turns one source into apparent independent confirmation.

The type prefix is not decoration. It makes identifier confusion (passing a claim id
where an evidence id is expected) a validation error rather than a silent lookup miss.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
import uuid
from enum import StrEnum
from typing import Annotated, Final

from pydantic import AfterValidator


class IdPrefix(StrEnum):
    """Type tag carried by every identifier."""

    INVESTIGATION = "inv"
    CASE = "case"
    ENTITY = "ent"
    EDGE = "edge"
    CLAIM = "clm"
    EVIDENCE = "evd"
    OBSERVATION = "obs"
    HYPOTHESIS = "hyp"
    PERSONA_CLUSTER = "prsn"
    ATTRIBUTION = "attr"
    CAPABILITY = "cap"
    OPERATION = "op"
    ACTOR = "actor"
    COLLECTION = "coll"
    AUDIT = "aud"


_UUID7_ID: Final = re.compile(r"^[a-z]+_[0-9a-f]{32}$")
_CONTENT_ID: Final = re.compile(r"^[a-z]+_sha256-[0-9a-f]{64}$")


def uuid7() -> uuid.UUID:
    """Generate a UUID version 7 per RFC 9562 section 5.7.

    Layout: 48-bit big-endian Unix epoch milliseconds, 4-bit version, 12 bits of
    randomness, 2-bit variant, 62 bits of randomness.

    Python 3.14 ships ``uuid.uuid7``; this implementation exists so the project runs
    on 3.13 and so the bit layout is auditable rather than assumed. Delete it when the
    floor moves to 3.14.
    """
    unix_ts_ms = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")

    rand_a = (rand >> 62) & 0x0FFF
    rand_b = rand & 0x3FFF_FFFF_FFFF_FFFF

    value = (unix_ts_ms & 0xFFFF_FFFF_FFFF) << 80
    value |= 0x7 << 76
    value |= rand_a << 64
    value |= 0b10 << 62
    value |= rand_b
    return uuid.UUID(int=value)


def new_id(prefix: IdPrefix) -> str:
    """Mint a fresh time-ordered identifier for the given object type."""
    return f"{prefix.value}_{uuid7().hex}"


def content_id(prefix: IdPrefix, payload: bytes) -> str:
    """Derive a deterministic identifier from content.

    Identical content always yields an identical identifier. This is what makes
    independent re-observation of the same artifact collapse to one object instead of
    being counted twice as corroborating evidence.
    """
    digest = hashlib.sha256(payload).hexdigest()
    return f"{prefix.value}_sha256-{digest}"


def timestamp_of(identifier: str) -> int | None:
    """Recover the millisecond timestamp embedded in a UUIDv7-backed identifier.

    Returns ``None`` for content-addressed identifiers, which carry no time.
    """
    _, _, raw = identifier.partition("_")
    if raw.startswith("sha256-") or len(raw) != 32:
        return None
    return int(raw[:12], 16)


def _make_validator(prefix: IdPrefix, *, content_addressed: bool) -> AfterValidator:
    pattern = _CONTENT_ID if content_addressed else _UUID7_ID
    expected = f"{prefix.value}_"

    def _validate(value: str) -> str:
        if not value.startswith(expected):
            raise ValueError(f"expected an identifier prefixed {expected!r}, got {value!r}")
        if not pattern.match(value):
            kind = "content-addressed" if content_addressed else "UUIDv7"
            raise ValueError(f"{value!r} is not a well-formed {kind} identifier")
        return value

    return AfterValidator(_validate)


InvestigationId = Annotated[str, _make_validator(IdPrefix.INVESTIGATION, content_addressed=False)]
CaseId = Annotated[str, _make_validator(IdPrefix.CASE, content_addressed=False)]
EntityId = Annotated[str, _make_validator(IdPrefix.ENTITY, content_addressed=False)]
EdgeId = Annotated[str, _make_validator(IdPrefix.EDGE, content_addressed=False)]
PersonaClusterId = Annotated[
    str, _make_validator(IdPrefix.PERSONA_CLUSTER, content_addressed=False)
]
AttributionId = Annotated[str, _make_validator(IdPrefix.ATTRIBUTION, content_addressed=False)]
CapabilityId = Annotated[str, _make_validator(IdPrefix.CAPABILITY, content_addressed=False)]
OperationId = Annotated[str, _make_validator(IdPrefix.OPERATION, content_addressed=False)]
ActorId = Annotated[str, _make_validator(IdPrefix.ACTOR, content_addressed=False)]
CollectionId = Annotated[str, _make_validator(IdPrefix.COLLECTION, content_addressed=False)]
AuditId = Annotated[str, _make_validator(IdPrefix.AUDIT, content_addressed=False)]

# Content-addressed: identity is the content itself.
ClaimId = Annotated[str, _make_validator(IdPrefix.CLAIM, content_addressed=True)]
EvidenceId = Annotated[str, _make_validator(IdPrefix.EVIDENCE, content_addressed=True)]
ObservationId = Annotated[str, _make_validator(IdPrefix.OBSERVATION, content_addressed=True)]
