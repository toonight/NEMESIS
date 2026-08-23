"""The Buzz wire format, checked byte for byte, because nothing in CI can ask a relay.

:mod:`nemesis.collaboration.providers.buzz.wire` is the whole of what NEMESIS would put on
a socket if an operator wired one. NEMESIS ships no transport and no BIP-340 signer
(ADR-0010), so no test here — and no test anywhere in this repository — can establish that
a relay accepted anything. What these tests can establish, and what a relay would otherwise
be the only judge of, is that the bytes are the bytes NIP-01 and NIP-29 specify. That makes
this file the single artifact standing between "the format is right" and "the format is
whatever we happened to write".

The failure modes it pins are all silent ones. A relay does not explain itself: it
recomputes an event id, compares, and answers ``OK false`` with a short prefix. So each of
the following would surface to an operator as an opaque rejection weeks after the change
that caused it, and each has a test below.

**The serialization is an ordered array and its order carries meaning.** The id covers
``[0, pubkey, created_at, kind, tags, content]``. The tests recompute that string by hand —
as a literal, not by calling the module's own encoder twice — so a change to the separators,
to ``ensure_ascii``, to the leading ``0`` or to the member order fails here rather than at a
relay. The sharpest edge is the tag list: :func:`~nemesis.core.canonical.canonical_bytes`
sorts arrays, and it is the obvious thing for a future reader to reach for when they see a
hand-rolled JSON encoder. Substituting it would produce an id every relay recomputes
differently, so one test asserts the substitution is *not* in effect rather than merely
describing the hazard in prose.

**Escaping is interop.** The relay parses with ``serde_json``. Non-ASCII content hashed
after ``\\uXXXX`` escaping produces a different digest from the same content hashed as
UTF-8, and both look correct to a human reading the message. The tests fix the UTF-8 answer
and assert the escaped one differs.

**The channel UUID is derived, not minted, and derivation is a promise across processes.**
Two NEMESIS instances must land on the same NIP-29 group for the same channel key, or a
workspace accumulates a room per deployment. A literal UUID is asserted for a known key so
that changing :data:`~nemesis.collaboration.providers.buzz.wire.CHANNEL_NAMESPACE` — which
silently renames every channel in every workspace — fails loudly here.

**Local bounds exist so refusals are legible.** The relay caps content at 256 KiB under a
512 KiB frame cap, so a well-behaved client can send a frame the relay accepts carrying an
event it discards. The bounds are checked locally, and the tests assert the message names
the cap, because a refusal that does not name its bound sends an operator to a packet
capture.

**Parsing an inbound message never raises.** Most traffic in a shared channel is people
talking. A parser that raised on ordinary chat would make polling a stream of handled
exceptions, and the handler is where a real malformed event goes to be ignored.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from nemesis.collaboration.events import (
    CollaborationEvent,
    EpistemicStanding,
    Reference,
    ReferenceScheme,
)
from nemesis.collaboration.providers.buzz import wire
from nemesis.core.canonical import canonical_bytes
from nemesis.core.identity import ActorKind

PUBKEY = "11" * 32
SIG = "ab" * 64
CREATED_AT = 1_777_000_000

CASE = "case-2026-000123"
INVESTIGATION = "inv-2026-000123"

CASE_CHANNEL_UUID = "5a668432-c9f1-5dd3-bbae-94c4ec83af64"
"""The channel UUID for ``case-2026-000123``, hard-coded rather than derived.

Computed once and pinned here on purpose: deriving it in the test with ``uuid5`` would
re-implement the function under test and agree with any namespace it was given, which is
precisely the change this literal exists to catch.
"""

T0 = datetime(2026, 5, 4, 9, 30, tzinfo=UTC)

AWKWARD_CONTENT = 'a "quoted" \\ back\nline\tcell'
"""Every character class ``serde_json`` and ``json`` escape differently if either is wrong."""

AWKWARD_CONTENT_AS_JSON = '"a \\"quoted\\" \\\\ back\\nline\\tcell"'
"""The same string's JSON encoding, written out by hand rather than produced by ``json``."""

EVIDENCE_LOCATOR = "evd_sha256-" + "ab" * 32
CLAIM_LOCATOR = "clm_sha256-" + "cd" * 32


def _collaboration_event(**overrides: object) -> CollaborationEvent:
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


def _valid_wire_fields(**overrides: object) -> dict[str, object]:
    """A well-formed signed event as a plain dict, so one field at a time can be broken."""
    tags: tuple[tuple[str, ...], ...] = (("h", CASE_CHANNEL_UUID),)
    content = "evil.example resolved to 203.0.113.7"
    fields: dict[str, object] = {
        "id": wire.event_id(
            pubkey=PUBKEY,
            created_at=CREATED_AT,
            kind=wire.KIND_GROUP_MESSAGE,
            tags=tags,
            content=content,
        ),
        "pubkey": PUBKEY,
        "created_at": CREATED_AT,
        "kind": wire.KIND_GROUP_MESSAGE,
        "tags": tags,
        "content": content,
        "sig": SIG,
    }
    fields.update(overrides)
    return fields


def _chat(content: str, *, kind: int = wire.KIND_GROUP_MESSAGE) -> wire.NostrEvent:
    """A signed event carrying arbitrary content, the way one arrives from a channel."""
    return wire.NostrEvent(
        **_valid_wire_fields(
            kind=kind,
            content=content,
            id=wire.event_id(
                pubkey=PUBKEY,
                created_at=CREATED_AT,
                kind=kind,
                tags=(("h", CASE_CHANNEL_UUID),),
                content=content,
            ),
        )
    )


# --- 1. NIP-01: the id is a hash of an ordered array -------------------------------


def test_the_event_id_is_sha256_over_the_nip01_serialization_written_out_by_hand() -> None:
    """The format, asserted against a literal rather than against the encoder itself.

    Calling :func:`event_id` twice would prove only that it is deterministic. The expected
    string here is assembled character by character, so the separators, the absence of
    whitespace, the leading ``0`` and the member order are each pinned independently of the
    implementation that produces them.
    """
    tags = (("h", CASE_CHANNEL_UUID), ("nemesis-standing", "observation"))
    content = "evil.example resolved to 203.0.113.7"

    serialization = (
        f'[0,"{PUBKEY}",{CREATED_AT},{wire.KIND_GROUP_MESSAGE},'
        f'[["h","{CASE_CHANNEL_UUID}"],["nemesis-standing","observation"]],'
        f'"{content}"]'
    )
    expected = hashlib.sha256(serialization.encode("utf-8")).hexdigest()

    assert (
        wire.event_id(
            pubkey=PUBKEY,
            created_at=CREATED_AT,
            kind=wire.KIND_GROUP_MESSAGE,
            tags=tags,
            content=content,
        )
        == expected
    )


def test_the_serialization_is_compact_and_unescaped_as_json_dumps_would_produce_it() -> None:
    """The second half of the same proof, in the encoder's own terms.

    Written with ``json.dumps`` so that a reader can see which two options are load-bearing
    — ``separators=(",", ":")`` and ``ensure_ascii=False`` — and so that a change to either
    fails with a readable diff rather than as a bare digest mismatch.
    """
    tags = (("h", CASE_CHANNEL_UUID),)
    content = "évil.example"

    serialization = json.dumps(
        [0, PUBKEY, CREATED_AT, wire.KIND_GROUP_MESSAGE, [list(tag) for tag in tags], content],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    prefix = f'[0,"{PUBKEY}",{CREATED_AT},{wire.KIND_GROUP_MESSAGE},[["h",'
    assert " " not in serialization
    assert serialization.startswith(prefix)
    assert (
        wire.event_id(
            pubkey=PUBKEY,
            created_at=CREATED_AT,
            kind=wire.KIND_GROUP_MESSAGE,
            tags=tags,
            content=content,
        )
        == hashlib.sha256(serialization.encode("utf-8")).hexdigest()
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"pubkey": "22" * 32},
        {"created_at": CREATED_AT + 1},
        {"kind": wire.KIND_CREATE_GROUP},
        {"tags": (("h", CASE_CHANNEL_UUID), ("e", "00" * 32))},
        {"content": "evil.example resolved to 203.0.113.8"},
    ],
    ids=["pubkey", "created_at", "kind", "tags", "content"],
)
def test_every_member_of_the_serialization_array_changes_the_id(
    overrides: dict[str, object],
) -> None:
    """A member the hash did not cover would let a relay-stored event be altered undetected.

    The provider's read path re-derives the id and refuses a mismatch; that check is only
    worth what the coverage of the hash is worth, so each of the five variable members is
    shown to move it.
    """
    base: dict[str, object] = {
        "pubkey": PUBKEY,
        "created_at": CREATED_AT,
        "kind": wire.KIND_GROUP_MESSAGE,
        "tags": (("h", CASE_CHANNEL_UUID),),
        "content": "evil.example resolved to 203.0.113.7",
    }
    assert wire.event_id(**base) != wire.event_id(**{**base, **overrides})  # type: ignore[arg-type]


# --- 2. Tag order is significant ---------------------------------------------------


def test_reordering_the_tags_of_an_event_changes_its_id() -> None:
    """NIP-01 hashes the tag list as written. Two orders are two events."""
    first = (("h", CASE_CHANNEL_UUID), ("nemesis-standing", "observation"))
    second = (("nemesis-standing", "observation"), ("h", CASE_CHANNEL_UUID))

    ids = {
        wire.event_id(
            pubkey=PUBKEY,
            created_at=CREATED_AT,
            kind=wire.KIND_GROUP_MESSAGE,
            tags=tags,
            content="x",
        )
        for tags in (first, second)
    }
    assert len(ids) == 2


def test_the_event_id_is_not_computed_with_the_array_sorting_canonical_encoder() -> None:
    """The specific substitution a future reader is most likely to make, refused.

    :func:`~nemesis.core.canonical.canonical_bytes` is this repository's signing encoder and
    is the obvious replacement for a hand-rolled ``json.dumps``. It sorts arrays, which is
    safe for everything it currently signs and fatal here: sorting the tag list yields an id
    the relay recomputes differently and rejects as ``invalid:``, with no indication of
    which field moved. Both halves are asserted — that sorting the tags changes the id, and
    that the canonical encoding of the serialization array is not what the id hashes.
    """
    tags = (("nemesis-standing", "observation"), ("h", CASE_CHANNEL_UUID))
    assert tuple(sorted(tags)) != tags
    content = "evil.example resolved to 203.0.113.7"

    identifier = wire.event_id(
        pubkey=PUBKEY,
        created_at=CREATED_AT,
        kind=wire.KIND_GROUP_MESSAGE,
        tags=tags,
        content=content,
    )
    sorted_identifier = wire.event_id(
        pubkey=PUBKEY,
        created_at=CREATED_AT,
        kind=wire.KIND_GROUP_MESSAGE,
        tags=tuple(sorted(tags)),
        content=content,
    )
    canonical_digest = hashlib.sha256(
        canonical_bytes(
            [
                0,
                PUBKEY,
                CREATED_AT,
                wire.KIND_GROUP_MESSAGE,
                [list(tag) for tag in tags],
                content,
            ]
        )
    ).hexdigest()

    assert identifier != sorted_identifier
    assert identifier != canonical_digest


def test_the_tag_order_a_builder_chose_survives_into_the_signed_event() -> None:
    """Not only the hash: the tags a relay stores are the tags in the order built."""
    event = wire.build_create_group(
        pubkey=PUBKEY,
        created_at=CREATED_AT,
        channel_key=CASE,
        display_name="Case 000123",
        purpose="Infrastructure pursuit",
        private=True,
    )
    assert [tag[0] for tag in event.tags] == [
        "h",
        "name",
        "visibility",
        "channel_type",
        "nemesis-channel-key",
        "about",
    ]
    assert event.sealed(SIG).tags == event.tags


# --- 3. Escaping and non-ASCII -----------------------------------------------------


def test_non_ascii_content_is_hashed_as_utf8_and_not_as_ascii_escapes() -> None:
    """``ensure_ascii`` is an interop decision, not a style one.

    ``serde_json`` on the relay emits UTF-8 and recomputes the id over it. Escaping to
    ``\\uXXXX`` here would produce a different digest for a message that renders
    identically in every client, which is the least debuggable kind of mismatch.
    """
    content = "évil.example — 日本語 — ✅"
    utf8_form = json.dumps(
        [0, PUBKEY, CREATED_AT, wire.KIND_GROUP_MESSAGE, [], content],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    ascii_form = json.dumps(
        [0, PUBKEY, CREATED_AT, wire.KIND_GROUP_MESSAGE, [], content],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    assert utf8_form != ascii_form

    identifier = wire.event_id(
        pubkey=PUBKEY,
        created_at=CREATED_AT,
        kind=wire.KIND_GROUP_MESSAGE,
        tags=(),
        content=content,
    )
    assert identifier == hashlib.sha256(utf8_form.encode("utf-8")).hexdigest()
    assert identifier != hashlib.sha256(ascii_form.encode("utf-8")).hexdigest()


def test_quotes_backslashes_newlines_and_tabs_hash_through_their_json_escapes() -> None:
    """The expected escaping is a hand-written literal, so the encoder cannot define it."""
    serialization = (
        f'[0,"{PUBKEY}",{CREATED_AT},{wire.KIND_GROUP_MESSAGE},[],{AWKWARD_CONTENT_AS_JSON}]'
    )
    assert json.loads(AWKWARD_CONTENT_AS_JSON) == AWKWARD_CONTENT

    assert (
        wire.event_id(
            pubkey=PUBKEY,
            created_at=CREATED_AT,
            kind=wire.KIND_GROUP_MESSAGE,
            tags=(),
            content=AWKWARD_CONTENT,
        )
        == hashlib.sha256(serialization.encode("utf-8")).hexdigest()
    )


def test_awkward_content_round_trips_through_a_signed_event_unchanged() -> None:
    """Byte-identical out and back, and the id is stable across two constructions."""
    first = wire.UnsignedEvent(
        pubkey=PUBKEY,
        created_at=CREATED_AT,
        kind=wire.KIND_GROUP_MESSAGE,
        content=AWKWARD_CONTENT,
    )
    second = wire.UnsignedEvent(
        pubkey=PUBKEY,
        created_at=CREATED_AT,
        kind=wire.KIND_GROUP_MESSAGE,
        content=AWKWARD_CONTENT,
    )
    assert first.event_id == second.event_id

    signed = first.sealed(SIG)
    assert signed.content == AWKWARD_CONTENT
    assert signed.to_wire()["content"] == AWKWARD_CONTENT


def test_a_summary_carrying_non_ascii_and_escapes_survives_the_whole_envelope() -> None:
    """The end-to-end shape of the same property, through the object callers actually build."""
    event = _collaboration_event(summary=f"évil.example — {AWKWARD_CONTENT}")
    unsigned = wire.build_collaboration_event(
        pubkey=PUBKEY, created_at=CREATED_AT, channel_key=CASE, event=event
    )
    recovered = wire.parse_collaboration_event(unsigned.sealed(SIG))
    assert recovered == event


# --- 4. NostrEvent refuses what a relay would refuse --------------------------------


def test_a_nostr_event_whose_id_does_not_match_its_content_is_refused_locally() -> None:
    """The relay recomputes and answers ``invalid:``; refusing here names the field."""
    fields = _valid_wire_fields(content="evil.example resolved to 198.51.100.9")
    with pytest.raises(ValidationError, match="does not match its content"):
        wire.NostrEvent(**fields)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", "0" * 63),
        ("id", "A" * 64),
        ("id", "z" * 64),
        ("pubkey", "0" * 63),
        ("pubkey", "A" * 64),
        ("pubkey", "z" * 64),
        ("sig", "0" * 127),
        ("sig", "A" * 128),
        ("sig", "z" * 128),
    ],
    ids=[
        "id-too-short",
        "id-uppercase",
        "id-non-hex",
        "pubkey-too-short",
        "pubkey-uppercase",
        "pubkey-non-hex",
        "sig-too-short",
        "sig-uppercase",
        "sig-non-hex",
    ],
)
def test_a_nostr_event_refuses_hex_of_the_wrong_shape(field: str, value: str) -> None:
    """Lowercase and exact length, because that is what the relay's parser accepts.

    Uppercase is the interesting case: it is valid hex, decodes to the same bytes, and is
    rejected by the relay all the same. A client that emitted it would look correct in every
    log and be refused by every relay.
    """
    with pytest.raises(ValidationError):
        wire.NostrEvent(**_valid_wire_fields(**{field: value}))


def test_a_nostr_event_refuses_content_over_the_relay_cap_and_names_the_cap() -> None:
    """The 512 KiB frame cap is the only one advertised; the 256 KiB content cap is not.

    So a client can build a frame the relay accepts carrying an event it discards, and the
    only signal is ``OK false``. Checking locally turns that into an error naming the bound.
    """
    oversized = "x" * (wire.MAX_CONTENT_BYTES + 1)
    fields = _valid_wire_fields(
        content=oversized,
        id=wire.event_id(
            pubkey=PUBKEY,
            created_at=CREATED_AT,
            kind=wire.KIND_GROUP_MESSAGE,
            tags=(("h", CASE_CHANNEL_UUID),),
            content=oversized,
        ),
    )
    with pytest.raises(ValidationError, match=str(wire.MAX_CONTENT_BYTES)):
        wire.NostrEvent(**fields)


def test_an_unsigned_event_refuses_content_over_the_relay_cap_before_it_is_signed() -> None:
    """The same bound, one step earlier, so a signer is never handed a doomed digest."""
    with pytest.raises(ValidationError, match=str(wire.MAX_CONTENT_BYTES)):
        wire.UnsignedEvent(
            pubkey=PUBKEY,
            created_at=CREATED_AT,
            kind=wire.KIND_GROUP_MESSAGE,
            content="x" * (wire.MAX_CONTENT_BYTES + 1),
        )


def test_content_measured_in_bytes_rather_than_characters() -> None:
    """A multi-byte character counts as its bytes, which is what the relay counts."""
    just_over = "é" * ((wire.MAX_CONTENT_BYTES // 2) + 1)
    assert len(just_over) <= wire.MAX_CONTENT_BYTES
    assert len(just_over.encode("utf-8")) > wire.MAX_CONTENT_BYTES

    with pytest.raises(ValidationError, match=str(wire.MAX_CONTENT_BYTES)):
        wire.UnsignedEvent(
            pubkey=PUBKEY,
            created_at=CREATED_AT,
            kind=wire.KIND_GROUP_MESSAGE,
            content=just_over,
        )


# --- 5. The digest a signer is handed ----------------------------------------------


def test_the_signing_digest_is_the_thirty_two_raw_bytes_of_the_event_id() -> None:
    """BIP-340 signs 32 bytes. Handing a signer the hex string would sign 64.

    The digest is the whole of the interface NEMESIS offers an injected signer, so an
    implementation never has to know NIP-01's serialization rules — and cannot get them
    wrong — but it also means a mistake here is invisible until a relay rejects a signature
    that verifies perfectly against the wrong message.
    """
    unsigned = wire.UnsignedEvent(
        pubkey=PUBKEY,
        created_at=CREATED_AT,
        kind=wire.KIND_GROUP_MESSAGE,
        tags=(("h", CASE_CHANNEL_UUID),),
        content="evil.example resolved to 203.0.113.7",
    )
    digest = unsigned.signing_digest()

    assert isinstance(digest, bytes)
    assert len(digest) == 32
    assert digest == bytes.fromhex(unsigned.event_id)
    assert digest.hex() == unsigned.event_id


def test_sealing_an_unsigned_event_produces_an_event_whose_id_recomputes() -> None:
    """``sealed`` attaches a signature and changes nothing the id covers."""
    unsigned = wire.UnsignedEvent(
        pubkey=PUBKEY,
        created_at=CREATED_AT,
        kind=wire.KIND_GROUP_MESSAGE,
        tags=(("h", CASE_CHANNEL_UUID),),
        content="evil.example resolved to 203.0.113.7",
    )
    signed = unsigned.sealed(SIG)

    assert signed.id == unsigned.event_id
    assert signed.sig == SIG
    assert (signed.pubkey, signed.created_at, signed.kind, signed.tags, signed.content) == (
        unsigned.pubkey,
        unsigned.created_at,
        unsigned.kind,
        unsigned.tags,
        unsigned.content,
    )
    assert wire.NostrEvent.model_validate(dict(signed.to_wire())) == signed


def test_the_wire_form_carries_tags_as_lists_because_json_has_no_tuple() -> None:
    """``to_wire`` is what a transport serialises; a tuple would not survive ``json.dumps``
    in every implementation an operator might supply."""
    signed = wire.build_add_user(
        pubkey=PUBKEY, created_at=CREATED_AT, channel_key=CASE, member_pubkey="22" * 32
    ).sealed(SIG)
    payload = signed.to_wire()

    assert payload["tags"] == [["h", CASE_CHANNEL_UUID], ["p", "22" * 32], ["role", "member"]]
    assert json.loads(json.dumps(payload))["id"] == signed.id


# --- 6. The derived channel UUID ---------------------------------------------------


def test_the_channel_uuid_for_a_known_key_is_this_exact_value() -> None:
    """A literal, so a change to the namespace fails here instead of in a workspace.

    :data:`CHANNEL_NAMESPACE` is arbitrary and fixed. Changing it renames every channel in
    every deployment, and the symptom is a second empty room beside a populated one — which
    nobody reads as a code change. This assertion is the loud failure that event deserves.
    """
    assert wire.channel_uuid(CASE) == CASE_CHANNEL_UUID
    assert wire.channel_uuid("approvals") == "b9720068-d3fd-5cce-bbf7-31294cffe354"


def test_the_channel_uuid_is_a_version_five_uuid_and_is_stable_across_calls() -> None:
    """Derived rather than minted, which is what makes ``open_channel`` idempotent."""
    derived = wire.channel_uuid(CASE)
    assert uuid.UUID(derived).version == 5
    assert wire.channel_uuid(CASE) == derived


def test_two_channel_keys_never_share_a_channel_uuid() -> None:
    keys = (CASE, "case-2026-000124", "approvals", "standing-intel", "a", "")
    assert len({wire.channel_uuid(key) for key in keys}) == len(keys)


# --- 7. What each builder puts on the wire -----------------------------------------


def test_build_create_group_uses_kind_9007_and_the_derived_channel_uuid() -> None:
    event = wire.build_create_group(
        pubkey=PUBKEY,
        created_at=CREATED_AT,
        channel_key=CASE,
        display_name="Case 000123",
        purpose="Infrastructure pursuit",
        private=True,
    )
    assert event.kind == wire.KIND_CREATE_GROUP == 9007
    assert {tag[0]: tag[1] for tag in event.tags} == {
        "h": wire.channel_uuid(CASE),
        "name": "Case 000123",
        "visibility": "private",
        "channel_type": "stream",
        "nemesis-channel-key": CASE,
        "about": "Infrastructure pursuit",
    }


@pytest.mark.parametrize(
    ("private", "visibility"), [(True, "private"), (False, "open")], ids=["private", "open"]
)
def test_a_channels_visibility_tag_says_private_only_when_it_was_asked_for(
    private: bool, visibility: str
) -> None:
    """The relay reads this tag and nothing else to decide who may read the room.

    A default that leaned open would put an investigation's traffic in front of every member
    of a workspace, and the mistake would be invisible until someone noticed.
    """
    event = wire.build_create_group(
        pubkey=PUBKEY,
        created_at=CREATED_AT,
        channel_key=CASE,
        display_name="Case 000123",
        purpose="",
        private=private,
    )
    assert {tag[0]: tag[1] for tag in event.tags}["visibility"] == visibility


def test_a_channel_with_no_purpose_carries_no_about_tag_rather_than_an_empty_one() -> None:
    """An empty ``about`` renders as a blank description in every NIP-29 client."""
    event = wire.build_create_group(
        pubkey=PUBKEY,
        created_at=CREATED_AT,
        channel_key=CASE,
        display_name="Case 000123",
        purpose="",
        private=True,
    )
    assert [tag[0] for tag in event.tags] == [
        "h",
        "name",
        "visibility",
        "channel_type",
        "nemesis-channel-key",
    ]


def test_build_add_user_uses_kind_9000_and_names_the_member_in_a_p_tag() -> None:
    event = wire.build_add_user(
        pubkey=PUBKEY,
        created_at=CREATED_AT,
        channel_key=CASE,
        member_pubkey="22" * 32,
        role="admin",
    )
    assert event.kind == wire.KIND_ADD_USER == 9000
    assert event.tags == (
        ("h", wire.channel_uuid(CASE)),
        ("p", "22" * 32),
        ("role", "admin"),
    )


def test_build_profile_uses_kind_0_and_carries_its_fields_as_json_in_the_content() -> None:
    """NIP-01 metadata is a JSON object in ``content``, not a set of tags."""
    event = wire.build_profile(
        pubkey=PUBKEY,
        created_at=CREATED_AT,
        display_name="nemesis-pursuit",
        about="Chooses the next pivot by deterministic rule policy.",
    )
    assert event.kind == wire.KIND_PROFILE == 0
    assert event.tags == ()
    assert json.loads(event.content) == {
        "name": "nemesis-pursuit",
        "display_name": "nemesis-pursuit",
        "about": "Chooses the next pivot by deterministic rule policy.",
    }


def test_build_auth_uses_kind_22242_and_carries_the_challenge_and_a_normalized_relay() -> None:
    """The relay compares the ``relay`` tag against its own normalised URL and says nothing
    useful when they differ, so the tag is normalised before it is sent."""
    event = wire.build_auth(
        pubkey=PUBKEY,
        created_at=CREATED_AT,
        challenge="deadbeefcafe",
        relay_url="ws://localhost:3000/",
    )
    assert event.kind == wire.KIND_AUTH == 22242
    assert event.content == ""
    assert event.tags == (("relay", "ws://127.0.0.1:3000"), ("challenge", "deadbeefcafe"))


def test_build_collaboration_event_travels_as_an_ordinary_group_message() -> None:
    """Kind 9, because the relay refuses every kind absent from its ingest map.

    Minting a ``kind:41337`` for "NEMESIS event" would read well and be rejected by every
    stock relay with ``restricted: unknown event kind``.
    """
    event = _collaboration_event()
    unsigned = wire.build_collaboration_event(
        pubkey=PUBKEY, created_at=CREATED_AT, channel_key=CASE, event=event
    )
    assert unsigned.kind == wire.KIND_GROUP_MESSAGE == 9
    assert unsigned.tags == (
        ("h", wire.channel_uuid(CASE)),
        ("nemesis-event-id", event.event_id),
        ("nemesis-standing", "observation"),
        ("nemesis-case", CASE),
        ("nemesis-correlation", "corr-1"),
        ("nemesis-type", "threat.infrastructure.observed"),
    )


def test_a_channel_message_filter_selects_by_group_rather_than_by_kind_alone() -> None:
    """The relay keeps channel-scoped and global delivery separate, so a kinds-only
    subscription receives none of a channel's traffic and looks like an empty room."""
    query = wire.channel_message_filter(channel_key=CASE, since=CREATED_AT, limit=25)
    assert query == {
        "kinds": [wire.KIND_GROUP_MESSAGE],
        "#h": [wire.channel_uuid(CASE)],
        "limit": 25,
        "since": CREATED_AT,
    }
    assert "since" not in wire.channel_message_filter(channel_key=CASE)


# --- 8. Relay URL normalisation ----------------------------------------------------


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("ws://localhost:3000", "ws://127.0.0.1:3000"),
        ("ws://localhost:3000/", "ws://127.0.0.1:3000"),
        ("ws://localhost", "ws://127.0.0.1"),
        ("ws://localhost/", "ws://127.0.0.1"),
        # IPv6 loopback is deliberately NOT folded, and this expectation was reversed
        # after a review read the relay more carefully. The relay's condition is
        # `host == "localhost" || host == "::1"`, but `host` comes from the url crate's
        # `host_str()`, which returns IPv6 addresses *inside brackets* — so `[::1]` never
        # equals `"::1"` and that arm cannot fire. Folding it here would send a tag the
        # relay normalises to 127.0.0.1 while its own `[::1]` config normalises to
        # something else, breaking a pair that works without us.
        ("ws://[::1]:3000", "ws://[::1]:3000"),
        ("ws://[::1]:3000/", "ws://[::1]:3000"),
        ("ws://::1", "ws://::1"),
        ("ws://127.0.0.1:3000/", "ws://127.0.0.1:3000"),
        # Case folding, which the URL parser does and this did not.
        ("ws://LOCALHOST:3000", "ws://127.0.0.1:3000"),
        ("wss://LocalHost:3000/", "wss://127.0.0.1:3000"),
        # Anchored on both sides: a host that merely CONTAINS "localhost" is untouched.
        # Without the trailing anchor, `ws://localhost.evil.example` became
        # `ws://127.0.0.1.evil.example`.
        ("ws://localhost.evil.example:3000", "ws://localhost.evil.example:3000"),
        ("ws://localhost-relay.example", "ws://localhost-relay.example"),
        ("ws://mylocalhost.example:3000", "ws://mylocalhost.example:3000"),
        ("wss://relay.localhost.example", "wss://relay.localhost.example"),
        ("wss://buzz.example.org/", "wss://buzz.example.org"),
        ("wss://buzz.example.org:443", "wss://buzz.example.org:443"),
    ],
)
def test_a_relay_url_is_normalized_the_way_the_relay_normalizes_it(
    given: str, expected: str
) -> None:
    """This mirrors the relay's own normalisation, and a mismatch is opaque.

    The relay folds ``localhost`` and ``::1`` to ``127.0.0.1`` and strips a trailing slash
    before comparing the NIP-42 ``relay`` tag to its configured URL. A client that skips any
    part of that sends a tag a human reads as correct and gets back
    ``auth-required: verification failed`` — which names neither the tag nor the difference,
    and is the single most confusing failure in bringing this integration up.
    """
    assert wire.normalize_relay_url(given) == expected


def test_normalisation_is_idempotent_so_a_normalised_url_survives_a_second_pass() -> None:
    for given in ("ws://localhost:3000/", "wss://buzz.example.org/", "ws://[::1]:3000"):
        once = wire.normalize_relay_url(given)
        assert wire.normalize_relay_url(once) == once


# --- 9. The NEMESIS envelope, out and back -----------------------------------------


def test_the_envelope_is_versioned_under_a_nemesis_key_in_the_content() -> None:
    """A NIP-29 client shows *something*, and a NEMESIS reader gets the typed object back.

    The wrapper is versioned so that a future envelope shape is recognisably not this one,
    rather than parsing partially into something that looks like an event.
    """
    event = _collaboration_event(
        references=(
            Reference(scheme=ReferenceScheme.EVIDENCE, case_id=CASE, locator=EVIDENCE_LOCATOR),
        ),
        confidence=0.62,
        uncertainty_note="Two independent collections, one registrar record.",
    )
    unsigned = wire.build_collaboration_event(
        pubkey=PUBKEY, created_at=CREATED_AT, channel_key=CASE, event=event
    )
    body = json.loads(unsigned.content)

    assert set(body) == {"nemesis"}
    assert body["nemesis"]["version"] == 1
    assert body["nemesis"]["integrity_hash"] == event.integrity_hash()
    assert body["nemesis"]["event"]["event_id"] == event.event_id


def test_a_published_event_round_trips_back_to_an_equal_collaboration_event() -> None:
    """Equality, not "looks similar": the parsed object is the object that was published.

    Anything less would make the outbox's deduplication a guess, since the only thing that
    makes a recovered envelope *ours* is that its ``event_id`` matches one we sent.
    """
    event = _collaboration_event(
        payload={"domain": "evil.example", "address": "203.0.113.7"},
        references=(
            Reference(scheme=ReferenceScheme.EVIDENCE, case_id=CASE, locator=EVIDENCE_LOCATOR),
            Reference(scheme=ReferenceScheme.CLAIM, case_id=CASE, locator=CLAIM_LOCATOR),
        ),
        confidence=0.62,
        uncertainty_note="Two independent collections, one registrar record.",
    )
    signed = wire.build_collaboration_event(
        pubkey=PUBKEY, created_at=CREATED_AT, channel_key=CASE, event=event
    ).sealed(SIG)

    recovered = wire.parse_collaboration_event(signed)
    assert recovered == event
    assert recovered is not None
    assert recovered.event_id == event.event_id
    assert recovered.references == event.references
    assert recovered.integrity_hash() == event.integrity_hash()


# --- 10. Parsing an inbound message never raises -----------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "looks good to me, approving",
        "",
        "{not json at all",
        "[1,2,3]",
        "42",
        '"a bare json string"',
        "null",
        '{"nemesis":{"version":2,"event":{}}}',
        '{"nemesis":{"version":"1","event":{}}}',
        '{"nemesis":"not an object"}',
        '{"nemesis":{"version":1}}',
        '{"nemesis":{"version":1,"event":{"event_id":"not-an-id"}}}',
        '{"something_else":{"version":1}}',
    ],
    ids=[
        "human-chat",
        "empty",
        "invalid-json",
        "json-array",
        "json-number",
        "json-string",
        "json-null",
        "wrong-version",
        "version-as-string",
        "wrapper-not-an-object",
        "wrapper-without-an-event",
        "event-fails-validation",
        "no-nemesis-key",
    ],
)
def test_a_message_that_is_not_a_nemesis_envelope_parses_to_none_rather_than_raising(
    content: str,
) -> None:
    """Most traffic in a shared channel is people talking.

    A parser that raised on ordinary chat would make polling a channel a stream of handled
    exceptions, and the handler that swallows them is where a genuinely malformed NEMESIS
    event would go to die unnoticed. A message that *claims* to carry an envelope and does
    not parse also returns ``None`` — it is not a NEMESIS event, whatever it says about
    itself.
    """
    assert wire.parse_collaboration_event(_chat(content)) is None


@pytest.mark.parametrize(
    "kind",
    [wire.KIND_PROFILE, wire.KIND_ADD_USER, wire.KIND_CREATE_GROUP, wire.KIND_AUTH],
    ids=["profile", "add-user", "create-group", "auth"],
)
def test_a_valid_envelope_carried_by_the_wrong_kind_is_not_a_nemesis_event(kind: int) -> None:
    """The kind is checked before the content is even read.

    An envelope in a ``kind:0`` profile is not a published collaboration event: it never
    passed the relay's channel-membership check on the write path, and treating it as one
    would accept an event nobody was authorised to put in the room.
    """
    event = _collaboration_event()
    body = wire.build_collaboration_event(
        pubkey=PUBKEY, created_at=CREATED_AT, channel_key=CASE, event=event
    ).content
    assert wire.parse_collaboration_event(_chat(body, kind=kind)) is None


def test_an_envelope_whose_event_id_was_tampered_with_parses_to_none() -> None:
    """The identifier is content-addressed, so an altered envelope fails its own validator.

    Not tamper-evidence — a relay operator could recompute both — but it does catch the
    stored-row edit the relay's own schema permits, where ``content`` is updated and nothing
    on the read path re-checks it.
    """
    event = _collaboration_event()
    body = json.loads(
        wire.build_collaboration_event(
            pubkey=PUBKEY, created_at=CREATED_AT, channel_key=CASE, event=event
        ).content
    )
    body["nemesis"]["event"]["summary"] = "evil.example resolved to 198.51.100.9"

    tampered = json.dumps(body, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    assert wire.parse_collaboration_event(_chat(tampered)) is None


def test_tag_value_returns_the_first_match_and_none_for_an_absent_tag() -> None:
    """How the provider reads ``e`` for a reply, without assuming a tag exists."""
    signed = wire.UnsignedEvent(
        pubkey=PUBKEY,
        created_at=CREATED_AT,
        kind=wire.KIND_GROUP_MESSAGE,
        tags=(("h", CASE_CHANNEL_UUID), ("e", "00" * 32), ("e", "ff" * 32)),
        content="reply",
    ).sealed(SIG)

    assert signed.tag_value("h") == CASE_CHANNEL_UUID
    assert signed.tag_value("e") == "00" * 32
    assert signed.tag_value("p") is None


# --- 11 and 12. Local bounds, so a refusal names its cap ---------------------------


def test_a_tag_element_over_the_bound_is_refused_and_the_message_names_the_bound() -> None:
    """Long material belongs in a reference, not in a tag.

    The relay indexes single-letter tag values and stores the rest; an oversized element is
    accepted by some relays, truncated by others and refused by a third, and NEMESIS
    publishing something whose stored form differs per deployment is not a wire format.
    """
    with pytest.raises(ValidationError, match=str(wire.MAX_TAG_VALUE_BYTES)):
        wire.UnsignedEvent(
            pubkey=PUBKEY,
            created_at=CREATED_AT,
            kind=wire.KIND_GROUP_MESSAGE,
            tags=(("nemesis-note", "x" * (wire.MAX_TAG_VALUE_BYTES + 1)),),
        )


def test_the_tag_bound_counts_bytes_and_applies_to_the_tag_name_as_well() -> None:
    """Every element, not only the value: a tag name is a tag element too."""
    with pytest.raises(ValidationError, match=str(wire.MAX_TAG_VALUE_BYTES)):
        wire.UnsignedEvent(
            pubkey=PUBKEY,
            created_at=CREATED_AT,
            kind=wire.KIND_GROUP_MESSAGE,
            tags=(("é" * wire.MAX_TAG_VALUE_BYTES, "value"),),
        )


def test_a_tag_element_exactly_at_the_bound_is_accepted() -> None:
    """The bound is inclusive, asserted so a later off-by-one is a visible change."""
    event = wire.UnsignedEvent(
        pubkey=PUBKEY,
        created_at=CREATED_AT,
        kind=wire.KIND_GROUP_MESSAGE,
        tags=(("nemesis-note", "x" * wire.MAX_TAG_VALUE_BYTES),),
    )
    assert len(event.tags[0][1]) == wire.MAX_TAG_VALUE_BYTES


def test_an_empty_tag_is_refused_because_it_has_no_name() -> None:
    """``[]`` in a tag list is syntactically valid JSON and semantically nothing."""
    with pytest.raises(ValidationError, match="empty tag"):
        wire.UnsignedEvent(
            pubkey=PUBKEY,
            created_at=CREATED_AT,
            kind=wire.KIND_GROUP_MESSAGE,
            tags=((),),
        )
