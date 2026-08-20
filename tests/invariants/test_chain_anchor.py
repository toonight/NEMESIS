"""The attacks the chains could not see, put in front of something that can.

Three strict `xfail` tests in this suite record what a hash-chained table cannot notice about
itself: delete its newest revocation and a withdrawn authority is silently restored; delete its
newest debit and spent autonomy comes back; delete the file and the budget resets. Interior
edits are caught — by the per-record signature, not by the chaining — but nothing follows the
tail, so nothing fails to follow it.

These tests are the other half. Each one runs an attack the chain is blind to and asserts the
anchor sees it, and each states plainly what the anchor is worth: exactly the trust boundary it
sits behind, which on a single-user machine is none. The contract is built so that crossing a
real boundary is a constructor argument rather than a redesign.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from nemesis.authz.anchor import (
    REVOCATION_CHAIN,
    AnchorEpochError,
    AnchorIndependence,
    AnchorPlacementError,
    AnchorRegistryError,
    ChainAnchor,
    FileAnchorStore,
    LocalAnchorSigner,
    RegisteredAnchorAuthority,
    anchor_for,
    chain_digest,
    local_anchor_authority,
    registered_authorities,
    verify_against_anchor,
)
from nemesis.authz.keys import CapabilitySigningKey

pytestmark = pytest.mark.invariant

NOW = datetime(2026, 8, 20, tzinfo=UTC)
LINKS = ("aa" * 32, "bb" * 32, "cc" * 32, "dd" * 32)


def _local(signer: LocalAnchorSigner) -> list[RegisteredAnchorAuthority]:
    """The deployment's registry with only our own key in it, at the only ceiling it can hold."""
    return [local_anchor_authority(signer.verifying_key)]


def _signed(links: tuple[str, ...], *, epoch: int = 1) -> tuple[ChainAnchor, LocalAnchorSigner]:
    signer = LocalAnchorSigner(CapabilitySigningKey.generate())
    return signer.sign(anchor_for(REVOCATION_CHAIN, links, epoch=epoch, anchored_at=NOW)), signer


# --- The three attacks the chain is blind to ---------------------------------


def test_tail_truncation_is_seen() -> None:
    """THE ONE THIS MODULE EXISTS FOR.

    Deleting the newest link leaves a chain that is internally perfect: every remaining link
    follows the one before it, every signature verifies, the sequence is contiguous. Nothing
    inside can object, because there is nothing after the hole to fail to follow. The anchor
    objects because it remembers how long the chain was.
    """
    anchor, signer = _signed(LINKS)

    assert verify_against_anchor(LINKS, anchor, authorities=_local(signer)) == ()

    truncated = LINKS[:-1]
    defects = verify_against_anchor(truncated, anchor, authorities=_local(signer))

    assert defects, "a record was deleted and the anchor reported the chain intact"
    assert any("removed after it was anchored" in d for d in defects)


def test_total_erasure_is_seen() -> None:
    """Emptying the table verifies clean from inside — an empty chain is a consistent chain.

    This is the cheapest attack in the family and the one a bare hash chain is least able to
    resist: there is no link left to disagree with anything.
    """
    anchor, signer = _signed(LINKS)

    defects = verify_against_anchor((), anchor, authorities=_local(signer))

    assert defects
    assert any("0 records and the anchor attests 4" in d for d in defects)


def test_truncate_then_reoccupy_is_seen_when_a_prior_tip_was_retained() -> None:
    """The sharper attack, and the honest limit on catching it.

    Delete the tail, then let the platform run normally: the next legitimate record is signed
    by the real gateway and chains onto the truncated tail. The table becomes fully
    self-consistent again — the deleted records do not read as missing, they read as never
    having existed. The chain validates end to end and no signature is out of place.

    It is caught here **only because the verifier still holds the pre-attack anchor**. That is
    the whole mechanism: memory the attacker did not get to rewrite. Where that memory lives is
    the security argument, and this module does not supply it.
    """
    anchor, signer = _signed(LINKS)

    rewritten = (*LINKS[:-1], "ee" * 32)  # same length, different history
    defects = verify_against_anchor(rewritten, anchor, authorities=_local(signer))

    assert defects, "the history was rewritten to the same length and nothing objected"
    assert any("not the ones that were anchored" in d for d in defects)
    # And the count check alone would NOT have caught it — the rewrite preserves length.
    assert len(rewritten) == anchor.record_count


# --- The anchor's own failure modes ------------------------------------------


def test_a_missing_anchor_is_reported_rather_than_passed() -> None:
    """Deleting the anchor must not be cheaper than deleting the chain.

    A verifier that read "no anchor" as silence would hand an attacker the simplest attack in
    the set. "Nobody ever attested to this chain" and "this chain matches its attestation" are
    different findings, and only one of them is evidence.
    """
    signer = LocalAnchorSigner(CapabilitySigningKey.generate())

    defects = verify_against_anchor(LINKS, None, authorities=_local(signer))

    assert defects
    assert any("attested by nothing" in d for d in defects)


def test_an_unsigned_or_forged_anchor_is_refused() -> None:
    """An anchor anyone could write attests nothing. The signature is what makes it memory
    rather than a note."""
    anchor, signer = _signed(LINKS)
    other = LocalAnchorSigner(CapabilitySigningKey.generate())

    unsigned = anchor.model_copy(update={"signature": None})
    assert any(
        "not signed by the attesting authority" in d
        for d in verify_against_anchor(LINKS, unsigned, authorities=_local(signer))
    )

    # Signed by a real key, but not the one this verifier trusts.
    assert any(
        "not signed by the attesting authority" in d
        for d in verify_against_anchor(LINKS, anchor, authorities=_local(other))
    )


def test_replaying_an_older_anchor_is_refused() -> None:
    """The failure an external review caught in the first draft of this contract.

    An attacker who cannot forge a signature can still present an *earlier, validly signed*
    anchor to make an older state look current. Nothing about the signature objects — it is
    genuine. Only the retained epoch does, which is why the epoch exists.

    And the reason it is `retained_epoch` rather than a field on the anchor: an epoch the
    attacker supplies alongside the anchor is one they choose.
    """
    stale, signer = _signed(LINKS[:2], epoch=1)

    assert verify_against_anchor(LINKS[:2], stale, authorities=_local(signer)) == ()

    defects = verify_against_anchor(LINKS[:2], stale, authorities=_local(signer), retained_epoch=7)
    assert any("older than the 7" in d for d in defects)


def test_records_added_without_re_anchoring_are_named_as_unattested() -> None:
    """Growth is not tampering, and is not silence either. The newest records are outside what
    anybody attested, which is a fact a reader needs — an anchor is only as fresh as its last
    publication."""
    anchor, signer = _signed(LINKS[:2])

    defects = verify_against_anchor(LINKS, anchor, authorities=_local(signer))

    assert any("added without re-anchoring" in d for d in defects)


# --- What the anchor is worth, said by the code ------------------------------


def test_an_anchor_cannot_be_promoted_to_a_tier_it_was_not_signed_at() -> None:
    """The honesty guard, moved to the field that now carries the claim.

    Independence is a ladder, not a flag: a second system account defeats a compromised pilot
    and not `root`; a separate host defeats a compromised host and not the operator who
    administers both; only a third party defeats us. `is_externally_held` is therefore true
    only at the top rung — a separated anchor is *separated*, not *external*.

    The claim is inside the signature, so editing it afterwards invalidates the thing that made
    it worth reading. Promotion is the attack worth naming: it costs nothing to write a
    stronger word into a file, and it is exactly what somebody would do to make an
    attestation look like more than it is.
    """
    anchor, signer = _signed(LINKS)

    assert anchor.independence is AnchorIndependence.NONE
    assert not anchor.is_externally_held
    assert not anchor.defeats_a_compromised_pilot()

    promoted = anchor.model_copy(update={"independence": AnchorIndependence.THIRD_PARTY})
    assert promoted.is_externally_held  # it *says* independent...
    assert any(  # ...and the signature no longer covers what it says
        "not signed by the attesting authority" in d
        for d in verify_against_anchor(LINKS, promoted, authorities=_local(signer))
    )


def test_each_tier_says_what_it_does_not_defeat() -> None:
    """A tier that only advertised its strength would be read as the tier above it.

    This pins the ladder itself, because the distinction is the whole security argument and it
    is the kind of thing a later refactor flattens back into a boolean — which is what this
    module shipped with, before an external reviewer pointed out that "external" is not one
    boundary.
    """

    def at(tier: AnchorIndependence) -> ChainAnchor:
        return ChainAnchor(
            chain_id=REVOCATION_CHAIN,
            epoch=1,
            record_count=1,
            tip_hash="x",
            anchored_at=NOW,
            authority="whoever",
            independence=tier,
        )

    # Same account as the chain: an accident, not an adversary.
    assert not at(AnchorIndependence.NONE).defeats_a_compromised_pilot()
    assert not at(AnchorIndependence.NONE).is_externally_held

    # A second system account stops the pilot — and not root, and not the administrator.
    assert at(AnchorIndependence.SEPARATE_ACCOUNT).defeats_a_compromised_pilot()
    assert not at(AnchorIndependence.SEPARATE_ACCOUNT).is_externally_held

    # A separate host stops a compromised host — and not an operator who administers both.
    assert at(AnchorIndependence.SEPARATE_HOST).defeats_a_compromised_pilot()
    assert not at(AnchorIndependence.SEPARATE_HOST).is_externally_held

    # Only a third party is beyond our own reach, which is where the vault operator sits in
    # this project's threat model.
    assert at(AnchorIndependence.THIRD_PARTY).is_externally_held


def test_a_clean_local_anchor_is_not_reported_as_a_defect() -> None:
    """The first draft appended the local-authority limitation to the defect list, so a caller
    writing the obvious `if defects: alarm()` would have alarmed on every healthy chain.

    "The data disagrees with its attestation" and "this attestation is weak" are different
    findings. The second belongs in what a caller *reports*, beside the result — never mixed
    into it.
    """
    anchor, signer = _signed(LINKS)

    assert verify_against_anchor(LINKS, anchor, authorities=_local(signer)) == ()
    assert not anchor.is_externally_held


# --- The store ---------------------------------------------------------------


def test_the_store_refuses_an_epoch_that_does_not_advance(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """An anchor that could be replaced by an older one is one an attacker replaces with an
    older one. Refused at write time as well as read time: cheap, and it stops `retained_epoch`
    from being the only defence."""
    store = FileAnchorStore(tmp_path / "anchors.jsonl")
    signer = LocalAnchorSigner(CapabilitySigningKey.generate())

    store.publish(signer.sign(anchor_for(REVOCATION_CHAIN, LINKS, epoch=2, anchored_at=NOW)))

    with pytest.raises(AnchorEpochError):
        store.publish(
            signer.sign(anchor_for(REVOCATION_CHAIN, LINKS[:2], epoch=1, anchored_at=NOW))
        )
    with pytest.raises(AnchorEpochError):  # equal is not advancing either
        store.publish(signer.sign(anchor_for(REVOCATION_CHAIN, LINKS, epoch=2, anchored_at=NOW)))

    latest = store.latest(REVOCATION_CHAIN)
    assert latest is not None and latest.epoch == 2


def test_the_store_answers_none_for_a_chain_nobody_anchored(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = FileAnchorStore(tmp_path / "anchors.jsonl")
    assert store.latest(REVOCATION_CHAIN) is None


def test_the_digest_binds_order_not_just_membership() -> None:
    """Two chains holding the same links in a different sequence are different histories. A
    fold that could not tell them apart would accept a reordering as intact — and reordering is
    exactly what a rewrite produces."""
    assert chain_digest(LINKS) != chain_digest(tuple(reversed(LINKS)))
    assert chain_digest(LINKS) == chain_digest(LINKS)
    # And the separator matters: without it, ("ab","c") and ("a","bc") would fold alike.
    assert chain_digest(("ab", "c")) != chain_digest(("a", "bc"))


# --- End to end, against the real store --------------------------------------


def test_the_real_revocation_chain_truncation_is_caught_when_anchored(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """THE PROOF THAT THIS IS A CONTROL AND NOT A MODULE.

    Everything above exercises the anchor against synthetic link lists. This runs the attack
    that `test_deleting_the_newest_revocation_is_currently_invisible` records as invisible —
    on the real `SqliteAuthorizationStore`, through the real gateway — and shows the two checks
    disagreeing, which is the entire point:

    * `store.verify_chain()` reports the truncated store sound. That is not a bug and the
      marker on that test stays: a chain cannot notice records that are no longer in it.
    * `verify_against_anchor()` reports it as records removed after anchoring, because the
      anchor remembers a length the chain cannot.

    What makes the second possible is memory the attacker did not rewrite. Here that memory is
    a file beside the database, which the same attacker could delete — so this proves the
    *mechanism*, and the placement remains the security argument.
    """
    import sqlite3
    from contextlib import closing
    from datetime import timedelta

    from nemesis.authz.store import SqliteAuthorizationStore
    from nemesis.core.authorization import Revocation
    from nemesis.core.ids import IdPrefix, new_id

    store = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")
    for index in range(3):
        tip = store.tip()
        store.record(
            Revocation(
                sequence=tip.sequence,
                previous_hash=tip.hash,
                capability_id=new_id(IdPrefix.CAPABILITY),
                revoked_at=NOW + timedelta(hours=index),
                revoked_by=new_id(IdPrefix.ACTOR),
                reason=f"withdrawal {index}",
            )
        )

    anchors = FileAnchorStore(tmp_path / "anchors.jsonl")
    signer = LocalAnchorSigner(CapabilitySigningKey.generate())
    links = tuple(r.chain_hash() for r in store.revocations())
    published = anchors.publish(
        signer.sign(anchor_for(REVOCATION_CHAIN, links, epoch=1, anchored_at=NOW))
    )
    assert verify_against_anchor(links, published, authorities=_local(signer)) == ()

    with closing(sqlite3.connect(store.path)) as connection, connection:
        connection.execute("DELETE FROM revocations WHERE sequence = 2")

    after = tuple(r.chain_hash() for r in store.revocations())
    assert len(after) == 2, "the attack did not actually remove a record"

    defects = verify_against_anchor(
        after, anchors.latest(REVOCATION_CHAIN), authorities=_local(signer)
    )
    assert defects, "the anchored check missed a deletion it was built to catch"
    assert any("removed after it was anchored" in d for d in defects)


# --- The gap: lying at signing time, not tampering afterwards ----------------


def test_a_third_party_anchor_really_signed_by_the_local_signer_is_refused() -> None:
    """THE TEST THIS FILE WAS MISSING, and the reason the ceiling exists.

    The guard that shipped first caught *promotion after signing*: edit the rung, and the
    signature no longer covers what the anchor says. It never looked at the cheaper attack —
    asking for the rung **before** signing, so the signature covers it perfectly.

    An external reviewer ran exactly that and got `authority: nemesis`,
    `independence: third_party`, `is_externally_held: True`, and no defects. Nothing was
    tampered with; nobody needed to. The signer simply signed what it was asked to, while its
    own docstring claimed it was "structurally unable to pose as" an external attestation.

    A signer cannot be the thing that limits what it signs. The refusal belongs in the
    deployment's registry, which is where an issuer's assurance ceiling lives for the same
    reason.
    """
    signer = LocalAnchorSigner(CapabilitySigningKey.generate())

    lied = signer.sign(
        anchor_for(
            REVOCATION_CHAIN,
            LINKS,
            epoch=1,
            anchored_at=NOW,
            independence=AnchorIndependence.THIRD_PARTY,
        )
    )

    # The signature is genuine — this is not a forgery, and checking it alone passes.
    assert lied.independence is AnchorIndependence.THIRD_PARTY
    assert lied.is_externally_held
    assert signer.verifying_key.verify(lied.signing_payload(), lied.signature or "")

    defects = verify_against_anchor(LINKS, lied, authorities=_local(signer))

    assert defects, "a local key minted a third-party attestation and nothing objected"
    assert any("claiming a rung it was never granted" in d for d in defects)


def test_the_local_authority_cannot_be_registered_above_none() -> None:
    """The other half: closing the ceiling in the verifier is worthless if a deployment can
    simply register itself higher.

    Refused at construction, because there is no honest configuration in which our own key
    attests to a distance from ourselves.
    """
    signer = LocalAnchorSigner(CapabilitySigningKey.generate())

    for rung in (
        AnchorIndependence.SEPARATE_ACCOUNT,
        AnchorIndependence.SEPARATE_HOST,
        AnchorIndependence.THIRD_PARTY,
    ):
        with pytest.raises(ValueError, match="cannot be registered above"):
            RegisteredAnchorAuthority(
                name="nemesis", verifier=signer.verifying_key, independence_ceiling=rung
            )

    # A genuinely separate authority may hold a higher ceiling — the ladder is not a ban. Its
    # key is a DIFFERENT key, and that matters: the first version of this test pointed the
    # notary's name at the local signer's own key, which demonstrated the contract while
    # proving nothing about independence. A reviewer caught it.
    notary_key = CapabilitySigningKey.generate().verifying_key
    notary = RegisteredAnchorAuthority(
        name="an-rfc3161-notary",
        verifier=notary_key,
        independence_ceiling=AnchorIndependence.THIRD_PARTY,
    )
    assert notary.independence_ceiling is AnchorIndependence.THIRD_PARTY

    # And even this proves only that the *contract* holds. Whether that key really belongs to
    # a notary is decided by how it reached the deployment, which no test here can establish.
    # `THIRD_PARTY` is evidence only when its key is pinned from a boundary the operator does
    # not control — a deployment limit, stated rather than implied by a passing assertion.


def test_an_anchor_from_an_unregistered_authority_attests_nothing() -> None:
    """Naming an authority nobody registered is the way around a ceiling that only checks
    registered ones. An anchor from a party this deployment never vouched for is refused
    whoever signed it."""
    signer = LocalAnchorSigner(CapabilitySigningKey.generate())
    stranger = signer.sign(anchor_for(REVOCATION_CHAIN, LINKS, epoch=1, anchored_at=NOW))
    stranger = stranger.model_copy(update={"authority": "a-notary-nobody-registered"})

    defects = verify_against_anchor(LINKS, stranger, authorities=_local(signer))

    assert any("has not registered" in d for d in defects)


def test_the_store_refuses_an_anchor_that_misstates_its_placement(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Declared placement and published claim must agree, or the field records what somebody
    hoped rather than where the file is."""
    beside_the_database = FileAnchorStore(
        tmp_path / "anchors.jsonl", independence=AnchorIndependence.NONE
    )
    signer = LocalAnchorSigner(CapabilitySigningKey.generate())

    with pytest.raises(AnchorPlacementError):
        beside_the_database.publish(
            signer.sign(
                anchor_for(
                    REVOCATION_CHAIN,
                    LINKS,
                    epoch=1,
                    anchored_at=NOW,
                    independence=AnchorIndependence.SEPARATE_ACCOUNT,
                )
            )
        )

    # The matching rung publishes normally.
    published = beside_the_database.publish(
        signer.sign(anchor_for(REVOCATION_CHAIN, LINKS, epoch=1, anchored_at=NOW))
    )
    assert published.independence is AnchorIndependence.NONE


def test_one_key_cannot_hold_two_authority_names() -> None:
    """The misconfiguration that looks correct, and that this file itself shipped.

    A registry mapping `an-rfc3161-notary` to a key the operator already holds as `nemesis`
    grants one signer two ceilings, and the higher one wins by accident. That is precisely how
    a locally held key comes to attest third-party independence — no tampering, no forgery,
    just a plausible line of configuration.

    What a registry can check is that two names are not one key. What it cannot check is
    whether the key behind a name belongs to the party the name claims: that is settled by how
    the key reached the deployment. The rung is only ever as good as its key's provenance.
    """
    ours = LocalAnchorSigner(CapabilitySigningKey.generate())
    theirs = CapabilitySigningKey.generate().verifying_key

    with pytest.raises(AnchorRegistryError, match="same key"):
        registered_authorities(
            local_anchor_authority(ours.verifying_key),
            RegisteredAnchorAuthority(
                name="an-rfc3161-notary",
                verifier=ours.verifying_key,  # our key, their name
                independence_ceiling=AnchorIndependence.THIRD_PARTY,
            ),
        )

    # Distinct keys register cleanly — the check refuses a collision, not a ladder.
    accepted = registered_authorities(
        local_anchor_authority(ours.verifying_key),
        RegisteredAnchorAuthority(
            name="an-rfc3161-notary",
            verifier=theirs,
            independence_ceiling=AnchorIndependence.THIRD_PARTY,
        ),
    )
    assert len(accepted) == 2
