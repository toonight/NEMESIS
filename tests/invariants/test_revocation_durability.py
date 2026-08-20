"""Revocation is the one control that cannot be answered offline, so it must be answerable.

A capability is signed, verifiable without a network, and deliberately unaffected by being
withdrawn — that last part is what keeps a revoked grant distinguishable from a forged one.
The whole weight of "this authority has been taken back" therefore rests on one question
asked of one oracle, immediately before acting.

An in-memory oracle answers for one process and forgets on restart. Four reviews recorded
that as residual risk in the same words, and ADR-0007 made it concrete by moving the Effects
plane into a child process. These tests cover the three properties a revocation store has to
have, and the third is the one that is easy to get wrong:

1. It survives a restart.
2. It is visible to another process.
3. **It fails closed.** An oracle that cannot answer must raise, and every caller must turn
   that into a refusal — never into "no revocation found".
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from nemesis.authz.attestation import PrincipalVerifier
from nemesis.authz.gateway import AuthorizationGateway
from nemesis.authz.keys import CapabilitySigningKey
from nemesis.authz.providers import LocalDevelopmentIdentityProvider
from nemesis.authz.store import AuthorizationStoreError, SqliteAuthorizationStore
from nemesis.core.authorization import (
    AuthorizationCapability,
    LegalBasis,
    OperationClass,
    Revocation,
    TargetFingerprint,
)
from nemesis.core.identity import Role
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.temporal import utcnow
from nemesis.effects.registry import default_registry
from nemesis.ports.authorization import CapabilityVerifier, RevocationLedger, RevocationOracle
from nemesis.ports.effects import EffectOutcome, EffectRequest

pytestmark = pytest.mark.invariant

DEV = LocalDevelopmentIdentityProvider()
ACTORS = PrincipalVerifier(DEV.registered_issuer())


def _target() -> TargetFingerprint:
    return TargetFingerprint.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type="domain",
        natural_key="glass-anvil.example",
        bound_attributes={"resolves_to": "198.51.100.23"},
    )


def _issued(
    store: SqliteAuthorizationStore,
    signer: CapabilitySigningKey | None = None,
    *,
    gateway_signer: AuthorizationGateway | None = None,
) -> tuple[AuthorizationGateway, AuthorizationCapability, TargetFingerprint]:
    """``gateway_signer`` reuses an existing gateway, so several capabilities share one key.

    A revocation chain is verified against one authority's key, and a test that minted a new
    key per capability would be checking that four unrelated authorities disagree.
    """
    gateway = gateway_signer or AuthorizationGateway(
        signer or CapabilitySigningKey.generate(), identity=ACTORS, revocations=store
    )
    target = _target()
    request = gateway.request(
        case_id=new_id(IdPrefix.CASE),
        audit_id=new_id(IdPrefix.AUDIT),
        requested_by=DEV.enrol("Grace", Role.ANALYST),
        justification="Rehearse the takedown.",
        targets=(target,),
        operations=frozenset({OperationClass.SIMULATION}),
        jurisdictions=("FR",),
        legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
        max_effect_description="A rehearsal that performs nothing.",
        lifetime=timedelta(hours=1),
    )
    gateway.approve(
        request.capability_id,
        approver=DEV.enrol("Ada", Role.INVESTIGATION_LEAD),
        rationale="Performs nothing.",
    )
    return gateway, gateway.issue(request.capability_id), target


def _request(target: TargetFingerprint) -> EffectRequest:
    return EffectRequest(
        operation_id=new_id(IdPrefix.OPERATION),
        operation=OperationClass.SIMULATION,
        target_fingerprint=target.fingerprint,
        target_natural_key=target.natural_key,
        current_target_attributes=dict(target.bound_attributes),
        parameters={},
        requested_by=new_id(IdPrefix.ACTOR),
        requested_at=utcnow(),
    )


# --- 1. It survives a restart -------------------------------------------------


def test_a_revocation_outlives_the_process_that_recorded_it(tmp_path: Path) -> None:
    """The in-memory registry forgot every withdrawal on restart.

    Which means a capability revoked at 09:00 was usable again after a deploy at 09:05, for
    as long as its expiry allowed. Short lifetimes bounded the damage; they did not make it
    correct.
    """
    store = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")
    gateway, capability, _ = _issued(store)
    gateway.revoke(
        capability.capability_id, "ownership disputed", revoked_by=new_id(IdPrefix.ACTOR)
    )

    # A new process would build a new store object over the same file. This is that.
    reopened = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")
    assert reopened.is_revoked(capability.capability_id)

    withdrawal = reopened.revocation(capability.capability_id)
    assert withdrawal is not None
    assert withdrawal.reason == "ownership disputed"


def test_the_earliest_revocation_wins_even_when_recorded_second(tmp_path: Path) -> None:
    """Re-revoking must not move the effective time later.

    If it could, a second revocation would be a way to *narrow* the window in which the
    first applied, and an operation performed in between would retroactively look
    authorized.

    Decided when the store is *read* rather than by editing the row already there. It used to
    be an upsert whose `WHERE` clause discarded the later write — which made earliest-wins a
    property of a mutation, in a table that is hash-chained and therefore must not mutate. The
    guarantee is unchanged; both withdrawals are now on the record and the earliest governs.
    """
    store = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")
    capability_id = new_id(IdPrefix.CAPABILITY)
    early = utcnow() - timedelta(hours=2)

    def append(moment: datetime, reason: str) -> Revocation:
        """Read the tip, then build — the store's contract, and what the gateway does. The
        sequence is part of what a caller signs, so it cannot be assigned after the fact."""
        tip = store.tip()
        return store.record(
            Revocation(
                sequence=tip.sequence,
                previous_hash=tip.hash,
                capability_id=capability_id,
                revoked_at=moment,
                revoked_by=new_id(IdPrefix.ACTOR),
                reason=reason,
            )
        )

    append(early, "first, and earliest")
    kept = append(utcnow(), "later, and must not win")

    assert kept.revoked_at == early
    assert kept.reason == "first, and earliest"
    stored = store.revocation(capability_id)
    assert stored is not None and stored.revoked_at == early
    # Both are on the record: an append-only chain does not lose the second attempt, it
    # declines to let it govern.
    assert len(store.revocations()) == 2


# --- 2. It is visible to another process --------------------------------------


def test_another_process_sees_the_revocation(tmp_path: Path) -> None:
    """The property the in-memory registry could never have.

    ADR-0007 put the Effects plane in a child process. The child is handed the parent's
    answer rather than the store — a worker that could reach the revocation store could
    reach the network — so what this test proves is the deployment-level property: two
    processes over one file agree.
    """
    path = tmp_path / "authz.sqlite3"
    store = SqliteAuthorizationStore(path)
    capability_id = new_id(IdPrefix.CAPABILITY)
    store.record(
        Revocation(
            capability_id=capability_id,
            revoked_at=utcnow(),
            revoked_by=new_id(IdPrefix.ACTOR),
            reason="withdrawn by the issuing authority",
        )
    )

    probe = subprocess.run(  # noqa: S603 - fixed command, no shell
        [
            sys.executable,
            "-c",
            "import sys\n"
            "from nemesis.authz.store import SqliteAuthorizationStore\n"
            f"store = SqliteAuthorizationStore({str(path)!r})\n"
            f"print('REVOKED' if store.is_revoked({capability_id!r}) else 'NOT REVOKED')\n",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert probe.stdout.strip() == "REVOKED", probe.stdout + probe.stderr


# --- 3. It fails closed -------------------------------------------------------


def test_an_unreadable_store_raises_rather_than_answering(tmp_path: Path) -> None:
    """The port says an implementation that cannot answer must raise. This is that clause."""
    path = tmp_path / "authz.sqlite3"
    store = SqliteAuthorizationStore(path)
    path.write_bytes(b"this is not a database")

    with pytest.raises(AuthorizationStoreError, match="could not be consulted"):
        store.is_revoked(new_id(IdPrefix.CAPABILITY))


@pytest.mark.anyio
async def test_a_store_that_cannot_answer_becomes_a_refusal_not_a_permission(
    tmp_path: Path,
) -> None:
    """End to end, because the failure direction is only worth anything if callers honour it.

    The Effects plane catches every exception from the oracle and refuses. A store that
    raised into a caller that shrugged would be a store that fails open with extra steps.
    """
    path = tmp_path / "authz.sqlite3"
    store = SqliteAuthorizationStore(path)
    gateway, capability, target = _issued(store)

    registry = default_registry(verifying_key=gateway.verifying_key, revocations=store)
    before = await registry.execute(_request(target), capability)
    assert before.outcome is EffectOutcome.SIMULATED

    path.write_bytes(b"corrupted between one operation and the next")
    after = await registry.execute(_request(target), capability)

    assert after.outcome is EffectOutcome.REFUSED_REVOKED
    assert "could not be consulted" in after.detail
    assert not after.authorization.permitted


def test_a_store_written_by_a_different_schema_is_refused(tmp_path: Path) -> None:
    """Reading rows under a different understanding of what they mean is not reading them."""
    path = tmp_path / "authz.sqlite3"
    SqliteAuthorizationStore(path)
    # `with sqlite3.connect(...)` is a *transaction* context manager and does not close the
    # connection — a distinction that leaks a handle and that this suite catches, because
    # warnings are errors here.
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("UPDATE schema_version SET version = 99")
        connection.commit()

    with pytest.raises(AuthorizationStoreError, match="schema version 99"):
        SqliteAuthorizationStore(path)


# --- The approval chain survives too ------------------------------------------


def test_the_approval_chain_is_recoverable_after_a_restart(tmp_path: Path) -> None:
    """What was requested, who decided, and what was issued — all readable afterwards.

    Not merely convenient: invariant 11 wants meaningful actions replayable, and an approval
    chain that exists only in one process's memory is replayable exactly until that process
    exits.
    """
    store = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")
    gateway, capability, _ = _issued(store)

    status = gateway.status(capability.capability_id)
    store.save_request(status.request)
    for decision in status.decisions:
        store.save_decision(capability.capability_id, decision)
    store.save_capability(capability)

    reopened = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")
    assert [r.capability_id for r in reopened.requests()] == [capability.capability_id]
    assert [c.capability_id for c in reopened.capabilities()] == [capability.capability_id]

    decisions = reopened.decisions(capability.capability_id)
    assert len(decisions) == 1
    assert decisions[0].approver_roles == frozenset({Role.INVESTIGATION_LEAD})

    # And the recovered capability is still the one that was signed: storage is not a place
    # where a grant quietly becomes trustworthy.
    recovered = reopened.capabilities()[0]
    assert recovered.signing_payload() == capability.signing_payload()
    assert recovered.signature == capability.signature


def test_one_approver_cannot_become_two_by_deciding_twice(tmp_path: Path) -> None:
    """Dual control expressed as a primary key.

    The gateway already refuses a duplicate approver. A storage layer that *could* represent
    the same person twice would be one a future gateway bug could exploit, so the schema
    cannot hold it either.
    """
    store = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")
    gateway, capability, _ = _issued(store)
    approval = gateway.status(capability.capability_id).decisions[0]

    store.save_decision(capability.capability_id, approval)
    store.save_decision(
        capability.capability_id, approval.model_copy(update={"rationale": "and again"})
    )

    assert len(store.decisions(capability.capability_id)) == 1


# --- What the store is, and is not --------------------------------------------


def test_the_store_satisfies_both_halves_of_the_port(tmp_path: Path) -> None:
    """The Effects plane gets the read half; only the gateway gets the ledger."""
    store = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")
    assert isinstance(store, RevocationOracle)
    assert isinstance(store, RevocationLedger)


def test_recording_a_revocation_is_still_unauthenticated(tmp_path: Path) -> None:
    """Stated as a test so nobody reads durability as authentication.

    Anyone who can write to the file can withdraw any capability. Persisting the list moves
    it from somewhere that evaporates to somewhere an attacker could find, and changes
    nothing about who may add to it. Recorded as an open gap in the threat model.
    """
    store = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")
    nobody_in_particular = new_id(IdPrefix.ACTOR)

    store.record(
        Revocation(
            capability_id=new_id(IdPrefix.CAPABILITY),
            revoked_at=utcnow(),
            revoked_by=nobody_in_particular,
            reason="no credential was checked to write this row",
        )
    )
    assert len(store.revocations()) == 1


# --- Round four: two defects a review found in this store ----------------------


def test_earliest_wins_survives_a_timestamp_from_another_timezone(tmp_path: Path) -> None:
    """The store orders by ISO-8601 text, which is only correct on UTC-normalised values.

    `revoked_at` accepted a `+02:00` offset and a naive datetime, so a withdrawal recorded
    as 12:00+02:00 — ten o'clock, and *earlier* — compared as later and was discarded. That
    is exactly the failure earliest-wins exists to prevent: a second revocation must not be
    able to narrow the window the first applied to.
    """
    from datetime import timezone

    store = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")
    capability_id = new_id(IdPrefix.CAPABILITY)
    east = timezone(timedelta(hours=2))

    # Each link is appended at the tip, which is the store's contract — the sequence is part
    # of what a real caller signs, so it is read before building rather than assigned by the
    # store afterwards. This test used to leave both at the default and rely on the second
    # row *overwriting* the first; the table is append-only now, and the property it checks is
    # unchanged: which withdrawal governs is decided by time, not by arrival order.
    first = store.tip()
    store.record(
        Revocation(
            sequence=first.sequence,
            previous_hash=first.hash,
            capability_id=capability_id,
            revoked_at=datetime(2026, 8, 16, 11, 0, tzinfo=UTC),
            revoked_by=new_id(IdPrefix.ACTOR),
            reason="recorded first, at 11:00Z",
        )
    )
    second = store.tip()
    kept = store.record(
        Revocation(
            sequence=second.sequence,
            previous_hash=second.hash,
            capability_id=capability_id,
            revoked_at=datetime(2026, 8, 16, 12, 0, tzinfo=east),
            revoked_by=new_id(IdPrefix.ACTOR),
            reason="recorded second, at 10:00Z — earlier, and must win",
        )
    )

    assert "must win" in kept.reason
    assert "must win" in (store.revocation(capability_id) or kept).reason, (
        "the governing withdrawal must be the earliest one on every read, not only on the "
        "write that happened to notice"
    )


def test_a_naive_revocation_timestamp_is_refused(tmp_path: Path) -> None:
    """A naive datetime has no defined position in an ordering the store depends on."""
    with pytest.raises(ValidationError, match="timezone-aware"):
        Revocation(
            capability_id=new_id(IdPrefix.CAPABILITY),
            revoked_at=datetime(2026, 8, 16, 9, 0),  # noqa: DTZ001 - naive on purpose
            revoked_by=new_id(IdPrefix.ACTOR),
            reason="no timezone",
        )


def test_a_store_whose_tables_were_removed_is_not_silently_repaired(tmp_path: Path) -> None:
    """`CREATE TABLE IF NOT EXISTS` on every open turned tampering into an empty list.

    Renaming the revocations table away and reopening answered "not revoked" for every
    capability, with no error and no trace. This is inside the documented "we do not
    authenticate revocation" gap and still the wrong direction: tampering must look like
    tampering.
    """
    import sqlite3
    from contextlib import closing

    path = tmp_path / "authz.sqlite3"
    store = SqliteAuthorizationStore(path)
    capability_id = new_id(IdPrefix.CAPABILITY)
    store.record(
        Revocation(
            capability_id=capability_id,
            revoked_at=utcnow(),
            revoked_by=new_id(IdPrefix.ACTOR),
            reason="withdrawn",
        )
    )

    with closing(sqlite3.connect(path)) as connection:
        connection.execute("ALTER TABLE revocations RENAME TO hidden")
        connection.commit()

    with pytest.raises(AuthorizationStoreError):
        SqliteAuthorizationStore(path).is_revoked(capability_id)


# --- Authenticated, and chained -------------------------------------------------
#
# Two different attacks, two different defences, and conflating them defends against
# neither. Forgery is stopped by a signature. Suppression is not — an attacker who can
# add a row can remove one — and that is what the chain is for.


def _verifier(gateway: AuthorizationGateway) -> CapabilityVerifier:
    return gateway.verifying_key


def test_a_revocation_the_gateway_did_not_mint_is_detected(tmp_path: Path) -> None:
    """Forging a withdrawal is a denial of service on lawful action.

    Anyone who could write the store could previously withdraw any capability, and nothing
    downstream could tell that from a decision the gateway had reached.
    """
    store = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")
    gateway, capability, _ = _issued(store)
    gateway.revoke(
        capability.capability_id, "genuine withdrawal", revoked_by=new_id(IdPrefix.ACTOR)
    )

    assert store.verify_chain(_verifier(gateway)) == ()

    # Somebody with file access adds one of their own.
    store.record(
        Revocation(
            capability_id=new_id(IdPrefix.CAPABILITY),
            revoked_at=utcnow(),
            revoked_by=new_id(IdPrefix.ACTOR),
            reason="a withdrawal nobody authorized",
            sequence=store.tip().sequence,
            previous_hash=store.tip().hash,
        )
    )

    defects = store.verify_chain(_verifier(gateway))
    assert any("not signed by the issuing authority" in d for d in defects)


def test_deleting_a_revocation_breaks_the_chain(tmp_path: Path) -> None:
    """The attack a signature does nothing about, and the more dangerous of the two.

    Removing a withdrawal makes a revoked capability work again. Without a chain, the store
    is a set of independent rows and a deletion leaves nothing behind — a reader cannot tell
    it from a capability that was never revoked.
    """
    import sqlite3
    from contextlib import closing

    path = tmp_path / "authz.sqlite3"
    store = SqliteAuthorizationStore(path)
    gateway, first, _ = _issued(store)
    gateway.revoke(first.capability_id, "the first withdrawal", revoked_by=new_id(IdPrefix.ACTOR))

    second_gateway, second, _ = _issued(store, gateway_signer=gateway)
    second_gateway.revoke(second.capability_id, "the second", revoked_by=new_id(IdPrefix.ACTOR))
    assert store.verify_chain(_verifier(gateway)) == ()

    with closing(sqlite3.connect(path)) as connection:
        connection.execute("DELETE FROM revocations WHERE sequence = 0")
        connection.commit()

    defects = store.verify_chain(_verifier(gateway))
    assert defects, "a deleted withdrawal must not be invisible"
    assert any("deleted from this store" in d or "removed or reordered" in d for d in defects)


def test_a_genuine_chain_verifies(tmp_path: Path) -> None:
    """The counterpart. A check that always fails is an outage, not a control."""
    store = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")
    gateway, capability, _ = _issued(store)
    for reason in ("first", "second", "third"):
        _, other, _ = _issued(store, gateway_signer=gateway)
        gateway.revoke(other.capability_id, reason, revoked_by=new_id(IdPrefix.ACTOR))
    gateway.revoke(capability.capability_id, "withdrawn", revoked_by=new_id(IdPrefix.ACTOR))

    assert store.verify_chain(_verifier(gateway)) == ()
    assert len(store.revocations()) == 4


# --- The earliest-wins path must not break the chain it lives in --------------

CHAIN_NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
"""A fixed instant for the chain tests, so "earlier" and "later" are unambiguous rather
than relative to a wall clock that moves while the test runs."""


def test_an_earliest_wins_re_revocation_leaves_the_chain_sound(tmp_path: Path) -> None:
    """THE ONE THIS SECTION EXISTS FOR — found by an adversarial review, verified here.

    Re-revoking with an earlier timestamp is a *supported* path: `revoke(revoked_at=...)`
    exists for it, and two processes with any clock skew produce it unaided. The SQL that
    implements it refreshed `revoked_at/revoked_by/reason/record` and left `sequence` and
    `chain_hash` at their old values — so the stored JSON described one position while the
    columns described another.

    The consequence is not a wrong authorization decision: `is_revoked` stays true and the
    withdrawal still bites. It is worse in a slower way. The control whose entire job is to
    make a *deletion* visible starts reporting deletions that never happened, permanently and
    on a store from which nothing was removed — and a tamper-evidence signal that cries wolf
    is one nobody reads on the day it is right.
    """
    store = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")
    gateway, first, _ = _issued(store)
    _, second, _ = _issued(store, gateway_signer=gateway)

    gateway.revoke(
        first.capability_id, "withdrawn", revoked_by=new_id(IdPrefix.ACTOR), revoked_at=CHAIN_NOW
    )
    gateway.revoke(
        second.capability_id,
        "withdrawn",
        revoked_by=new_id(IdPrefix.ACTOR),
        revoked_at=CHAIN_NOW + timedelta(hours=1),
    )
    assert store.verify_chain(_verifier(gateway)) == (), "the chain was not sound to begin with"

    # The supported path: the same capability, withdrawn again, effective earlier.
    gateway.revoke(
        first.capability_id,
        "the withdrawal was actually effective an hour earlier",
        revoked_by=new_id(IdPrefix.ACTOR),
        revoked_at=CHAIN_NOW - timedelta(hours=1),
    )

    assert store.is_revoked(first.capability_id), "the withdrawal must still bite"
    assert store.verify_chain(_verifier(gateway)) == (), (
        "an ordinary earliest-wins re-revocation reported tampering on a store nobody tampered with"
    )


def test_the_chain_survives_an_ordinary_revocation_after_a_re_revocation(tmp_path: Path) -> None:
    """The damage was persistent, not transient: a stale `sequence` column left `tip()`
    handing the next revocation a position already taken, so the next perfectly ordinary
    withdrawal inherited the break."""
    store = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")
    gateway, first, _ = _issued(store)
    _, second, _ = _issued(store, gateway_signer=gateway)
    _, third, _ = _issued(store, gateway_signer=gateway)

    gateway.revoke(
        first.capability_id, "one", revoked_by=new_id(IdPrefix.ACTOR), revoked_at=CHAIN_NOW
    )
    gateway.revoke(
        second.capability_id,
        "two",
        revoked_by=new_id(IdPrefix.ACTOR),
        revoked_at=CHAIN_NOW + timedelta(hours=1),
    )
    gateway.revoke(
        first.capability_id,
        "earlier after all",
        revoked_by=new_id(IdPrefix.ACTOR),
        revoked_at=CHAIN_NOW - timedelta(hours=1),
    )
    gateway.revoke(
        third.capability_id,
        "three",
        revoked_by=new_id(IdPrefix.ACTOR),
        revoked_at=CHAIN_NOW + timedelta(hours=2),
    )

    assert store.verify_chain(_verifier(gateway)) == ()
    assert len({r.sequence for r in store.revocations()}) == len(store.revocations()), (
        "two revocations claim the same position in the chain"
    )


def test_a_later_re_revocation_still_changes_nothing_at_all(tmp_path: Path) -> None:
    """The other half of earliest-wins, asserted so the fix cannot be a blanket overwrite.

    A *later* re-revocation must not move the effective time, and must not renumber the chain
    either — a fix that simply refreshed every column on conflict would pass the tests above
    and quietly destroy the property those tests exist alongside.
    """
    store = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")
    gateway, capability, _ = _issued(store)

    gateway.revoke(
        capability.capability_id, "first", revoked_by=new_id(IdPrefix.ACTOR), revoked_at=CHAIN_NOW
    )
    governing = store.revocation(capability.capability_id)

    gateway.revoke(
        capability.capability_id,
        "second, later",
        revoked_by=new_id(IdPrefix.ACTOR),
        revoked_at=CHAIN_NOW + timedelta(hours=1),
    )

    # The chain grew — it is append-only, and a second withdrawal is a real event the record
    # should not lose. What must not change is which withdrawal *governs*.
    assert len(store.revocations()) == 2
    still = store.revocation(capability.capability_id)
    assert still is not None and governing is not None
    assert still.model_dump_json() == governing.model_dump_json(), (
        "a later re-revocation moved the effective time; it could then narrow the window the "
        "first applied to, and an operation performed in between would look authorized"
    )
    assert still.revoked_at == CHAIN_NOW
    assert store.verify_chain(_verifier(gateway)) == ()


# --- The tail is where a hash chain cannot see -------------------------------


def _permissive() -> CapabilityVerifier:
    """A verifier that accepts every signature, so these tests measure the CHAIN alone."""

    class Anything:
        def verify(self, payload: bytes, signature: str) -> bool:
            return True

    return cast(CapabilityVerifier, Anything())


@pytest.mark.xfail(
    strict=True,
    reason="tail truncation needs an external anchor; PROPOSED, not built. Remove this "
    "marker the day it is — a strict xfail turns red when the gap closes.",
)
def test_deleting_the_newest_revocation_is_currently_invisible(tmp_path: Path) -> None:
    """A KNOWN, MEASURED GAP — marked xfail so it turns red the day it is closed.

    Verification walks rows in order and checks each link against the one before it. That
    catches an *interior* deletion, because the row after the hole no longer follows. It cannot
    catch a deletion at the **tail**: nothing comes after, so nothing fails to follow, and
    truncating a chain is indistinguishable from a chain that was never that long.

    Measured, not reasoned: three revocations, delete the newest, `verify_chain` returns no
    defects and `is_revoked` for that capability goes back to False. A withdrawn authority is
    silently restored while the tamper-evidence control certifies the store as intact. Emptying
    the table entirely also verifies clean.

    **Not fixable from inside the store.** Any in-table marker — a count row, a sentinel, a
    genesis binding — is deletable by the same write access that deleted the tail. Detecting
    the loss of the most recent state needs memory the attacker cannot reach: a signed tip held
    on the far side of a trust boundary, carrying a monotonic epoch so an older valid tip cannot
    simply be replayed in its place. That is the same external anchor `nemesis.evidence.
    anchoring` already marks `PROPOSED` for the vault, and the same limitation — this chain
    simply had not admitted to it.

    **Why this is urgent rather than merely open:** once a later write reoccupies the freed
    sequence, its `previous_hash` links to the truncated tail and the whole chain validates end
    to end. Truncation followed by a write is a history *rewrite*, and no anchor retrofitted
    afterwards can recover what was there.
    """
    store = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")
    ids = []
    for index in range(3):
        tip = store.tip()
        capability_id = new_id(IdPrefix.CAPABILITY)
        ids.append(capability_id)
        store.record(
            Revocation(
                sequence=tip.sequence,
                previous_hash=tip.hash,
                capability_id=capability_id,
                revoked_at=CHAIN_NOW + timedelta(hours=index),
                revoked_by=new_id(IdPrefix.ACTOR),
                reason=f"withdrawal {index}",
            )
        )
    assert store.verify_chain(_permissive()) == ()
    assert store.is_revoked(ids[2])

    with closing(sqlite3.connect(store.path)) as connection, connection:
        connection.execute("DELETE FROM revocations WHERE sequence = 2")

    assert not store.is_revoked(ids[2]), "the withdrawal is gone — that part is not in doubt"
    assert store.verify_chain(_permissive()) != (), (
        "a withdrawal was deleted and the chain reported itself sound"
    )


def test_truncate_then_reoccupy_is_a_history_rewrite_that_validates(tmp_path: Path) -> None:
    """The attack the earlier test does NOT cover, and the sharper one.

    Deleting the tail and stopping leaves a short chain. Deleting the tail and then letting the
    system *run normally* is different in kind: the next legitimate withdrawal is signed by the
    real gateway and chains onto the truncated tail, so the table becomes fully self-consistent
    again — every signature valid, every link following, sequence contiguous. The deleted
    withdrawals are not merely missing; the history now reads as though they never existed.

    That is why the window is "before the next write" rather than "before the next audit": no
    anchor retrofitted afterwards can recover what was there, because nothing in the store
    disagrees with anything else.

    **This test asserts what happens today, which is ACCEPT.** It is a characterisation of a
    blind spot, not a wish, and it earns its place by proving the attack harness actually
    executes a full rewrite — if verification ever *rejects* here, the harness is broken rather
    than the verifier vindicated. The detection half cannot be written until an anchor exists:
    catching this needs a pre-attack head the verifier retained, and there is nowhere on a
    single-user laptop to keep one that the modelled adversary cannot also rewrite. Recorded so
    the green bar below is never mistaken for coverage.
    """
    store = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")
    gateway, first, _ = _issued(store)
    kept = []
    for index in range(4):
        _, capability, _ = _issued(store, gateway_signer=gateway)
        kept.append(capability)
        gateway.revoke(
            capability.capability_id,
            f"withdrawal {index}",
            revoked_by=new_id(IdPrefix.ACTOR),
            revoked_at=CHAIN_NOW + timedelta(hours=index),
        )
    assert store.verify_chain(_verifier(gateway)) == ()
    before = len(store.revocations())

    # The attack: drop the two newest links, then let the platform carry on normally.
    with closing(sqlite3.connect(store.path)) as connection, connection:
        connection.execute("DELETE FROM revocations WHERE sequence >= 2")
    gateway.revoke(
        first.capability_id,
        "an ordinary withdrawal, after the tampering",
        revoked_by=new_id(IdPrefix.ACTOR),
        revoked_at=CHAIN_NOW + timedelta(hours=9),
    )

    assert len(store.revocations()) < before, "two withdrawals are gone"
    assert not store.is_revoked(kept[2].capability_id)
    assert not store.is_revoked(kept[3].capability_id)
    assert store.verify_chain(_verifier(gateway)) == (), (
        "if this now reports a defect the harness stopped reproducing the rewrite — fix the "
        "harness, do not celebrate the verifier"
    )
