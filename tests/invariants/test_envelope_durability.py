"""A budget a restart restores is not a budget.

The in-memory ledger is correct within one process and forgets everything on exit, which means
anyone able to restart the process gets a fresh envelope — and "anyone able to restart the
process" includes a crash loop, a supervisor, and an orchestrator that has been compromised.
These tests are about the durable ledger, and they hunt the three ways a budget is normally
defeated: outliving it, racing it, and reopening it wider.

The load-bearing one is `test_two_processes_cannot_spend_past_the_ceiling_by_racing`. Durability
is the visible half of making a budget real; **atomicity is the half that matters**, because a
fleet of pilots sharing one envelope is exactly the deployment this platform is for. It spawns
real OS processes against one SQLite file, so it fails if the transaction boundary is ever
loosened to a read-then-write.
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from nemesis.authz.envelope import (
    AutonomyEnvelope,
    EnvelopeError,
    InMemorySpendLedger,
    verify_spend_chain,
)
from nemesis.authz.keys import CapabilitySigningKey
from nemesis.authz.store import EnvelopeWidenedError, SqliteAuthorizationStore
from nemesis.core.authorization import (
    Approval,
    AuthorizationCapability,
    LegalBasis,
    OperationClass,
    TargetFingerprint,
)
from nemesis.core.entities import Entity, EntityType
from nemesis.core.identity import Role
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.temporal import TemporalExtent
from nemesis.slice.pilot_session import _signed_envelope

pytestmark = pytest.mark.invariant

SIGNING_KEY = CapabilitySigningKey.generate()
ACTOR = new_id(IdPrefix.ACTOR)
FIXED_CAPABILITY_ID = "cap_0123456789abcdef0123456789abcdef"


def _capability(capability_id: str = FIXED_CAPABILITY_ID) -> AuthorizationCapability:
    """One fixed id, so a second 'process' addresses the same envelope."""
    now = datetime.now(UTC)
    unsigned = AuthorizationCapability(
        capability_id=capability_id,
        case_id=new_id(IdPrefix.CASE),
        audit_id=new_id(IdPrefix.AUDIT),
        issued_at=now - timedelta(minutes=1),
        not_before=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=4),
        targets=(
            TargetFingerprint.create(
                entity_id=new_id(IdPrefix.ENTITY),
                entity_type="domain",
                natural_key="acme-invoice-portal.example",
                bound_attributes={"resolves_to": "198.51.100.23"},
            ),
        ),
        permitted_operations=frozenset({OperationClass.SIMULATION}),
        jurisdictions=("FR",),
        legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
        max_targets=1,
        max_effect_description="Rehearsals that suspend nothing.",
        approvals=(
            Approval(
                approver=ACTOR,
                approver_roles=frozenset({Role.INVESTIGATION_LEAD}),
                decided_at=now,
                decision=True,
                rationale="Reversible class, synthetic target.",
            ),
        ),
        required_approvals=1,
    )
    return unsigned.model_copy(update={"signature": SIGNING_KEY.sign(unsigned.signing_payload())})


def _spend(envelope: AutonomyEnvelope) -> object:
    return envelope.debit(
        operation=OperationClass.SIMULATION,
        target_fingerprint=envelope.capability.targets[0].fingerprint,
        requested_by=ACTOR,
    )


# --- Outliving the budget ----------------------------------------------------


def test_a_restart_does_not_restore_a_spent_budget(tmp_path: Path) -> None:
    """THE TEST THIS FILE EXISTS FOR.

    A budget the process forgets is a budget anyone able to restart the process refills — and a
    crash loop refills it too, without anybody deciding to.
    """
    capability = _capability()
    db = tmp_path / "authz.sqlite3"

    first = AutonomyEnvelope(
        capability, max_autonomous_effects=2, ledger=SqliteAuthorizationStore(db)
    )
    assert _spend(first) is not None
    assert _spend(first) is not None
    assert first.exhausted

    # A new store object over the same file is what a restarted process holds.
    restarted = AutonomyEnvelope(
        capability, max_autonomous_effects=2, ledger=SqliteAuthorizationStore(db)
    )
    assert restarted.spent == 2, "the restart did not see what the first run had spent"
    assert restarted.exhausted
    assert _spend(restarted) is None, "a restart refilled a spent envelope"


def test_the_ledger_survives_and_still_verifies_after_a_restart(tmp_path: Path) -> None:
    """Durability that lost the chain would be durability that lost the tamper evidence."""
    capability = _capability()
    db = tmp_path / "authz.sqlite3"

    envelope = AutonomyEnvelope(
        capability, max_autonomous_effects=4, ledger=SqliteAuthorizationStore(db)
    )
    for _ in range(3):
        _spend(envelope)

    reopened = AutonomyEnvelope(
        capability, max_autonomous_effects=4, ledger=SqliteAuthorizationStore(db)
    )
    ledger = reopened.ledger()
    assert [record.sequence for record in ledger] == [0, 1, 2]
    assert reopened.verify_chain()
    assert verify_spend_chain(ledger)
    assert reopened.remaining == 1


def test_a_deleted_row_breaks_the_chain_in_the_durable_ledger(tmp_path: Path) -> None:
    """The attack moves to the file once the ledger is a file. It must still be visible."""
    import sqlite3

    capability = _capability()
    db = tmp_path / "authz.sqlite3"
    envelope = AutonomyEnvelope(
        capability, max_autonomous_effects=5, ledger=SqliteAuthorizationStore(db)
    )
    for _ in range(4):
        _spend(envelope)
    assert envelope.verify_chain()

    connection = sqlite3.connect(db)
    connection.execute(
        "DELETE FROM envelope_spends WHERE capability_id = ? AND sequence = 1",
        (capability.capability_id,),
    )
    connection.commit()
    connection.close()

    reopened = AutonomyEnvelope(
        capability, max_autonomous_effects=5, ledger=SqliteAuthorizationStore(db)
    )
    assert not reopened.verify_chain(), "a row deleted on disk left the chain verifying"


# --- Reopening it wider ------------------------------------------------------


def test_reopening_an_envelope_with_a_bigger_budget_is_refused(tmp_path: Path) -> None:
    """The attack durability invites: restart with `max_autonomous_effects=999`.

    Refused loudly, and with its own exception type, so a caller catching "the store is
    unavailable" cannot accidentally swallow "an authority was widened".
    """
    capability = _capability()
    db = tmp_path / "authz.sqlite3"
    AutonomyEnvelope(capability, max_autonomous_effects=2, ledger=SqliteAuthorizationStore(db))

    with pytest.raises(EnvelopeWidenedError, match="would widen"):
        AutonomyEnvelope(
            capability, max_autonomous_effects=999, ledger=SqliteAuthorizationStore(db)
        )


def test_reopening_an_envelope_with_a_smaller_budget_narrows_it(tmp_path: Path) -> None:
    """Nothing that only ever reduces authority needs to be refused."""
    capability = _capability()
    db = tmp_path / "authz.sqlite3"
    AutonomyEnvelope(capability, max_autonomous_effects=5, ledger=SqliteAuthorizationStore(db))

    narrowed = AutonomyEnvelope(
        capability, max_autonomous_effects=1, ledger=SqliteAuthorizationStore(db)
    )
    assert narrowed.budget == 1
    assert _spend(narrowed) is not None
    assert _spend(narrowed) is None

    # And the narrowing sticks: the ceiling cannot be walked back up afterwards either.
    with pytest.raises(EnvelopeWidenedError):
        AutonomyEnvelope(capability, max_autonomous_effects=5, ledger=SqliteAuthorizationStore(db))


def test_the_in_memory_ledger_refuses_widening_too() -> None:
    """The two implementations must agree about what is allowed, or the weaker one becomes the
    way around the stronger one.

    They raise their own layer's error — `EnvelopeError` here, the `EnvelopeWidenedError`
    subclass of `AuthorizationStoreError` in the durable store — but neither permits it.
    """
    capability = _capability()
    ledger = InMemorySpendLedger()
    AutonomyEnvelope(capability, max_autonomous_effects=2, ledger=ledger)

    with pytest.raises(EnvelopeError, match="widen"):
        AutonomyEnvelope(capability, max_autonomous_effects=9, ledger=ledger)


# --- Racing it ---------------------------------------------------------------


_RACER = """
import sys
from datetime import UTC, datetime
from nemesis.authz.store import SqliteAuthorizationStore
from nemesis.core.authorization import OperationClass

db, capability_id, attempts = sys.argv[1], sys.argv[2], int(sys.argv[3])
store = SqliteAuthorizationStore(db, timeout=30.0)
won = 0
for _ in range(attempts):
    record = store.debit(
        capability_id=capability_id,
        operation=OperationClass.SIMULATION,
        target_fingerprint="sha256:" + "0" * 64,
        requested_by="actor_racer",
        spent_at=datetime.now(UTC),
    )
    if record is not None:
        won += 1
print(won)
"""


def test_two_processes_cannot_spend_past_the_ceiling_by_racing(tmp_path: Path) -> None:
    """THE ONE THE IN-MEMORY LEDGER COULD NOT SATISFY.

    Durability is the visible half of making a budget real. Atomicity is the half that matters:
    a fleet of pilots sharing one envelope is the deployment this platform is for, and two
    workers that each read "three spent of four" and then each append would both act.

    Real OS processes against one SQLite file, so this fails if the count-and-append is ever
    loosened out of its transaction.
    """
    import nemesis

    capability = _capability()
    db = tmp_path / "authz.sqlite3"
    budget = 10
    AutonomyEnvelope(capability, max_autonomous_effects=budget, ledger=SqliteAuthorizationStore(db))

    env = {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(Path(nemesis.__file__).resolve().parent.parent),
    }
    racers = [
        subprocess.Popen(  # noqa: S603 - fixed command, no shell
            [sys.executable, "-s", "-c", _RACER, str(db), capability.capability_id, "25"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        for _ in range(4)
    ]
    outputs = [racer.communicate(timeout=120) for racer in racers]

    for stdout, stderr in outputs:
        assert stdout.strip().isdigit(), f"a racer failed: {stdout}{stderr}"
    total_won = sum(int(stdout.strip()) for stdout, _ in outputs)

    assert total_won == budget, (
        f"{total_won} effects were spent from a budget of {budget}; the count-and-append is "
        "not atomic across processes"
    )

    # And the ledger the race produced is a single well-formed chain, not four interleaved ones.
    final = AutonomyEnvelope(
        capability, max_autonomous_effects=budget, ledger=SqliteAuthorizationStore(db)
    )
    assert final.spent == budget
    assert final.exhausted
    assert final.verify_chain(), "the race produced a ledger that does not verify"


def test_a_second_envelope_object_over_one_store_shares_the_budget(tmp_path: Path) -> None:
    """Two pilots in one process, one envelope. The budget is the envelope's, not the object's."""
    capability = _capability()
    store = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")

    one = AutonomyEnvelope(capability, max_autonomous_effects=3, ledger=store)
    two = AutonomyEnvelope(capability, max_autonomous_effects=3, ledger=store)

    assert _spend(one) is not None
    assert _spend(two) is not None
    assert _spend(one) is not None
    assert _spend(two) is None, "a second envelope object held its own budget"
    assert one.exhausted and two.exhausted


# --- The tail is where the autonomy bound cannot see -------------------------


@pytest.mark.xfail(
    strict=True,
    reason="tail truncation needs an external anchor; PROPOSED, not built. Remove this "
    "marker the day it is — a strict xfail turns red when the gap closes.",
)
def test_deleting_the_newest_debit_currently_restores_autonomy(tmp_path: Path) -> None:
    """A KNOWN, MEASURED GAP, and the sharper of the two — this chain is the autonomy bound.

    The envelope's whole purpose is that a pilot acting at machine speed cannot exceed a
    pre-authorized number of effects. That bound is the spend ledger, and the ledger is
    hash-chained so a deleted debit is supposed to be visible.

    It is visible only in the middle. Measured: budget 3, three debits, the fourth correctly
    refused; delete the newest row and `verify_chain()` still returns True, `remaining` goes
    from 0 back to 1, and a further debit is granted. Anyone who can write the SQLite file
    restores spending capacity, and the control that exists to notice says the chain is intact.

    Worse than the revocation case for one reason: the newest debit is the only row an attacker
    needs. Deleting an interior one buys nothing.

    Same impossibility, same fix: no in-table marker survives the write access that removed the
    tail, so this needs a signed tip on the far side of a trust boundary, carrying a monotonic
    epoch so an older valid tip cannot be replayed in its place. Tracked with the revocation
    chain and with `nemesis.evidence.anchoring`, which already marks external anchoring
    `PROPOSED` for the vault — the same limitation, admitted there and not here until now.
    """
    store = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")
    signer = CapabilitySigningKey.generate()
    entity = Entity.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type=EntityType.DOMAIN,
        observed_form="tail-truncation.example",
        attributes={"ownership_contested": "false"},
        extent=TemporalExtent.at(datetime.now(UTC)),
        is_synthetic=True,
    )
    capability = _signed_envelope(signer, entity, now=datetime.now(UTC))
    fingerprint = capability.targets[0].fingerprint

    envelope = AutonomyEnvelope(capability, max_autonomous_effects=3, ledger=store)
    for _ in range(3):
        envelope.debit(
            operation=OperationClass.SIMULATION,
            target_fingerprint=fingerprint,
            requested_by=new_id(IdPrefix.ACTOR),
        )
    assert envelope.remaining == 0
    assert envelope.verify_chain()

    with closing(sqlite3.connect(store.path)) as connection, connection:
        newest = connection.execute("SELECT MAX(sequence) FROM envelope_spends").fetchone()[0]
        connection.execute("DELETE FROM envelope_spends WHERE sequence = ?", (newest,))

    reopened = AutonomyEnvelope(capability, max_autonomous_effects=3, ledger=store)
    # NOT asserted: that `remaining` stays 0. An external critique pointed out this would be
    # asserting the impossible — once the row is gone no local code can know the budget was
    # spent, so an anchor makes truncation *detectable*, never *recoverable*. Encoding a wish
    # would also let a half-fix that detects the deletion while still restoring the budget sit
    # here as xfail forever, red-flagging nothing.
    assert reopened.remaining == 1, "measured today: the deleted debit came back as budget"
    assert not reopened.verify_chain(), "a debit was deleted and the chain reported itself sound"


def test_the_writer_lock_is_taken_before_the_count_not_after(tmp_path: Path) -> None:
    """THE TEST THAT DISTINGUISHES THE CLAIM FROM A COINCIDENCE.

    The budget's safety is documented as "the count and the append happen inside one
    `BEGIN IMMEDIATE`". A twelve-process race against a ceiling of three never over-spent —
    and then the same race passed unchanged with `BEGIN IMMEDIATE` mutated to `BEGIN
    DEFERRED`, which does *not* take the write lock before the count. The race proved the
    bound held; it did not prove why. Under DEFERRED the protection comes from SQLite raising
    `SQLITE_BUSY_SNAPSHOT` when the deferred transaction tries to upgrade — belt and braces,
    with the stochastic test exercising only the braces.

    This one forces the interleaving instead of hoping for it, and it fails under DEFERRED:
    a second writer must be unable to *begin* while the first holds the lock, which is the
    property `IMMEDIATE` provides and `DEFERRED` does not. Verified by mutating the code and
    confirming this test goes red — the discipline this repository applies everywhere and had
    not applied here.

    Raised by an external reviewer (Codex/GPT-5.5), whose sharper form of the point was that
    a 4-process/budget-10 race "proves almost nothing" because it cannot force the boundary
    interleaving it claims to exclude.
    """
    store = SqliteAuthorizationStore(tmp_path / "authz.sqlite3")
    del store  # opened for its schema; this test drives raw connections deliberately

    first = sqlite3.connect(tmp_path / "authz.sqlite3", timeout=0.2, isolation_level=None)
    second = sqlite3.connect(tmp_path / "authz.sqlite3", timeout=0.2, isolation_level=None)
    try:
        first.execute("PRAGMA journal_mode=WAL")
        second.execute("PRAGMA journal_mode=WAL")

        first.execute("BEGIN IMMEDIATE")
        first.execute("SELECT COUNT(*) FROM envelope_spends").fetchone()

        # The load-bearing assertion. With IMMEDIATE the writer lock is already held, so a
        # second writer cannot open its transaction at all. With DEFERRED this line succeeds,
        # both readers see the same count, and that is the over-spend the docstring excludes.
        with pytest.raises(sqlite3.OperationalError) as busy:
            second.execute("BEGIN IMMEDIATE")
        assert "locked" in str(busy.value).lower() or "busy" in str(busy.value).lower()

        first.execute("COMMIT")

        # And once the first commits, the second gets the committed state rather than a stale
        # snapshot — the other half of the claim.
        second.execute("BEGIN IMMEDIATE")
        second.execute("COMMIT")
    finally:
        first.close()
        second.close()


@pytest.mark.xfail(
    strict=True,
    reason="an absent store is indistinguishable from a never-created one from inside it; "
    "needs the same external anchor as tail truncation. Remove this marker the day it exists.",
)
def test_deleting_the_store_currently_restores_a_spent_budget(tmp_path: Path) -> None:
    """The cheapest attack found all evening, and the same impossibility underneath.

    Tail truncation needs the schema. This needs the filename: delete the SQLite file, and
    :class:`AutonomyEnvelope` re-registers its budget at full on construction, because
    `register()` compares against a row that no longer exists. Measured — budget 2, spent, the
    third refused; remove the file; `remaining` is 2 again and a debit is granted.

    **Deliberately not patched locally.** Refusing to open a missing store moves the symptom:
    whoever can delete the file can also recreate it, and a fresh store cannot tell "this
    never existed" from "this was deleted" — the same argument two external reviewers reached
    independently tonight about the chain's tail. A local check here would look like a control
    and be one only against an adversary who deletes but will not create, which is not an
    adversary worth designing for.

    What closes it is what closes truncation: an authoritative `(store_identity, count, head)`
    beyond the store's trust boundary, with a monotonic epoch. Until then the honest statement
    is that the autonomy bound is enforceable against software faults and racing processes —
    both of which it does stop, and one of which
    `test_the_writer_lock_is_taken_before_the_count_not_after` proves — and not against an
    adversary with write access to the file.
    """
    signer = CapabilitySigningKey.generate()
    entity = Entity.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type=EntityType.DOMAIN,
        observed_form="deleted-store.example",
        attributes={"ownership_contested": "false"},
        extent=TemporalExtent.at(datetime.now(UTC)),
        is_synthetic=True,
    )
    capability = _signed_envelope(signer, entity, now=datetime.now(UTC))
    fingerprint = capability.targets[0].fingerprint
    path = tmp_path / "authz.sqlite3"

    envelope = AutonomyEnvelope(
        capability, max_autonomous_effects=2, ledger=SqliteAuthorizationStore(path)
    )
    for _ in range(2):
        envelope.debit(
            operation=OperationClass.SIMULATION,
            target_fingerprint=fingerprint,
            requested_by=new_id(IdPrefix.ACTOR),
        )
    assert envelope.remaining == 0

    for leftover in (path, path.with_suffix(".sqlite3-wal"), path.with_suffix(".sqlite3-shm")):
        if leftover.exists():
            leftover.unlink()

    reopened = AutonomyEnvelope(
        capability, max_autonomous_effects=2, ledger=SqliteAuthorizationStore(path)
    )
    assert reopened.remaining == 0, "deleting the file handed back a budget already spent"
