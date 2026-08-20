"""The pre-signed autonomy envelope: authority delegated in advance, and *counted*.

Founder decision (2026-08-17, ADR-0008): autonomy of an effect lives inside an envelope a
legal authority signs **before** the run. Inside it the pilot acts alone, at machine speed,
with no human in the hot path; the envelope's edges are cryptographic. The human moves from
approving each action to defining the envelope.

:class:`~nemesis.core.authorization.AuthorizationCapability` already carries the edges — target
fingerprints, permitted and forbidden operation classes, jurisdiction, expiry, max effect, stop
conditions. That is enough when a human approves each use. It is **not** enough when the thing
spending it is autonomous, and this module exists for exactly that gap:

**A capability bounds what may be done, not how often.** Approved per-action, that distinction
never arises — a human is the rate limit. Hand the same capability to a pilot running at machine
speed and "four approved targets" becomes an unbounded number of operations against four
approved targets. Nothing in the signed object says otherwise; ``max_targets`` bounds the target
list, not the spending. So an envelope carries a **budget of autonomous effects**, and every
attempt debits it before anything executes.

**Debited before, recorded regardless.** The ledger entry is written before the effect runs and
is never removed, so a crash mid-effect costs the budget rather than losing the record. A
counter that decrements only on success is a counter an adversary empties by failing.

**Hash-chained, like every other record here.** Deleting a spend to buy another one is the
obvious attack on a budget, and a signature does nothing about deletion. The ledger chains, so a
missing entry breaks every link after it (the reasoning of
:class:`~nemesis.core.authorization.Revocation`, applied to consumption).

**What this deliberately is not.** It holds no signing key and cannot widen the capability it
wraps: it can only refuse. Its budget is *narrower* than the grant, never wider — an envelope
that could raise its own ceiling would be the standing permission invariant 9 exists to prevent.

**The ledger is a port.** :class:`InMemorySpendLedger` is the default and is honest about what
it is: a budget that a restart restores, which is no budget at all against anyone who can
restart the process. :class:`~nemesis.authz.store.SqliteAuthorizationStore` implements the same
protocol durably and, more importantly, *atomically* — two processes debiting the same envelope
serialize on the write lock, so a fleet cannot spend past the ceiling by racing. Durability is
the visible half of that fix; atomicity is the half that matters.

Status: `IMPLEMENTED` for the mechanism, in memory and durably. Issuing an envelope for anything
beyond `SIMULATION` remains `REQUIRES_LEGAL_AUTHORITY`: the authority to pre-authorize autonomous
action is not ours.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Final, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from nemesis.core.authorization import (
    GENESIS_HASH,
    AuthorizationCapability,
    OperationClass,
)
from nemesis.core.canonical import canonical_bytes
from nemesis.core.temporal import utcnow

DEFAULT_AUTONOMOUS_EFFECT_BUDGET: Final = 8
"""Effects a pilot may spend inside one envelope before it must go back to a human.

A deliberately small default. The number is a choice, not a measurement — like every constant
in this repository it is stated in code so it can be argued with, and an operator sets it when
they define the envelope."""


class EnvelopeError(RuntimeError):
    """The envelope was asked for something it cannot give."""


class SpendRecord(BaseModel):
    """One debit against an envelope, chained to its predecessor.

    Written *before* the effect is attempted, so it records what was authorized to happen
    rather than what happened to succeed.
    """

    model_config = ConfigDict(frozen=True)

    sequence: Annotated[int, Field(ge=0)]
    capability_id: str
    operation: OperationClass
    target_fingerprint: str
    requested_by: str
    spent_at: datetime
    previous_hash: str = GENESIS_HASH

    def chain_hash(self) -> str:
        """This link's hash, over its own contents and its predecessor's."""
        return hashlib.sha256(canonical_bytes(self.model_dump(mode="json"))).hexdigest()


@runtime_checkable
class SpendLedger(Protocol):
    """Where an envelope's consumption is counted. The port, so it can be made durable.

    ``debit`` is the whole reason this is a protocol rather than a field. The sequence number
    and the predecessor hash are only knowable *inside* whatever serializes concurrent writers,
    so the ledger constructs the record; a caller that built one and handed it over would have
    read the count before taking the lock, which is the classic way two writers both believe
    they are the last.
    """

    def register(self, capability_id: str, budget: int) -> int:
        """Record this envelope's ceiling and return the effective one.

        Called once per envelope. An implementation must refuse a budget *larger* than one
        already recorded for the same capability — reopening an envelope with a bigger number
        is how a restart turns a spent budget into a fresh one.
        """
        ...

    def debit(
        self,
        *,
        capability_id: str,
        operation: OperationClass,
        target_fingerprint: str,
        requested_by: str,
        spent_at: datetime,
    ) -> SpendRecord | None:
        """Spend one effect atomically, or return ``None`` when the budget is gone."""
        ...

    def spends(self, capability_id: str) -> tuple[SpendRecord, ...]: ...


class InMemorySpendLedger:
    """The default ledger. Correct within one process, and forgetful across a restart.

    Kept because a test, a rehearsal and a single-process run do not need a file — and because
    naming it makes the limitation visible at the call site. Anything that must survive a
    restart, or that runs in more than one process, wants
    :class:`~nemesis.authz.store.SqliteAuthorizationStore`: this class cannot serialize a second
    process, so two of them would each believe they hold the whole budget.
    """

    def __init__(self) -> None:
        self._budgets: dict[str, int] = {}
        self._spends: dict[str, list[SpendRecord]] = {}

    def register(self, capability_id: str, budget: int) -> int:
        recorded = self._budgets.get(capability_id)
        if recorded is not None and budget > recorded:
            raise EnvelopeError(
                f"{capability_id} was opened with a budget of {recorded}; reopening it with "
                f"{budget} would widen an authority already in circulation"
            )
        effective = budget if recorded is None else min(recorded, budget)
        self._budgets[capability_id] = effective
        return effective

    def debit(
        self,
        *,
        capability_id: str,
        operation: OperationClass,
        target_fingerprint: str,
        requested_by: str,
        spent_at: datetime,
    ) -> SpendRecord | None:
        spends = self._spends.setdefault(capability_id, [])
        if len(spends) >= self._budgets.get(capability_id, 0):
            return None
        record = SpendRecord(
            sequence=len(spends),
            capability_id=capability_id,
            operation=operation,
            target_fingerprint=target_fingerprint,
            requested_by=requested_by,
            spent_at=spent_at,
            previous_hash=spends[-1].chain_hash() if spends else GENESIS_HASH,
        )
        spends.append(record)
        return record

    def spends(self, capability_id: str) -> tuple[SpendRecord, ...]:
        return tuple(self._spends.get(capability_id, ()))


def verify_spend_chain(spends: tuple[SpendRecord, ...]) -> bool:
    """Whether a ledger's entries are intact: none removed, reordered or edited.

    Shared by every implementation so the in-memory and durable ledgers cannot disagree about
    what an intact chain is — the check being identical is the point of writing it once.
    """
    expected = GENESIS_HASH
    for position, record in enumerate(spends):
        if record.sequence != position or record.previous_hash != expected:
            return False
        expected = record.chain_hash()
    return True


class EnvelopeStatus(BaseModel):
    """What an envelope has left, for a human or a briefing to read."""

    model_config = ConfigDict(frozen=True)

    capability_id: str
    budget: int
    spent: int
    remaining: int
    expires_at: datetime
    permitted_operations: tuple[str, ...]
    forbidden_operations: tuple[str, ...]
    exhausted: bool

    def render(self) -> str:
        return f"{self.remaining}/{self.budget} autonomous effects remaining" + (
            " — EXHAUSTED" if self.exhausted else ""
        )


class AutonomyEnvelope:
    """A signed capability, plus the counted, chained ledger of what has been spent inside it.

    Wraps rather than subclasses :class:`AuthorizationCapability` on purpose. The capability is
    the signed object and must stay exactly what the authority signed; the ledger is mutable
    local state about consumption. Merging them would put a mutable count inside the signed
    payload, and every debit would then invalidate the signature.
    """

    def __init__(
        self,
        capability: AuthorizationCapability,
        *,
        max_autonomous_effects: int = DEFAULT_AUTONOMOUS_EFFECT_BUDGET,
        ledger: SpendLedger | None = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        """``ledger`` defaults to :class:`InMemorySpendLedger`, which a restart forgets.

        Pass :class:`~nemesis.authz.store.SqliteAuthorizationStore` for an envelope whose budget
        survives a restart and is enforced across processes. The default is the weaker one on
        purpose: a caller that wanted durability and got it silently would never learn that the
        single-process ledger cannot serialize a second process.
        """
        if max_autonomous_effects < 0:
            raise EnvelopeError("an autonomous effect budget cannot be negative")
        if capability.signature is None:
            # An unsigned capability is valid only for SIMULATION and is marked as such
            # wherever it appears; delegating *autonomy* to one would be delegating from an
            # authority nobody can check.
            raise EnvelopeError(
                "an autonomy envelope must wrap a signed capability: delegating autonomous "
                "action under a grant nobody signed is not a narrower authority, it is none"
            )
        self._capability = capability
        self._clock = clock
        self._ledger_impl: SpendLedger = ledger if ledger is not None else InMemorySpendLedger()
        # Registration is what stops a restart from becoming a fresh budget: the ledger keeps
        # the ceiling, and reopening the same capability with a larger one is refused rather
        # than believed.
        self._budget = self._ledger_impl.register(capability.capability_id, max_autonomous_effects)

    @property
    def capability(self) -> AuthorizationCapability:
        """The signed grant, unchanged. What the Effects plane verifies against."""
        return self._capability

    @property
    def budget(self) -> int:
        return self._budget

    @property
    def spent(self) -> int:
        return len(self._ledger_impl.spends(self._capability.capability_id))

    @property
    def remaining(self) -> int:
        return max(0, self._budget - self.spent)

    @property
    def exhausted(self) -> bool:
        return self.remaining == 0

    def ledger(self) -> tuple[SpendRecord, ...]:
        """Every debit, in order. Append-only by construction: nothing here removes one."""
        return self._ledger_impl.spends(self._capability.capability_id)

    def status(self) -> EnvelopeStatus:
        return EnvelopeStatus(
            capability_id=self._capability.capability_id,
            budget=self._budget,
            spent=self.spent,
            remaining=self.remaining,
            expires_at=self._capability.expires_at,
            permitted_operations=tuple(
                sorted(op.value for op in self._capability.permitted_operations)
            ),
            forbidden_operations=tuple(
                sorted(op.value for op in self._capability.forbidden_operations)
            ),
            exhausted=self.exhausted,
        )

    def debit(
        self,
        *,
        operation: OperationClass,
        target_fingerprint: str,
        requested_by: str,
    ) -> SpendRecord | None:
        """Spend one autonomous effect, or return ``None`` when the envelope is empty.

        Called **before** the effect is attempted. Returns ``None`` rather than raising, because
        an exhausted envelope is an expected outcome the pilot must be told about and the
        mediator must record — not an error that unwinds a session.

        Debiting does not authorize anything: the capability still decides whether the operation
        is permitted against that target, and the Effects plane still verifies the signature and
        asks the revocation oracle. This is a *second, narrower* bound, and a bound that only
        ever refuses is safe to consult before the expensive checks.

        The count-and-append is the ledger's, not this method's, and deliberately so: reading
        the count here and appending there would leave a window in which two writers both
        believe they are last. A durable ledger closes that window with its write lock; the
        in-memory one has no second writer to close it against.
        """
        return self._ledger_impl.debit(
            capability_id=self._capability.capability_id,
            operation=operation,
            target_fingerprint=target_fingerprint,
            requested_by=requested_by,
            spent_at=self._clock(),
        )

    def verify_chain(self) -> bool:
        """Whether the ledger is intact: no entry removed, reordered or edited.

        Deleting a spend to buy another effect is the obvious attack on a budget, and one a
        signature would not catch. A gap breaks every link after it.
        """
        return verify_spend_chain(self.ledger())


__all__ = [
    "DEFAULT_AUTONOMOUS_EFFECT_BUDGET",
    "AutonomyEnvelope",
    "EnvelopeError",
    "EnvelopeStatus",
    "InMemorySpendLedger",
    "SpendLedger",
    "SpendRecord",
    "verify_spend_chain",
]
