"""The audit trail's tail, attested somewhere the trail cannot reach.

:mod:`nemesis.authz.anchor` specifies and implements the whole contract — a signed
``(epoch, record_count, tip_hash)``, an independence ladder that cannot be climbed by writing a
stronger word in a file, a registry that refuses one key under two names. It was built for the
revocation and spend chains, it is tested to twenty-odd cases, and until now **nothing in the
running platform called it.** A contract exercised only by its own tests is a design, not a
control.

This module is the wiring, and the gap it closes is measurable rather than theoretical:

    :meth:`~nemesis.audit.trail.AppendOnlyAuditTrail.verify` detects tail truncation by comparing
    what it reads on disk against ``self._count`` — a number that exists only because *this
    process* wrote those entries. Truncate the file and restart, and the fresh instance's
    counters are the truncated ones. The chain links perfectly, the head matches the last row,
    and the deleted entries do not read as missing: they read as never having existed.

An anchor is the memory that survives the restart. Nothing else can be: as
:mod:`nemesis.authz.anchor` argues at length, no in-file marker helps, because the write access
that removed the tail removes the marker too.

**Where this module sits, and why it is not in `nemesis.audit`.** The plane layering puts
``nemesis.audit`` below ``nemesis.authz``, so the trail cannot import the anchor. Inverting that
— moving the anchor primitives down, or defining a parallel checkpoint type in ``nemesis.ports``
— would either drag signing into a lower plane or produce a second serialization of the same
attestation, and two formats for one signed object is how a verifier ends up unable to read what
a signer wrote. So the trail grew one read-only accessor
(:meth:`~nemesis.audit.trail.AppendOnlyAuditTrail.links`) and the binding lives up here, where
importing both is legal and ordinary.

**What it is worth, at the rung the MVP ships.** ``FileAnchorStore`` beside the trail is
``AnchorIndependence.NONE``: it catches an accident, a partial restore, a chain rebuilt by a
repair script, and a trail copied in from another deployment. It does not catch the named
adversary, who holds the same account. Moving the store behind a boundary that adversary cannot
write is a constructor argument — which is the entire reason the contract was built before the
placement was decided, and the reason this module takes an ``AnchorStore`` rather than a path.

Status: `IMPLEMENTED` (the binding, at ``NONE``). ``SEPARATE_ACCOUNT`` and above are a deployment
decision; ``THIRD_PARTY`` is `REQUIRES_EXTERNAL_DATA` and has no implementation here on purpose.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final, Protocol

from nemesis.authz.anchor import (
    AnchorIndependence,
    AnchorRegistry,
    AnchorStore,
    ChainAnchor,
    anchor_for,
    verify_against_anchor,
)

AUDIT_CHAIN: Final = "audit_trail"
"""The chain id every audit anchor is published under.

A named constant beside ``REVOCATION_CHAIN`` and ``SPEND_CHAIN`` for the reason those are named:
an anchor published against a chain nobody meant verifies against nothing, quietly.
"""


ANCHOR_FILE: Final = "anchors.jsonl"
ANCHOR_PUBLIC_KEY_FILE: Final = "anchor-key.pub"
"""Conventional filenames inside a workspace, so a writer and a verifier in different processes
agree without either being told.

Named here rather than at each end because the writer is a scenario and the reader is a CLI
command, and a filename spelled twice is a filename that eventually differs by a character —
after which the verifier finds no anchor and reports the honest-looking "this chain is attested
by nothing", which is the worst possible failure for a check whose whole job is noticing absence.
"""


class AnchoredChain(Protocol):
    """What this module needs from an append-only chain: its links, in order.

    A Protocol rather than the concrete trail, so the same anchoring works for any chain that can
    say what it holds — and so a test can drive it from a list of literals. It is deliberately
    read-only: anchoring must never be able to change the thing it attests to.
    """

    async def links(self) -> tuple[str, ...]: ...


class AnchorSigner(Protocol):
    """Signs an anchor. Structurally :class:`~nemesis.authz.anchor.LocalAnchorSigner`.

    Taken as a Protocol so this module never holds a key type: whatever signs is handed in, and
    a deployment that moves signing behind a boundary — a second account, an HSM, a remote
    notary — replaces the argument rather than this file.
    """

    def sign(self, anchor: ChainAnchor) -> ChainAnchor: ...


@dataclass(frozen=True)
class AuditIntegrityReport:
    """What the trail's own chain says, and what the anchor says about it.

    Two verdicts kept apart, deliberately, because they answer different questions and only one
    of them survives an operator. The **trail's own** ``verify()`` is it checking itself, which
    an insider who rewrote the file can always make true; :attr:`defects` is the anchor
    disagreeing with the file, which they cannot — unless they also hold whatever the anchor sits
    behind, and :attr:`independence` says exactly how much that is.

    Collapsing the two into one boolean is the mistake this whole ladder exists to prevent: it
    would let a clean internal chain read as integrity, which is the claim the evidence vault
    already refuses to make about itself.

    **The trail's verdict is deliberately not a field here**, and an earlier version of this
    docstring said it was. That was documentation contradicting the code, which this repository
    treats as a defect: this report is what *the anchor* found, and a caller wanting both prints
    both — which is what `nemesis verify` does, on adjacent lines. Folding the trail's answer in
    would have made one object able to say "sound" about two different things.
    """

    chain_id: str
    links_examined: int
    anchor: ChainAnchor | None
    defects: tuple[str, ...]
    independence: AnchorIndependence

    @property
    def sound(self) -> bool:
        """No defect between the chain and its attestation. Not the same as *defensible*."""
        return not self.defects

    @property
    def is_defensible_against_the_operator(self) -> bool:
        """Whether anyone but us could tell if we rewrote this.

        True only at :attr:`~nemesis.authz.anchor.AnchorIndependence.THIRD_PARTY`, matching
        :attr:`~nemesis.authz.anchor.ChainAnchor.is_externally_held` and the vault's
        ``is_defensible_against_insider``. Three places, one answer, and the answer today is
        False everywhere.
        """
        return self.sound and self.anchor is not None and self.anchor.is_externally_held

    def render(self) -> str:
        head = (
            f"{self.chain_id}: {self.links_examined} entries, "
            f"{'sound' if self.sound else f'{len(self.defects)} DEFECT(S)'}, "
            f"anchored at {self.independence.value}"
        )
        if not self.defects:
            return head
        return head + "\n  - " + "\n  - ".join(self.defects)


async def anchor_audit_trail(
    trail: AnchoredChain,
    *,
    store: AnchorStore,
    signer: AnchorSigner,
    independence: AnchorIndependence = AnchorIndependence.NONE,
    anchored_at: datetime | None = None,
) -> ChainAnchor:
    """Attest the trail's current length and tip, and publish the attestation.

    The epoch advances from whatever the store already holds, so a caller cannot accidentally
    republish at the same epoch and cannot move the attestation backwards — the store refuses
    that anyway (:class:`~nemesis.authz.anchor.AnchorEpochError`), and computing it here means
    the ordinary caller never has to think about it.

    **When to call this is a deployment decision with real teeth.** The window in which
    truncate-then-reoccupy is recoverable is *before the next write*, not before the next audit,
    because a truncated chain that is then extended legitimately becomes self-consistent again.
    So anchoring after every session close buys far more than anchoring nightly, and anchoring
    nightly buys far more than anchoring never — which is what the platform did until this
    module existed.
    """
    links = await trail.links()
    unsigned = anchor_for(
        AUDIT_CHAIN,
        links,
        epoch=_next_epoch(store),
        anchored_at=anchored_at,
        independence=independence,
    )
    return store.publish(signer.sign(unsigned))


async def verify_audit_trail(
    trail: AnchoredChain,
    *,
    store: AnchorStore,
    authorities: AnchorRegistry,
    retained_epoch: int | None = None,
) -> AuditIntegrityReport:
    """Check the trail against what was attested about it.

    An **absent anchor is reported as a defect**, not as silence, and that is
    :func:`~nemesis.authz.anchor.verify_against_anchor`'s rule rather than a choice made here: a
    verifier that treated a missing anchor as a pass would hand an attacker the cheapest attack
    in the set, which is to delete the anchor.

    ``retained_epoch`` is the greatest epoch this verifier has previously accepted, held wherever
    the verifier's own state lives. Without it a stale but validly-signed anchor replays cleanly.
    """
    links = await trail.links()
    anchor = store.latest(AUDIT_CHAIN)
    defects = verify_against_anchor(
        links, anchor, authorities=authorities, retained_epoch=retained_epoch
    )
    return AuditIntegrityReport(
        chain_id=AUDIT_CHAIN,
        links_examined=len(links),
        anchor=anchor,
        defects=defects,
        independence=anchor.independence if anchor else AnchorIndependence.NONE,
    )


RETAINED_EPOCH_FILE: Final = "anchor-epoch"
"""Where a verifier remembers the greatest epoch it has accepted.

**Without it the rollback half of this contract is not wired**, which an adversarial review
pointed out is the same failure the module was written to fix, one level up: the anchor was being
called and its replay protection was not. A stale but validly-signed anchor, presented alongside
a file rolled back to match it, verifies perfectly against a verifier with no memory.

A file beside the anchors, which is worth exactly what its placement is worth — at
``AnchorIndependence.NONE`` an adversary who can roll back the trail can roll back this too. What
it buys at that rung is the same as everything else at that rung: an accident, a partial restore
and a stale backup are caught. What it buys at a higher rung is real, and it is a path argument.
"""


def retained_epoch(workspace: Path) -> int | None:
    """The greatest anchor epoch this workspace has accepted, or ``None`` if it has none.

    Unreadable or malformed is ``None`` — the same reading as absent. A verifier that raised here
    would turn a corrupt one-line file into a failed verification rather than a weaker one, and
    the honest answer to "I cannot read my own memory" is that I have none.
    """
    path = workspace / RETAINED_EPOCH_FILE
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def retain_epoch(workspace: Path, epoch: int) -> None:
    """Record an accepted epoch, never moving it backwards.

    Monotonic on write as well as on read: a caller that verified an older anchor must not be
    able to lower the bar for the next one, which would hand back exactly the replay this file
    exists to refuse.
    """
    current = retained_epoch(workspace)
    if current is not None and epoch <= current:
        return
    (workspace / RETAINED_EPOCH_FILE).write_text(str(epoch), encoding="utf-8")


def _next_epoch(store: AnchorStore) -> int:
    current = store.latest(AUDIT_CHAIN)
    return 0 if current is None else current.epoch + 1


__all__ = [
    "ANCHOR_FILE",
    "ANCHOR_PUBLIC_KEY_FILE",
    "AUDIT_CHAIN",
    "RETAINED_EPOCH_FILE",
    "AnchorSigner",
    "AnchoredChain",
    "AuditIntegrityReport",
    "anchor_audit_trail",
    "retain_epoch",
    "retained_epoch",
    "verify_audit_trail",
]
