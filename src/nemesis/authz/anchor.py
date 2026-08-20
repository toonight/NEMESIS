"""What an append-only chain cannot know about itself, held somewhere it cannot reach.

WHY THIS EXISTS, MEASURED RATHER THAN ARGUED

Both hash-chained tables in this plane — revocations and the autonomy spend ledger — fail to
notice the deletion of their newest row. Interior edits are caught by the per-record signature:
an attacker who rewrites a row and recomputes every hash downstream is refused on *not signed
by the issuing authority*, because forging a record needs the Ed25519 key. But nothing follows
the tail, so nothing fails to follow it, and truncating a chain is indistinguishable from a
chain that was never that long. Emptying a table entirely also verifies clean.

Measured, and pinned by strict `xfail` tests: delete the newest revocation and a withdrawn
authority is silently restored; delete the newest debit and spent autonomy comes back; delete
the store file and the budget resets to full.

**Truncate-then-reoccupy is worse than truncation.** Delete the tail, then let the platform run
normally: the next legitimate record is signed by the real gateway and chains onto the
truncated tail, and the table becomes fully self-consistent again. The deleted records do not
read as missing — they read as never having existed. That is why the window is *before the next
write* rather than before the next audit.

**No in-table marker can fix this.** A count row, a sentinel, a genesis binding: all are
deletable by the same write access that removed the tail. Detecting the loss of the most recent
state needs memory the adversary cannot reach. Two external reviews (Kimi K3 and Codex/GPT-5.6)
reached that conclusion independently, by different routes, and this module implements what
they specified.

WHAT THIS DETECTS, AND WHAT IT DOES NOT

Detected: blunt tail truncation; total erasure; replay of a stale anchor; and
truncate-then-reoccupy **only when the verifier retained a pre-attack tip**.

Not detected: reoccupation for which the adversary obtained a *fresh, legitimately issued*
anchor. Epoch e+1 > e, signature valid, tip matching, every check passing. **The epoch is
monotonic, not honest** — it orders anchors, it does not vouch for their contents.

THE PLACEMENT IS THE WHOLE SECURITY ARGUMENT, AND THIS MODULE DOES NOT SUPPLY IT

An anchor is worth exactly the trust boundary it sits behind. Under this MVP's own constraints
— one laptop, one user account, and an adversary that is the autonomous pilot running with that
account's shell — **there is no placement that defeats it**: the anchor file, the epoch counter
and the verifier's retained state are all files that account can write, and integrity cannot be
bootstrapped from storage the adversary controls. The argument applies recursively to the
anchor itself.

So :class:`FileAnchorStore` is deliberately named for what it is and stamps every anchor it
publishes with :data:`LOCAL_ANCHOR_AUTHORITY`, exactly as the vault's local head signer does,
and :meth:`ChainAnchor.is_externally_held` reports False for it. What the contract buys is that
crossing a real boundary later — a second system account owning the gateway, a host the pilot
cannot reach, a transparency log — becomes a deployment decision rather than a redesign.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Final, Protocol

from pydantic import BaseModel, ConfigDict, Field

from nemesis.authz.keys import CapabilitySigningKey
from nemesis.core.canonical import canonical_bytes
from nemesis.core.temporal import utcnow
from nemesis.ports.authorization import CapabilityVerifier

LOCAL_ANCHOR_AUTHORITY: Final = "nemesis"
"""The authority stamped on an anchor this platform signed itself.

The same value, and the same reasoning, as the vault's local head signer: naming ourselves is
what keeps a locally signed anchor from being counted as external by anything downstream. An
insider who rewrote the chain holds this key too.
"""

REVOCATION_CHAIN: Final = "revocations"
SPEND_CHAIN: Final = "envelope_spends"
"""The two chains this plane keeps. Named constants rather than free strings, so an anchor
cannot be published against a chain nobody meant and quietly verify against nothing."""


class ChainAnchor(BaseModel):
    """What the chain looked like at one instant, attested from outside it.

    The three fields that matter are ``epoch``, ``record_count`` and ``tip_hash``. The count is
    what makes truncation visible at all — a chain can always recompute its own links, and can
    never notice that there used to be more of them. The tip binds the count to specific
    content, so a chain of the right length but different history fails too. The epoch orders
    anchors so an older valid one cannot be replayed in place of a newer.
    """

    model_config = ConfigDict(frozen=True)

    chain_id: str = Field(min_length=1)
    epoch: int = Field(ge=0)
    record_count: int = Field(ge=0)
    tip_hash: str = Field(min_length=1)
    anchored_at: datetime
    authority: str = Field(min_length=1)
    signature: str | None = None

    def signing_payload(self) -> bytes:
        """The exact bytes the signature covers.

        The timestamp and the authority are *inside* the signature, not merely beside it. An
        anchor whose signed content was only the tip could be re-dated at will, and one whose
        authority could be edited after signing could be promoted from local to external by
        whoever wanted it to look stronger.
        """
        return canonical_bytes(self.model_dump(mode="json", exclude={"signature"}))

    @property
    def is_externally_held(self) -> bool:
        """Whether this anchor is held by a party that is not us.

        False for anything this platform signed. The distinction is the entire value of an
        anchor: one we hold proves the chain is self-consistent, which the chain already
        claimed, and proves nothing about an insider who can rewrite both.
        """
        return self.authority != LOCAL_ANCHOR_AUTHORITY


class AnchorStore(Protocol):
    """Where anchors live. The security of this whole mechanism is this protocol's placement.

    Kept as a protocol precisely because the implementation decides everything: a store on the
    same filesystem as the chain defends against accidents, and a store on the far side of a
    trust boundary the adversary cannot cross defends against the adversary. The code cannot
    tell which it was handed, so it never claims the stronger one.
    """

    def latest(self, chain_id: str) -> ChainAnchor | None: ...

    def publish(self, anchor: ChainAnchor) -> ChainAnchor: ...


class AnchorVerifier(Protocol):
    """Checks an anchor's signature. Same shape as the capability verifier, for the same
    reason: the thing that validates a signature must not be the thing that produced it."""

    def verify(self, payload: bytes, signature: str) -> bool: ...


def chain_digest(links: Sequence[str]) -> str:
    """Fold a chain's link hashes into one value, in order.

    Order is load-bearing here in a way it is not elsewhere in this codebase: two chains
    holding the same records in a different sequence are different histories, and an anchor
    that could not tell them apart would accept a reordering as intact.
    """
    folded = hashlib.sha256()
    for link in links:
        folded.update(link.encode("ascii"))
        folded.update(b"\x00")  # unambiguous separator: no concatenation collisions
    return folded.hexdigest()


def anchor_for(
    chain_id: str, links: Sequence[str], *, epoch: int, anchored_at: datetime | None = None
) -> ChainAnchor:
    """Describe a chain as it stands, unsigned. Signing is the caller's, and deliberate."""
    return ChainAnchor(
        chain_id=chain_id,
        epoch=epoch,
        record_count=len(links),
        tip_hash=chain_digest(links),
        anchored_at=anchored_at or utcnow(),
        authority=LOCAL_ANCHOR_AUTHORITY,
    )


def verify_against_anchor(
    links: Sequence[str],
    anchor: ChainAnchor | None,
    *,
    verifier: AnchorVerifier,
    retained_epoch: int | None = None,
) -> tuple[str, ...]:
    """Check a chain against what was attested about it. Returns defects, empty when sound.

    **An absent anchor is not a pass.** It is reported, because "nobody ever attested to this
    chain" and "this chain matches its attestation" are different findings and only one of them
    is evidence. A verifier that treated a missing anchor as silence would hand an attacker the
    cheapest possible attack: delete the anchor.

    ``retained_epoch`` is the greatest epoch this verifier has previously accepted. Without it
    a stale but validly-signed anchor replays cleanly — which is the failure an external review
    caught in the first draft of this contract, and the reason the epoch exists at all.
    """
    defects: list[str] = []

    if anchor is None:
        return (
            "no anchor exists for this chain, so its length is attested by nothing. A chain "
            "can always recompute its own links and can never notice that there used to be "
            "more of them: truncation is invisible from inside.",
        )

    if anchor.signature is None or not verifier.verify(anchor.signing_payload(), anchor.signature):
        defects.append(
            f"the anchor for {anchor.chain_id} is not signed by the attesting authority — "
            "somebody who is not the anchoring party wrote it"
        )

    if retained_epoch is not None and anchor.epoch < retained_epoch:
        defects.append(
            f"anchor epoch {anchor.epoch} is older than the {retained_epoch} this verifier "
            "already accepted: an earlier, validly-signed anchor is being presented to make an "
            "older state look current"
        )

    if len(links) != anchor.record_count:
        defects.append(
            f"the chain holds {len(links)} records and the anchor attests {anchor.record_count}"
            + (
                " — records were removed after it was anchored"
                if len(links) < anchor.record_count
                else " — records were added without re-anchoring, so the newest are unattested"
            )
        )

    measured = chain_digest(links)
    if measured != anchor.tip_hash:
        defects.append(
            f"the chain folds to {measured[:16]}… and the anchor attests {anchor.tip_hash[:16]}…"
            " — the records are not the ones that were anchored, or their order changed"
        )

    # A locally-held anchor is NOT reported here, and the first draft of this function got that
    # wrong: it appended the limitation to the defect list, so a caller writing the obvious
    # `if defects: alarm()` would have alarmed on every healthy chain. "The data disagrees with
    # its attestation" and "this attestation is weak" are different findings, and a list that
    # mixes them is one nobody can act on. The limitation is a property of the anchor —
    # `is_externally_held` — and belongs in what the caller *reports*, exactly as the vault
    # reports `is_defensible_against_insider` beside a clean chain.
    return tuple(defects)


__all__ = [
    "LOCAL_ANCHOR_AUTHORITY",
    "REVOCATION_CHAIN",
    "SPEND_CHAIN",
    "AnchorEpochError",
    "AnchorStore",
    "AnchorVerifier",
    "ChainAnchor",
    "FileAnchorStore",
    "LocalAnchorSigner",
    "anchor_for",
    "chain_digest",
    "verify_against_anchor",
]


class LocalAnchorSigner:
    """Signs an anchor with a key this platform holds.

    Not a substitute for an external attestation and structurally unable to pose as one: every
    anchor it produces carries :data:`LOCAL_ANCHOR_AUTHORITY`, there is no argument that
    changes it, and :attr:`ChainAnchor.is_externally_held` reports False for the result. The
    same shape, and the same refusal to flatter itself, as the vault's local head signer.
    """

    __slots__ = ("_key",)

    def __init__(self, key: CapabilitySigningKey) -> None:
        self._key = key

    def sign(self, anchor: ChainAnchor) -> ChainAnchor:
        stamped = anchor.model_copy(update={"authority": LOCAL_ANCHOR_AUTHORITY, "signature": None})
        return stamped.model_copy(update={"signature": self._key.sign(stamped.signing_payload())})

    @property
    def verifying_key(self) -> CapabilityVerifier:
        return self._key.verifying_key


class FileAnchorStore:
    """Anchors in a file beside the chain. **Named for what it is.**

    On a single-user machine this is not a trust boundary: whoever can truncate the SQLite
    table can delete this file, and the argument that made truncation invisible applies
    recursively. It defends against an accident, a partial restore, a half-finished copy — and
    against nothing that wants to get past it.

    It exists so the contract has an implementation to be tested against, and so that moving
    the anchors somewhere real — a directory owned by a second system account, a host the
    pilot cannot reach, a transparency log — is a constructor argument rather than a redesign.
    That is the whole reason to build the contract before the placement is decided.

    Append-only on purpose: :meth:`publish` refuses an epoch that does not advance, so a caller
    cannot quietly overwrite a newer attestation with an older one. That refusal lives here
    rather than in the verifier because it is cheap, and because a store that accepted it would
    make `retained_epoch` the only defence against replay.
    """

    __slots__ = ("_path",)

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def _read(self) -> list[ChainAnchor]:
        if not self._path.exists():
            return []
        return [
            ChainAnchor.model_validate_json(line)
            for line in self._path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def latest(self, chain_id: str) -> ChainAnchor | None:
        """The highest-epoch anchor for a chain, or None when nothing was ever attested."""
        for_chain = [a for a in self._read() if a.chain_id == chain_id]
        return max(for_chain, key=lambda a: a.epoch, default=None)

    def publish(self, anchor: ChainAnchor) -> ChainAnchor:
        current = self.latest(anchor.chain_id)
        if current is not None and anchor.epoch <= current.epoch:
            raise AnchorEpochError(
                f"anchor for {anchor.chain_id} carries epoch {anchor.epoch}, which does not "
                f"advance on the {current.epoch} already published. An anchor that could be "
                "replaced by an older one is one an attacker replaces with an older one."
            )
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(anchor.model_dump_json() + "\n")
        return anchor


class AnchorEpochError(RuntimeError):
    """An anchor was published whose epoch does not advance.

    Its own type because the caller's correct response is specific — re-read the latest epoch
    and attest again — and a caller catching "the anchor store is unavailable" must not swallow
    "you tried to move the attestation backwards".
    """
