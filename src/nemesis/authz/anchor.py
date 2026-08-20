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
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Final, Protocol

from pydantic import BaseModel, ConfigDict, Field

from nemesis.authz.keys import CapabilitySigningKey
from nemesis.core.canonical import canonical_bytes
from nemesis.core.temporal import utcnow
from nemesis.ports.authorization import CapabilityVerifier


class AnchorIndependence(StrEnum):
    """How far the anchor sits from the thing it attests — which decides what it defends against.

    **The tier is the security argument.** An anchor is worth exactly the trust boundary
    between it and the adversary, and "external" is not one boundary but a ladder. The first
    version of this module carried a boolean, which could say *ours* or *not ours* and could
    not say the thing that actually matters: independent of the pilot, and not of `root`.

    Each tier names the adversary it defeats **and the one it does not**, because a tier that
    only advertised its strength would be read as the tier above it.
    """

    NONE = "none"
    """Same account, same host as the chain. Defeats an accident, a partial restore, a
    half-finished copy — and nothing that wants to get past it. Whoever can truncate the table
    can delete the anchor."""

    SEPARATE_ACCOUNT = "separate_account"
    """A second system account with its own ACLs, which the platform's account cannot write.
    **Defeats a compromised pilot**, which is this MVP's named adversary: the model runs with
    the platform's credentials and cannot reach the anchor. **Does not defeat `root`, nor the
    machine's administrator** — both hold every account on the host."""

    SEPARATE_HOST = "separate_host"
    """A remote service with credentials and administration held separately. **Defeats a
    compromised application host**, since owning the machine no longer implies owning the
    attestation. **Does not defeat an operator who administers both.**"""

    THIRD_PARTY = "third_party"
    """An independent party: RFC 3161 timestamping, or a transparency log. **Defeats a
    malicious internal operator**, because the attestation is held by someone with no
    obligation to us. The only tier that makes evidence defensible against ourselves, which is
    the standing this project's own threat model puts the vault operator in."""


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

    independence: AnchorIndependence = AnchorIndependence.NONE
    """Declared by whoever published it, and covered by the signature so it cannot be promoted
    afterwards. Defaults to the weakest tier: a store that forgot to declare its placement is
    treated as having none, because the alternative is inheriting a claim nobody made."""

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
        """Whether a party with no obligation to us holds this attestation.

        True only at :attr:`AnchorIndependence.THIRD_PARTY`. A second system account and a
        separate host are *separated*, not *external* — they raise the adversary's required
        move without putting the attestation beyond our own reach, and an operator who
        administers the estate holds both. Collapsing that distinction is what a boolean did
        before this enum existed.
        """
        return self.independence is AnchorIndependence.THIRD_PARTY

    def defeats_a_compromised_pilot(self) -> bool:
        """The MVP's named adversary: the model running with the platform's own credentials."""
        return self.independence is not AnchorIndependence.NONE


class AnchorStore(Protocol):
    """Where anchors live. The security of this whole mechanism is this protocol's placement.

    Kept as a protocol precisely because the implementation decides everything: a store on the
    same filesystem as the chain defends against accidents, and a store on the far side of a
    trust boundary the adversary cannot cross defends against the adversary. The code cannot
    tell which it was handed, so it never claims the stronger one.
    """

    def latest(self, chain_id: str) -> ChainAnchor | None: ...

    def publish(self, anchor: ChainAnchor) -> ChainAnchor: ...


INDEPENDENCE_RANK: Final[dict[AnchorIndependence, int]] = {
    AnchorIndependence.NONE: 0,
    AnchorIndependence.SEPARATE_ACCOUNT: 1,
    AnchorIndependence.SEPARATE_HOST: 2,
    AnchorIndependence.THIRD_PARTY: 3,
}
"""An explicit order, because a `StrEnum` has none and comparing these by name would rank
`separate_account` above `third_party`. Spelled out rather than derived from declaration order,
so inserting a rung later cannot silently reorder the ladder."""


class AnchorVerifier(Protocol):
    """Checks an anchor's signature. Same shape as the capability verifier, for the same
    reason: the thing that validates a signature must not be the thing that produced it."""

    @property
    def key_id(self) -> str:
        """Stable identifier for the key, so a registry can tell two authorities apart — and
        can notice when two of them are the same key wearing different names."""
        ...

    def verify(self, payload: bytes, signature: str) -> bool: ...


@dataclass(frozen=True)
class RegisteredAnchorAuthority:
    """An attesting authority this deployment believes, and how far.

    ``independence_ceiling`` is the control, and it is the same one
    :class:`~nemesis.authz.attestation.RegisteredIssuer` applies to identity: an authority
    states what it is; the deployment states what that authority's word is worth here. When
    they disagree the ceiling wins.

    **This exists because the first version of this module did not have it, and an external
    reviewer walked straight through the gap.** `LocalAnchorSigner.sign()` preserved whatever
    rung the caller asked for, so a key we hold minted a `THIRD_PARTY` anchor that verified
    with no defects — while the signer's own docstring claimed it was "structurally unable to
    pose as one". The guard that existed caught *promotion after signing* and never looked at
    *lying while signing*, which is the cheaper attack and the one nobody has to tamper for.

    Unlike identity, an over-claim here is **refused rather than capped**. A principal
    presenting more assurance than its issuer is granted is trimmed and remains a valid
    principal; an anchor claiming independence it was never entitled to is somebody having
    written a stronger word next to a weaker key, and quietly downgrading it would hide that.
    """

    name: str
    verifier: AnchorVerifier
    independence_ceiling: AnchorIndependence

    def __post_init__(self) -> None:
        if (
            self.name == LOCAL_ANCHOR_AUTHORITY
            and self.independence_ceiling is not AnchorIndependence.NONE
        ):
            raise ValueError(
                f"{LOCAL_ANCHOR_AUTHORITY!r} is this platform's own key and cannot be "
                f"registered above {AnchorIndependence.NONE.value!r}. An anchor is worth the "
                "distance between it and the adversary, and there is none: whoever can rewrite "
                "the chain holds this key. Registering it higher would let a deployment grant "
                "itself independence from itself."
            )


class AnchorRegistry:
    """The attesting authorities a deployment believes, indexed by name and bijective.

    **A mapping, not a list, and that is the fix rather than the style.** The first version
    took a sequence and looked authorities up with ``next(a for a in authorities if ...)``, so
    two entries sharing a name meant the first one registered won — and which anchors verified
    depended on the order somebody happened to write the registry in. Order-dependence in a
    security check is the kind of defect that is invisible until the day it decides something.

    Three configurations are refused, and the third is the one that looks harmless:

    * **one key under two names** — one signer with two ceilings, the higher winning by
      accident, which is how a locally held key comes to attest third-party independence;
    * **one name over two keys** — a name is what an anchor cites, so two keys behind it means
      an anchor's authority is whichever entry is found first;
    * **the same name twice at all**, even with the same key, because the two entries may carry
      different ceilings and nothing about the duplicate says which was meant.

    What this cannot check is key provenance: whether the key behind a third-party name belongs
    to that third party is settled by how it reached the deployment. A bijective registry
    removes the ambiguity in the mapping; it does not manufacture independence.
    """

    __slots__ = ("_by_name",)

    def __init__(self, *authorities: RegisteredAnchorAuthority) -> None:
        by_name: dict[str, RegisteredAnchorAuthority] = {}
        by_key: dict[str, str] = {}
        for authority in authorities:
            if authority.name in by_name:
                raise AnchorRegistryError(
                    f"{authority.name!r} is registered twice. Even with the same key the two "
                    "entries may carry different ceilings, and nothing about a duplicate says "
                    "which was meant — so the answer would depend on registration order."
                )
            key_id = authority.verifier.key_id
            seen = by_key.get(key_id)
            if seen is not None:
                raise AnchorRegistryError(
                    f"{authority.name!r} and {seen!r} are registered against the same key "
                    f"({key_id}). Two names for one key are two ceilings for one signer, and "
                    "the higher one wins by accident — which is exactly how a locally held key "
                    "comes to attest third-party independence."
                )
            by_name[authority.name] = authority
            by_key[key_id] = authority.name
        self._by_name = by_name

    def for_name(self, name: str) -> RegisteredAnchorAuthority | None:
        """The single authority registered under this name, or None. Never ambiguous."""
        return self._by_name.get(name)

    def __len__(self) -> int:
        return len(self._by_name)

    def __contains__(self, name: object) -> bool:
        return name in self._by_name


def registered_authorities(*authorities: RegisteredAnchorAuthority) -> AnchorRegistry:
    """Build a deployment's anchor registry, refusing the configurations that look fine."""
    return AnchorRegistry(*authorities)


def local_anchor_authority(verifier: AnchorVerifier) -> RegisteredAnchorAuthority:
    """The platform's own key, at the only ceiling it can honestly hold."""
    return RegisteredAnchorAuthority(
        name=LOCAL_ANCHOR_AUTHORITY,
        verifier=verifier,
        independence_ceiling=AnchorIndependence.NONE,
    )


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
    chain_id: str,
    links: Sequence[str],
    *,
    epoch: int,
    anchored_at: datetime | None = None,
    independence: AnchorIndependence = AnchorIndependence.NONE,
) -> ChainAnchor:
    """Describe a chain as it stands, unsigned. Signing is the caller's, and deliberate.

    ``independence`` defaults to the weakest tier. A deployment that has actually put the
    anchor somewhere its platform account cannot write declares that here — and the code takes
    it on trust, because nothing in Python can verify that a path really sits behind an ACL the
    running process cannot cross. What the field buys is that the *claim* is explicit, signed,
    and reportable, instead of a reader assuming the strongest tier from the word "anchor".
    """
    return ChainAnchor(
        chain_id=chain_id,
        epoch=epoch,
        record_count=len(links),
        tip_hash=chain_digest(links),
        anchored_at=anchored_at or utcnow(),
        authority=LOCAL_ANCHOR_AUTHORITY,
        independence=independence,
    )


def verify_against_anchor(
    links: Sequence[str],
    anchor: ChainAnchor | None,
    *,
    authorities: AnchorRegistry,
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

    registered = authorities.for_name(anchor.authority)
    if registered is None:
        defects.append(
            f"the anchor names {anchor.authority!r}, which this deployment has not registered "
            "as an attesting authority. An anchor from a party nobody vouched for attests "
            "nothing, whoever signed it"
        )
    elif anchor.signature is None or not registered.verifier.verify(
        anchor.signing_payload(), anchor.signature
    ):
        defects.append(
            f"the anchor for {anchor.chain_id} is not signed by the attesting authority — "
            "somebody who is not the anchoring party wrote it"
        )
    elif (
        INDEPENDENCE_RANK[anchor.independence] > INDEPENDENCE_RANK[registered.independence_ceiling]
    ):
        # The gap an external reviewer found: the signature check alone passes here, because
        # the anchor really was signed by a key we hold. What it was not entitled to is the
        # *rung*, and only the deployment's registry knows that.
        defects.append(
            f"the anchor claims {anchor.independence.value!r} independence and "
            f"{anchor.authority!r} is registered up to "
            f"{registered.independence_ceiling.value!r}. An authority cannot attest to a "
            "distance from itself that it does not have — this anchor is signed, and it is "
            "claiming a rung it was never granted"
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
    "INDEPENDENCE_RANK",
    "LOCAL_ANCHOR_AUTHORITY",
    "REVOCATION_CHAIN",
    "SPEND_CHAIN",
    "AnchorEpochError",
    "AnchorIndependence",
    "AnchorPlacementError",
    "AnchorRegistry",
    "AnchorRegistryError",
    "AnchorStore",
    "AnchorVerifier",
    "ChainAnchor",
    "FileAnchorStore",
    "LocalAnchorSigner",
    "RegisteredAnchorAuthority",
    "anchor_for",
    "chain_digest",
    "local_anchor_authority",
    "registered_authorities",
    "verify_against_anchor",
]


class LocalAnchorSigner:
    """Signs an anchor with a key this platform holds.

    Every anchor it produces carries :data:`LOCAL_ANCHOR_AUTHORITY`, and there is no argument
    that changes it.

    **What it does NOT do, corrected after an external review walked through the gap:** it does
    not police the *rung*. It signs whatever :class:`AnchorIndependence` the caller asked for,
    so this class alone will mint a `THIRD_PARTY` anchor with a local key — which it did, and
    which verified with no defects, while this docstring claimed it was "structurally unable to
    pose as one". It was not; it was merely not asked to.

    The refusal lives where it can be enforced: :class:`RegisteredAnchorAuthority` caps
    :data:`LOCAL_ANCHOR_AUTHORITY` at :attr:`AnchorIndependence.NONE`, refuses to be registered
    higher, and :func:`verify_against_anchor` rejects an anchor claiming a rung its authority
    was never granted. A signer cannot be the thing that limits what it signs — the deployment's
    registry is, exactly as an issuer's assurance ceiling is not held by the issuer.
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

    __slots__ = ("_independence", "_path")

    def __init__(
        self,
        path: Path | str,
        *,
        independence: AnchorIndependence = AnchorIndependence.NONE,
    ) -> None:
        """``independence`` is what the *deployment* claims about this path, not what the code
        checked. A file under a directory owned by a second system account genuinely defeats a
        compromised pilot; the same file beside the database defeats an accident. Python cannot
        tell those apart from the path alone, so the placement is declared and signed rather
        than inferred — and it defaults to the weakest reading."""
        self._path = Path(path)
        self._independence = independence
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

    @property
    def independence(self) -> AnchorIndependence:
        """What this store claims about its own placement."""
        return self._independence

    def publish(self, anchor: ChainAnchor) -> ChainAnchor:
        if anchor.independence is not self._independence:
            # Declared placement and published claim must agree. Otherwise the field records
            # what somebody hoped rather than where the file is, and a store beside the
            # database would happily hold anchors calling themselves third-party.
            raise AnchorPlacementError(
                f"this store is placed at {self._independence.value!r} and the anchor claims "
                f"{anchor.independence.value!r}. A store cannot publish an attestation about a "
                "boundary it does not sit behind."
            )
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


class AnchorPlacementError(RuntimeError):
    """An anchor was published claiming a placement the store does not have.

    Its own type because the caller's mistake is specific — the store was constructed at one
    rung and handed an anchor built at another — and a caller catching "the anchor store is
    unavailable" must not swallow "you tried to publish a claim this location cannot support".
    """


class AnchorRegistryError(RuntimeError):
    """A deployment's anchor registry is internally inconsistent.

    Its own type because it is a configuration refusal rather than a verification failure: no
    anchor is at fault, the set of authorities is. A caller catching "this anchor is bad" must
    not swallow "your registry grants one key two ceilings".
    """
