"""The two things the Effects plane needs in order to refuse.

Declared here rather than in :mod:`nemesis.authz` because they are ports: the Effects plane
depends on the *ability to check*, not on the gateway that happens to provide it. Keeping
them here also keeps the layering honest — ports sit below authz, so a port that imported
the gateway would invert the dependency it exists to describe.

Neither confers authority. A verifying key cannot mint or widen a capability, and a
revocation oracle is read-only. Handing both to an adapter gives it the means to say no,
which is the opposite of ambient authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from nemesis.core.authorization import Revocation


@runtime_checkable
class CapabilityVerifier(Protocol):
    """Establishes that a capability was signed by an authority this plane trusts."""

    @property
    def key_id(self) -> str:
        """Stable identifier for the key, so a refusal can name which key it checked."""
        ...

    def verification_failure(self, payload: bytes, signature: str | None) -> str | None:
        """``None`` when the signature is good, otherwise the reason it is not.

        A reason rather than a bare boolean, because "signed by a key we do not know" and
        "signed by our key over different bytes" are different incidents — someone minting
        their own capability, versus one altered after approval.
        """
        ...

    def verify(self, payload: bytes, signature: str | None) -> bool: ...

    def public_pem(self) -> bytes:
        """The public key itself, so two verifiers can be compared by what they hold.

        Comparing :attr:`key_id` instead would compare labels, and a label is exactly what
        an object gets to choose about itself.
        """
        ...


@runtime_checkable
class RevocationOracle(Protocol):
    """Answers whether a grant still stands.

    Necessarily stateful, and therefore the one check that cannot be made offline. An
    implementation that cannot answer must raise rather than return False: the caller fails
    closed, because an unreachable oracle is not an oracle reporting no revocation.
    """

    def is_revoked(self, capability_id: str) -> bool: ...


@runtime_checkable
class RevocationLedger(Protocol):
    """An oracle that can also be written to.

    Split from :class:`RevocationOracle` on purpose. The gateway needs both halves; the
    Effects plane is handed the read half and nothing else, so a compromised effect cannot
    withdraw a capability it dislikes any more than it can mint one.
    """

    def is_revoked(self, capability_id: str) -> bool: ...

    def record(self, revocation: Revocation) -> Revocation: ...

    def revocations(self) -> tuple[Revocation, ...]: ...

    def tip(self) -> ChainTip:
        """Where the next revocation attaches. A store with none returns the genesis tip."""
        ...


@dataclass(frozen=True)
class ChainTip:
    """The end of a revocation chain: how many links, and the last one's hash."""

    sequence: int
    hash: str


@dataclass(frozen=True)
class TrustAnchor:
    """What an adapter needs to CHECK, which is not authority to act.

    A public key and a read-only oracle. Neither can mint a capability, widen one, or reach
    anything in the intelligence platform, so holding them does not give an adapter ambient
    authority — it gives it the means to refuse.

    Held by the adapter from construction rather than passed on every call. The version that
    passed them per call let a caller choose which authorizer the adapter would believe: an
    adversarial review took an adapter straight out of ``registry.adapters``, handed it a
    capability signed by its own key together with that key, and got a drafted document. The
    port's own docstring claimed the adapter "re-verifies rather than trusting the caller",
    and it was verifying against a key the caller supplied.

    What this buys, stated precisely: an adapter cannot be re-pointed at a foreign
    authorizer. It does not stop an attacker who can execute arbitrary code in this process
    from constructing their own adapter around their own anchor — nothing in-process can.
    That is what process isolation is for, and it is `PROPOSED`, not `IMPLEMENTED`.
    """

    verifying_key: CapabilityVerifier
    revocations: RevocationOracle
