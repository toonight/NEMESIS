"""Ed25519 key material for capability issuance and verification.

The Effects plane must be able to prove that a capability was minted by an authorizer, and
must be structurally unable to mint one itself. That asymmetry is the reason a signature is
used here rather than a shared secret or a flag in a database: verification needs only the
public half, so the plane that acts never holds the material that grants authority.

Two types, deliberately unrelated by inheritance:

:class:`CapabilitySigningKey` signs, and can derive its own public half.
:class:`CapabilityVerifyingKey` only verifies, and holds nothing from which a private key
could be recovered.

Because the signing key is not a subclass of the verifying key and exposes no ``verify``,
a function annotated to take a verifying key rejects a signing key under ``mypy --strict``.
The separation is a type error rather than a convention, which is what makes it survive a
refactor by someone who has not read this docstring.

**What does not yet stop an agent from obtaining the signing key.** In this MVP the gateway
runs in the same process as the rest of the platform. Anything able to execute arbitrary
Python in that process can reach the key object and sign whatever it likes; nothing in this
module prevents that, and implying otherwise would be worse than stating it. What exists
today is that no agent-facing code path is handed a :class:`CapabilitySigner`, and that the
key is never written into the repository. What does not exist yet is process isolation.
:class:`CapabilitySigner` is the seam for it: an out-of-process signer or an HSM implements
the same two members, and the gateway does not change. In boundary-discipline terms the
in-process key is `IMPLEMENTED` and the isolated signer is `PROPOSED`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nemesis.authz.verification import (
    SIGNATURE_SCHEME,
    CapabilityVerifyingKey,
    SignatureFormatError,
    _b64,
)

__all__ = [
    "SIGNATURE_SCHEME",
    "CapabilitySigner",
    "CapabilitySigningKey",
    "CapabilityVerifyingKey",
    "SignatureFormatError",
]
"""Re-exported so existing call sites keep working.

The split is deliberate and one-directional: :mod:`nemesis.authz.verification` knows nothing
about this module, so a process that needs to *check* a signature never has to import the
one place a signing key is constructed.
"""

_ED25519_SIGNATURE_BYTES: Final = 64
_KEY_ID_HEX_CHARS: Final = 16


class CapabilitySigner(Protocol):
    """Whatever can mint a signature over a capability's canonical bytes.

    The gateway depends on this rather than on a concrete key so that moving the private
    key out of the process — to a signing daemon, a smartcard, an HSM — is a change of
    implementation and not a change of the authorization flow.
    """

    @property
    def key_id(self) -> str: ...

    def sign(self, payload: bytes) -> str:
        """Return a detached signature envelope over ``payload``."""
        ...


class CapabilitySigningKey:
    """The private half. Lives in the control plane and nowhere else.

    Deliberately *not* a :class:`CapabilityVerifyingKey`: handing this object where a
    verifying key is expected is a type error, so a plane that only needs to check
    signatures cannot end up holding the ability to make them.
    """

    __slots__ = ("_private_key",)

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    @classmethod
    def generate(cls) -> CapabilitySigningKey:
        """Mint an ephemeral key. Nothing is written to disk."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, data: bytes, *, passphrase: bytes | None = None) -> CapabilitySigningKey:
        loaded = serialization.load_pem_private_key(data, password=passphrase)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError(f"expected an Ed25519 private key, got {type(loaded).__name__}")
        return cls(loaded)

    @classmethod
    def load(cls, path: Path, *, passphrase: bytes | None = None) -> CapabilitySigningKey:
        """Load from a path supplied by the operator.

        There is no default location on purpose. A well-known path is a well-known path for
        an attacker too, and a default would eventually be a path inside a deployment
        artifact — which is how signing keys end up in repositories.
        """
        return cls.from_pem(path.read_bytes(), passphrase=passphrase)

    def export_private_pem(self, *, passphrase: bytes) -> bytes:
        """Serialize the private key, encrypted. A passphrase is not optional.

        An unencrypted private key at rest defeats the entire arrangement: anyone who can
        read the file becomes an authorizer. Refusing to produce one is cheap; the operator
        who wants it unencrypted has to go around this API and leave a trace of doing so.
        """
        if not passphrase:
            raise ValueError(
                "refusing to export an unencrypted signing key: a readable private key makes "
                "its reader an authorizer"
            )
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
        )

    @property
    def verifying_key(self) -> CapabilityVerifyingKey:
        """The public half. Derivation runs one way only."""
        return CapabilityVerifyingKey(self._private_key.public_key())

    @property
    def key_id(self) -> str:
        return self.verifying_key.key_id

    def sign(self, payload: bytes) -> str:
        """Sign the canonical bytes, tagging the envelope with the key that produced it."""
        return f"{SIGNATURE_SCHEME}:{self.key_id}:{_b64(self._private_key.sign(payload))}"

    def __repr__(self) -> str:
        """Never render the key material.

        Objects reach logs, tracebacks and LLM context windows through paths nobody planned.
        A default repr would put the private key in all of them.
        """
        return f"CapabilitySigningKey(key_id={self.key_id!r}, private material withheld)"
