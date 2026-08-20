"""Anchoring a vault head, and refusing to overstate what an anchor is worth.

Invariant 10 puts the vault operator inside the threat model, and that makes the vault's
own hash chain circular: whoever can rewrite the log can recompute every link in it. An
anchor is the way out of the circle, but only when the party holding it is not us.

This module makes that distinction executable instead of advisory. The anchor it can
produce is signed with a key this platform holds, so it is stamped with
:data:`LOCAL_ANCHOR_AUTHORITY` and :attr:`~nemesis.core.evidence.IntegrityAnchor.is_externally_held`
reports False for it. A vault carrying only local anchors therefore still reports
``is_defensible_against_insider = False``, however clean its bookkeeping looks — which is
the honest answer, because an insider who rewrote the log holds this key too.

What a local anchor does buy: a head signed at a moment, verifiable later without
re-deriving it from the log. It catches a store restored from the wrong backup, a chain
rebuilt by a repair script, and an anchor copied in from another vault. It catches nothing
an operator with the signing key did on purpose.

Status: local head signing is `IMPLEMENTED`. External anchoring — an RFC 3161 timestamping
authority, a certificate-transparency-style log, a public ledger — is
`REQUIRES_EXTERNAL_DATA` and has no implementation here on purpose. An anchor we minted
ourselves and labelled with someone else's authority would be worse than no anchor: it
would flip the one flag that tells a reader the evidence cannot be defended against us.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from datetime import datetime
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from nemesis.core.evidence import IntegrityAnchor
from nemesis.core.temporal import utcnow

LOCAL_ANCHOR_AUTHORITY: Final = "nemesis"
"""The authority stamped on an anchor we signed ourselves.

Deliberately one of the values :attr:`IntegrityAnchor.is_externally_held` rejects. Naming
ourselves is what keeps a locally signed anchor from being counted as external by any
consumer, including ones written later by someone who has not read this module.
"""

LOCAL_ANCHOR_TYPE: Final = "local_ed25519_head_signature"

SIGNATURE_SCHEME: Final = "ed25519"

_ED25519_SIGNATURE_BYTES: Final = 64
_KEY_ID_HEX_CHARS: Final = 16


def _b64(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def signed_payload(*, head: str, anchored_at: datetime) -> bytes:
    """The exact bytes a local anchor's signature covers.

    The timestamp is inside the signature, not merely beside it. An anchor whose only
    signed content was the head could be re-dated at will, and the whole point of an anchor
    is the claim that this head existed *at that moment*.
    """
    return f"{LOCAL_ANCHOR_TYPE}\n{head}\n{anchored_at.isoformat()}".encode()


class LocalHeadSigner:
    """Signs a vault head with a key this platform holds.

    Not a substitute for an external anchor and structurally unable to pose as one: every
    anchor it produces carries :data:`LOCAL_ANCHOR_AUTHORITY`, and there is no argument
    that changes it.
    """

    __slots__ = ("_private_key",)

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    @classmethod
    def generate(cls) -> LocalHeadSigner:
        """Mint an ephemeral key. Nothing is written to disk."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, data: bytes, *, passphrase: bytes | None = None) -> LocalHeadSigner:
        loaded = serialization.load_pem_private_key(data, password=passphrase)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError(f"expected an Ed25519 private key, got {type(loaded).__name__}")
        return cls(loaded)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    @property
    def key_id(self) -> str:
        raw = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return hashlib.sha256(raw).hexdigest()[:_KEY_ID_HEX_CHARS]

    def sign_bytes(self, payload: bytes) -> bytes:
        """Sign arbitrary bytes with this key.

        Used by the evidence export to bind a package to a key. Deliberately raw rather than
        wrapped in an :class:`IntegrityAnchor`: an anchor declares itself internal and says
        what it is worth against the operator, and a package seal is a different claim —
        that nothing changed between us and the recipient. Conflating the two would let a
        package seal read as an anchor, which is the overstatement this module exists to
        refuse.
        """
        return self._private_key.sign(payload)

    def anchor(self, head: str, *, anchored_at: datetime | None = None) -> IntegrityAnchor:
        """Sign ``head``, returning an anchor that declares itself internal."""
        moment = anchored_at or utcnow()
        signature = self._private_key.sign(signed_payload(head=head, anchored_at=moment))
        return IntegrityAnchor(
            anchor_type=LOCAL_ANCHOR_TYPE,
            anchored_at=moment,
            authority=LOCAL_ANCHOR_AUTHORITY,
            proof=f"{SIGNATURE_SCHEME}:{self.key_id}:{_b64(signature)}",
            covers_hash=head,
        )

    def verification_failure(self, anchor: IntegrityAnchor) -> str | None:
        """``None`` when the anchor is one this key signed over these exact contents.

        A reason rather than a bare False: "signed by another key" and "signed by this key
        over a different head" are different incidents. The first is an anchor from
        somewhere else, the second is a chain that was rewritten under an anchor.
        """
        if anchor.anchor_type != LOCAL_ANCHOR_TYPE:
            return f"anchor type {anchor.anchor_type!r} is not {LOCAL_ANCHOR_TYPE!r}"

        parts = anchor.proof.split(":")
        if len(parts) != 3:
            return f"malformed proof; expected '{SIGNATURE_SCHEME}:<key_id>:<base64>'"
        scheme, key_id, encoded = parts
        if scheme != SIGNATURE_SCHEME:
            return f"unsupported signature scheme {scheme!r}; expected {SIGNATURE_SCHEME!r}"
        if key_id != self.key_id:
            return f"anchor was signed by key {key_id!r}, not by {self.key_id!r}"
        try:
            raw = _unb64(encoded)
        except (binascii.Error, ValueError):
            return "proof is not valid base64"
        if len(raw) != _ED25519_SIGNATURE_BYTES:
            return f"proof is {len(raw)} bytes, expected {_ED25519_SIGNATURE_BYTES} for Ed25519"

        payload = signed_payload(head=anchor.covers_hash, anchored_at=anchor.anchored_at)
        try:
            self.public_key.verify(raw, payload)
        except InvalidSignature:
            return (
                "proof does not cover this head and time: the anchored head was changed, "
                "the anchor was re-dated, or the proof was forged"
            )
        return None

    def verifies(self, anchor: IntegrityAnchor) -> bool:
        return self.verification_failure(anchor) is None

    def __repr__(self) -> str:
        """Never render the key material: reprs reach logs, tracebacks and context windows."""
        return f"LocalHeadSigner(key_id={self.key_id!r}, private material withheld)"
