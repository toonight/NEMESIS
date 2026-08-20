"""Checking a capability, with nothing that could produce one.

Split out of :mod:`nemesis.authz.keys` and :mod:`nemesis.authz.gateway` so that the Effects
plane can verify without importing either. That is not tidiness: :mod:`nemesis.effects.worker`
seals both of those modules out of a sandboxed child at runtime, and a plane that had to
import the module where signing keys are constructed in order to check a signature would
have had the means to mint one the moment something owned it.

Everything here is offline and public. A holder of this module and a public key can tell an
authentic capability from a forged one, and can produce neither.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, ValidationError

from nemesis.core.authorization import AuthorizationCapability
from nemesis.core.ids import CapabilityId
from nemesis.core.temporal import utcnow
from nemesis.ports.authorization import CapabilityVerifier

SIGNATURE_SCHEME: Final = "ed25519"
"""The only scheme accepted. Named in the envelope so that adding a second one later is a
visible change rather than a silent reinterpretation of existing signatures."""

_ED25519_SIGNATURE_BYTES: Final = 64
_KEY_ID_HEX_CHARS: Final = 16


class SignatureFormatError(ValueError):
    """A signature envelope that cannot be parsed at all, as opposed to one that fails."""


def _fingerprint(public_key: Ed25519PublicKey) -> str:
    """Short, stable identifier for a public key.

    Truncated to 64 bits, which is enough to tell operational keys apart in a log line and
    deliberately not enough to be trusted on its own: the identifier selects which key to
    check against, the signature is what decides.
    """
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:_KEY_ID_HEX_CHARS]


def _b64(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class CapabilityVerifyingKey:
    """The public half. Everything the Effects plane needs, and nothing more.

    Verification with this key is offline: it consults no store, no clock and no network.
    A holder of this object can tell an authentic capability from a forged one and can do
    nothing else — in particular it cannot produce a capability, and it cannot tell whether
    one has been revoked, which is a separate question requiring state.
    """

    __slots__ = ("_public_key",)

    def __init__(self, public_key: Ed25519PublicKey) -> None:
        self._public_key = public_key

    @classmethod
    def from_pem(cls, data: bytes) -> CapabilityVerifyingKey:
        loaded = serialization.load_pem_public_key(data)
        if not isinstance(loaded, Ed25519PublicKey):
            raise ValueError(
                f"expected an Ed25519 public key, got {type(loaded).__name__}; a capability "
                "signed under another algorithm is not one this platform issued"
            )
        return cls(loaded)

    @classmethod
    def load(cls, path: Path) -> CapabilityVerifyingKey:
        return cls.from_pem(path.read_bytes())

    @property
    def key_id(self) -> str:
        return _fingerprint(self._public_key)

    def public_pem(self) -> bytes:
        """Serialize for distribution. Safe to publish, safe to commit."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def verification_failure(self, payload: bytes, signature: str | None) -> str | None:
        """``None`` when the signature is good, otherwise the reason it is not.

        A reason rather than a bare False: "signed by an unknown key" and "signed by our key
        over different bytes" are different incidents. The first is someone presenting a
        capability they minted themselves; the second is a capability that was altered after
        approval. Collapsing them loses the distinction exactly when it matters.
        """
        if signature is None:
            return "capability carries no signature"

        parts = signature.split(":")
        if len(parts) != 3:
            return f"malformed signature envelope; expected '{SIGNATURE_SCHEME}:<key_id>:<base64>'"
        scheme, key_id, encoded = parts
        if scheme != SIGNATURE_SCHEME:
            return f"unsupported signature scheme {scheme!r}; expected {SIGNATURE_SCHEME!r}"
        if key_id != self.key_id:
            return (
                f"signature was produced by key {key_id!r} but verification used key "
                f"{self.key_id!r}: this capability was not signed by this authorizer"
            )
        try:
            raw = _unb64(encoded)
        except (binascii.Error, ValueError):
            return "signature is not valid base64"
        if len(raw) != _ED25519_SIGNATURE_BYTES:
            return f"signature is {len(raw)} bytes, expected {_ED25519_SIGNATURE_BYTES} for Ed25519"

        try:
            self._public_key.verify(raw, payload)
        except InvalidSignature:
            return (
                "signature does not match the signed bytes: the capability was altered "
                "after approval, or it was forged"
            )
        return None

    def verify(self, payload: bytes, signature: str | None) -> bool:
        return self.verification_failure(payload, signature) is None

    def __repr__(self) -> str:
        return f"CapabilityVerifyingKey(key_id={self.key_id!r})"


class CapabilityVerification(BaseModel):
    """The outcome of checking a capability against a public key and a clock.

    Three questions kept apart because they fail differently and are remedied differently:
    is this object what an authorizer signed, is it internally well-formed, and is it usable
    at this instant. An expired capability answers yes, yes, no — and must stay clearly
    distinct from a forged one, which answers no.
    """

    model_config = ConfigDict(frozen=True)

    capability_id: CapabilityId
    verified_at: datetime
    signature_valid: bool
    signed_by: str | None = None
    """Key id taken from the signature envelope, present even when verification failed:
    a capability signed by an unexpected key is the interesting case, and dropping the id
    would discard the only lead about which key produced it."""

    signature_failure: str | None = None
    structural_failures: tuple[str, ...] = ()
    time_status: str = "valid"
    """``valid`` | ``expired`` | ``not_yet_valid``."""

    authenticated: AuthorizationCapability | None = None
    """The grant as reconstructed from the signed bytes. ``None`` when nothing verified.

    **This, and not the object handed to the verifier, is what a caller must act on.** The
    two can differ while the signature stays valid: an adversarial review passed a
    capability whose permitted operations serialized as ``simulation`` and compared as
    ``provider_notification``, and the Effects plane drafted a provider notification from a
    rehearsal grant. Reconstructing from text is what makes that impossible — a parsed enum
    is a real member, a parsed timestamp is a real ``datetime``.

    Carries no revocation state, because revocation is outside the signature by design. Ask
    the oracle."""

    @property
    def is_authentic(self) -> bool:
        """The object is what an authorizer signed and is internally coherent.

        Says nothing about whether it may be used now. An expired capability is authentic.
        """
        return self.signature_valid and not self.structural_failures

    @property
    def is_usable_now(self) -> bool:
        """Authentic *and* within its validity window.

        Still not sufficient to act: revocation is not visible offline, and the operation
        and target must be checked against the grant with
        :meth:`~nemesis.core.authorization.AuthorizationCapability.authorizes`.
        """
        return self.is_authentic and self.time_status == "valid"

    def render(self) -> str:
        if self.is_usable_now:
            return f"VERIFIED: {self.capability_id} signed by {self.signed_by}"
        reasons = list(self.structural_failures)
        if self.signature_failure:
            reasons.insert(0, self.signature_failure)
        if self.is_authentic and self.time_status != "valid":
            reasons.append(f"capability is {self.time_status}")
        return f"NOT USABLE: {self.capability_id} — " + "; ".join(reasons)


def verify_capability(
    capability: AuthorizationCapability,
    verifying_key: CapabilityVerifier,
    *,
    now: datetime | None = None,
) -> CapabilityVerification:
    """Decide authenticity and structural validity from the capability, a key and a clock.

    Offline by construction: this function reaches nothing. It is the whole verification
    surface the Effects plane needs, which is why the Effects plane can be given a public
    key and nothing else.

    Structural validity is re-derived rather than assumed. A capability that arrives over a
    wire, or that was built with ``model_construct`` or mutated with ``model_copy``, has
    never been through the model's validators; re-validating here catches a target
    fingerprint that no longer matches its bound attributes even in the case where the
    signature was recomputed by someone holding the key.
    """
    moment = now or utcnow()
    payload = capability.signing_payload()
    failure = verifying_key.verification_failure(payload, capability.signature)

    signed_by: str | None = None
    if capability.signature is not None:
        parts = capability.signature.split(":")
        if len(parts) == 3:
            signed_by = parts[1]

    # Reconstruct from the signed bytes rather than re-validating the object in hand. The
    # difference is the whole point: re-validation proves the object *could* be built, and
    # then everybody carries on using the original. Reconstruction produces the object the
    # authorizer actually signed, and that is what is returned for the caller to act on.
    structural: tuple[str, ...] = ()
    authenticated: AuthorizationCapability | None = None
    try:
        authenticated = AuthorizationCapability.from_signed_payload(payload)
    except ValidationError as exc:
        structural = tuple(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors()
        )
    except ValueError as exc:
        structural = (f"signed payload is not readable: {exc}",)

    return CapabilityVerification(
        capability_id=capability.capability_id,
        verified_at=moment,
        signature_valid=failure is None,
        signed_by=signed_by,
        signature_failure=failure,
        structural_failures=structural,
        # From the reconstruction, so a capability carrying a `datetime` subclass that lies
        # about its own expiry cannot report itself valid.
        time_status=(authenticated or capability).time_status(moment),
        authenticated=authenticated if failure is None and not structural else None,
    )
