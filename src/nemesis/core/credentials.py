"""Credentials NEMESIS finds, represented so that finding one grants nothing.

An investigation that reads a C2 panel, a leaked dump or a misconfigured bucket index will
encounter authentication material: API tokens, cloud keys, SSH private keys, session cookies,
panel logins. That material is **evidence about the adversary**. It is not, and must never
become, a way for NEMESIS to authenticate as anyone.

The distinction is not a policy someone applies later. It is the shape of the types here:

**There is no field that holds a secret.** :class:`SecretReference` carries a keyed
fingerprint, a length and a pointer into the vault. :class:`CredentialIndicator` carries a
kind, a reference and a masked preview. Neither has anywhere to put the material, so no
caller can serialize it into a briefing, a document, a log line or a message — the same
construction :class:`~nemesis.attribute.disclosure.ExternalAttributionProduct` uses against
persona linkage, for the same reason: you cannot leak what the type cannot represent.

**Discovery and use are different verbs, and only one of them exists.** Nothing in this
module returns authentication material, and nothing anywhere in the repository consumes a
:class:`CredentialIndicator` to authenticate. Using a discovered credential against
infrastructure we do not own is prohibited outright by CLAUDE.md and by invariant 15; if a
legally authorized deployment ever needed it, it would need a signed capability naming that
operation class, issued through :class:`~nemesis.authz.gateway.AuthorizationGateway` by a
human — an independent path that this module cannot reach and does not know about.

**The fingerprint is keyed, not bare.** ``sha256("hunter2")`` is a password oracle: anybody
holding the digest can confirm a guess in microseconds, so a "redacted" store of bare digests
of weak human passwords is a store of the passwords. The fingerprint here is
HMAC-SHA256 under a deployment key, which keeps the one property correlation actually needs —
two sightings of the same credential fingerprint identically — while making the digest useless
to anyone without the key. A deployment that supplies a weak key gets the weak property; the
constructor refuses an absent or short one rather than defaulting to none.

**A credential is RESTRICTED, by category and not by remembering.**
:data:`~nemesis.core.entities.EntityType.CREDENTIAL_INDICATOR` sits in
:data:`~nemesis.core.entities.EntityCategory.CREDENTIAL`, which
:mod:`nemesis.core.disclosure` maps to :attr:`~nemesis.core.disclosure.DisclosureClass.RESTRICTED`.
Every wall that already exists therefore applies without a line of new enforcement: the pilot is
never briefed on it, may not pivot on it and may not request an effect against it; the analyst
view filters it; an export redacts it. That reuse is deliberate — a second, parallel
credential-specific wall would be a second thing to keep in step with the first.

Status: `IMPLEMENTED`. Nothing in this repository collects a real credential; the types exist
so that the first connector that does cannot put one anywhere it should not go.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Final, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.core.temporal import require_utc

MIN_FINGERPRINT_KEY_BYTES: Final = 32
"""How much key material a deployment must supply before a fingerprint means anything.

Thirty-two bytes, matching the SHA-256 block security level. A shorter key is refused rather
than accepted with a warning: the whole value of keying the digest is that guessing the key is
not cheaper than guessing the credential, and a caller that passes eight bytes has silently
bought back the password oracle this exists to remove.
"""

FINGERPRINT_PREFIX: Final = "credfp"
_FINGERPRINT_HEX: Final = 32
_FINGERPRINT_RE: Final = re.compile(rf"^{FINGERPRINT_PREFIX}-[0-9a-f]{{{_FINGERPRINT_HEX}}}$")

MAX_PREVIEW_LENGTH: Final = 24
MAX_UNMASKED_PREVIEW_CHARS: Final = 6
_MASK_CHARS: Final = frozenset("*•.·…")


class CredentialHandlingError(ValueError):
    """A credential was about to be represented in a way that would expose or empower it.

    A ``ValueError`` and not a ``RuntimeError``, unlike
    :class:`~nemesis.core.disclosure.DisclosureViolationError`, because every case it covers is
    a caller passing the wrong thing — an unkeyed fingerprint, a preview that is not masked, a
    natural key that is the secret itself. It is a construction error, caught at construction.
    """


class CredentialKind(StrEnum):
    """What sort of authentication material was found.

    A closed vocabulary rather than free text, so a retention policy, an export filter or an
    escalation rule can reason about kinds without parsing prose. Every member is something a
    dark-web or OSINT collection can plausibly surface; none of them is something NEMESIS may
    use.
    """

    API_TOKEN = "api_token"  # noqa: S105 — an enum member naming a credential kind, not one
    CLOUD_CREDENTIAL = "cloud_credential"
    C2_PANEL_LOGIN = "c2_panel_login"
    LEAKED_PASSWORD = "leaked_password"  # noqa: S105 — an enum member naming a credential kind, not one
    SSH_PRIVATE_KEY = "ssh_private_key"
    VPN_CREDENTIAL = "vpn_credential"
    SESSION_COOKIE = "session_cookie"
    BOT_TOKEN = "bot_token"  # noqa: S105 — an enum member naming a credential kind, not one
    HOSTING_CREDENTIAL = "hosting_credential"
    DATABASE_CREDENTIAL = "database_credential"
    SIGNING_KEY = "signing_key"
    UNCLASSIFIED = "unclassified"
    """Recognised as authentication material and not as any known kind. Kept as a member so a
    classifier that cannot decide records that it could not, rather than guessing a kind an
    export filter would then act on."""


def fingerprint(material: str | bytes, *, key: bytes) -> str:
    """A correlation handle for one credential, useless without the deployment key.

    HMAC-SHA256 truncated to 128 bits and tagged. Truncation is safe for this purpose — the
    property needed is that two sightings of one credential collide and two different ones do
    not, and 128 bits of a keyed MAC gives that with an enormous margin — while a shorter string
    is one a human can compare by eye in an audit record.

    Raises :class:`CredentialHandlingError` on a key shorter than
    :data:`MIN_FINGERPRINT_KEY_BYTES`. There is deliberately no default key and no unkeyed mode:
    a module-level fallback would be in the source tree, which makes it public, which makes the
    fingerprint a bare digest again.
    """
    if len(key) < MIN_FINGERPRINT_KEY_BYTES:
        raise CredentialHandlingError(
            f"a credential fingerprint key must be at least {MIN_FINGERPRINT_KEY_BYTES} bytes; "
            f"{len(key)} were supplied. A short key makes the fingerprint guessable, which "
            "turns a redacted record back into the credential it was redacting"
        )
    raw = material.encode("utf-8") if isinstance(material, str) else material
    if not raw:
        raise CredentialHandlingError("empty material has no credential fingerprint")
    digest = hmac.new(key, raw, hashlib.sha256).hexdigest()[:_FINGERPRINT_HEX]
    return f"{FINGERPRINT_PREFIX}-{digest}"


def is_fingerprint(value: str) -> bool:
    """Whether a string has the shape this module produces. Used to refuse anything else."""
    return bool(_FINGERPRINT_RE.match(value))


class SecretReference(BaseModel):
    """A pointer to credential material, holding none of it.

    What it carries is what correlation and provenance need: a keyed fingerprint so two
    sightings can be recognised as one credential, the length so an analyst can tell a
    four-character PIN from a private key, and the evidence id under which the raw bytes were
    sealed. What it does not carry is the material, and there is no field it could go in.

    ``vault_evidence_id`` is how the raw bytes remain retrievable *by the evidence plane*, under
    that plane's own controls — content-addressed, quarantined before sealing, access recorded.
    A reference is not a read: holding this object gets you nothing out of the vault, and the
    vault does not consult it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    fingerprint: Annotated[str, Field(min_length=1, max_length=64)]
    byte_length: Annotated[int, Field(ge=1)]
    vault_evidence_id: str | None = None
    """Where the sealed bytes live, when they were sealed at all.

    ``None`` is a legitimate and common answer: material classified
    :attr:`~nemesis.core.evidence.ContentSafety.MANDATORY_REPORT` never reaches the vault, and a
    deployment may decide not to retain a third party's password at all. A reference with no
    vault id still correlates and still carries provenance — which is the point of separating
    the reference from the material.
    """

    @model_validator(mode="after")
    def _refuse_anything_that_is_not_a_fingerprint(self) -> Self:
        if not is_fingerprint(self.fingerprint):
            raise CredentialHandlingError(
                f"{self.fingerprint!r} is not a keyed credential fingerprint. This field is the "
                "one place a caller could paste the secret itself, so it accepts only the "
                "output of fingerprint()"
            )
        return self


def _is_masked(preview: str, *, material_length: int) -> bool:
    """Whether a preview shows a shape rather than a secret.

    Counted rather than pattern-matched: a regex over known token prefixes would pass ``ghp_``
    and fail an unfamiliar vendor's format, which is the wrong direction for a guard whose
    failure mode is storing a live credential.

    **Two bounds, and the second was missing.** A fixed ceiling of
    :data:`MAX_UNMASKED_PREVIEW_CHARS` is right for a long token and useless for a short one: an
    adversarial review pointed out that any credential of six characters or fewer passed
    *intact*, so ``1234``, ``hunter`` and ``123456`` were accepted whole into a field whose
    validator says "not so the credential can be reconstructed from the record that was supposed
    to redact it". PINs, six-digit one-time codes and short reused passwords are precisely
    :attr:`CredentialKind.LEAKED_PASSWORD`'s domain.

    So a preview must also reveal strictly **less** than the material it previews. A four-byte
    credential gets at most three unmasked characters; a forty-byte one still gets six.
    """
    unmasked = sum(1 for char in preview if char not in _MASK_CHARS)
    return unmasked <= MAX_UNMASKED_PREVIEW_CHARS and unmasked < material_length


class CredentialIndicator(BaseModel):
    """The fact that authentication material of some kind was observed somewhere.

    An observation about the adversary, at the same standing as any other observation and with
    the same provenance requirements (invariant 3). It is deliberately dull: a kind, a
    reference, where it was seen, and a masked preview an analyst can eyeball. It asserts
    nothing about who the credential belongs to, and it confers nothing on whoever holds it.

    ``service_hint`` is the one field pointing outward, and it is bounded on purpose: the
    *service* a credential is for is ordinary infrastructure intelligence — a domain, a panel
    URL host, a provider name — while the *account* it belongs to is a digital identity and
    frequently a natural person's. So the hint names the service and there is no field for the
    account, which is the same asymmetry the disclosure wall draws everywhere else.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: CredentialKind
    reference: SecretReference
    observed_at: datetime
    observed_in_evidence_id: Annotated[str, Field(min_length=1)]
    """The artifact this was found in. Required, not optional: a credential indicator with no
    derivation chain back to collected material is an assertion, and invariant 3 does not admit
    one."""

    service_hint: Annotated[str, Field(max_length=253)] = ""
    masked_preview: Annotated[str, Field(max_length=MAX_PREVIEW_LENGTH)] = ""

    @model_validator(mode="after")
    def _require_utc_and_a_masked_preview(self) -> Self:
        require_utc(self.observed_at, "observed_at")
        if self.masked_preview and not _is_masked(
            self.masked_preview, material_length=self.reference.byte_length
        ):
            raise CredentialHandlingError(
                f"masked_preview {self.masked_preview!r} reveals too much of a "
                f"{self.reference.byte_length}-byte credential: a preview may show at most "
                f"{MAX_UNMASKED_PREVIEW_CHARS} unmasked characters and must always show fewer "
                "than the material has. A preview exists so a human can recognise a format, not "
                "so the credential can be reconstructed from the record that was supposed to "
                "redact it"
            )
        return self

    @property
    def natural_key(self) -> str:
        """The graph identity of this credential: its kind and its fingerprint, never its value.

        This is what :func:`~nemesis.core.entities.normalize_identifier` accepts for a
        ``CREDENTIAL_INDICATOR`` node, and the reason that function refuses anything else. A
        node keyed on the credential would put the credential in every edge, every audit line
        and every projection that names the node.
        """
        return f"{self.kind.value}:{self.reference.fingerprint}"


CREDENTIAL_MATERIAL_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "private key block",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?=-----END|\Z)", re.DOTALL),
    ),
    ("aws access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b")),
    ("slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("anthropic key", re.compile(r"\bsk-ant-[0-9A-Za-z_-]{20,}\b")),
    ("openai key", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("google api key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("bearer token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    (
        "url embedded credentials",
        re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@"),
    ),
    (
        "assigned secret",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|pass|secret|api[_-]?key|access[_-]?token|"
            r"private[_-]?key|credentials?)\b"
            r"\s*(?:[:=]|\bis\b|\bare\b)\s*"
            r"\S{4,}"
        ),
    ),
)
"""Shapes that look like live authentication material in free text.

A blunt instrument, and it says so — the same honesty
:data:`~nemesis.core.disclosure.INTERNAL_MARKERS` and
:data:`~nemesis.evolution.memory.INSTRUCTION_PATTERNS` apply to themselves. It catches the
recognisable vendor formats and the ``password = ...`` shape. It does not catch a bare
high-entropy string, because nothing distinguishes one from a malware hash, and a guard that
redacted every long token would redact the evidence.

Its job is the *accidental* path: a collector, a claim's natural-language text or an effect
parameter carrying a live token onward into a briefing, a document or a channel. It is not the
control that keeps credentials out of those places — the RESTRICTED disclosure class is — it is
the backstop for material that never got typed as a credential in the first place.

**The length bound was wrong and the docstring example proved it.** The ``assigned secret``
pattern required eight non-space characters, and this module motivated the whole function with
``password = hunter2`` — which is seven, and did not match. An adversarial review noticed that the
example did not work. Four is the bound now, with ``pass``, ``credentials`` and the ``is``/``are``
forms added, because ``the password is hunter2`` and ``pwd=abc123`` are the shapes a forum post
actually uses. A short assigned value is still a secret; ``password = true`` in a config file
being redacted is a cost worth paying, and cheaper than the reverse.
"""

CREDENTIAL_REDACTION: Final = "[redacted-credential]"


def credential_shapes(text: str) -> tuple[str, ...]:
    """Which credential shapes this text matches. Empty means none of them did.

    Names the shapes rather than returning a boolean, for the reason
    :func:`~nemesis.evolution.memory.reads_as_an_instruction` does: an operator has to be able
    to argue with a finding, and "something in here looked like a secret" is not arguable.
    """
    return tuple(name for name, pattern in CREDENTIAL_MATERIAL_PATTERNS if pattern.search(text))


def redact_credential_material(text: str) -> str:
    """Replace anything credential-shaped with a fixed token.

    Redaction, not refusal, and the choice is the one this codebase has already made twice — for
    an entity's natural key in :mod:`nemesis.pilot.mediator` and for an untrusted hint in
    :mod:`nemesis.evolution.memory`. The text this runs over is adversary-reachable: a forum post
    can contain ``password = hunter2``. Treating that as a violation would hand anyone who can
    write into a collected page a way to halt an investigation, which is a denial of service
    dressed as a control.

    The token is fixed-length and shorter than any pattern it can replace, so redaction never
    lengthens a string past a bound that was checked before it ran.
    """
    redacted = text
    for _, pattern in CREDENTIAL_MATERIAL_PATTERNS:
        redacted = pattern.sub(CREDENTIAL_REDACTION, redacted)
    return redacted


__all__ = [
    "CREDENTIAL_MATERIAL_PATTERNS",
    "CREDENTIAL_REDACTION",
    "FINGERPRINT_PREFIX",
    "MAX_PREVIEW_LENGTH",
    "MAX_UNMASKED_PREVIEW_CHARS",
    "MIN_FINGERPRINT_KEY_BYTES",
    "CredentialHandlingError",
    "CredentialIndicator",
    "CredentialKind",
    "SecretReference",
    "credential_shapes",
    "fingerprint",
    "is_fingerprint",
    "redact_credential_material",
]
