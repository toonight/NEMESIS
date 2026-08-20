"""Who did something, established rather than claimed.

The gateway used to take an actor id and a role as strings supplied by whoever was calling.
Dual control therefore meant *two distinct strings*, and an audit trail recorded the name
the caller typed rather than the person who acted. Nothing behind either was checked.

A :class:`Principal` is the opposite: an identity that has been **established** by an
identity provider, carrying what that establishment was worth. It cannot be constructed
from a bare string by ordinary calling code — not because the constructor is hidden, but
because it carries an assurance level and a provider name that a caller inventing a
principal would have to invent too, visibly, in the audit record.

The control that matters is :data:`MINIMUM_ASSURANCE`. A development identity can approve a
simulation and nothing else. That is what turns "we have no real authentication yet" from a
paragraph in a document into a refusal at runtime — and it is the reason this module exists
in a system that has no identity provider to speak of.
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Annotated, Final, Self

from pydantic import BaseModel, ConfigDict, Field

from nemesis.core.canonical import canonical_bytes
from nemesis.core.ids import ActorId


class AssuranceLevel(IntEnum):
    """How much the claim "this is who they say they are" is worth.

    An ``IntEnum`` because these are ordered and the ordering is used: a floor is a
    comparison, and expressing it as one keeps the policy readable.
    """

    DEVELOPMENT = 0
    """No authentication happened. A local fixture identity, for tests and demonstrations.

    Deliberately the lowest value so that every floor above zero excludes it. A deployment
    that reaches production with development principals will refuse to authorize anything
    beyond simulation rather than silently accepting them."""

    SINGLE_FACTOR = 1
    """A password, an API token — something the person knows or holds, once."""

    MULTI_FACTOR = 2
    """Two independent factors."""

    HARDWARE_BACKED = 3
    """A factor bound to hardware the person physically holds: a security key, a smartcard.

    The level at which "somebody phished the approver" stops being the cheapest attack on
    the authorization chain."""


class Role(StrEnum):
    """What a person is entitled to do. Checked by the gateway, never accepted from a caller."""

    ANALYST = "analyst"
    """Runs investigations. May request an operation; may not approve one."""

    INVESTIGATION_LEAD = "investigation_lead"
    """May approve reversible, internal operation classes."""

    LEGAL_REVIEWER = "legal_reviewer"
    """May approve operations that need a legal basis, which the lead alone cannot."""

    OPERATOR = "operator"
    """May execute an approved operation. Distinct from approving it on purpose: the person
    who decides and the person who acts should be able to be different people."""

    AUDITOR = "auditor"
    """Reads everything, approves nothing, executes nothing. Separated so that oversight
    does not require the ability to act."""


DEFAULT_TENANT: Final = "tenant:single"
"""The tenant of a deployment that serves one customer.

A named sentinel rather than ``None``, so every code path handles a real value and the
single-customer case is the degenerate case of the general one rather than a separate branch
somebody forgets. A deployment serving more than one customer registers an issuer per tenant;
see :class:`~nemesis.authz.attestation.RegisteredIssuer`.
"""


class Principal(BaseModel):
    """An identity that was established, with what the establishment was worth.

    Frozen, and carrying its own provenance: which provider vouched for it, when, and at
    what assurance. A principal with no provider is not an identity, it is a claim.
    """

    model_config = ConfigDict(frozen=True)

    actor_id: ActorId
    display_name: Annotated[str, Field(min_length=1, max_length=200)]
    roles: frozenset[Role]
    assurance: AssuranceLevel

    authenticated_by: Annotated[str, Field(min_length=1)]
    """The provider that established this. Recorded in the audit trail, so a reader can see
    that an approval rests on a development fixture rather than on a real login."""

    authenticated_at: datetime
    session_id: str | None = None

    tenant: Annotated[str, Field(min_length=1)] = DEFAULT_TENANT
    """Which customer's intelligence this principal may touch.

    **Established by the deployment, never claimed by the caller.** It comes from the
    registered issuer that vouched for this identity — the same place the assurance ceiling
    comes from, and for the same reason: a value a caller supplies is a value an attacker
    supplies. An assertion carrying its own tenant field would let anyone address anyone
    else's graph by editing one string.
    """

    def has(self, role: Role) -> bool:
        return role in self.roles

    @property
    def is_development_identity(self) -> bool:
        return self.assurance is AssuranceLevel.DEVELOPMENT

    def describe(self) -> str:
        """One line for an audit record or a refusal."""
        roles = ", ".join(sorted(role.value for role in self.roles)) or "no roles"
        return (
            f"{self.display_name} ({self.actor_id}) — {roles}; "
            f"assurance {self.assurance.name.lower()} via {self.authenticated_by}"
        )


class IdentityAssertion(BaseModel):
    """A signed statement by an issuer that a person is who they say, at a stated strength.

    The reason this exists: a :class:`Principal` is an ordinary model, so any caller can
    build one claiming ``HARDWARE_BACKED`` assurance from an issuer called
    ``corporate-sso``. An audit reproduced exactly that and the gateway issued a genuine
    Ed25519 capability on top of it. The signature protected the claim from later edits and
    proved nothing about whether it was ever true.

    An assertion closes that by being **verifiable**: it carries an issuer, an audience, a
    validity window and a signature over its own canonical bytes. The gateway accepts a
    principal only when it arrives inside one of these and the verifier accepts it against
    an allowlist of issuers.

    This is deliberately not an OIDC implementation and does not pretend to be one. It is
    the shape an OIDC id-token would arrive in, so that wiring a real provider is a matter
    of implementing one verifier rather than rewriting the gateway.
    """

    model_config = ConfigDict(frozen=True)

    issuer: Annotated[str, Field(min_length=1)]
    subject: ActorId
    audience: Annotated[str, Field(min_length=1)]
    """Who the assertion was minted for. An assertion issued for another audience is not
    evidence here — that is what stops a token obtained elsewhere being replayed at us."""

    display_name: Annotated[str, Field(min_length=1, max_length=200)]
    roles: frozenset[Role]
    assurance: AssuranceLevel

    authenticated_at: datetime
    expires_at: datetime
    assertion_id: Annotated[str, Field(min_length=1)]
    """Unique per assertion, and signed.

    **Nothing currently keeps the set of spent ids**, and that is deliberate rather than
    forgotten: an assertion here is a session token presented on every gateway call, not a
    one-time code, so refusing a second presentation would refuse the second approval of the
    same login. Replay protection at this layer needs a nonce the relying party issues, and
    NEMESIS has no such exchange because it has no real identity provider.

    The consequence is that possession of a signed assertion is the ability to act as that
    person until it expires. In-process that changes nothing — anyone who can read one can
    already call the gateway — and it becomes a real exposure the day assertions cross a
    process or a network. Recorded as a gap in the threat model rather than papered over
    with a cache that would break the first honest caller."""

    signature: str | None = None

    def signing_payload(self) -> bytes:
        """The exact bytes the issuer signs: this assertion, whole.

        Everything except the signature. Enumerating fields by hand is how the previous
        version was broken — a role signed as ``role.value`` while the policy compared role
        objects let an assertion render as ``analyst`` and establish a ``legal_reviewer``.
        See :mod:`nemesis.core.canonical`.
        """
        return canonical_bytes(self.model_dump(mode="json", exclude={"signature"}))

    @classmethod
    def from_signed_payload(cls, payload: bytes) -> Self:
        """Reconstruct what the issuer actually asserted.

        A verifier must use this rather than the object it was handed: the signature proves
        only that the issuer produced these bytes, and the object beside them is whatever
        the caller chose to build.
        """
        rebuilt = cls.model_validate(json.loads(payload))
        if rebuilt.signing_payload() != payload:
            # The bytes parse, but they are not the canonical encoding of what they parse
            # to. Today no such bytes exist — the only source of a valid signature is
            # `signing_payload()` on a validated model — and the day a signature arrives
            # from a second implementation, a wire format or an HSM that signs a
            # caller-supplied buffer, this is what stops `{"max_targets":1,"max_targets":9999}`
            # from parsing as 9999 while the reader believed it signed 1.
            raise ValueError(
                "signed bytes are not the canonical encoding of the assertion they parse to; "
                "duplicate keys, unknown fields or a non-canonical ordering would let two "
                "readers disagree about what was signed"
            )
        return rebuilt

    def to_principal(self) -> Principal:
        """The principal this assertion establishes. Only a verifier should call this."""
        return Principal(
            actor_id=self.subject,
            display_name=self.display_name,
            roles=self.roles,
            assurance=self.assurance,
            authenticated_by=self.issuer,
            authenticated_at=self.authenticated_at,
            session_id=self.assertion_id,
        )
