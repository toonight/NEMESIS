"""Turning an identity assertion into a principal the gateway may act on.

The gap this closes, reproduced by an audit: a :class:`Principal` is an ordinary model, so
a caller could construct one claiming ``HARDWARE_BACKED`` assurance from an issuer named
``corporate-sso``, hand it to the gateway, and receive a genuine Ed25519 capability. The
capability signature was authentic. What it attested was a claim nobody had checked.

A verifier is now the only route from an assertion to a principal, and it enforces four
things a self-declared object cannot:

1. **The issuer is on an allowlist.** An unknown issuer is refused, so inventing a
   provider name buys nothing.
2. **The assertion's own signature verifies** against that issuer's key.
3. **The audience is us.** A token minted for another relying party is not evidence here.
4. **The assurance is capped by the issuer**, not asserted by the assertion. This is the
   part that matters today: the development issuer is capped at ``DEVELOPMENT``, so an
   assertion from it claiming hardware-backed assurance is downgraded rather than believed.

No OIDC provider is simulated. There is exactly one registered issuer, it is the local
development one, and it is capped — which is a system that accepts development identities
for rehearsals and nothing else, stated as code rather than as a caveat.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from pydantic import ValidationError

from nemesis.core.identity import DEFAULT_TENANT, AssuranceLevel, IdentityAssertion, Principal
from nemesis.core.temporal import utcnow
from nemesis.ports.authorization import CapabilityVerifier

AUDIENCE = "nemesis-authorization-gateway"
"""What an assertion must be addressed to. A token minted for anything else is refused."""


class AttestationError(PermissionError):
    """An identity assertion did not establish a principal."""


@dataclass(frozen=True)
class RegisteredIssuer:
    """An issuer this deployment is willing to believe, and how far.

    ``assurance_ceiling`` is the control. An issuer states what it did; the deployment
    states what that issuer's word is worth here. When the two disagree the ceiling wins,
    so a provider cannot promote itself by claiming a stronger level.
    """

    name: str
    verifier: CapabilityVerifier
    assurance_ceiling: AssuranceLevel

    tenant: str = DEFAULT_TENANT
    """Which customer this issuer speaks for.

    The same control as ``assurance_ceiling``, applied to a different question. An issuer
    states who somebody is; the deployment states **whose data that identity may touch**. A
    tenant carried in the assertion instead would be a value the caller supplies, and a value
    the caller supplies is a value an attacker supplies — one edited string and they address
    another customer's graph.

    Registering a second issuer for a second tenant is therefore the whole of multi-tenant
    configuration, and there is no way to hold an identity for a tenant nobody registered.
    """


class PrincipalVerifier:
    """The only supported way to obtain a :class:`Principal`.

    A gateway constructed without one cannot decide anything, which is deliberate: the
    version that accepted a bare principal is the version an audit walked straight through.
    """

    def __init__(self, *issuers: RegisteredIssuer, audience: str = AUDIENCE) -> None:
        if not issuers:
            raise ValueError(
                "a verifier with no registered issuer would refuse everything; register the "
                "development issuer explicitly rather than leaving the set empty by accident"
            )
        self._issuers = {issuer.name: issuer for issuer in issuers}
        self._audience = audience

    @property
    def issuers(self) -> frozenset[str]:
        return frozenset(self._issuers)

    def verify(self, assertion: IdentityAssertion, *, now: datetime | None = None) -> Principal:
        """Establish a principal, or refuse and say why.

        The order is load-bearing. The object passed in is treated as an *envelope*: it is
        used to choose a candidate key and to carry the signature, and then it is discarded.
        Every field the policy will read comes from :meth:`IdentityAssertion.from_signed_payload`
        — the signed bytes, parsed back through the model's validators.

        An adversarial review is the reason. It built an assertion whose roles serialized as
        ``analyst`` and compared as ``legal_reviewer``: the bytes were identical, the
        issuer's signature was genuine, and the gateway recorded a legal review that had
        never happened. Checking fields on the delivered object is checking the attacker's
        copy of the statement.
        """
        moment = now or utcnow()

        candidate = self._issuers.get(assertion.issuer)
        if candidate is None:
            raise AttestationError(
                f"{assertion.issuer!r} is not an issuer this deployment accepts "
                f"(registered: {sorted(self._issuers)}). Naming a provider does not make it one."
            )

        payload = assertion.signing_payload()
        if assertion.signature is None or not candidate.verifier.verify(
            payload, assertion.signature
        ):
            raise AttestationError(
                f"the assertion's signature does not verify against {candidate.name}'s key"
            )

        # From here on the envelope is irrelevant: `stated` is what the issuer signed.
        try:
            stated = IdentityAssertion.from_signed_payload(payload)
        except (ValidationError, ValueError) as exc:
            raise AttestationError(
                f"the signed bytes are not a well-formed assertion: {exc}"
            ) from exc

        issuer = self._issuers.get(stated.issuer)
        if issuer is None or issuer.name != candidate.name:
            raise AttestationError(
                f"the signed bytes name issuer {stated.issuer!r}, which is not the issuer "
                f"whose key verified them ({candidate.name!r})"
            )

        if stated.audience != self._audience:
            raise AttestationError(
                f"assertion was minted for {stated.audience!r}, not for {self._audience!r}; "
                "a token obtained elsewhere is not evidence here"
            )

        if moment >= stated.expires_at:
            raise AttestationError(
                f"the assertion expired at {stated.expires_at.isoformat()}; an identity "
                "established long enough ago is a session, not a login"
            )

        principal = stated.to_principal()
        if principal.assurance > issuer.assurance_ceiling:
            # The issuer said more than this deployment is willing to believe from it. Cap
            # rather than refuse: the identity is real, its strength is overstated, and
            # downgrading is the honest reading of both facts.
            principal = principal.model_copy(update={"assurance": issuer.assurance_ceiling})

        # The tenant is stamped here, from the registered issuer, and is not read from the
        # assertion at all. Same place and same reasoning as the ceiling above: an issuer
        # states who somebody is, and the deployment states whose data that identity may
        # touch. Taken from the assertion it would be a caller-supplied value, and one edited
        # string would address another customer's graph.
        return principal.model_copy(update={"tenant": issuer.tenant})
