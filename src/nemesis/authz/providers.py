"""Identity providers. One, and it refuses to pretend it is more than it is.

There is no directory, no OIDC client and no credential store in this repository, and this
module does not simulate one. What it offers is a **local development provider** that
stamps every principal it issues with :attr:`AssuranceLevel.DEVELOPMENT`, so that the
policy in :mod:`nemesis.authz.rbac` refuses those principals for anything beyond a
rehearsal.

That refusal is the design. A convincing fake authenticator is worse than none: it produces
audit records that look like logins, approvals that look reviewed, and a system that reads
as authenticated to everybody except the person who wrote it. This provider is impossible
to mistake for real, on purpose — its name appears in every principal it issues and in
every audit entry those principals touch.
"""

from __future__ import annotations

from datetime import timedelta

from nemesis.authz.attestation import AUDIENCE, RegisteredIssuer
from nemesis.authz.keys import CapabilitySigningKey, CapabilityVerifyingKey
from nemesis.core.identity import AssuranceLevel, IdentityAssertion, Principal, Role
from nemesis.core.ids import ActorId, IdPrefix, new_id
from nemesis.core.temporal import utcnow
from nemesis.ports.identity import AuthenticationError

PROVIDER_NAME = "local-development-fixture"

ASSERTION_LIFETIME = timedelta(hours=8)
"""How long a development assertion stands. A login is not permanent."""


class LocalDevelopmentIdentityProvider:
    """Hands out development identities for tests and the demonstration.

    Satisfies :class:`~nemesis.ports.identity.IdentityProvider`. It authenticates nothing:
    a credential here is a name, and presenting a name is not proof of anything. Every
    principal it issues is capped at ``DEVELOPMENT`` assurance and therefore cannot approve
    an operation that leaves the system.
    """

    def __init__(
        self, signing_key: CapabilitySigningKey | None = None, *, name: str = PROVIDER_NAME
    ) -> None:
        """``name`` exists for tests that need a second, distinguishable issuer.

        Renaming buys nothing on its own: what an issuer's word is worth is decided by the
        deployment when it registers the issuer with a ceiling, not by the issuer's name.
        """
        self.name = name
        self._signing_key = signing_key or CapabilitySigningKey.generate()
        self._people: dict[str, Principal] = {}
        self._assertions: dict[str, IdentityAssertion] = {}

    @property
    def verifying_key(self) -> CapabilityVerifyingKey:
        return self._signing_key.verifying_key

    def registered_issuer(self) -> RegisteredIssuer:
        """How a deployment registers this provider: capped at DEVELOPMENT, always.

        The ceiling lives with the registration rather than with the provider, so a
        deployment decides what an issuer's word is worth here. This one is worth a
        rehearsal.
        """
        return RegisteredIssuer(
            name=self.name,
            verifier=self.verifying_key,
            assurance_ceiling=AssuranceLevel.DEVELOPMENT,
        )

    def enrol(
        self,
        display_name: str,
        *roles: Role,
        claimed: AssuranceLevel | None = None,
        subject: ActorId | None = None,
        audience: str = AUDIENCE,
    ) -> IdentityAssertion:
        """Mint a signed assertion. Not a registration flow; a fixture.

        ``claimed`` exists so a test can mint an assertion that OVERSTATES its assurance and
        watch the verifier cap it. There is no way for this provider to actually establish
        an identity more strongly than it does, which is the whole of what it is.

        ``audience`` exists so a test can mint a genuine assertion addressed to a different
        relying party and watch it be refused here. A real issuer serves several audiences;
        pretending otherwise would leave the audience check untested against the only case
        it is for, since a *tampered* audience now breaks the signature instead.

        ``subject`` lets a caller re-establish a known person — the same human arriving
        through a second channel — rather than minting a new one. Enrolling the same display
        name twice without it also keeps the same subject, because a directory in which
        logging in twice makes two people is not a directory.
        """
        known = self._assertions.get(display_name)
        assertion = IdentityAssertion(
            issuer=self.name,
            subject=subject or (known.subject if known else new_id(IdPrefix.ACTOR)),
            audience=audience,
            display_name=display_name,
            roles=frozenset(roles),
            assurance=claimed or AssuranceLevel.DEVELOPMENT,
            authenticated_at=utcnow(),
            expires_at=utcnow() + ASSERTION_LIFETIME,
            assertion_id=new_id(IdPrefix.ACTOR),
        )
        signed = assertion.model_copy(
            update={"signature": self._signing_key.sign(assertion.signing_payload())}
        )
        self._assertions[display_name] = signed
        self._people[display_name] = signed.to_principal()
        return signed

    def authenticate(self, credential: str) -> IdentityAssertion:
        """Return the enrolled identity with this name.

        No secret is checked, because there is none. The method exists so that call sites
        are written against the port rather than against this class, and so that replacing
        it with something real is a wiring change rather than a rewrite.
        """
        assertion = self._assertions.get(credential)
        if assertion is None:
            raise AuthenticationError("no identity established")
        return assertion

    def established(self, display_name: str) -> Principal:
        """What this provider *would* establish, ignoring the verifier's ceiling.

        For assertions about the fixture itself. Nothing in the authorization path may use
        this: the principal that counts is the one the verifier returns.
        """
        return self._people[display_name]

    def principal(self, actor_id: str) -> Principal | None:
        return next((item for item in self._people.values() if item.actor_id == actor_id), None)
