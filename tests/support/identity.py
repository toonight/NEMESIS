"""Identity fixtures for tests that need an approver above the development floor.

Several tests exercise operation classes that a development identity may not authorize —
that refusal is a control, and it is tested on its own elsewhere. Those tests need an
identity established more strongly, and how they get one matters.

The wrong way, which these tests used to use, is ``principal.model_copy(update={"assurance":
HARDWARE_BACKED})``. It works because a :class:`~nemesis.core.identity.Principal` is an
ordinary model — which was precisely the bypass an audit walked through to obtain a real
signed capability. A test suite that relies on the bypass cannot notice when it is closed,
and a test helper that edits an assurance field is a working exploit shipped as a fixture.

The right way is the one a deployment would use: register a second issuer, and have the
deployment state what that issuer's word is worth. :func:`hardware_backed_issuer` returns a
provider whose assertions the verifier will honour up to ``HARDWARE_BACKED`` — because the
registration says so, not because a field was overwritten. Nothing here can raise an
identity above what its issuer is registered for.
"""

from __future__ import annotations

from nemesis.authz.attestation import PrincipalVerifier, RegisteredIssuer
from nemesis.authz.providers import LocalDevelopmentIdentityProvider
from nemesis.core.identity import AssuranceLevel, IdentityAssertion, Role

ELEVATED_ISSUER_NAME = "test-fixture-hardware-backed"
"""Named so that an audit record produced in a test is never mistaken for a real login."""


def hardware_backed_issuer() -> tuple[LocalDevelopmentIdentityProvider, RegisteredIssuer]:
    """A fixture issuer this deployment (the test suite) trusts up to hardware-backed."""
    provider = LocalDevelopmentIdentityProvider(name=ELEVATED_ISSUER_NAME)
    return provider, RegisteredIssuer(
        name=provider.name,
        verifier=provider.verifying_key,
        assurance_ceiling=AssuranceLevel.HARDWARE_BACKED,
    )


def elevated(
    provider: LocalDevelopmentIdentityProvider,
    display_name: str,
    *roles: Role,
    subject: str | None = None,
) -> IdentityAssertion:
    """Mint an assertion claiming hardware-backed assurance.

    Honoured only if ``provider`` is registered with a ceiling that high. Pass a plain
    development provider and the verifier will hand back a ``DEVELOPMENT`` principal.

    ``subject`` re-establishes a person already known under another issuer, so that "the
    same human, authenticated more strongly" stays the same actor id in the audit record.
    """
    return provider.enrol(
        display_name, *roles, claimed=AssuranceLevel.HARDWARE_BACKED, subject=subject
    )


def verifier_over(*providers: LocalDevelopmentIdentityProvider) -> PrincipalVerifier:
    """A verifier trusting the development provider, plus any elevated fixture issuers."""
    return PrincipalVerifier(
        *(
            RegisteredIssuer(
                name=provider.name,
                verifier=provider.verifying_key,
                assurance_ceiling=(
                    AssuranceLevel.HARDWARE_BACKED
                    if provider.name == ELEVATED_ISSUER_NAME
                    else AssuranceLevel.DEVELOPMENT
                ),
            )
            for provider in providers
        )
    )
