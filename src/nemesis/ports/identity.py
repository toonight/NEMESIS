"""Where an identity assertion comes from.

A provider does not produce principals. It produces **assertions**: signed statements that
somebody authenticated, at a stated strength, for a stated audience, until a stated time.
What those assertions establish is decided elsewhere, by
:class:`~nemesis.authz.attestation.PrincipalVerifier`, against an allowlist of issuers and a
per-issuer ceiling.

The split is the point. When a provider returned a :class:`Principal` directly, the
provider's own claim about its assurance was the last word, and any caller who could build
a Principal was indistinguishable from a provider. Now the issuing side states, and the
relying side decides — which is the shape every real federated identity protocol has, and
the reason swapping this fixture for an OIDC client is a new verifier rather than a rewrite.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from nemesis.core.identity import IdentityAssertion, Principal


class AuthenticationError(RuntimeError):
    """A credential did not establish an identity.

    Deliberately not carrying the reason to the caller. Distinguishing "no such account"
    from "wrong secret" is an account-enumeration oracle, and the gateway has no use for the
    difference: both mean no principal was established.
    """


@runtime_checkable
class IdentityProvider(Protocol):
    """Establishes who somebody is, and states what that establishment was worth."""

    @property
    def name(self) -> str:
        """Recorded inside every principal this provider issues."""
        ...

    def authenticate(self, credential: str) -> IdentityAssertion:
        """Return the signed assertion this credential yields.

        Raises :class:`AuthenticationError` when it establishes none. A provider must never
        assert a higher assurance than the credential actually supports — but a provider
        that lies is no longer catastrophic, because the verifier caps each issuer at what
        the deployment is willing to believe from it.
        """
        ...

    def principal(self, actor_id: str) -> Principal | None:
        """Look up an already-established identity, for audit rendering.

        Returns ``None`` rather than raising: a missing principal in a historical record is
        an ordinary fact about a person who has since left, not an error.
        """
        ...
