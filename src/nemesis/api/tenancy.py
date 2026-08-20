"""Keeping one customer's intelligence out of another's, structurally.

The write path landed everything in one graph, which is exactly the reason it was recorded as
not-a-product: a deployment serving two customers would let each write into the other's
intelligence and read it back. This closes that, and the shape of the fix matters more than
the fix.

**The rejected design: a ``tenant_id`` column and a filter on every query.** It works until
somebody writes a query without the filter, and then it fails silently and completely. This
codebase has spent its whole life rejecting that pattern — the read blocklist that was
"incomplete by construction", the disclosure markers that catch a token and not an idea — and
a tenancy filter is the same shape with worse consequences.

**What is here instead: one store per tenant.** A component is handed the store for its
tenant and holds no reference to any other, so it cannot address another customer's data
because it has no way to *name* it. There is no filter to forget, because there is no query
that could reach across.

**And the tenant is never supplied by the caller.** It is stamped onto the
:class:`~nemesis.core.identity.Principal` by
:class:`~nemesis.authz.attestation.PrincipalVerifier`, from the *registered issuer* — the same
place the assurance ceiling comes from, and for the same reason. An assertion carrying its own
tenant field would be a caller-supplied value, and a caller-supplied value is an
attacker-supplied one: a single edited string and they are in another customer's graph.
Registering a second issuer for a second tenant is therefore the whole of multi-tenant
configuration, and there is no way to obtain an identity for a tenant nobody registered.

**Honest scope.** This isolates the *stores this registry hands out*. It is not a guarantee
about a shared SQLite file, an operator with disk access, or a bug in a store implementation
that leaks across its own instances — the vault operator has always been in the threat model
and remains there. What it removes is the entire class of "somebody forgot the WHERE clause",
which is the one that actually happens.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from nemesis.core.identity import DEFAULT_TENANT, Principal

UNREGISTERED_TENANT_REFUSAL: Final = (
    "no store is registered for this principal's tenant. A deployment serving a customer "
    "registers that customer's issuer and its stores together; an identity for a tenant "
    "nobody configured is an identity this deployment cannot serve"
)


class TenantIsolationError(RuntimeError):
    """A principal asked for a tenant this deployment does not serve.

    Its own type because it is a configuration refusal rather than an outage, and a caller
    catching "the store is unavailable" must not swallow "this identity belongs to nobody
    we serve".
    """


class TenantStores[StoreT]:
    """One store per tenant, handed out by verified identity and nothing else.

    ``factory`` builds a fresh store the first time a tenant is served, so a deployment does
    not have to enumerate its customers at construction. Creation is the *only* way a tenant
    enters the registry, and ``strict`` decides whether an unknown tenant may create one:
    a single-customer deployment wants that, a multi-customer one must not have it, because
    then any identity from any issuer silently gets a private graph rather than being refused.
    """

    def __init__(
        self,
        factory: Callable[[str], StoreT],
        *,
        strict: bool = False,
    ) -> None:
        self._factory = factory
        self._strict = strict
        self._stores: dict[str, StoreT] = {}

    def register(self, tenant: str) -> StoreT:
        """Serve a tenant from now on, and return its store."""
        if tenant not in self._stores:
            self._stores[tenant] = self._factory(tenant)
        return self._stores[tenant]

    def for_principal(self, principal: Principal) -> StoreT:
        """The store this principal may touch, and the only one it can reach.

        Takes a :class:`Principal` rather than a tenant string on purpose. A function that
        accepted a tenant name would be one a route could call with a value from a header, and
        the header is the attack. The only tenant reachable here is the one the verifier
        stamped from the registered issuer.
        """
        tenant = principal.tenant
        if tenant not in self._stores:
            if self._strict:
                raise TenantIsolationError(UNREGISTERED_TENANT_REFUSAL)
            self._stores[tenant] = self._factory(tenant)
        return self._stores[tenant]

    @property
    def served(self) -> frozenset[str]:
        return frozenset(self._stores)

    def is_multi_tenant(self) -> bool:
        """Whether this deployment actually serves more than the single-customer case.

        Worth asking out loud: a deployment that believes it is multi-tenant and serves one
        tenant has an untested isolation boundary, and one that believes it is single-tenant
        while serving several has no boundary at all.
        """
        return self.served - {DEFAULT_TENANT} != frozenset()


__all__ = [
    "UNREGISTERED_TENANT_REFUSAL",
    "TenantIsolationError",
    "TenantStores",
]
