"""One customer's intelligence must not reach another's, and not because of a filter.

The write path landed everything in one graph, which is why it was recorded as not-a-product.
These tests are about the boundary that fixes it, and about the two ways a tenancy boundary is
normally hollow:

- **The caller picks their own tenant.** If the tenant comes from anything the request
  carries — a header, a body field, a claim inside the assertion — then one edited string
  reaches another customer's graph. Here it is stamped from the *registered issuer*, which is
  deployment configuration, and a test proves an assertion cannot override it.
- **A query forgets the filter.** The rejected design is a `tenant_id` column checked
  everywhere; it fails silently the first time somebody omits it. Here a component holds the
  store for its tenant and no other, so there is no query that could reach across — which is
  what `test_a_tenant_cannot_even_name_another_tenants_store` is really asserting.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from nemesis.api.app import InvestigationView, build_app
from nemesis.api.tenancy import TenantIsolationError, TenantStores
from nemesis.authz.attestation import PrincipalVerifier, RegisteredIssuer
from nemesis.authz.providers import PROVIDER_NAME, LocalDevelopmentIdentityProvider
from nemesis.core.identity import DEFAULT_TENANT, AssuranceLevel, Role
from nemesis.graph.memory import InMemoryClaimStore
from nemesis.ports.storage import ClaimStore
from nemesis.slice.scenario import ScenarioResult, run_glass_anvil_scenario

pytestmark = pytest.mark.invariant

ACME = "tenant:acme"
INITECH = "tenant:initech"


def _issuer(provider: LocalDevelopmentIdentityProvider, tenant: str) -> RegisteredIssuer:
    return RegisteredIssuer(
        name=provider.name,
        verifier=provider.verifying_key,
        assurance_ceiling=AssuranceLevel.DEVELOPMENT,
        tenant=tenant,
    )


ACME_IDP = LocalDevelopmentIdentityProvider(name="acme-sso")
INITECH_IDP = LocalDevelopmentIdentityProvider(name="initech-sso")
VERIFIER = PrincipalVerifier(_issuer(ACME_IDP, ACME), _issuer(INITECH_IDP, INITECH))


def _credential(provider: LocalDevelopmentIdentityProvider) -> dict[str, str]:
    assertion = provider.enrol("Ada", Role.ANALYST)
    return {"Authorization": f"Assertion {assertion.model_dump_json()}"}


@pytest.fixture(scope="module")
def result(tmp_path_factory: pytest.TempPathFactory) -> ScenarioResult:
    return run_glass_anvil_scenario(workspace=tmp_path_factory.mktemp("tenancy"))


def _app(result: ScenarioResult, stores: TenantStores[ClaimStore]) -> TestClient:
    view = InvestigationView(
        stages=(),
        attribution=result.attribute.result,
        names_a_person=result.attribute.result.names_a_person,
        entity_count=0,
        relationship_count=0,
        evidence_sealed=0,
    )
    return TestClient(
        build_app(
            investigation=view,
            verifier=VERIFIER,
            provider_name=PROVIDER_NAME,
            claims=stores,
        )
    )


def _body(key: str) -> dict[str, object]:
    return {
        "entity_type": "domain",
        "entity_key": key,
        "observed_at": "2026-08-17T00:00:00+00:00",
        "summary": "reported",
    }


# --- The tenant is deployment configuration, not a caller's word --------------


def test_the_tenant_comes_from_the_issuer_and_not_from_the_assertion() -> None:
    """THE TEST THIS FILE EXISTS FOR.

    If the tenant were carried in the assertion it would be a caller-supplied value, and a
    caller-supplied value is an attacker-supplied one. It is stamped from the registered
    issuer instead — the same place, and the same reasoning, as the assurance ceiling.
    """
    acme = VERIFIER.verify(ACME_IDP.enrol("Ada", Role.ANALYST))
    initech = VERIFIER.verify(INITECH_IDP.enrol("Ada", Role.ANALYST))

    assert acme.tenant == ACME
    assert initech.tenant == INITECH
    # Same display name, same roles, same provider software — different tenant, because a
    # different issuer vouched.
    assert acme.display_name == initech.display_name


def test_an_unregistered_issuer_yields_no_identity_at_all() -> None:
    """There is no way to hold an identity for a tenant nobody configured."""
    stranger = LocalDevelopmentIdentityProvider(name="somebody-elses-sso")

    with pytest.raises(Exception) as refused:
        VERIFIER.verify(stranger.enrol("Mallory", Role.ANALYST))
    assert "issuer" in str(refused.value).lower()


# --- One store per tenant, with nothing that could reach across ---------------


def test_a_tenant_cannot_even_name_another_tenants_store() -> None:
    """The structural claim, and the reason this is not a filter.

    `for_principal` takes a Principal rather than a tenant string, so there is no call a route
    could make with a value from a header. A component holds the store for its tenant and no
    reference to any other — there is no query to forget a filter on, because there is no
    query that could reach across.
    """
    stores: TenantStores[InMemoryClaimStore] = TenantStores(lambda _: InMemoryClaimStore())
    acme = VERIFIER.verify(ACME_IDP.enrol("Ada", Role.ANALYST))
    initech = VERIFIER.verify(INITECH_IDP.enrol("Bob", Role.ANALYST))

    assert stores.for_principal(acme) is not stores.for_principal(initech)

    # And the only way to reach a store from a request path takes a verified Principal. A
    # method accepting a tenant *string* would be one a route could call with a header value,
    # and the header is the attack — so the signature is the control.
    # Behavioural rather than by signature: a raw tenant name — the shape a header value
    # would arrive in — cannot be spent here at all. Checking the annotation would only prove
    # what the code *says*; this proves what it does.
    with pytest.raises(AttributeError):
        stores.for_principal(INITECH)  # type: ignore[arg-type]

    import inspect

    assert list(inspect.signature(stores.for_principal).parameters) == ["principal"], (
        "for_principal grew a parameter; if any of them can carry a tenant name from a "
        "request, the boundary is a filter again"
    )


def test_submissions_from_two_tenants_do_not_meet(result: ScenarioResult) -> None:
    stores: TenantStores[ClaimStore] = TenantStores(lambda _: InMemoryClaimStore())
    client = _app(result, stores)

    acme_response = client.post(
        "/submissions", json=_body("acme-only.example"), headers=_credential(ACME_IDP)
    )
    initech_response = client.post(
        "/submissions", json=_body("initech-only.example"), headers=_credential(INITECH_IDP)
    )
    assert acme_response.status_code == 201
    assert initech_response.status_code == 201

    acme_store = stores.register(ACME)
    initech_store = stores.register(INITECH)

    acme_claim = asyncio.run(acme_store.get(acme_response.json()["claim_id"]))
    assert acme_claim is not None, "the submission did not reach its own tenant's store"

    crossed = asyncio.run(initech_store.get(acme_response.json()["claim_id"]))
    assert crossed is None, "one customer's submission was readable from another's store"


def test_strict_mode_refuses_a_tenant_nobody_registered() -> None:
    """A multi-customer deployment must not silently mint a private graph for any identity
    that turns up. A single-customer one wants exactly that, which is why it is a flag and
    why the flag is named."""
    lenient: TenantStores[InMemoryClaimStore] = TenantStores(lambda _: InMemoryClaimStore())
    strict: TenantStores[InMemoryClaimStore] = TenantStores(
        lambda _: InMemoryClaimStore(), strict=True
    )
    acme = VERIFIER.verify(ACME_IDP.enrol("Ada", Role.ANALYST))

    assert lenient.for_principal(acme) is not None

    with pytest.raises(TenantIsolationError):
        strict.for_principal(acme)

    strict.register(ACME)
    assert strict.for_principal(acme) is not None


def test_a_refused_tenant_is_a_403_and_not_a_500(result: ScenarioResult) -> None:
    """A configuration refusal an operator can read, not an outage they have to diagnose."""
    stores: TenantStores[ClaimStore] = TenantStores(lambda _: InMemoryClaimStore(), strict=True)
    stores.register(ACME)
    client = _app(result, stores)

    served = client.post("/submissions", json=_body("a.example"), headers=_credential(ACME_IDP))
    unserved = client.post(
        "/submissions", json=_body("b.example"), headers=_credential(INITECH_IDP)
    )

    assert served.status_code == 201
    assert unserved.status_code == 403
    assert "no store is registered" in unserved.json()["detail"]


# --- The single-customer case is the degenerate case, not a separate branch ----


def test_a_single_tenant_deployment_still_works() -> None:
    """A named sentinel rather than None, so every path handles a real value and nobody
    writes the "no tenant" branch that later diverges."""
    provider = LocalDevelopmentIdentityProvider()
    verifier = PrincipalVerifier(provider.registered_issuer())

    principal = verifier.verify(provider.enrol("Ada", Role.ANALYST))

    assert principal.tenant == DEFAULT_TENANT


def test_a_registry_says_whether_it_is_actually_multi_tenant() -> None:
    """A deployment that believes it is multi-tenant and serves one has an untested isolation
    boundary; one that believes it is single-tenant while serving several has none."""
    stores: TenantStores[InMemoryClaimStore] = TenantStores(lambda _: InMemoryClaimStore())

    stores.register(DEFAULT_TENANT)
    assert stores.is_multi_tenant() is False

    stores.register(ACME)
    assert stores.is_multi_tenant() is True
    assert stores.served == {DEFAULT_TENANT, ACME}
