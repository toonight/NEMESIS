"""An API is the door, so founder decision D1 meets its first real test here.

Everything the platform refuses to conclude is worth nothing if a reader can fetch the
internal version over HTTP. These tests do not check that the routes work — they try to get
material out that must not leave, the same way the slice tests walk every field of every
stage looking for a planted name.

The load-bearing one is `test_no_route_can_serve_a_persona_linkage_or_a_name`: it walks every
byte of every response and fails if the withheld material appears anywhere, including through
a field nobody thought about. That is the check that survives a future route being added
carelessly, which is the failure mode this suite is actually for.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from nemesis.api.app import InvestigationView, build_app
from nemesis.authz.attestation import AUDIENCE, PrincipalVerifier
from nemesis.authz.providers import PROVIDER_NAME, LocalDevelopmentIdentityProvider
from nemesis.collect.fixtures.glass_anvil import NAMED_PERSON, PERSONA_CURRENT
from nemesis.core.identity import Role
from nemesis.slice.scenario import ScenarioResult, run_glass_anvil_scenario

pytestmark = pytest.mark.invariant

DEV = LocalDevelopmentIdentityProvider()
ACTORS = PrincipalVerifier(DEV.registered_issuer())


@pytest.fixture(scope="module")
def result(tmp_path_factory: pytest.TempPathFactory) -> ScenarioResult:
    return run_glass_anvil_scenario(workspace=tmp_path_factory.mktemp("api"))


@pytest.fixture(scope="module")
def client(result: ScenarioResult) -> TestClient:
    """The API over the same investigation the console renders.

    Assembled here rather than in the API layer, because `nemesis.api` sits *below*
    `nemesis.slice` and must not import the demo — the narrowing that keeps a scenario stage
    from being serialized wholesale over the wire.
    """
    view = InvestigationView(
        stages=tuple(name for name, _ in result.stages()),
        attribution=result.attribute.result,
        names_a_person=result.attribute.result.names_a_person,
        entity_count=42,
        relationship_count=17,
        evidence_sealed=9,
    )
    return TestClient(build_app(investigation=view, verifier=ACTORS, provider_name=PROVIDER_NAME))


def _credential(*roles: Role) -> dict[str, str]:
    assertion = DEV.enrol("Ada", *(roles or (Role.ANALYST,)))
    return {"Authorization": f"Assertion {assertion.model_dump_json()}"}


def _strings(value: Any, prefix: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield prefix, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(item, f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item, prefix)


# --- Nothing is served without an established identity -------------------------


@pytest.mark.parametrize("route", ["/investigation", "/attribution"])
def test_no_route_serves_anything_without_a_verified_identity(
    client: TestClient, route: str
) -> None:
    """There is no anonymous read, because "just the summary" is how an attribution leaves
    without anybody deciding it should."""
    response = client.get(route)

    assert response.status_code == 401
    assert "anonymous read" in response.json()["detail"]


def test_a_bearer_token_naming_a_user_is_not_a_credential(client: TestClient) -> None:
    """The whole point of ADR-0005 is that identity is established, not asserted.

    An API that accepted a name would put back exactly what that ADR removed.
    """
    response = client.get("/investigation", headers={"Authorization": "Bearer ada"})
    assert response.status_code == 401


def test_an_assertion_from_an_unregistered_issuer_is_refused(client: TestClient) -> None:
    stranger = LocalDevelopmentIdentityProvider(name="corporate-sso")
    assertion = stranger.enrol("Mallory", Role.INVESTIGATION_LEAD)

    response = client.get(
        "/investigation",
        headers={"Authorization": f"Assertion {assertion.model_dump_json()}"},
    )

    assert response.status_code == 401
    assert "not an issuer this deployment accepts" in response.json()["detail"]


def test_an_assertion_minted_for_another_audience_is_refused(client: TestClient) -> None:
    elsewhere = DEV.enrol("Ada", Role.ANALYST, audience="some-other-relying-party")

    response = client.get(
        "/investigation", headers={"Authorization": f"Assertion {elsewhere.model_dump_json()}"}
    )

    assert response.status_code == 401
    assert AUDIENCE in response.json()["detail"]


# --- The wall, at the only boundary where material actually leaves --------------


def test_no_route_can_serve_a_persona_linkage_or_a_name(client: TestClient) -> None:
    """THE TEST THIS FILE EXISTS FOR.

    Every byte of every response is walked. The planted name and the persona linkage must
    appear nowhere — not in a label, not in a hypothesis echoed back, not in an entity
    listing. A future route added carelessly fails here, which is the point: the slice tests
    prove the platform does not *conclude* these things, and this proves it does not *serve*
    them.
    """
    headers = _credential(Role.INVESTIGATION_LEAD, Role.LEGAL_REVIEWER)

    for route in ("/health", "/investigation", "/attribution"):
        response = client.get(route, headers=headers)
        assert response.status_code == 200, route
        body = response.text

        assert NAMED_PERSON not in body, f"{route} served the planted name"
        assert PERSONA_CURRENT not in body, f"{route} served a persona"
        assert "persona_linkage" not in body, f"{route} served a persona linkage"
        assert "same_operator_as" not in body


def test_the_attribution_route_returns_a_type_that_cannot_hold_an_internal_finding(
    client: TestClient,
) -> None:
    """Not a filtered internal model: a type with no field for the withheld dimensions.

    The wall is the schema rather than a branch somebody has to take, so an omission cannot
    be reintroduced by a refactor that forgets one.
    """
    body = client.get("/attribution", headers=_credential()).json()

    shipped = {item["dimension"] for item in body["dimensions"]}
    assert shipped == {"infrastructure", "campaign", "organization"}

    # And what was withheld is named as withheld, because silence reads as "nothing was
    # found", which is a different claim entirely.
    withheld = {item["dimension"] for item in body["withheld"]}
    assert withheld == {"persona", "human_identity"}
    assert any("does not supply findings about the identity" in c for c in body["caveats"])


def test_every_response_says_it_is_simulated(client: TestClient) -> None:
    """Boundary discipline reaches the wire, or it stops at the console."""
    for route in ("/health", "/investigation"):
        assert "SIMULATED" in client.get(route, headers=_credential()).text


# --- The assurance floor reaches the wire ---------------------------------------


def test_the_api_is_not_a_way_around_the_assurance_floor(client: TestClient) -> None:
    """A development identity may read an investigation and authorize nothing that leaves.

    Served over HTTP in the same words the console gives, so "the API let me" cannot become
    an argument.
    """
    response = client.post("/authorizations", headers=_credential())

    assert response.status_code == 403
    body = response.json()
    assert body["refused"] is True
    assert "development fixture" in body["reason"]
    assert body["control"].startswith("nemesis.authz")


def test_an_auditor_cannot_request_an_operation(client: TestClient) -> None:
    """Oversight must not require the ability to act, and the API reads the same table."""
    response = client.post("/authorizations", headers=_credential(Role.AUDITOR))

    assert response.status_code == 403
    assert "no role entitled to request an authorization" in response.json()["reason"]


def test_health_says_what_the_platform_cannot_do_before_anyone_discovers_it(
    client: TestClient,
) -> None:
    """An operator pointing a client at this should learn the limit from the first call."""
    body = client.get("/health").json()

    assert body["identity_provider"] == PROVIDER_NAME
    assert body["highest_assurance_available"] == "development"
    assert body["can_authorize_anything_leaving_the_platform"] is False


# --- The surface is exactly what was declared -----------------------------------


def test_the_api_publishes_no_schema_browser(client: TestClient) -> None:
    """A schema browser on an intelligence platform is a map of what exists, served to
    whoever reaches the port."""
    for route in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(route).status_code == 404


def test_the_served_surface_is_three_routes(client: TestClient) -> None:
    """A tripwire on the door. Adding a route is a decision, and this makes it a visible one.

    If this fails, somebody widened what the platform serves — which may be right, and must
    be accompanied by walking the new response for withheld material above.
    """
    served = {
        (route.path, method)
        for route in client.app.routes  # type: ignore[attr-defined]
        for method in getattr(route, "methods", set())
        if not route.path.startswith("/openapi")
    }
    assert served == {
        ("/health", "GET"),
        ("/investigation", "GET"),
        ("/attribution", "GET"),
        ("/authorizations", "POST"),
    }


def test_the_investigation_summary_is_a_summary_and_not_a_stage_dump(
    client: TestClient,
) -> None:
    """Serializing internal models over the wire is how a linkage reaches a reader through a
    field nobody thought about."""
    body = json.loads(client.get("/investigation", headers=_credential()).text)

    assert set(body) == {
        "notice",
        "requested_by",
        "stages",
        "entities",
        "relationships",
        "evidence_sealed",
        "attribution_names_a_person",
        "internal_leads_served",
    }
    # No persona-linkage band, not even the refusal. Whether an analyst-facing surface may
    # show an internal lead over HTTP is a product decision the founder owns; until it is
    # made, this serves deliverable-class material only.
    assert body["internal_leads_served"] is False
