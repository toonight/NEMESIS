"""The write path is the mechanism graph poisoning would use.

Every other surface here reads. This one lets an outside party append to the Global Adversary
Graph, so these tests assume the submitter is the attacker — the same posture the Effects
plane takes toward its caller.

The load-bearing one is `test_a_submission_can_never_become_an_observation`. The domain model
already refuses to construct an observation without sealed evidence, and a submission seals
nothing; that refusal is the real control, and this proves the write path does not work around
it rather than trusting that nobody will.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from nemesis.api.app import InvestigationView, build_app
from nemesis.api.submission import (
    MAY_SUBMIT,
    IncidentSubmission,
    RateLimiter,
    SubmissionRefusedError,
    check_may_submit,
    submission_claim,
)
from nemesis.authz.attestation import PrincipalVerifier
from nemesis.authz.providers import PROVIDER_NAME, LocalDevelopmentIdentityProvider
from nemesis.core.claims import Claim, ClaimKind, DerivationKind, Statement
from nemesis.core.entities import EntityType
from nemesis.core.identity import Role
from nemesis.core.temporal import TemporalExtent
from nemesis.graph.memory import InMemoryClaimStore
from nemesis.slice.scenario import ScenarioResult, run_glass_anvil_scenario

pytestmark = pytest.mark.invariant

DEV = LocalDevelopmentIdentityProvider()
ACTORS = PrincipalVerifier(DEV.registered_issuer())
NOW = datetime(2026, 8, 17, tzinfo=UTC)


@pytest.fixture(scope="module")
def result(tmp_path_factory: pytest.TempPathFactory) -> ScenarioResult:
    return run_glass_anvil_scenario(workspace=tmp_path_factory.mktemp("write"))


def _client(result: ScenarioResult, **kwargs: object) -> tuple[TestClient, InMemoryClaimStore]:
    claims = InMemoryClaimStore()
    view = InvestigationView(
        stages=tuple(name for name, _ in result.stages()),
        attribution=result.attribute.result,
        names_a_person=result.attribute.result.names_a_person,
        entity_count=1,
        relationship_count=0,
        evidence_sealed=0,
    )
    app = build_app(
        investigation=view,
        verifier=ACTORS,
        provider_name=PROVIDER_NAME,
        claims=claims,
        **kwargs,  # type: ignore[arg-type]
    )
    return TestClient(app), claims


def _credential(*roles: Role) -> dict[str, str]:
    assertion = DEV.enrol("Ada", *(roles or (Role.ANALYST,)))
    return {"Authorization": f"Assertion {assertion.model_dump_json()}"}


def _body() -> dict[str, object]:
    return {
        "entity_type": "domain",
        "entity_key": "reported-by-a-stranger.example",
        "observed_at": NOW.isoformat(),
        "summary": "Seen serving a credential-harvesting page.",
    }


# --- A submission is an assertion, never an observation ----------------------


def test_a_submission_can_never_become_an_observation() -> None:
    """THE TEST THIS FILE EXISTS FOR.

    An observation must cite sealed evidence and a submission seals nothing — nobody
    collected anything, somebody typed something. The domain model refuses the dangerous
    object outright; this proves the write path does not route around that refusal.
    """
    with pytest.raises(Exception) as refused:
        Claim.create(
            kind=ClaimKind.OBSERVATION,
            statement=Statement(
                subject="domain:x.example",
                predicate="was_reported",
                obj="anything",
                natural_language="a submission pretending to be an observation",
            ),
            derivation=DerivationKind.EXTERNAL_REPORT,
            asserted_by="actor_" + "0" * 32,
            asserted_at=NOW,
            valid_extent=TemporalExtent.at(NOW),
        )
    assert "evidence" in str(refused.value).lower()


def test_what_a_submission_actually_becomes(result: ScenarioResult) -> None:
    client, _ = _client(result)
    response = client.post("/submissions", json=_body(), headers=_credential(Role.ANALYST))

    assert response.status_code == 201, response.text
    receipt = response.json()
    assert receipt["kind"] == "hypothesis"
    assert receipt["derivation"] == "external_report"
    assert receipt["is_evidence"] is False
    assert receipt["corroborated"] is False
    assert "not an observation" in receipt["notice"]


def test_the_stored_claim_carries_the_submitter_and_no_evidence(result: ScenarioResult) -> None:
    """Provenance is the whole point: a submission that did not name who made it would be
    material of unknown origin in a graph whose central promise is a resolvable derivation."""
    import asyncio

    client, claims = _client(result)
    response = client.post("/submissions", json=_body(), headers=_credential(Role.ANALYST))
    stored = asyncio.run(claims.get(response.json()["claim_id"]))

    assert stored is not None
    assert stored.kind is ClaimKind.HYPOTHESIS
    assert stored.derivation is DerivationKind.EXTERNAL_REPORT
    assert stored.supported_by_evidence == ()
    assert stored.asserted_by.startswith("actor_")


def test_a_submitter_cannot_assert_a_conclusion(result: ScenarioResult) -> None:
    """Confidence and attribution are what this platform derives from evidence. Accepting
    them over HTTP would let a submitter write conclusions into a graph meant to reach them."""
    body = _body() | {"confidence": 0.99, "attributed_to": "GLASS ANVIL", "kind": "observation"}
    client, _ = _client(result)
    response = client.post("/submissions", json=body, headers=_credential(Role.ANALYST))

    assert response.status_code == 201
    assert set(IncidentSubmission.model_fields) == {
        "entity_type",
        "entity_key",
        "observed_at",
        "summary",
        "reporter_reference",
    }, "the submission model grew a field that lets a caller assert a conclusion"


# --- Not everyone may write --------------------------------------------------


def test_an_auditor_cannot_write_into_the_graph(result: ScenarioResult) -> None:
    """Oversight must not require the ability to act — the same reasoning that keeps an
    auditor from requesting an authorization."""
    client, _ = _client(result)
    response = client.post("/submissions", json=_body(), headers=_credential(Role.AUDITOR))

    assert response.status_code == 403
    assert "no role entitled to write" in response.json()["detail"]


def test_only_the_named_roles_may_submit() -> None:
    """A tripwire on the set. Widening who may append to the adversary graph is a decision."""
    assert {Role.ANALYST, Role.INVESTIGATION_LEAD} == MAY_SUBMIT


def test_there_is_no_anonymous_write(result: ScenarioResult) -> None:
    """An endpoint that accepted a submitter's *name* would be worse than an anonymous one:
    poisoning with a scapegoat baked into the provenance."""
    client, _ = _client(result)
    assert client.post("/submissions", json=_body()).status_code == 401
    assert (
        client.post(
            "/submissions", json=_body(), headers={"Authorization": "Bearer ada"}
        ).status_code
        == 401
    )


# --- Rate limited, per principal, refusing rather than queueing ---------------


def test_writing_at_machine_speed_is_refused(result: ScenarioResult) -> None:
    """Poisoning a graph at machine speed is a different attack from doing it by hand."""
    client, _ = _client(result, rate_limiter=RateLimiter(per_hour=3))
    headers = _credential(Role.ANALYST)

    codes = [
        client.post("/submissions", json=_body(), headers=headers).status_code for _ in range(5)
    ]

    assert codes[:3] == [201, 201, 201]
    assert codes[3:] == [429, 429], codes


def test_a_failed_submission_still_costs_the_limit() -> None:
    """A limiter counting only accepted writes lets an attacker probe at any rate by sending
    submissions designed to fail validation."""
    limiter = RateLimiter(per_hour=2)
    limiter.check("actor_a")
    limiter.check("actor_a")

    with pytest.raises(SubmissionRefusedError) as refused:
        limiter.check("actor_a")
    assert refused.value.status == 429


def test_the_limit_is_per_principal_and_not_shared() -> None:
    """Per principal because an attacker chooses their connections and not their verified
    identity — a limit on the thing they control limits nothing."""
    limiter = RateLimiter(per_hour=1)
    limiter.check("actor_a")
    limiter.check("actor_b")  # must not raise

    with pytest.raises(SubmissionRefusedError):
        limiter.check("actor_a")


def test_the_window_rolls_rather_than_resetting() -> None:
    """A fixed window lets an attacker send two full quotas back to back across its boundary."""
    clock = {"now": NOW}
    limiter = RateLimiter(per_hour=2, clock=lambda: clock["now"])
    limiter.check("actor_a")
    limiter.check("actor_a")

    clock["now"] = NOW + timedelta(minutes=61)
    limiter.check("actor_a")  # the first two have aged out
    assert limiter.remaining("actor_a") == 1


# --- The route does not exist unless a store is wired ------------------------


def test_no_claim_store_means_no_write_route(result: ScenarioResult) -> None:
    """The absence of a store is the absence of the route, rather than a flag somebody can
    flip by accident."""
    view = InvestigationView(
        stages=(),
        attribution=result.attribute.result,
        names_a_person=result.attribute.result.names_a_person,
        entity_count=0,
        relationship_count=0,
        evidence_sealed=0,
    )
    client = TestClient(build_app(investigation=view, verifier=ACTORS, provider_name=PROVIDER_NAME))

    assert client.post("/submissions", json=_body(), headers=_credential()).status_code == 404


def test_a_submission_claim_is_built_the_same_way_outside_the_route() -> None:
    """The claim shape is the module's, not the route's, so a second caller cannot mint a
    stronger claim by going around the endpoint."""
    principal = ACTORS.verify(DEV.enrol("Ada", Role.ANALYST))
    claim = submission_claim(
        IncidentSubmission(
            entity_type=EntityType.DOMAIN,
            entity_key="x.example",
            observed_at=NOW,
            summary="reported",
        ),
        principal,
        now=NOW,
    )

    assert claim.kind is ClaimKind.HYPOTHESIS
    assert claim.derivation is DerivationKind.EXTERNAL_REPORT
    assert claim.supported_by_evidence == ()


def test_check_may_submit_raises_rather_than_returning_a_verdict() -> None:
    """A caller that forgets to check a boolean writes to the graph."""
    auditor = ACTORS.verify(DEV.enrol("Otto", Role.AUDITOR))
    with pytest.raises(SubmissionRefusedError):
        check_may_submit(auditor)
