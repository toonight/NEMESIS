"""The HTTP surface, and the first place material actually leaves the platform.

Every control in this repository has so far defended a boundary inside one process. An API is
different in kind: it is the door. Founder decision D1 says persona linkage and human-identity
material are internal leads that never ship, and until now that was enforced by a type nobody
serialized and a guard on effect parameters. Here it meets a request from outside.

Three properties, each enforced by construction rather than by remembering:

**Nothing is served without an established identity.** A dependency verifies a signed
:class:`~nemesis.core.identity.IdentityAssertion` on every route but ``/health``, through the
same :class:`~nemesis.authz.attestation.PrincipalVerifier` the gateway uses. There is no
"unauthenticated read" path, because "just the summary" is how an attribution leaves without
anybody deciding it should.

**The attribution route returns a type that cannot hold an internal finding.** Not a filtered
internal model — :class:`~nemesis.attribute.disclosure.ExternalAttributionProduct` has no
field for persona linkage or a human identity, so the wall is the schema and not a branch
somebody has to take. `redact_for_disclosure` is the only route to one.

**The assurance floor reaches the wire.** Every identity this platform can currently establish
is a development fixture, so the API can read an investigation and authorize nothing that
leaves. A request for anything more is refused with the reason, over HTTP, in the same words
the CLI gives — which is what stops "the API let me" from becoming an argument.

Status: `IMPLEMENTED` for the read surface, the authorization request, and the write path.
This docstring once named three gaps — no write path, no multi-tenancy, no rate limiting —
and all three have since been closed: :mod:`nemesis.api.submission` for the write path and
its per-principal limiter, :mod:`nemesis.api.tenancy` for one store per tenant. What remains
is the assurance floor above: every identity is a development fixture, so this surface reads
an investigation and authorizes nothing that leaves.
"""

from __future__ import annotations

from typing import Annotated, Any, Final

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, ValidationError

from nemesis.api.submission import (
    IncidentSubmission,
    RateLimiter,
    SubmissionReceipt,
    SubmissionRefusedError,
    check_may_submit,
    submission_claim,
)
from nemesis.api.tenancy import TenantIsolationError, TenantStores
from nemesis.attribute.disclosure import ExternalAttributionProduct, redact_for_disclosure
from nemesis.attribute.engine import AttributionResult
from nemesis.authz.attestation import AttestationError, PrincipalVerifier
from nemesis.authz.rbac import AuthorizationPolicyError, check_may_request
from nemesis.core.identity import IdentityAssertion, Principal
from nemesis.ports.storage import ClaimStore

API_VERSION: Final = "0.1.0"

SIMULATED_NOTICE: Final = (
    "Every figure in this response comes from a SIMULATED investigation over fixture data. "
    "It is not intelligence about anybody."
)


class Health(BaseModel):
    """What is running, and what it is honest about being."""

    model_config = ConfigDict(frozen=True)

    version: str = API_VERSION
    status: str = "ok"
    identity_provider: str
    highest_assurance_available: str
    notice: str = SIMULATED_NOTICE
    can_authorize_anything_leaving_the_platform: bool = False
    """False on every build that has only a development identity provider.

    Served on the health route on purpose: an operator pointing a client at this should learn
    what it cannot do before they discover it in a refusal."""


class Refusal(BaseModel):
    """A refusal, with the reason, in the same words the operator console gives."""

    model_config = ConfigDict(frozen=True)

    refused: bool = True
    reason: str
    control: str
    """Which control refused, so a reader does not mistake a policy for an outage."""


class InvestigationView(BaseModel):
    """What the API is allowed to know about an investigation.

    A deliberate narrowing, and the reason this layer sits *below* the demo rather than
    importing it. Handed the whole scenario result, the obvious next commit serializes a
    stage "just to see it" and a persona linkage leaves through a field nobody thought
    about. What the API can serve is enumerated here, so widening it is an edit somebody
    has to make on purpose.
    """

    model_config = ConfigDict(frozen=True)

    stages: tuple[str, ...]
    attribution: AttributionResult
    names_a_person: bool
    entity_count: int
    relationship_count: int
    evidence_sealed: int


def build_app(
    *,
    investigation: InvestigationView,
    verifier: PrincipalVerifier,
    provider_name: str,
    claims: ClaimStore | TenantStores[ClaimStore] | None = None,
    rate_limiter: RateLimiter | None = None,
) -> FastAPI:
    """Build the API over one investigation.

    ``claims`` enables the write path and is optional on purpose: a deployment that does not
    want an HTTP route appending to its adversary graph gets one without it, and the absence
    of a store is the absence of the route rather than a flag somebody can flip by accident.

    Takes the view rather than reaching for a global, so a test drives the same object a
    deployment does and there is exactly one place that decides what is served.
    """
    app = FastAPI(
        title="NEMESIS",
        version=API_VERSION,
        description=SIMULATED_NOTICE,
        # No interactive docs by default: a schema browser on an intelligence platform is a
        # map of what exists, served to whoever reaches the port.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    async def principal(
        authorization: Annotated[str | None, Header()] = None,
    ) -> Principal:
        """Establish who is calling, or refuse the request.

        The header carries a signed assertion, not a bearer token naming a user: the whole
        point of ADR-0005 is that identity is established by a verifier rather than asserted
        by a caller, and an API that accepted a name would put that back.
        """
        if not authorization or not authorization.startswith("Assertion "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="an Assertion credential is required; this API has no anonymous read",
            )
        try:
            assertion = IdentityAssertion.model_validate_json(authorization[len("Assertion ") :])
            return verifier.verify(assertion)
        except (ValidationError, AttestationError) as exc:
            # The reason is returned deliberately: an operator holding a stale or
            # wrong-audience assertion needs to know which, and none of it tells an attacker
            # anything they did not already supply.
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    # `caller: Principal = Depends(principal)` rather than an `Annotated` alias: this module
    # uses `from __future__ import annotations`, so FastAPI resolves hints as strings against
    # module globals — where a local alias does not exist, and every route silently became a
    # required query parameter named `caller`.
    @app.get("/health", response_model=Health)
    async def health() -> Health:
        """The one route that needs no identity, and says what the platform cannot do."""
        return Health(
            identity_provider=provider_name,
            highest_assurance_available="development",
        )

    @app.get("/investigation", response_model=dict)
    async def investigation_summary(
        caller: Principal = Depends(principal),
    ) -> dict[str, Any]:
        """The shape of the run: stages, counts, and what each stage refused.

        Deliberately not the stage objects themselves. Serializing internal models over the
        wire is how a persona linkage reaches a reader through a field nobody thought about
        — the walk in the slice tests exists because that is not hypothetical.
        """
        return {
            "notice": SIMULATED_NOTICE,
            "requested_by": caller.describe(),
            "stages": list(investigation.stages),
            "entities": investigation.entity_count,
            "relationships": investigation.relationship_count,
            "evidence_sealed": investigation.evidence_sealed,
            "attribution_names_a_person": investigation.names_a_person,
            # The persona-linkage band is deliberately NOT served, and its absence is a
            # decision rather than an oversight. D1 makes persona linkage an internal lead;
            # whether an *analyst-facing* surface may show one over HTTP is a product
            # question the founder owns, not one to settle inside a route handler. Until it
            # is settled this API serves deliverable-class material only, which is the
            # conservative reading and the one that cannot leak by accident.
            "internal_leads_served": False,
        }

    @app.get("/attribution", response_model=ExternalAttributionProduct)
    async def attribution(
        caller: Principal = Depends(principal),
    ) -> ExternalAttributionProduct:
        """The attribution, as a product a recipient may be given.

        Redacted at the only place that produces one, so the internal dimensions are not
        filtered out here — they were never in the object. What was withheld is named as
        withheld, because silence would read as "nothing was found", which is a different
        claim entirely.
        """
        return redact_for_disclosure(investigation.attribution)

    @app.post("/authorizations", response_model=Refusal, status_code=status.HTTP_403_FORBIDDEN)
    async def request_authorization(caller: Principal = Depends(principal)) -> Refusal:
        """Ask for an operation, and be refused for the reason that actually applies.

        The route exists to make the assurance floor reachable over HTTP. Every identity this
        build can establish is a development fixture, so a request for anything that leaves
        the platform is refused here exactly as it is at the console — and an operator cannot
        conclude that the API is a way around it.
        """
        try:
            check_may_request(caller)
        except AuthorizationPolicyError as exc:
            return Refusal(reason=str(exc), control="nemesis.authz.rbac.check_may_request")
        return Refusal(
            reason=(
                "This build establishes no identity stronger than a development fixture, so "
                "it may authorize a rehearsal and nothing meant to leave the platform. "
                "Issuing a capability over HTTP is not implemented, and the refusal is the "
                "control rather than a missing feature."
            ),
            control="nemesis.authz.rbac.MINIMUM_ASSURANCE",
        )

    if claims is not None:
        limiter = rate_limiter or RateLimiter()

        @app.post("/submissions", response_model=SubmissionReceipt, status_code=201)
        async def submit_incident(
            submission: IncidentSubmission,
            caller: Principal = Depends(principal),
        ) -> SubmissionReceipt:
            """Accept an incident report from outside, as an assertion and nothing more.

            The highest-risk route here: graph poisoning is in the threat model and this is
            the mechanism it would use. What lands is a HYPOTHESIS from an EXTERNAL_REPORT,
            attributed to the caller — never an observation, which the domain model would
            refuse anyway because no artifact was sealed.
            """
            try:
                limiter.check(caller.actor_id)
                check_may_submit(caller)
            except SubmissionRefusedError as refusal:
                raise HTTPException(status_code=refusal.status, detail=refusal.reason) from refusal

            # One store per tenant, resolved from the verified principal. A route that
            # picked a tenant from a header would be picking it from the attacker.
            try:
                store = claims.for_principal(caller) if isinstance(claims, TenantStores) else claims
            except TenantIsolationError as isolated:
                raise HTTPException(status_code=403, detail=str(isolated)) from isolated

            stored = await store.record(submission_claim(submission, caller))
            return SubmissionReceipt(
                claim_id=stored.claim_id,
                submitted_by=caller.describe(),
                recorded_at=stored.asserted_at,
            )

    return app
