"""Plane 10 — Effects. Every test here assumes the caller is the attacker.

The Effects plane is the one place where NEMESIS could touch the world, so its adapters
are written to distrust the component that invokes them. These tests are therefore not
"does the adapter draft a nice letter" tests. Each one removes a control in spirit and
asserts that the adapter refuses: a stale approval, a target that changed hands, an
expired capability, a request routed to the wrong adapter, a parameter trying to forge a
line of a legal document.

Two conventions worth stating once:

- ``preflight`` reads the wall clock itself, deliberately: a caller-supplied "now" is all
  an attacker needs to revive an expired capability. So the fixtures here are built
  relative to real time rather than to a frozen instant.
- There is no async test plugin in this project, so coroutines are driven with
  ``asyncio.run``. Each call therefore gets a fresh event loop, which incidentally is a
  fair model of the statelessness the port demands.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from nemesis.authz.gateway import RevocationRegistry
from nemesis.authz.keys import CapabilitySigningKey
from nemesis.core.authorization import (
    MVP_IMPLEMENTED_OPERATIONS,
    NO_CAPABILITY,
    Approval,
    AuthorizationCapability,
    LegalBasis,
    OperationClass,
    StopCondition,
    TargetFingerprint,
)
from nemesis.core.identity import Role
from nemesis.core.ids import IdPrefix, new_id
from nemesis.effects.drafting import (
    DRAFT_BANNER,
    MAX_LISTED_EVIDENCE_IDS,
    NOT_SENT_FOOTER,
    OUTPUT_DIRECTORY_PARAMETER,
    EvidenceExportAdapter,
    ProviderNotificationAdapter,
    TakedownRequestDraftAdapter,
)
from nemesis.effects.registry import (
    STOP_CONDITION_CLEARED,
    STOP_CONDITION_PARAMETER_PREFIX,
    EffectsRegistry,
    default_registry,
)
from nemesis.effects.simulation import SimulationEffectsAdapter
from nemesis.ports.authorization import TrustAnchor
from nemesis.ports.effects import (
    EffectOutcome,
    EffectRequest,
    EffectResult,
    EffectsAdapter,
)

# The GLASS ANVIL target, from docs/architecture/DEMO_SCENARIO.md §2.2.
TARGET_KEY = "acme-invoice-portal.example"
APPROVED_STATE = {"resolves_to": "198.51.100.23", "registrar": "BulletproofReg"}

ALICE = new_id(IdPrefix.ACTOR)
BOB = new_id(IdPrefix.ACTOR)


def _now() -> datetime:
    return datetime.now(UTC)


def _target(
    *, natural_key: str = TARGET_KEY, bound: dict[str, str] | None = None
) -> TargetFingerprint:
    return TargetFingerprint.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type="domain",
        natural_key=natural_key,
        bound_attributes=dict(APPROVED_STATE if bound is None else bound),
    )


def _approval(approver: str) -> Approval:
    return Approval(
        approver=approver,
        approver_roles=frozenset({Role.INVESTIGATION_LEAD}),
        decided_at=_now(),
        decision=True,
        rationale="Infrastructure cluster reviewed; reversible class; synthetic targets.",
    )


SIGNING_KEY = CapabilitySigningKey.generate()
"""One ephemeral key for the whole module. Never written to disk."""

ANCHOR = TrustAnchor(verifying_key=SIGNING_KEY.verifying_key, revocations=RevocationRegistry())
"""The authorizer these adapters believe, fixed at construction as a real one would be.

Adapters used to take the key per call, which meant a test — and an attacker — chose which
authorizer the adapter trusted. Building them around one anchor is both closer to how they
are wired and the only way these tests can notice if that changes back.
"""


def _registry() -> EffectsRegistry:
    """A registry holding the public half of the module key and an empty revocation list."""
    return default_registry(
        verifying_key=SIGNING_KEY.verifying_key, revocations=RevocationRegistry()
    )


def _capability(
    operation: OperationClass, target: TargetFingerprint, **overrides: object
) -> AuthorizationCapability:
    """A capability permitting exactly one operation against exactly one target.

    **Signed.** An earlier version of this helper built unsigned capabilities and expected
    them to succeed, which meant the whole Effects suite asserted that a document could be
    drafted from a grant nobody had authorized. The plane now refuses those, and this helper
    signs so the tests exercise the path a real caller takes.
    """
    simulation_only = operation is OperationClass.SIMULATION
    defaults: dict[str, object] = {
        "capability_id": new_id(IdPrefix.CAPABILITY),
        "case_id": new_id(IdPrefix.CASE),
        "audit_id": new_id(IdPrefix.AUDIT),
        "issued_at": _now() - timedelta(minutes=1),
        "not_before": _now() - timedelta(minutes=1),
        "expires_at": _now() + timedelta(hours=4),
        "targets": (target,),
        "permitted_operations": frozenset({operation}),
        "jurisdictions": ("FR", "NL"),
        "legal_basis": (
            LegalBasis.NONE_SIMULATION_ONLY
            if simulation_only
            else LegalBasis.PROVIDER_TERMS_OF_SERVICE
        ),
        "legal_authority_reference": None if simulation_only else "CASE-GLASS-ANVIL-2026-0042",
        "max_targets": 4,
        "max_effect_description": "One draft document. No external contact.",
        "approvals": (_approval(ALICE),),
        "required_approvals": 1,
    }
    unsigned = AuthorizationCapability(**(defaults | overrides))
    if "signature" in overrides:
        return unsigned
    return unsigned.model_copy(update={"signature": SIGNING_KEY.sign(unsigned.signing_payload())})


def _request(
    operation: OperationClass, target: TargetFingerprint, **parameters: str
) -> EffectRequest:
    """A well-formed request: the target's observed state is the state that was approved."""
    return EffectRequest(
        operation_id=new_id(IdPrefix.OPERATION),
        operation=operation,
        target_fingerprint=target.fingerprint,
        target_natural_key=target.natural_key,
        current_target_attributes=dict(APPROVED_STATE),
        parameters=dict(parameters),
        requested_by="analyst-01",
        requested_at=_now(),
    )


def _observing(request: EffectRequest, attributes: dict[str, str]) -> EffectRequest:
    """The same request, reporting a different current state — the world moved on."""
    return request.model_copy(update={"current_target_attributes": attributes})


def _naming(request: EffectRequest, natural_key: str) -> EffectRequest:
    """The same request, aimed at a different name while still quoting the approval."""
    return request.model_copy(update={"target_natural_key": natural_key})


def _run(
    adapter: EffectsAdapter, request: EffectRequest, cap: AuthorizationCapability
) -> EffectResult:
    return asyncio.run(adapter.execute(request, cap))


def _adapter_for(operation: OperationClass) -> EffectsAdapter:
    adapter = _registry().adapter_for(operation)
    assert adapter is not None, f"no adapter registered for {operation}"
    return adapter


IMPLEMENTED = sorted(MVP_IMPLEMENTED_OPERATIONS)


# --- Invariant 8 / 15: nothing in this plane can reach the world -------------


def test_the_registry_serves_every_implemented_class_and_nothing_else() -> None:
    """A class gaining an adapter is how NEMESIS acquires a capability it did not have.

    Asserting equality rather than containment means a new adapter cannot be added
    quietly: this test fails, and someone has to justify the change.
    """
    registry = _registry()
    assert registry.operations == MVP_IMPLEMENTED_OPERATIONS
    assert len(registry.adapters) == len(MVP_IMPLEMENTED_OPERATIONS)


def test_no_adapter_in_the_registry_declares_external_contact() -> None:
    """Iterates the whole registry so the day an adapter starts making contact is visible.

    Written against ``registry.adapters`` rather than a hand-written list precisely so a
    fifth adapter cannot be added without this assertion running over it.
    """
    adapters = _registry().adapters
    assert adapters, "an empty registry would make this assertion vacuous"
    for adapter in adapters:
        assert adapter.makes_external_contact is False, (
            f"{adapter.name} declares external contact; the MVP acts against no "
            "infrastructure it does not own (invariant 15)"
        )


def test_no_adapter_in_the_registry_reports_contact_after_executing() -> None:
    """The declaration is a promise; this asserts the promise over actual results.

    An adapter could declare ``makes_external_contact = False`` and still return a result
    admitting contact, which is the shape a partially-reverted change would take.
    """
    registry = _registry()
    for adapter in registry.adapters:
        target = _target()
        result = _run(
            adapter,
            _request(adapter.operation, target),
            _capability(adapter.operation, target),
        )
        assert result.succeeded, f"{adapter.name}: {result.detail}"
        assert result.external_contact_made is False


def test_registering_an_adapter_that_makes_contact_is_refused() -> None:
    class _ContactingAdapter:
        name = "contacting-adapter"
        operation = OperationClass.SIMULATION
        makes_external_contact = True
        anchor = ANCHOR

        async def execute(
            self, request: EffectRequest, capability: AuthorizationCapability
        ) -> EffectResult:  # pragma: no cover - registration never succeeds
            raise AssertionError("must never be reached")

    with pytest.raises(ValueError, match="declares that it makes external contact"):
        EffectsRegistry(
            verifying_key=SIGNING_KEY.verifying_key, revocations=RevocationRegistry()
        ).register(_ContactingAdapter())


# --- Refusals: every one returns a record, none raises -----------------------


@pytest.mark.parametrize("operation", IMPLEMENTED)
def test_an_expired_capability_is_refused_and_returned(operation: OperationClass) -> None:
    """Invariant 9. The clock is not a caller-supplied value, so an expired grant is dead.

    The refusal must be an ``EffectResult``: an exception can be caught and ignored by the
    very caller we do not trust, and would leave no record that anything was attempted.
    """
    adapter = _adapter_for(operation)
    target = _target()
    expired = _capability(
        operation,
        target,
        issued_at=_now() - timedelta(hours=8),
        not_before=_now() - timedelta(hours=8),
        expires_at=_now() - timedelta(hours=4),
    )
    result = _run(adapter, _request(operation, target), expired)

    assert result.outcome is EffectOutcome.REFUSED_UNAUTHORIZED
    assert not result.succeeded
    assert result.external_contact_made is False
    assert not result.authorization.permitted
    assert any("expired" in reason for reason in result.authorization.denial_reasons)


@pytest.mark.parametrize("operation", IMPLEMENTED)
def test_a_changed_bound_attribute_is_refused(operation: OperationClass) -> None:
    """The scenario invariant 9 exists for: the domain was transferred after approval.

    The caller quotes the approved fingerprint — it is genuine — but the target's current
    resolution is not the one that was approved. Trusting the quoted fingerprint would
    apply a stale decision to what may now be a legitimate owner's infrastructure.
    """
    adapter = _adapter_for(operation)
    target = _target()
    moved = dict(APPROVED_STATE) | {"resolves_to": "192.0.2.77"}
    result = _run(
        adapter,
        _observing(_request(operation, target), moved),
        _capability(operation, target),
    )

    assert result.outcome is EffectOutcome.REFUSED_TARGET_CHANGED
    assert "resolves_to" in result.detail


@pytest.mark.parametrize("operation", IMPLEMENTED)
def test_an_unobserved_bound_attribute_is_refused(operation: OperationClass) -> None:
    """Omitting an attribute must not be a way to pass the check by not looking.

    If a missing observation were treated as unchanged, target binding would be defeated
    by the cheapest possible attack: send fewer fields.
    """
    adapter = _adapter_for(operation)
    target = _target()
    result = _run(
        adapter,
        _observing(_request(operation, target), {"resolves_to": "198.51.100.23"}),
        _capability(operation, target),
    )

    assert result.outcome is EffectOutcome.REFUSED_TARGET_CHANGED
    assert "registrar" in result.detail


@pytest.mark.parametrize("operation", IMPLEMENTED)
def test_an_approved_fingerprint_cannot_be_spent_on_a_different_name(
    operation: OperationClass,
) -> None:
    """The attack this stops: quote the approval for the malicious domain, name an
    innocent one. Every bound attribute matches; only the natural key differs. If the
    natural key were left out of the recomputation, the innocent target would be acted on
    under a genuine approval — and the audit trail would show a permitted operation.
    """
    adapter = _adapter_for(operation)
    target = _target()
    result = _run(
        adapter,
        _naming(_request(operation, target), "initech-payments-secure.example"),
        _capability(operation, target),
    )

    assert result.outcome is EffectOutcome.REFUSED_TARGET_CHANGED
    assert "initech-payments-secure.example" in result.detail


@pytest.mark.parametrize("operation", IMPLEMENTED)
def test_an_unstated_blocking_stop_condition_refuses(operation: OperationClass) -> None:
    """Fail closed. The adapter cannot observe whether ownership is disputed, so silence
    must not read as "no dispute" — that would make every stop condition decoration.
    """
    adapter = _adapter_for(operation)
    target = _target()
    cap = _capability(
        operation,
        target,
        stop_conditions=(
            StopCondition(
                condition="target_ownership_disputed",
                description="Abort if the registrant contests ownership.",
            ),
        ),
    )
    result = _run(adapter, _request(operation, target), cap)

    assert result.outcome is EffectOutcome.REFUSED_STOP_CONDITION
    assert "target_ownership_disputed" in result.detail


@pytest.mark.parametrize("operation", IMPLEMENTED)
def test_a_stop_condition_stated_as_cleared_lets_the_operation_proceed(
    operation: OperationClass,
) -> None:
    adapter = _adapter_for(operation)
    target = _target()
    cap = _capability(
        operation,
        target,
        stop_conditions=(
            StopCondition(
                condition="target_ownership_disputed",
                description="Abort if the registrant contests ownership.",
            ),
        ),
    )
    request = _request(
        operation,
        target,
        **{f"{STOP_CONDITION_PARAMETER_PREFIX}target_ownership_disputed": STOP_CONDITION_CLEARED},
    )
    assert _run(adapter, request, cap).succeeded


@pytest.mark.parametrize("operation", IMPLEMENTED)
def test_a_wrong_value_does_not_clear_a_stop_condition(operation: OperationClass) -> None:
    """Only the exact sentinel clears. "false", "n/a" or "checked" must not."""
    adapter = _adapter_for(operation)
    target = _target()
    cap = _capability(
        operation,
        target,
        stop_conditions=(
            StopCondition(condition="ownership_disputed", description="Abort if contested."),
        ),
    )
    request = _request(
        operation,
        target,
        **{f"{STOP_CONDITION_PARAMETER_PREFIX}ownership_disputed": "checked"},
    )
    assert _run(adapter, request, cap).outcome is EffectOutcome.REFUSED_STOP_CONDITION


def test_a_request_routed_to_the_wrong_adapter_is_refused() -> None:
    """A request labelled ``simulation`` handed to the takedown drafter would otherwise be
    authorized as a simulation and executed as a takedown. The adapter checks its own
    class rather than the label it was handed.
    """
    target = _target()
    cap = _capability(OperationClass.SIMULATION, target)
    result = _run(
        TakedownRequestDraftAdapter(ANCHOR),
        _request(OperationClass.SIMULATION, target),
        cap,
    )

    assert result.outcome is EffectOutcome.REFUSED_UNAUTHORIZED
    assert "takedown_request_draft" in result.detail
    assert result.produced_artifacts == ()


def test_a_capability_for_a_different_target_is_refused() -> None:
    adapter = _adapter_for(OperationClass.PROVIDER_NOTIFICATION)
    approved = _target(natural_key="acme-billing-secure.example")
    other = _target(natural_key="globex-invoice-portal.example")
    result = _run(
        adapter,
        _request(OperationClass.PROVIDER_NOTIFICATION, other),
        _capability(OperationClass.PROVIDER_NOTIFICATION, approved),
    )
    assert result.outcome is EffectOutcome.REFUSED_UNAUTHORIZED


def test_a_revoked_capability_is_refused() -> None:
    adapter = _adapter_for(OperationClass.SIMULATION)
    target = _target()
    cap = _capability(
        OperationClass.SIMULATION,
        target,
        revoked_at=_now(),
        revocation_reason="target ownership disputed by the registrant",
    )
    result = _run(adapter, _request(OperationClass.SIMULATION, target), cap)
    assert result.outcome is EffectOutcome.REFUSED_REVOKED
    assert "marked revoked" in result.detail


# --- Unimplemented classes ---------------------------------------------------


def test_a_fully_authorized_unimplemented_class_still_returns_refused_no_adapter() -> None:
    """Authorization is not the obstacle here, and the record must say so.

    The capability below is impeccable: dual control, a court order, an unexpired grant
    naming this exact target. It still refuses, because ``registrar_suspension`` has no
    adapter by design. An analyst reading a REFUSED_UNAUTHORIZED here would go and widen
    the capability, which would achieve nothing and normalize widening capabilities.
    """
    target = _target()
    cap = _capability(
        OperationClass.REGISTRAR_SUSPENSION,
        target,
        permitted_operations=frozenset({OperationClass.REGISTRAR_SUSPENSION}),
        legal_basis=LegalBasis.COURT_ORDER,
        legal_authority_reference="TGI Paris, ord. 2026/1234",
        required_approvals=2,
        approvals=(_approval(ALICE), _approval(BOB)),
    )
    request = _request(OperationClass.REGISTRAR_SUSPENSION, target)
    result = asyncio.run(_registry().execute(request, cap))

    assert result.outcome is EffectOutcome.REFUSED_NO_ADAPTER
    assert "REQUIRES_LEGAL_AUTHORITY" in result.detail
    assert result.external_contact_made is False

    # The distinction an analyst needs — "authorization is not the obstacle here" — is
    # carried by the outcome and the detail, not by a `permitted` flag.
    #
    # It used to be carried by that flag, computed by calling `authorizes()` on the
    # capability. Nothing had verified that capability: no adapter means no preflight, so
    # the record was asserting the validity of a grant nobody had checked, from a value the
    # caller supplied. A review found the same shape on the forged path, where the recorded
    # decision — including its capability id — was authored by the attacker and written
    # into the hash-chained trail, which then verified.
    assert not result.authorization.permitted
    assert result.authorization.capability_id == NO_CAPABILITY
    assert result.authorization.denial_reasons == (
        "no adapter is registered for registrar_suspension",
    )


@pytest.mark.parametrize("operation", sorted(set(OperationClass) - MVP_IMPLEMENTED_OPERATIONS))
def test_every_unimplemented_class_refuses_rather_than_raising(
    operation: OperationClass,
) -> None:
    target = _target()
    cap = _capability(OperationClass.SIMULATION, target)
    result = asyncio.run(_registry().execute(_request(operation, target), cap))
    assert result.outcome is EffectOutcome.REFUSED_NO_ADAPTER


def test_an_adapter_that_raises_is_recorded_as_failed_not_propagated() -> None:
    """The port says refusals are returned, not thrown. One buggy adapter must not become
    an operation whose outcome nobody recorded.
    """

    class _RaisingAdapter:
        name = "raising-adapter"
        operation = OperationClass.SIMULATION
        makes_external_contact = False
        anchor = ANCHOR

        async def execute(
            self, request: EffectRequest, capability: AuthorizationCapability
        ) -> EffectResult:
            raise RuntimeError("adapter bug")

    registry = EffectsRegistry(
        verifying_key=SIGNING_KEY.verifying_key, revocations=RevocationRegistry()
    )
    registry.register(_RaisingAdapter())
    target = _target()
    result = asyncio.run(
        registry.execute(
            _request(OperationClass.SIMULATION, target),
            _capability(OperationClass.SIMULATION, target),
        )
    )

    assert result.outcome is EffectOutcome.FAILED
    assert "RuntimeError" in result.detail
    assert result.external_contact_made is False


# --- Statelessness -----------------------------------------------------------


@pytest.mark.parametrize("operation", IMPLEMENTED)
def test_an_earlier_authorization_does_not_carry_into_a_later_call(
    operation: OperationClass,
) -> None:
    """The ambient-authority failure mode, expressed as a test.

    The same adapter instance is called twice: once with a valid capability, then with an
    expired one. An adapter that cached the first decision — or the target, or a session —
    would let the second call ride on the first call's approval, which is exactly the
    standing authority invariant 8 removes.
    """
    adapter = _adapter_for(operation)
    target = _target()

    first = _run(adapter, _request(operation, target), _capability(operation, target))
    assert first.succeeded

    expired = _capability(
        operation,
        target,
        issued_at=_now() - timedelta(hours=8),
        not_before=_now() - timedelta(hours=8),
        expires_at=_now() - timedelta(hours=4),
    )
    second = _run(adapter, _request(operation, target), expired)
    assert second.outcome is EffectOutcome.REFUSED_UNAUTHORIZED


def test_a_refusal_does_not_poison_a_later_legitimate_call() -> None:
    adapter = ProviderNotificationAdapter(ANCHOR)
    target = _target()
    refused = _run(
        adapter,
        _observing(_request(OperationClass.PROVIDER_NOTIFICATION, target), {"resolves_to": "x"}),
        _capability(OperationClass.PROVIDER_NOTIFICATION, target),
    )
    assert refused.outcome is EffectOutcome.REFUSED_TARGET_CHANGED

    accepted = _run(
        adapter,
        _request(OperationClass.PROVIDER_NOTIFICATION, target),
        _capability(OperationClass.PROVIDER_NOTIFICATION, target),
    )
    assert accepted.outcome is EffectOutcome.DRAFTED


# --- The drafts themselves ---------------------------------------------------

DRAFTERS = [
    ProviderNotificationAdapter(ANCHOR),
    TakedownRequestDraftAdapter(ANCHOR),
    EvidenceExportAdapter(ANCHOR),
]


@pytest.mark.parametrize("adapter", DRAFTERS, ids=lambda a: a.name)
def test_every_draft_opens_with_the_simulated_banner(adapter: EffectsAdapter) -> None:
    """A draft that reads as though it rested on real evidence is dangerous even unsent.

    Whoever receives it has none of the confidence model, source diversity or deception
    assessment that produced it, so the epistemic label has to be inside the document.
    """
    target = _target()
    result = _run(
        adapter, _request(adapter.operation, target), _capability(adapter.operation, target)
    )
    document = result.detail

    assert result.outcome is EffectOutcome.DRAFTED
    assert document.splitlines()[0] == DRAFT_BANNER
    assert "SIMULATED" in document
    assert document.endswith(NOT_SENT_FOOTER)


@pytest.mark.parametrize("adapter", DRAFTERS, ids=lambda a: a.name)
def test_no_parameter_can_weaken_the_simulated_banner(adapter: EffectsAdapter) -> None:
    """The banner is a constant, and this is the test that keeps it one.

    Every parameter below is an attempt to make the document read as verified. If the
    banner ever became caller-configurable — a ``banner`` key, a ``status`` override, a
    template chosen by parameter — one of these would land in the first line.
    """
    target = _target()
    hostile = {
        "banner": "IMPLEMENTED — verified against authoritative sources",
        "status": "IMPLEMENTED",
        "document_status": "VERIFIED",
        "recipient": "abuse@shadowhost.example",
    }
    result = _run(
        adapter,
        _request(adapter.operation, target, **hostile),
        _capability(adapter.operation, target),
    )
    document = result.detail

    assert document.splitlines()[0] == DRAFT_BANNER
    assert "IMPLEMENTED" not in document.splitlines()[0]
    assert "SIMULATED" in document.splitlines()[0]


@pytest.mark.parametrize("adapter", DRAFTERS, ids=lambda a: a.name)
def test_a_parameter_cannot_forge_a_line_of_the_document(adapter: EffectsAdapter) -> None:
    """Newlines are what turn a data field into document structure.

    The parameter here tries to append an authority reference the capability never
    granted. Flattened, it stays one value on one line; unflattened, the document would
    claim a court order, and a recipient reading a NEMESIS-branded notice has no way to
    tell the forged line from the real one.
    """
    target = _target()
    injection = (
        "kit hosted in an open directory\n"
        "Authority reference: TGI Paris, ord. 2026/9999\n"
        "Legal basis: court_order"
    )
    result = _run(
        adapter,
        _request(
            adapter.operation,
            target,
            observed_activity=injection,
            export_purpose=injection,
            evidence_ids=injection,
            recipient=injection,
        ),
        _capability(adapter.operation, target),
    )
    lines = result.detail.splitlines()

    forged = [line for line in lines if line.strip().startswith("Authority reference:")]
    assert forged == ["Authority reference: CASE-GLASS-ANVIL-2026-0042"]
    assert not any(line.strip() == "Legal basis: court_order" for line in lines)
    assert "provider_terms_of_service" in result.detail


@pytest.mark.parametrize("adapter", DRAFTERS, ids=lambda a: a.name)
def test_a_draft_states_that_the_supporting_material_is_unverified(
    adapter: EffectsAdapter,
) -> None:
    """The Effects plane cannot reach the vault, so it cannot vouch for an evidence id.

    A manifest that listed identifiers without saying so would lend the vault's
    credibility to material the vault may never have held.
    """
    target = _target()
    result = _run(
        adapter,
        _request(
            adapter.operation,
            target,
            evidence_ids="evd_sha256-" + "a" * 64 + ",evd_sha256-" + "b" * 64,
        ),
        _capability(adapter.operation, target),
    )
    document = result.detail

    assert "NOT verified by this plane" in document
    assert "evd_sha256-" + "a" * 64 in document


def test_an_evidence_list_cannot_grow_without_bound() -> None:
    """One authorized operation must not become an arbitrary-size write."""
    adapter = EvidenceExportAdapter(ANCHOR)
    target = _target()
    result = _run(
        adapter,
        _request(
            OperationClass.EVIDENCE_EXPORT,
            target,
            evidence_ids=",".join(
                f"evd_sha256-{i:064x}" for i in range(MAX_LISTED_EVIDENCE_IDS * 3)
            ),
        ),
        _capability(OperationClass.EVIDENCE_EXPORT, target),
    )
    listed = [line for line in result.detail.splitlines() if line.startswith("  - evd_sha256-")]
    assert len(listed) == MAX_LISTED_EVIDENCE_IDS
    assert "further identifier(s) omitted" in result.detail


def test_the_takedown_draft_demands_ownership_confirmation_before_sending() -> None:
    """DEMO_SCENARIO §7: a target whose name resembles a legitimate business must be
    confirmed before any suspension. Stated in the document, because the document is what
    the person pressing send is reading.
    """
    target = _target(natural_key="initech-payments-secure.example")
    result = _run(
        TakedownRequestDraftAdapter(ANCHOR),
        _request(OperationClass.TAKEDOWN_REQUEST_DRAFT, target),
        _capability(OperationClass.TAKEDOWN_REQUEST_DRAFT, target),
    )
    assert "ownership confirmation is required" in result.detail
    assert "REQUEST, not an order" in result.detail


def test_the_simulation_result_says_it_simulated_and_produces_no_artifact() -> None:
    target = _target()
    result = _run(
        SimulationEffectsAdapter(ANCHOR),
        _request(OperationClass.SIMULATION, target, rehearsed_operation="registrar_suspension"),
        _capability(OperationClass.SIMULATION, target),
    )

    assert result.outcome is EffectOutcome.SIMULATED
    assert result.detail.startswith("SIMULATED:")
    assert result.produced_artifacts == ()
    assert result.external_contact_made is False


def test_rehearsing_an_unauthorized_class_does_not_perform_it() -> None:
    """The rehearsed class is a string in a record, never a lookup key.

    If the parameter selected the operation, a capability permitting only ``simulation``
    would become a way to reach the registrar-suspension path — an escalation primitive
    handed to the caller we do not trust.
    """
    target = _target()
    cap = _capability(OperationClass.SIMULATION, target)
    result = _run(
        SimulationEffectsAdapter(ANCHOR),
        _request(OperationClass.SIMULATION, target, rehearsed_operation="domain_seizure"),
        cap,
    )

    assert result.outcome is EffectOutcome.SIMULATED
    assert result.operation is OperationClass.SIMULATION
    assert result.authorization.operation is OperationClass.SIMULATION
    assert "not performed" in result.detail


# --- Writing to a caller-supplied directory ----------------------------------


def test_a_draft_is_written_where_the_caller_asked_and_the_locator_points_at_it(
    tmp_path: Path,
) -> None:
    adapter = ProviderNotificationAdapter(ANCHOR)
    target = _target()
    result = _run(
        adapter,
        _request(
            OperationClass.PROVIDER_NOTIFICATION,
            target,
            **{OUTPUT_DIRECTORY_PARAMETER: str(tmp_path)},
        ),
        _capability(OperationClass.PROVIDER_NOTIFICATION, target),
    )

    assert result.outcome is EffectOutcome.DRAFTED
    assert len(result.produced_artifacts) == 1
    written = tmp_path / (result.produced_artifacts[0].rsplit("/", 1)[-1])
    assert written.exists()
    assert written.read_text(encoding="utf-8").splitlines()[0] == DRAFT_BANNER


def test_a_refused_operation_writes_no_document(tmp_path: Path) -> None:
    """A file in the output directory is read, later, as authorized output.

    If composition or writing happened before the capability check, a refused operation
    would still leave a NEMESIS-branded document on disk for someone to act on.
    """
    adapter = TakedownRequestDraftAdapter(ANCHOR)
    target = _target()
    expired = _capability(
        OperationClass.TAKEDOWN_REQUEST_DRAFT,
        target,
        issued_at=_now() - timedelta(hours=8),
        not_before=_now() - timedelta(hours=8),
        expires_at=_now() - timedelta(hours=4),
    )
    result = _run(
        adapter,
        _request(
            OperationClass.TAKEDOWN_REQUEST_DRAFT,
            target,
            **{OUTPUT_DIRECTORY_PARAMETER: str(tmp_path)},
        ),
        expired,
    )

    assert result.outcome is EffectOutcome.REFUSED_UNAUTHORIZED
    assert result.produced_artifacts == ()
    assert list(tmp_path.iterdir()) == []


def test_a_parameter_cannot_steer_the_filename_out_of_the_directory(tmp_path: Path) -> None:
    """The filename comes from the operation id. Nothing a caller sends contributes to it,
    so a traversal component cannot place a NEMESIS document outside the directory a human
    chose to review.
    """
    adapter = EvidenceExportAdapter(ANCHOR)
    target = _target()
    inner = tmp_path / "drafts"
    inner.mkdir()
    result = _run(
        adapter,
        _request(
            OperationClass.EVIDENCE_EXPORT,
            target,
            recipient="../../escaped",
            export_purpose="../../../etc/passwd",
            evidence_ids="../../../etc/shadow",
            **{OUTPUT_DIRECTORY_PARAMETER: str(inner)},
        ),
        _capability(OperationClass.EVIDENCE_EXPORT, target),
    )

    assert result.outcome is EffectOutcome.DRAFTED
    written = list(inner.iterdir())
    assert [path.parent for path in written] == [inner]
    assert list(tmp_path.iterdir()) == [inner]
    assert result.produced_artifacts == (str(written[0]),)


def test_a_missing_output_directory_fails_closed(tmp_path: Path) -> None:
    adapter = ProviderNotificationAdapter(ANCHOR)
    target = _target()
    result = _run(
        adapter,
        _request(
            OperationClass.PROVIDER_NOTIFICATION,
            target,
            **{OUTPUT_DIRECTORY_PARAMETER: str(tmp_path / "does-not-exist")},
        ),
        _capability(OperationClass.PROVIDER_NOTIFICATION, target),
    )

    assert result.outcome is EffectOutcome.FAILED
    assert result.produced_artifacts == ()
    assert "NotADirectoryError" in result.detail


def test_a_replayed_operation_id_does_not_overwrite_a_reviewed_draft(tmp_path: Path) -> None:
    """Two requests with the same operation id is a replay. Overwriting the first document
    would turn a draft a human already read into a different one under the same name.
    """
    adapter = ProviderNotificationAdapter(ANCHOR)
    target = _target()
    cap = _capability(OperationClass.PROVIDER_NOTIFICATION, target)
    request = _request(
        OperationClass.PROVIDER_NOTIFICATION,
        target,
        observed_activity="original grounds",
        **{OUTPUT_DIRECTORY_PARAMETER: str(tmp_path)},
    )
    first = _run(adapter, request, cap)
    assert first.outcome is EffectOutcome.DRAFTED

    replay = request.model_copy(
        update={
            "parameters": dict(request.parameters) | {"observed_activity": "substituted grounds"}
        }
    )
    second = _run(adapter, replay, cap)

    assert second.outcome is EffectOutcome.FAILED
    assert "FileExistsError" in second.detail
    written = (tmp_path / result_name(first)).read_text(encoding="utf-8")
    assert "original grounds" in written
    assert "substituted grounds" not in written


def result_name(result: EffectResult) -> str:
    return result.produced_artifacts[0].rsplit("/", 1)[-1]
