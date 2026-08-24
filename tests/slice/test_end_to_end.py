"""The end-to-end vertical slice: the ten properties that decide whether this is safe to run.

Every test here is written to fail if the control it covers is removed, not to confirm that
the demonstration produced output. The run happens once, module-scoped, and each test
interrogates it — so a control that quietly stopped working cannot be hidden by a second,
differently-configured run.

The first test is the one that matters. NEMESIS exists to be the thing that does not name
an innocent person on a planted, uncorroborated, hostile-channel assertion, and the
scenario plants exactly that. A run that produces a name anywhere except as a recorded,
refused lead has failed at the only thing it cannot be allowed to get wrong.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine, Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel
from rich.console import Console

from nemesis.attribute.dimensions import AttributionDimension, RefusalReason
from nemesis.authz.providers import PROVIDER_NAME
from nemesis.cli.main import render
from nemesis.collect.fixtures.glass_anvil import (
    CDN_IP,
    CDN_POPULATION,
    CERT_FINGERPRINT,
    CLUSTER_DOMAINS,
    CLUSTER_IP,
    CLUSTER_POPULATION,
    FRAMED_ORGANIZATION,
    NAMED_PERSON,
    PERSONA_CURRENT,
    PERSONA_RESURGENT,
    PGP_FINGERPRINT,
    RESURGENCE_IP,
)
from nemesis.core.authorization import MVP_IMPLEMENTED_OPERATIONS, OperationClass
from nemesis.core.claims import Claim, ClaimKind
from nemesis.core.confidence import ConfidenceBand
from nemesis.core.entities import EntityCategory, EntityType
from nemesis.core.evidence import AdmissibilityDefect
from nemesis.core.relationships import (
    IDENTITY_ASSERTING_RELATIONS,
    PivotMethod,
    RelationType,
)
from nemesis.pursuit.investigation import InvestigationState
from nemesis.slice.scenario import STAGE_NAMES, ScenarioResult, run_glass_anvil_scenario

pytestmark = pytest.mark.slice

CDN_TENANTS = ("static-assets.example", "weather-widget.example")

NAME_MAY_APPEAR_AT = frozenset({"darkweb.identity_lead.lead_display"})
"""The only path in the whole result where the planted name is allowed to appear.

Not "the attribution does not name them" — every field of every stage is walked, because
the name leaks through a label, a hypothesis echoed back, or an entity listing long before
it reaches a conclusion. One allowed location, and it is the record of the refused lead
itself.
"""

WEAK_METHODS = frozenset(
    {
        PivotMethod.CODE_SIMILARITY,
        PivotMethod.LINGUISTIC_SIMILARITY,
        PivotMethod.BEHAVIORAL_PATTERN,
        PivotMethod.TEMPORAL_CORRELATION,
        PivotMethod.ANALYST_ASSERTION,
    }
)


def run[T](coroutine: Coroutine[Any, Any, T]) -> T:
    """Drive one store call to completion. There is no async test plugin in this project."""
    return asyncio.run(coroutine)


@pytest.fixture(scope="module")
def result(tmp_path_factory: pytest.TempPathFactory) -> ScenarioResult:
    """One run of the whole scenario, shared by every test in this module."""
    workspace: Path = tmp_path_factory.mktemp("glass-anvil")
    return run_glass_anvil_scenario(workspace=workspace)


@pytest.fixture(scope="module")
def rendered(result: ScenarioResult) -> str:
    """What an operator would actually see on the console."""
    console = Console(width=160, force_terminal=False, no_color=True, record=True)
    render(console, result)
    return console.export_text()


def _walk(prefix: str, value: object) -> Iterator[tuple[str, str]]:
    """Every string in a serialized stage, with the path that reaches it."""
    if isinstance(value, str):
        yield prefix, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _walk(f"{prefix}.{key}" if prefix else str(key), item)
    elif isinstance(value, list | tuple | set | frozenset):
        for item in value:
            # Deliberately not indexed: a name that moves from element 0 to element 1 is
            # the same leak, and an index in the allowlist would make the test pass on it.
            yield from _walk(prefix, item)


def _strings(result: ScenarioResult) -> Iterator[tuple[str, str]]:
    for name, stage in result.stages():
        assert isinstance(stage, BaseModel)
        yield from _walk(name, stage.model_dump(mode="json"))


def _mentions(result: ScenarioResult, needle: str) -> list[str]:
    lowered = needle.casefold()
    return sorted({path for path, value in _strings(result) if lowered in value.casefold()})


# ======================================================================================
# A. No attribution names a natural person.
# ======================================================================================


def test_the_planted_name_appears_only_as_a_recorded_refused_lead(
    result: ScenarioResult,
) -> None:
    """THE MOST IMPORTANT TEST IN THIS REPOSITORY.

    The scenario plants a name on a criminal forum: one source, a channel the adversary
    writes into, a persona with no history. The whole result object is walked, and the name
    is permitted in exactly one place — the record of the lead that was refused.

    Both halves matter. That the name appears *somewhere* is required: a platform that
    silently drops the assertion cannot show an analyst what it declined to act on, and
    cannot honour the retention obligations that attach to it. That it appears *nowhere
    else* is what this platform is for.
    """
    found = _mentions(result, NAMED_PERSON)

    assert found, (
        "the planted identity lead is not recorded anywhere; the refusal must be visible, "
        "not silent"
    )
    leaked = sorted(set(found) - NAME_MAY_APPEAR_AT)
    assert not leaked, f"the planted name leaked outside the refused-lead record: {leaked}"

    lead = result.darkweb.identity_lead
    assert lead.lead_display == NAMED_PERSON
    assert lead.category is EntityCategory.HUMAN_IDENTITY
    assert lead.entity_type is EntityType.HUMAN_IDENTITY_LEAD
    assert lead.promoted_to_attribution is False
    assert lead.is_personal_data is True


def test_the_human_identity_dimension_is_insufficient_basis(result: ScenarioResult) -> None:
    """Not a low probability, not a hedge: a refusal to estimate, reached before scoring."""
    human = result.attribute.result.for_dimension(AttributionDimension.HUMAN_IDENTITY)

    assert result.attribute.human_identity_band is ConfidenceBand.INSUFFICIENT_BASIS
    assert human.band is ConfidenceBand.INSUFFICIENT_BASIS
    assert human.is_refused
    assert human.opinion.is_vacuous
    assert human.supporting_claims == ()
    assert result.attribute.result.names_a_person is False

    gate = human.identity_gate
    assert gate is not None and not gate.passed
    assert set(gate.reasons) == {
        RefusalReason.SINGLE_SOURCED,
        RefusalReason.ONLY_ADVERSARY_INFLUENCEABLE,
        RefusalReason.NO_CORROBORATION,
    }
    # The claim is recorded against the refusal rather than under "supporting", so no
    # downstream reader can present it as grounds for a name.
    assert gate.refused_claims


def test_the_resolution_engine_refuses_to_name_the_operator(result: ScenarioResult) -> None:
    assert result.resolve.refusal.refused is True
    assert result.resolve.refusal.retained_identity_material is False
    assert result.resolve.refusal.persona == PERSONA_CURRENT
    assert "legal determination" in result.resolve.refusal.reason
    assert NAMED_PERSON.casefold() not in result.resolve.refusal.model_dump_json().casefold()


def test_no_identity_asserting_edge_touches_the_human_lead(result: ScenarioResult) -> None:
    """The lead is associated with a persona; nothing controls, operates or authors it.

    ``ASSOCIATED_WITH`` records that an assertion was made. An identity-asserting relation
    would record that the platform believes it, and those are the edges that end up in a
    referral.
    """
    graph = result.stores.graph
    leads = [
        entity for entity in graph.entities() if entity.category is EntityCategory.HUMAN_IDENTITY
    ]
    assert leads, "the scenario plants an identity lead; it must be in the graph"

    lead_ids = {entity.entity_id for entity in leads}
    touching = [
        edge
        for edge in graph.relationships()
        if edge.source_id in lead_ids or edge.target_id in lead_ids
    ]
    assert touching, "the lead is in the graph unconnected; the record of what was asserted is lost"
    assert not [edge for edge in touching if edge.relation in IDENTITY_ASSERTING_RELATIONS]


def test_the_rendered_output_never_prints_the_name(rendered: str) -> None:
    """The console output is what leaves the building first."""
    assert NAMED_PERSON.casefold() not in rendered.casefold()
    assert "INSUFFICIENT BASIS" in rendered
    assert "names no natural person" in rendered


# ======================================================================================
# B. The planted RedOctober string is contradicting evidence, never supporting.
# ======================================================================================


def test_the_false_flag_is_recorded_as_contradicting_evidence(result: ScenarioResult) -> None:
    """Trap A. It was offered in support and the engine turned it around.

    A marker this cheap to plant is better explained by someone having placed it than by
    the party it names having been careless, so it is evidence about the planter. Both
    halves are asserted: where it landed, and that it landed nowhere else.
    """
    claim_id = result.attribute.false_flag_claim_id
    organization = result.attribute.result.for_dimension(AttributionDimension.ORGANIZATION)

    assert claim_id in organization.contradicting_claims
    for dimension in AttributionDimension:
        assessment = result.attribute.result.for_dimension(dimension)
        assert claim_id not in assessment.supporting_claims, (
            f"the false flag is offered as support on the {dimension.value} dimension"
        )

    assert any(
        "recorded as contradicting evidence" in warning
        for warning in result.attribute.result.warnings
    )


def test_the_framed_organization_keeps_an_argued_alternative(result: ScenarioResult) -> None:
    """Retained and argued against, never deleted: it is what an opposing expert will raise."""
    organization = result.attribute.result.for_dimension(AttributionDimension.ORGANIZATION)
    named = [
        alt
        for alt in organization.alternatives
        if alt.name == f"{FRAMED_ORGANIZATION} is responsible"
    ]

    assert named, f"no alternative proposes that {FRAMED_ORGANIZATION} is responsible"
    for alternative in named:
        assert alternative.argument_against
        assert alternative.band is ConfidenceBand.INSUFFICIENT_BASIS

    planting = [alt for alt in organization.alternatives if alt.is_deception_hypothesis]
    assert planting, "the engine raised no planting hypothesis for a trivially plantable marker"


def test_no_dimension_attributes_the_operation_to_the_framed_organization(
    result: ScenarioResult,
) -> None:
    for dimension in AttributionDimension:
        assessment = result.attribute.result.for_dimension(dimension)
        assert FRAMED_ORGANIZATION not in assessment.hypothesis


# ======================================================================================
# C. The cluster is found; the CDN address does not build one.
# ======================================================================================


def test_the_four_domain_cluster_is_discovered(result: ScenarioResult) -> None:
    assert set(result.graph.cluster_domains) == set(CLUSTER_DOMAINS)
    assert set(result.graph.victim_domains_discovered) == {
        "globex-invoice-portal.example",
        "initech-payments-secure.example",
    }

    selective = result.graph.selective_pivot
    assert selective.population_size == CLUSTER_POPULATION
    assert selective.is_informative
    assert selective.projected_probability > result.graph.min_confidence


def test_the_cdn_address_pulls_nothing_into_the_cluster(result: ScenarioResult) -> None:
    """DEMO_SCENARIO.md §2.3, the control case.

    Three assertions, because two of them alone would pass on a graph where the CDN simply
    was not collected: the edge is *there*, it is scored as noise, and the tenants behind it
    are reachable with no floor and absent from the cluster with one. If the count or the
    scoring changed, the third assertion is the one that breaks.
    """
    worthless = result.graph.worthless_pivot
    assert worthless.population_size == CDN_POPULATION
    assert not worthless.is_informative
    assert worthless.band is ConfidenceBand.INSUFFICIENT_BASIS
    assert worthless.projected_probability < result.graph.min_confidence
    assert any("too many" in caveat for caveat in worthless.caveats)

    assert result.graph.cdn_tenants_in_cluster == ()
    assert result.graph.cdn_tenants_behind_the_filter == ()
    assert set(result.graph.cdn_tenants_reachable_unfiltered) == set(CDN_TENANTS)

    for tenant in CDN_TENANTS:
        assert tenant not in result.graph.cluster_entity_keys


def test_the_traversal_stops_at_shared_infrastructure(result: ScenarioResult) -> None:
    """The registrar and the announcing network are in the cluster as leaves, not as paths."""
    assert set(result.graph.excluded_shared_infrastructure) >= {"AS64512", "bulletproofreg"}


# ======================================================================================
# D and E. The vault holds it, verifies it, and says what it cannot defend.
# ======================================================================================


def test_evidence_is_actually_sealed_and_verifies(result: ScenarioResult) -> None:
    report = run(result.stores.vault.verify_integrity())

    assert report.objects_checked > 0
    assert report.artifacts_verified == report.objects_checked
    assert report.artifacts_missing == ()
    assert report.artifacts_corrupted == ()
    assert report.metadata_corrupted == ()
    assert report.unlogged_artifacts == ()
    assert report.hash_chain_intact
    assert report.is_intact

    # The bytes are on disk, not merely described: a sealed object whose artifact is
    # missing is exactly what "no preserved artifact" means.
    objects = run(result.stores.vault.list_evidence())
    assert objects
    for evidence in objects:
        assert evidence.vault_locator is not None
        assert (result.stores.vault.root / evidence.vault_locator).is_file()


def test_the_vault_does_not_claim_to_be_defensible_against_its_operator(
    result: ScenarioResult,
) -> None:
    """Invariant 10. The chain we compute ourselves proves nothing against ourselves.

    A local anchor was recorded during the run, deliberately: it is signed with a key this
    platform holds, so it must *not* move the verdict. If it did, the one flag that tells a
    reader the evidence cannot be defended against us would be flipped by us.
    """
    report = run(result.stores.vault.verify_integrity())

    assert report.is_defensible_against_insider is False
    assert report.externally_anchored == 0
    assert report.anchors_verified >= 1
    assert result.evidence.anchor_is_externally_held is False
    assert result.evidence.is_defensible_against_insider is False

    assert AdmissibilityDefect.NO_EXTERNAL_ANCHOR.value in result.evidence.admissibility_defects
    assert AdmissibilityDefect.SIMULATED_COLLECTION.value in result.evidence.admissibility_defects
    for evidence in run(result.stores.vault.list_evidence()):
        assert not evidence.is_admissible
        assert AdmissibilityDefect.NO_EXTERNAL_ANCHOR in evidence.admissibility()


# ======================================================================================
# F. The audit chain verifies and holds both decisions.
# ======================================================================================


def test_the_audit_chain_verifies_and_keeps_the_rejection(result: ScenarioResult) -> None:
    """A trail that recorded only the approvals hides the decision an operator most needs."""
    chain = run(result.stores.audit.verify())
    assert chain.intact, chain.reason
    assert chain.entries_checked > 0

    approvals = run(result.stores.audit.query(outcome="approved", limit=100))
    rejections = run(result.stores.audit.query(outcome="rejected", limit=100))

    assert approvals, "no approval reached the audit trail"
    assert rejections, "the rejection was not recorded; an unreadable refusal did not happen"
    assert any("registrar-suspension" in event.outcome for event in rejections)
    assert all(event.inputs["rationale"] for event in rejections)

    # And it remains readable through the gateway, not only as a log line.
    assert result.authorize.rejection.decision is False
    assert result.authorize.rejection.rationale
    assert result.authorize.rejected_request_state.value == "rejected"


def test_the_audit_trail_records_what_the_engine_and_the_analyst_each_did(
    result: ScenarioResult,
) -> None:
    pivots = run(result.stores.audit.query(action="pivot.execute", limit=500))
    directed = run(result.stores.audit.query(action="collection.directed", limit=500))
    effects = run(result.stores.audit.query(action="effect.execute", limit=500))

    assert pivots and directed and effects
    assert {event.actor_kind for event in pivots} == {"agent"}
    assert {event.actor_kind for event in directed} == {"human"}
    for event in directed:
        assert event.inputs["reason"], "a directed collection with no stated reason is unreviewable"


# ======================================================================================
# G. The issued capability is narrowly scoped.
# ======================================================================================


def test_the_capability_is_bound_expiring_and_authorizes_nothing_else(
    result: ScenarioResult,
) -> None:
    capability = result.authorize.capability

    assert result.authorize.verification.is_usable_now
    assert len(capability.targets) == len(CLUSTER_DOMAINS)
    assert {target.natural_key for target in capability.targets} == set(CLUSTER_DOMAINS)
    for target in capability.targets:
        assert set(target.bound_attributes) == {"resolves_to", "registrar"}

    assert capability.expires_at > capability.not_before
    assert result.authorize.lifetime_hours == 4.0
    # Only the rehearsal. The drafting class was requested and could not be approved by a
    # development identity, so it never entered the grant — a narrower capability than the
    # investigation asked for, which is the direction this control is supposed to fail in.
    assert capability.permitted_operations == frozenset({OperationClass.SIMULATION})

    approved = capability.targets[0].fingerprint
    for operation in OperationClass:
        decision = capability.authorizes(operation=operation, target_fingerprint=approved)
        assert decision.permitted is (operation in capability.permitted_operations), (
            f"{operation.value} is authorized outside the permitted set"
        )

    # Every probe the run recorded refused, and each refusal names its reason.
    assert result.authorize.scope_probes
    for probe in result.authorize.scope_probes:
        assert not probe.decision.permitted, probe.question
        assert probe.decision.denial_reasons


def test_dual_control_is_not_bypassed_by_the_issued_grant(result: ScenarioResult) -> None:
    """Nothing irreversible is permitted, so one approver is the correct threshold here."""
    capability = result.authorize.capability
    assert capability.required_approvals == 1
    assert not capability.permitted_operations - MVP_IMPLEMENTED_OPERATIONS
    assert OperationClass.REGISTRAR_SUSPENSION in capability.forbidden_operations


def test_the_demonstration_is_refused_the_one_operation_that_would_leave_the_platform(
    result: ScenarioResult,
) -> None:
    """The demo has to be told no, not merely to avoid asking.

    It used to request only the rehearsal it was allowed and describe the assurance floor in
    prose beside it, which demonstrates nothing: an option never requested proves nothing
    about whether it would have been refused. Now the notification is requested, the
    approval is refused, and the refusal is what gets printed.
    """
    stage = result.authorize
    assert stage.assurance_refused_operation is OperationClass.PROVIDER_NOTIFICATION
    assert "not established well enough" in stage.assurance_refusal
    assert "is the control" in stage.assurance_refusal
    assert stage.assurance_refused_by == PROVIDER_NAME

    # And therefore absent from the grant, which is the second refusal.
    assert OperationClass.PROVIDER_NOTIFICATION not in stage.capability.permitted_operations


def test_the_refusal_is_in_the_audit_trail_and_not_only_on_screen(
    result: ScenarioResult,
) -> None:
    """A control nobody can find afterwards is a control that did not happen."""
    events = run(result.stores.audit.query(action="authorization.refused_by_policy", limit=10))
    assert len(events) == 1
    assert events[0].inputs["operation"] == OperationClass.PROVIDER_NOTIFICATION.value
    assert events[0].inputs["assurance"] == "development"
    assert events[0].inputs["authenticated_by"] == PROVIDER_NAME


def test_every_recorded_decision_says_what_the_identity_was_worth(
    result: ScenarioResult,
) -> None:
    """Otherwise a reader six months later cannot tell a fixture from a login."""
    decisions = run(result.stores.audit.query(action="authorization.decision", limit=10))
    assert decisions
    for event in decisions:
        assert event.inputs["approver_assurance"] == "development"
        assert event.inputs["authenticated_by"] == PROVIDER_NAME


# ======================================================================================
# H. Nothing left the system.
# ======================================================================================


def test_no_effect_made_external_contact(result: ScenarioResult) -> None:
    assert result.effect.results
    for effect in result.effect.results:
        assert effect.external_contact_made is False, effect.operation.value
    assert result.effect.external_contact_made is False

    # Across the whole registry, not only the adapters this run happened to invoke.
    for adapter in result.stores.effects.adapters:
        assert adapter.makes_external_contact is False
    for record in result.effect.adapters:
        assert record.makes_external_contact is False


def test_the_simulated_takedown_ran_and_the_rejected_class_could_not(
    result: ScenarioResult,
) -> None:
    outcomes = {(effect.operation, effect.outcome.value) for effect in result.effect.results}

    assert (OperationClass.SIMULATION, "simulated") in outcomes
    # The drafting class is no longer granted. A development identity is entitled to
    # authorize a rehearsal and nothing meant to leave the platform, so the notification was
    # never in the capability and the attempt is refused for want of authorization. That
    # refusal is the demonstration: the gap is enforced rather than documented.
    assert (OperationClass.PROVIDER_NOTIFICATION, "refused_unauthorized") in outcomes
    # Refused at authorization, not for want of an adapter. Both are true of
    # ``registrar_suspension`` — the capability forbids it explicitly *and* nothing here
    # implements it — and since effects now run in a confined child process, the
    # authorization refusal happens first, in the trusted process, before any child exists.
    # That ordering is deliberate: whether we *could* perform an operation nobody authorized
    # is the wrong question, and asking it first is how a forgery becomes a capability
    # question. The no-adapter refusal is covered on its own in tests/planes/test_effects.py.
    assert (OperationClass.REGISTRAR_SUSPENSION, "refused_unauthorized") in outcomes

    refused = next(
        effect
        for effect in result.effect.results
        if effect.operation is OperationClass.REGISTRAR_SUSPENSION
    )
    assert "explicitly forbidden" in refused.detail
    assert not refused.authorization.permitted


# ======================================================================================
# I. The resurgence reconnects on artifacts, not on resemblance.
# ======================================================================================


def test_resurgence_reconnects_through_the_certificate_and_the_key(
    result: ScenarioResult,
) -> None:
    """Phase 8. The answer to "why do you think this is the same operator?" is two artifacts.

    Asserted on the explanation an analyst would be shown, not on an internal field: the
    obligation in invariant 12 is that the platform can say why, in words, on demand.
    """
    links = {link.pivot_method: link for link in result.resurgence.links}
    assert set(links) == {PivotMethod.INFRASTRUCTURE_REUSE, PivotMethod.CRYPTOGRAPHIC_IDENTITY}

    certificate = links[PivotMethod.INFRASTRUCTURE_REUSE]
    assert certificate.successor.endswith(RESURGENCE_IP)
    assert certificate.predecessor.endswith(CLUSTER_IP)
    assert CERT_FINGERPRINT in " ".join(certificate.explanation.reasons)

    key = links[PivotMethod.CRYPTOGRAPHIC_IDENTITY]
    assert key.successor.endswith(PERSONA_RESURGENT)
    assert key.predecessor.endswith(PERSONA_CURRENT)
    assert PGP_FINGERPRINT in " ".join(key.explanation.reasons)

    for link in result.resurgence.links:
        reasons = " ".join(link.explanation.reasons).casefold()
        assert "similarity" not in reasons
        assert "score" not in reasons
        assert link.pivot_method not in WEAK_METHODS


def test_the_reconnection_is_an_inference_that_cites_both_observations(
    result: ScenarioResult,
) -> None:
    """A conclusion never carries more standing than its weakest premise."""
    store = result.stores.claims
    for link in result.resurgence.links:
        claim = store.get_version(link.inference_claim_id)
        assert claim is not None
        assert claim.kind is ClaimKind.INFERENCE
        assert claim.rule_name == "resurgence.shared-artifact-reconnection"
        assert len(claim.derived_from_claims) == 2
        for parent_id in claim.derived_from_claims:
            parent = store.get_version(parent_id)
            assert parent is not None
            assert parent.kind is ClaimKind.OBSERVATION


def test_the_succession_edges_are_in_the_graph(result: ScenarioResult) -> None:
    successions = [
        edge
        for edge in result.stores.graph.relationships()
        if edge.relation is RelationType.SUCCEEDED_BY
    ]
    assert len(successions) == 2
    for edge in successions:
        assert edge.supporting_claims
        assert edge.is_synthetic


# ======================================================================================
# J. Everything in the run announces that it is synthetic.
# ======================================================================================


def test_every_entity_and_relationship_is_flagged_synthetic(result: ScenarioResult) -> None:
    """A synthetic node that loses the flag corrupts every figure downstream of it.

    Checked over the whole store rather than over a traversal: a sample cannot fail on the
    node nobody queried.
    """
    entities = result.stores.graph.entities()
    relationships = result.stores.graph.relationships()

    assert entities and relationships
    assert [entity.natural_key for entity in entities if not entity.is_synthetic] == []
    assert [edge.edge_id for edge in relationships if not edge.is_synthetic] == []


def test_every_claim_traces_back_to_simulated_collection(result: ScenarioResult) -> None:
    """No claim in this run rests on anything a court could be shown.

    Followed transitively: an inference is synthetic because its premises are, and a chain
    of individually reasonable steps is exactly how a synthetic origin gets laundered into
    something that looks collected.
    """
    store = result.stores.claims
    simulated_evidence = {
        evidence.evidence_id
        for evidence in run(result.stores.vault.list_evidence())
        if evidence.provenance.is_simulated
    }
    assert simulated_evidence

    by_id = {claim.claim_id: claim for claim in store.claims()}
    assert by_id

    def rests_on_simulated(claim: Claim, seen: frozenset[str]) -> bool:
        if claim.claim_id in seen:
            return False
        if claim.supported_by_evidence:
            return all(
                evidence_id in simulated_evidence for evidence_id in claim.supported_by_evidence
            )
        if not claim.derived_from_claims:
            return False
        return all(
            parent_id in by_id and rests_on_simulated(by_id[parent_id], seen | {claim.claim_id})
            for parent_id in claim.derived_from_claims
        )

    unflagged = [
        claim.claim_id for claim in by_id.values() if not rests_on_simulated(claim, frozenset())
    ]
    assert unflagged == []


def test_every_sealed_object_declares_simulated_collection(result: ScenarioResult) -> None:
    objects = run(result.stores.vault.list_evidence())
    assert objects
    for evidence in objects:
        assert evidence.provenance.is_simulated
        assert AdmissibilityDefect.SIMULATED_COLLECTION in evidence.admissibility()


# ======================================================================================
# The demonstration itself
# ======================================================================================


def test_the_run_reaches_every_stage(result: ScenarioResult) -> None:
    assert [name for name, _ in result.stages()] == list(STAGE_NAMES)
    assert result.pursue.autonomous_pivots > 0
    assert result.pursue.directed
    assert result.darkweb.persona_in_graph and result.darkweb.pgp_key_in_graph
    assert result.blockchain.signal_claim_id
    # The persona linkage is now margined like every other shared-origin claim. In this
    # scenario it rests on one published fingerprint, in a dark-web channel the adversary
    # writes into — one plantable fact — so the reported band is a refusal and the
    # evidential figure is carried beside it. That the demonstration's own headline linkage
    # is the thing refused is the point: the scenario plants exactly this shape.
    assert result.resolve.assessment.band is ConfidenceBand.INSUFFICIENT_BASIS
    evidential = result.resolve.assessment.fusion.evidential_opinion
    assert evidential is not None and evidential.projected_probability > 0.55
    assert result.resurgence.links


def test_the_dark_web_persona_and_its_key_reached_the_graph(result: ScenarioResult) -> None:
    graph = result.stores.graph
    persona = run(graph.find_entity(EntityType.PERSONA, PERSONA_CURRENT.lower()))
    key = run(graph.find_entity(EntityType.PGP_KEY, PGP_FINGERPRINT))

    assert persona is not None and key is not None
    assert result.darkweb.pgp_key_bits == 160
    # A short key id is collidable and must never establish identity; the model refuses one,
    # and the scenario's whole persona linkage rests on this being the full fingerprint.
    assert len(PGP_FINGERPRINT) == 40


def test_the_persona_linkage_is_carried_by_the_fingerprint_alone(
    result: ScenarioResult,
) -> None:
    """Phase 5. The alias is in the record and absent from the conclusion."""
    assessment = result.resolve.assessment
    decisive = assessment.decisive_signals

    assert len(decisive) == 1
    assert decisive[0].kind.value == "shared_cryptographic_identity"
    assert any(
        contribution.kind.value == "alias_similarity" and contribution.is_negligible
        for contribution in assessment.contributions
    )
    assert assessment.collapsed_groups, (
        "the correlated self-presentation signals were not collapsed"
    )


def test_the_two_phase_one_sensors_are_one_source(result: ScenarioResult) -> None:
    """Two sensors, one operator. Agreement here is not corroboration."""
    assert result.detect.fusion.total_sources == 2
    assert result.detect.fusion.independent_source_count == 1
    assert result.detect.sensors_collapsed_to_one_origin
    assert len({sensor.independence_key for sensor in result.detect.sensors}) == 1
    assert any("not corroboration" in warning for warning in result.detect.fusion.warnings)


def test_the_cdn_pivot_was_recorded_rather_than_dropped(result: ScenarioResult) -> None:
    """ "We looked and it means nothing" is a finding; silence is not."""
    directed = {
        (collection.pivot_type.value, collection.entity_key)
        for collection in result.pursue.directed
    }
    assert ("reverse_resolution", CDN_IP) in directed

    failed = [collection for collection in result.pursue.directed if not collection.succeeded]
    assert failed, "the fixture set contains a pivot that cannot be answered; it must be recorded"
    for collection in failed:
        assert collection.error


@pytest.mark.parametrize("stage", STAGE_NAMES)
def test_every_stage_renders(result: ScenarioResult, stage: str) -> None:
    console = Console(width=140, force_terminal=False, no_color=True, record=True)
    render(console, result, stage=stage)
    text = console.export_text()

    assert text.strip()
    assert NAMED_PERSON.casefold() not in text.casefold()


def test_the_rendered_output_makes_uncertainty_visible(rendered: str) -> None:
    """A band without its range is a word, and words are read differently by everyone."""
    assert "point estimate" in rendered
    assert "uncertainty" in rendered
    assert "(55% to 80%)" in rendered
    assert "independent origin(s)" in rendered
    assert "counted once" in rendered
    assert "cannot defend" in rendered
    assert "defensible against insider      False" in rendered


def test_the_demonstrated_effects_ran_confined(result: ScenarioResult) -> None:
    """Invariant 8, demonstrated by the kernel rather than asserted by the adapters.

    The demonstration used to conclude "external contact anywhere: False" from what the
    adapters declared about themselves — a claim by the components under suspicion. The
    rehearsals now run in a child process that holds no signing key, cannot import the
    intelligence platform, and on macOS cannot open a socket at all.
    """
    report = result.effect.isolation

    assert report.separate_process, "the report must come from a run that actually dispatched"
    assert report.private_key_withheld
    assert report.imports_sealed_by_worker
    assert report.deadline_seconds

    # On a platform that cannot deny the child a socket, this stays False and the demo says
    # so. Asserting the *consistency* rather than the value is the honest test: it fails if
    # the platform ever reports a confinement it did not get.
    assert report.egress_denied_from_this_process == (report.mechanism == "sandbox-exec")
    assert not report.contact_claimed_by_worker
    assert not result.effect.external_contact_made


def test_the_approval_chain_is_on_disk_when_the_run_ends(result: ScenarioResult) -> None:
    """A demonstration that lost its authorization state on exit could not be audited.

    The evidence vault and the audit trail have always persisted. The approval chain — what
    was asked for, who decided, what was issued, and what has since been withdrawn — lived
    in one process's dictionaries, which made revocation in particular a control with the
    lifetime of a process.
    """
    store = result.stores.authorization

    assert store.path.exists()
    capabilities = store.capabilities()
    assert [c.capability_id for c in capabilities] == [result.authorize.capability.capability_id]

    # Recovered from disk and still the grant that was signed: storage is not a place where
    # a capability quietly becomes trustworthy.
    recovered = capabilities[0]
    assert recovered.signing_payload() == result.authorize.capability.signing_payload()
    assert recovered.signature == result.authorize.capability.signature

    decisions = store.decisions(recovered.capability_id)
    assert [d.approver for d in decisions] == [result.authorize.approvals[0].approver]
    assert store.revocations() == ()


def test_the_investigation_itself_is_on_disk_when_the_run_ends(
    result: ScenarioResult,
) -> None:
    """The graph and the claims outlive the process, and replay into the same investigation.

    The vault and the audit trail always persisted; what the platform *believed* did not. A
    second store is opened over the same directory here — the way a restart would — and asked
    the same questions.
    """
    from nemesis.graph.journal import JournalBackedClaimStore, JournalBackedGraphStore

    workspace = result.stores.workspace / "graph"
    assert (workspace / "graph.jsonl").exists()
    assert (workspace / "claims.jsonl").exists()

    recovered = run(JournalBackedGraphStore.open(workspace))
    assert run(recovered.entity_count()) == run(result.stores.graph.entity_count())
    assert run(recovered.relationship_count()) == run(result.stores.graph.relationship_count())

    claims = run(JournalBackedClaimStore.open(workspace))
    assert len(claims.claims()) == len(result.stores.claims.claims())


def test_the_resurgence_stage_is_scored_and_the_score_is_a_lead(
    result: ScenarioResult,
) -> None:
    """Phase 8's prose says the reconnection happened; the engine says what it is worth.

    **It is worth a lead, and that is the corrected answer.** An earlier version of this test
    asserted VERY_LIKELY and actionable, because the assessment it checked named an OWN_SENSOR
    as the observer of the certificate reuse. The platform never collected it that way:
    ``CERTIFICATE_REUSE`` is served by the internet-scan connector, and the PGP fingerprint
    comes off a dark-web forum. Both are channels an adversary can write into — putting a
    certificate where a scanner will find it, or a fingerprint on a forum profile, is exactly
    how you arrange to have somebody else blamed for your return.

    So the robustness margin removes both facts and the finding does not stand. That is the
    control working on the proposition it was built for rather than a regression: this
    scenario's reconnection genuinely rests on two arrangeable observations, and a platform
    reporting it as very likely would be reporting a number its own evidence cannot support.

    What would move it is one fact from a channel an adversary cannot author into. The
    allowlist is ``{OWN_SENSOR, LAW_ENFORCEMENT}``, and neither collected this.
    """
    from nemesis.core.confidence import ConfidenceBand
    from nemesis.core.disclosure import DisclosureClass

    assessment = result.resurgence.assessment

    assert assessment.band is ConfidenceBand.UNLIKELY
    assert not assessment.is_actionable
    assert assessment.fusion.rests_only_on_plantable_evidence
    assert any("plant" in warning for warning in assessment.fusion.warnings)

    # The PGP fingerprint names a persona, and persona linkage is an investigative lead under
    # founder decision D1. The wrapper takes the classification of its most restricted part.
    assert assessment.disclosure is DisclosureClass.INTERNAL_LEAD
    assert assessment.rests_on_internal_material

    # A finding with no competing account on the page is an argument, not an assessment.
    assert len(assessment.alternatives) >= 2


def test_the_blind_graph_walk_agrees_with_the_narrated_assessment(
    result: ScenarioResult,
) -> None:
    """Both halves of phase 8 reach the same verdict, which is what the resolver bought.

    Before provenance could be resolved they disagreed loudly — the walk scored 0.007 and the
    hand-written assessment 0.811 — and that gap was read as the value of checking where an
    observation came from. Checking it revealed that the higher number was the wrong one.
    """
    assert result.resurgence.graph_signals
    unplantable = [
        signal
        for signal in result.resurgence.graph_signals
        if not signal.observed_by.is_adversary_influenceable
    ]
    # Exactly one, and it arrived with the own-sensor connector. This assertion read "nothing"
    # until that connector existed; it is what changed the count. The narrated assessment still
    # rests on the internet scan and the forum, so both halves continue to agree that nothing
    # in this run is actionable.
    assert len(unplantable) == 1
    assert not result.resurgence.assessment.is_actionable
    assert not result.resurgence.watch.resumes


def test_the_resurgence_watch_actually_runs_and_records_its_refusal(
    result: ScenarioResult,
) -> None:
    """The loop's last edge, exercised rather than merely available.

    Phase 8 used to end with the case parked in MONITORING_RESURGENCE and nothing ever asking
    whether the adversary had come back. Now the watch runs — after the phase-8 collection has
    landed, which is the only order in which the answer can mean anything — and it refuses.

    Refusing is the expected outcome here and it is not a gap. Everything this run collects
    arrives through a channel an adversary can write into, so no candidate can clear the
    robustness margin. A watch that resumed anyway would spend the remaining budget on a
    coincidence, which is the failure this design exists to prevent.

    The pass is in the audit trail either way: a watch that ran and refused must be
    distinguishable from a watch that stopped running.
    """
    watch = result.resurgence.watch

    assert watch.not_watching_reason is None, "the watch declined to run"
    assert watch.candidates_examined >= 1
    assert watch.investigation_id == result.pursue.investigation.investigation_id

    assert not watch.resumes
    assert result.resurgence.resumed is None
    assert result.pursue.investigation.state is InvestigationState.MONITORING_RESURGENCE

    recorded = run(result.stores.audit.query(action="resurgence.watch", limit=10))
    assert recorded, "the watch pass left no audit record"
    assert recorded[0].inputs["candidates_examined"] == str(watch.candidates_examined)
    assert recorded[0].outcome == "no candidate cleared the bar"


def test_the_watch_examines_only_what_the_case_actually_worked_on(
    result: ScenarioResult,
) -> None:
    """The cluster comes from the investigation's own branch foci.

    Not from a separately maintained inventory of what the campaign owns, which would be a
    second thing to keep true. The consequence is visible and worth pinning: a hand-picked
    seed list produces more candidates than the case's own branches do, and the case's own is
    the defensible one — it is what this investigation established rather than what somebody
    assumed it covered.
    """
    watch = result.resurgence.watch
    branch_keys = {b.focus_entity_key for b in result.pursue.investigation.branches}

    assert branch_keys, "the investigation opened no branches"
    assert watch.candidates_examined <= len(result.resurgence.graph_signals)
    assert all(finding.candidate_key not in branch_keys for finding in watch.findings), (
        "a candidate the case already worked on is last month, not a return"
    )


def test_the_own_sensor_gives_exactly_one_candidate_an_unplantable_fact(
    result: ScenarioResult,
) -> None:
    """What the own-sensor connector actually bought, measured rather than asserted.

    Before it existed every candidate in this run rested only on plantable evidence, so the
    robustness margin stripped all of them and no amount of bridge-finding could have produced
    a finding. Now exactly one candidate — the returning domain, recognised through a kit build
    path our own gateway captured in both waves — has a fact the margin will not remove.

    **It is still not actionable, and that is the honest state.** The marker's edge carries no
    usable population, because ``Relationship`` refuses selectivity on a direct observation and
    it is right to: the gateway observed the kit, it did not infer anything from a shared
    attribute. So the signal weighs nothing, the candidate is single-origin, and the verdict is
    a lead.

    What would close the loop is a second *weighted* fact about the same domain. That is a
    property of what this scenario collects, not of the machinery, and shaping the fixtures
    until the number came out would be manufacturing the result.
    """
    from nemesis.pursuit.resurgence import ResurgenceEngine
    from nemesis.pursuit.watch import signals_by_candidate

    grouped = signals_by_candidate(result.resurgence.graph_signals)
    assert grouped, "the walk found nothing"

    survived = {
        key
        for key, members in grouped.items()
        if not ResurgenceEngine()
        .assess(
            campaign="x",
            signals=members,
            candidate_population=40,
            assessed_at=result.resurgence.as_of,
        )
        .fusion.rests_only_on_plantable_evidence
    }
    assert len(survived) == 1
    assert survived.pop()[1] == "acme-invoice-secure2.example"

    # And the loop still does not close, for the reason above.
    assert not result.resurgence.watch.resumes
