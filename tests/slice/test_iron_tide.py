"""Operation IRON TIDE: the properties that decide whether an IP-seeded run is honest.

Every test here is written to fail if the control it covers is removed, not to confirm that
the run produced output. The run happens once, module-scoped, and each test interrogates it —
so a control that quietly stopped working cannot be hidden by a second, differently-configured
run.

What this module covers that ``test_end_to_end.py`` cannot. GLASS ANVIL seeds on a domain, so
it never exercises the question an address forces: *is co-location on this thing worth
anything at all?* Those tests therefore cannot fail if the tenant count stops being collected,
if the shared-hosting control stops being worthless, or if a strong edge onto a crowded node
starts licensing weak edges out of it. These can.
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
from nemesis.cli.main import _render_trace
from nemesis.collect.fixtures.iron_tide import (
    CERT_FINGERPRINT,
    CLUSTER_DOMAINS,
    FRAMED_ORGANIZATION,
    IMPLANT_SHA256,
    NAMED_PERSON,
    PERSONA,
    SECOND_C2_IP,
    SEED_IP,
    SEED_POPULATION,
    SHARED_HOST_IP,
    SHARED_HOST_POPULATION,
    dark_web_fixtures,
    malware_fixtures,
    own_sensor_fixtures,
)
from nemesis.core.confidence import ConfidenceBand
from nemesis.core.entities import EntityType
from nemesis.core.evidence import AdmissibilityDefect
from nemesis.core.provenance import SourceClass
from nemesis.core.relationships import PivotMethod, RelationType
from nemesis.ports.collection import PivotType
from nemesis.ports.storage import GraphQuery
from nemesis.slice.iron_tide import STAGE_NAMES, IronTideResult, run_iron_tide

pytestmark = pytest.mark.slice

NAME_MAY_APPEAR_AT = frozenset({"pursue.refused_lead.lead_display"})
"""The only path in the whole result where the planted name is allowed to appear.

Not "the attribution does not name them" — every field of every stage is walked, because a
name leaks through a label, an echoed hypothesis or an entity listing long before it reaches a
conclusion. One allowed location, and it is the record of the refused lead itself.
"""


def run[T](coroutine: Coroutine[Any, Any, T]) -> T:
    """Drive one store call to completion. There is no async test plugin in this project."""
    return asyncio.run(coroutine)


@pytest.fixture(scope="module")
def result(tmp_path_factory: pytest.TempPathFactory) -> IronTideResult:
    workspace: Path = tmp_path_factory.mktemp("iron-tide")
    return run_iron_tide(workspace=workspace)


@pytest.fixture(scope="module")
def rendered(result: IronTideResult) -> str:
    """What an operator would actually see on the console."""
    console = Console(width=160, force_terminal=False, no_color=True, record=True)
    _render_trace(console, result)
    return console.export_text()


def _walk(prefix: str, value: object) -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield prefix, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _walk(f"{prefix}.{key}" if prefix else str(key), item)
    elif isinstance(value, list | tuple | set | frozenset):
        for item in value:
            # Deliberately not indexed: a name that moves from element 0 to element 1 is the
            # same leak, and an index in the allowlist would make the test pass on it.
            yield from _walk(prefix, item)


def _strings(result: IronTideResult) -> Iterator[tuple[str, str]]:
    for name, stage in result.stages():
        assert isinstance(stage, BaseModel)
        yield from _walk(name, stage.model_dump(mode="json"))


def _mentions(result: IronTideResult, needle: str) -> list[str]:
    lowered = needle.casefold()
    return sorted({path for path, value in _strings(result) if lowered in value.casefold()})


# ======================================================================================
# A. The seed is an address, and an address is guilty of nothing.
# ======================================================================================


def test_the_run_is_seeded_on_an_ip_address(result: IronTideResult) -> None:
    """The premise. If this ever becomes a domain the module is testing GLASS ANVIL again."""
    assert result.detect.seed_entity_type is EntityType.IP_ADDRESS
    assert result.detect.seed_entity_key == SEED_IP
    assert result.pursue.investigation.seed.entity_type is EntityType.IP_ADDRESS
    assert result.pursue.investigation.seed.entity_key == SEED_IP


def test_the_detection_establishes_use_and_says_it_establishes_nothing_else(
    result: IronTideResult,
) -> None:
    """Two sensors, one operator, and an explicit record of what the seed does not say.

    The silence is a stage field rather than a docstring because it has to survive into the
    rendered output an operator reads. A run that shows a beacon and no caveat invites exactly
    the inference the rest of the run spends its budget refusing to make.
    """
    assert result.detect.fusion.independent_source_count == 1
    assert result.detect.fusion.total_sources == 2
    assert len(result.detect.what_the_seed_does_not_say) >= 3
    assert any("who operates" in line for line in result.detect.what_the_seed_does_not_say)


def test_the_seed_address_is_never_classified_as_the_adversarys(result: IronTideResult) -> None:
    """The role gate refuses to promote the seed, and the attribution does not overrule it.

    This is the test that would fail if somebody wired the attribution into the standing
    producer to "finish the picture". The infrastructure dimension reaches a real band and the
    address stays `unknown`, because nothing in the graph asserts that an adversary entity
    controls *that node* — and control is what the effects boundary reads. Attribution is not
    authorization; this asserts the two really are separate rather than merely described as
    separate.
    """
    seed = next(r for r in result.standing.records if r.entity_key == SEED_IP)
    assert seed.role.value == "unknown"

    infrastructure = result.attribute.dimension(AttributionDimension.INFRASTRUCTURE)
    assert infrastructure.band is not ConfidenceBand.INSUFFICIENT_BASIS, (
        "the infrastructure dimension is expected to reach a band; if it does not, this test "
        "is passing for the wrong reason"
    )


# ======================================================================================
# B. Counting the tenants is what licenses the pivot.
# ======================================================================================


def test_the_tenant_count_is_collected_before_co_location_is_believed(
    result: IronTideResult,
) -> None:
    """`proxy_classification` runs on the seed and returns a population of one.

    Until this connector existed the pivot came back `REQUIRES_EXTERNAL_DATA` on every address
    in every run. Without it there is no honest way to read three names on an address as three
    names under one hand, and the whole cluster below rests on an uncounted assumption.
    """
    classified = [
        p
        for p in result.pursue.autonomous
        if p.pivot_type is PivotType.PROXY_CLASSIFICATION and p.succeeded
    ]
    assert {p.entity_key for p in classified} >= {SEED_IP, SECOND_C2_IP, SHARED_HOST_IP}

    lease = next(
        edge
        for edge in result.cluster.selective_edges
        if edge.source_key == SEED_IP and edge.relation is RelationType.HOSTED_ON
    )
    assert lease.population_size == 1
    assert lease.is_informative


def test_the_reverse_pivot_on_the_seed_is_selective_and_the_one_on_the_platform_is_not(
    result: IronTideResult,
) -> None:
    """Same relation, same method, opposite analytic value. The only difference is the count."""
    selective = [
        e
        for e in result.cluster.selective_edges
        if e.target_key == SEED_IP and e.relation is RelationType.RESOLVES_TO
    ]
    assert len(selective) == SEED_POPULATION
    assert all(e.population_size == SEED_POPULATION for e in selective)
    assert all(e.is_informative for e in selective)

    worthless = [
        e
        for e in result.cluster.worthless_edges
        if e.target_key == SHARED_HOST_IP and e.relation is RelationType.RESOLVES_TO
    ]
    assert worthless, "the shared-hosting control produced no edges; the control is gone"
    assert all(e.population_size == SHARED_HOST_POPULATION for e in worthless)
    assert all(not e.is_informative for e in worthless)
    assert all(e.band is ConfidenceBand.INSUFFICIENT_BASIS for e in worthless)
    assert all(e.pivot_method is PivotMethod.SHARED_ATTRIBUTE for e in worthless)


def test_a_strong_edge_onto_a_crowded_node_licenses_nothing_out_of_it(
    result: IronTideResult,
) -> None:
    """The lesson an address-seeded case has to teach and a domain-seeded one never meets.

    The certificate — the strongest pivot in the run — reaches `192.0.2.144`. Every edge out of
    that node is then worth 0.07 and bands as insufficient basis. If a future change ever lets
    reachability confer weight, this fails.
    """
    onto = [
        e
        for e in result.cluster.selective_edges
        if e.source_key == SHARED_HOST_IP and e.relation is RelationType.PRESENTS_CERTIFICATE
    ]
    assert onto and all(e.is_informative for e in onto)

    out_of = [e for e in result.cluster.worthless_edges if e.target_key == SHARED_HOST_IP]
    assert out_of
    assert max(e.evidential_weight for e in out_of) < min(e.evidential_weight for e in onto)


def test_the_uninvolved_co_tenants_are_reported_rather_than_absorbed(
    result: IronTideResult,
) -> None:
    """The planner walks onto them; the graph believes nothing about them; the run says so.

    `_spawn_branches` does not consult edge confidence, so a co-tenant of a 12,400-name
    platform gets a branch and a budget exactly like a name on a dedicated lease. That is a
    real cost and the important half is not the budget — it is three uninvolved parties now
    present in an investigation's graph. A run that did not surface them would be hiding a
    collateral-collection fact behind a spend figure.
    """
    assert result.cluster.bystanders, (
        "no bystanders were reported; either the control stopped returning co-tenants or the "
        "measurement stopped looking"
    )
    assert result.cluster.bystander_pivots >= len(result.cluster.bystanders)
    for name in result.cluster.bystanders:
        assert not any(
            edge.source_key == name and edge.is_informative
            for edge in result.cluster.selective_edges
        ), f"{name} acquired an informative edge; the control has stopped controlling"


# ======================================================================================
# C. The one fact an adversary could not have written.
# ======================================================================================


def test_one_statement_is_attested_by_two_origins_one_of_which_is_unplantable() -> None:
    """The fixture-level property the campaign dimension rests on.

    Asserted against the fixtures directly, not through a run, because the failure mode is
    silent: :meth:`Statement.canonical` includes the qualifier dict, so adding a qualifier to
    one attestation and not the other splits one fact into two, and every downstream number
    still looks reasonable.
    """
    own = {
        r.statement.canonical()
        for r in own_sensor_fixtures()[(PivotType.OWN_TELEMETRY, SEED_IP)].records
    }
    config = {
        r.statement.canonical()
        for r in malware_fixtures()[(PivotType.C2_EXTRACTION, IMPLANT_SHA256)].records
    }
    shared = own & config
    assert len(shared) == len(CLUSTER_DOMAINS), (
        "the two attestations no longer produce identical statements; the run's only "
        "unplantable fact has silently split in two"
    )


def test_the_only_multi_origin_dimension_is_the_only_one_to_reach_very_likely(
    result: IronTideResult,
) -> None:
    """What independent corroboration is actually worth, measured rather than asserted.

    Campaign is the one dimension attested by two provenance clusters — the victim's own
    resolver and a commercial configuration extraction — and it is the one dimension that
    reaches `very_likely`. Every other dimension has one origin and lands lower. If a future
    change lets a single-origin dimension reach the same band, the distinction this platform is
    built on has stopped costing anything.
    """
    campaign = result.attribute.dimension(AttributionDimension.CAMPAIGN)
    assert campaign.source_diversity.independent_source_count == 2
    assert campaign.band is ConfidenceBand.VERY_LIKELY

    others = [
        result.attribute.dimension(d)
        for d in AttributionDimension
        if d is not AttributionDimension.CAMPAIGN
    ]
    assert all(a.source_diversity.independent_source_count == 1 for a in others)
    assert all(a.band is not ConfidenceBand.VERY_LIKELY for a in others)


def test_the_campaign_dimension_carries_an_unplantable_signal(result: IronTideResult) -> None:
    campaign = result.attribute.dimension(AttributionDimension.CAMPAIGN)
    diversity = campaign.source_diversity
    assert diversity.adversary_influenceable_sources < diversity.total_signals


def test_every_dimension_reports_what_the_robustness_margin_did(
    result: IronTideResult,
) -> None:
    """And reports it through the summariser, never as the raw fact key.

    A fact key is a JSON object carrying the subject, the predicate and every qualifier. This
    repository has already had one leak into an external product twice; the third surface is
    this stage.
    """
    assert len(result.attribute.what_the_margin_removed) == len(AttributionDimension)
    for line in result.attribute.what_the_margin_removed:
        assert '{"' not in line, f"a raw fact key reached the stage output: {line}"
        assert "qualifiers" not in line


# ======================================================================================
# D. Cheap-to-plant material is turned around, not weighted.
# ======================================================================================


def test_the_false_flag_is_recorded_as_contradicting_what_it_was_offered_to_support(
    result: IronTideResult,
) -> None:
    """It is offered in support on purpose, so that the engine has to be the thing that refuses.

    A scenario that never offered the planted marker would prove nothing about the inversion.
    """
    organization = result.attribute.dimension(AttributionDimension.ORGANIZATION)
    assert result.attribute.false_flag_claim_id in organization.contradicting_claims
    assert result.attribute.false_flag_claim_id not in organization.supporting_claims
    assert any(alt.is_deception_hypothesis for alt in organization.alternatives)


def test_an_organization_resting_on_one_plantable_fact_is_refused(
    result: IronTideResult,
) -> None:
    """Once the build tag inverts, one plantable fact is left and the margin removes it.

    Reported as no basis rather than as a weak finding, which is the whole argument of the
    robustness margin: a conclusion an adversary can produce by planting one artifact is not a
    conclusion.
    """
    organization = result.attribute.dimension(AttributionDimension.ORGANIZATION)
    assert organization.band is ConfidenceBand.INSUFFICIENT_BASIS
    assert organization.margin_outcome == "every_fact_removed"


def test_the_framed_organization_is_never_the_attributed_one(result: IronTideResult) -> None:
    organization = result.attribute.dimension(AttributionDimension.ORGANIZATION)
    assert FRAMED_ORGANIZATION not in organization.hypothesis
    assert any(FRAMED_ORGANIZATION in alt.name for alt in organization.alternatives)


def test_the_reused_handle_is_not_treated_as_two_facts(result: IronTideResult) -> None:
    """A cheap string in a config file and the same string in a profile is one string, twice."""
    persona = result.attribute.dimension(AttributionDimension.PERSONA)
    assert len(persona.contradicting_claims) >= 1
    assert any("tidehook_ops" in warning for warning in persona.warnings)


# ======================================================================================
# E. No attribution names a natural person.
# ======================================================================================


def test_the_planted_name_appears_only_as_a_recorded_refused_lead(
    result: IronTideResult,
) -> None:
    """The most important test in this module, for the same reason as in GLASS ANVIL.

    Both halves matter. That the name appears *somewhere* is required: a platform that silently
    drops the assertion cannot show an analyst what it declined to act on, and cannot honour the
    retention obligations that attach to it. That it appears *nowhere else* is what this
    platform is for.
    """
    found = _mentions(result, NAMED_PERSON)
    assert found, (
        "the planted identity lead is not recorded anywhere; the refusal must be visible, "
        "not silent"
    )
    leaked = sorted(set(found) - NAME_MAY_APPEAR_AT)
    assert not leaked, f"the planted name leaked outside the refused-lead record: {leaked}"

    lead = result.pursue.refused_lead
    assert lead.lead_display == NAMED_PERSON
    assert lead.entity_type is EntityType.HUMAN_IDENTITY_LEAD
    assert lead.asserted_by_source is SourceClass.DARK_WEB
    assert lead.promoted_to_attribution is False
    assert lead.is_personal_data is True


def test_the_human_identity_dimension_is_refused_before_scoring(result: IronTideResult) -> None:
    human = result.attribute.dimension(AttributionDimension.HUMAN_IDENTITY)
    assert result.attribute.human_identity_band is ConfidenceBand.INSUFFICIENT_BASIS
    assert human.is_refused
    assert human.opinion.is_vacuous
    assert human.supporting_claims == ()
    assert result.attribute.result.names_a_person is False

    gate = human.identity_gate
    assert gate is not None and not gate.passed
    assert RefusalReason.SINGLE_SOURCED in gate.reasons


def test_the_rendered_output_does_not_carry_the_name(rendered: str) -> None:
    """The console is a second surface and it is the one people paste into tickets."""
    assert NAMED_PERSON.casefold() not in rendered.casefold()


# ======================================================================================
# F. Three tiers of agency, kept apart.
# ======================================================================================


def test_the_policy_the_pilot_and_the_analyst_are_reported_separately(
    result: IronTideResult,
) -> None:
    """A run that folded them into one number would be unreviewable.

    Which move was whose is the question ADR-0008 exists to keep answerable: the pilot is
    external and untrusted, so "the engine found this" and "a model asked for this and the
    engine allowed it" are different claims about the same evidence.
    """
    assert {p.chosen_by for p in result.pursue.autonomous} == {"policy"}
    assert {p.chosen_by for p in result.pursue.pilot} == {"pilot"}
    assert {p.chosen_by for p in result.pursue.analyst} == {"analyst"}
    assert result.pursue.autonomous and result.pursue.pilot and result.pursue.analyst


def test_the_autonomous_walk_reaches_the_second_address_through_the_certificate(
    result: IronTideResult,
) -> None:
    """No pilot and no analyst in this chain: address, names, certificate, more addresses.

    `CERTIFICATE_HISTORY` is not proposed for an IP address, so an IP-seeded run can only meet
    the certificate through `service_fingerprint`. If that pivot ever stops being answered the
    cluster collapses back to one address and this fails.
    """
    by_policy = {(p.pivot_type, p.entity_key) for p in result.pursue.autonomous if p.succeeded}
    assert (PivotType.SERVICE_FINGERPRINT, SEED_IP) in by_policy
    assert (PivotType.CERTIFICATE_REUSE, CERT_FINGERPRINT) in by_policy
    assert (PivotType.REVERSE_RESOLUTION, SECOND_C2_IP) in by_policy


def test_the_pilots_pivots_go_through_the_engine_and_are_budgeted(
    result: IronTideResult,
) -> None:
    """The seam, and the reason it is a seam rather than a side channel.

    Every pilot move carries a real connector name and a real cost, because it went through
    `execute_pivot` — the same routing, budget and provenance ordering the policy's own moves
    use. A pilot that could collect outside the engine would be a pilot the engine cannot
    limit.
    """
    for record in result.pursue.pilot:
        assert record.connector not in {"", "none"} or not record.succeeded
        assert record.rationale
    assert sum(r.cost for r in result.pursue.pilot) > 0
    assert result.pursue.budget_spent <= result.pursue.investigation.total_budget


def test_a_refused_capability_is_a_failure_and_never_an_absence(
    result: IronTideResult,
) -> None:
    """A refusal and an absence are different findings, and only one is evidence."""
    similarity = next(
        r for r in result.pursue.pilot if r.pivot_type is PivotType.MALWARE_SIMILARITY
    )
    assert not similarity.succeeded
    assert similarity.error and "not an observation" in similarity.error


def test_the_analysts_leap_is_the_one_no_connector_can_answer(
    result: IronTideResult,
) -> None:
    """And the reason is recorded on the stage, not left to a reader to reconstruct."""
    assert "no connector" in result.pursue.analyst_because.casefold()
    assert {p.entity_type for p in result.pursue.analyst} == {EntityType.PERSONA}


# ======================================================================================
# G. Provenance, and what the run refuses to claim.
# ======================================================================================


def test_every_sealed_artifact_is_marked_synthetic(result: IronTideResult) -> None:
    """A demonstration that could be mistaken for a case is a defect, not a demonstration."""
    objects = run(result.stores.vault.list_evidence())
    assert objects
    for obj in objects:
        assert AdmissibilityDefect.SIMULATED_COLLECTION in obj.admissibility()


def test_the_vault_and_the_audit_chain_verify(result: IronTideResult) -> None:
    assert result.evidence.vault_intact
    assert result.evidence.audit_chain_intact
    assert result.evidence.sealed_objects > 0
    assert result.evidence.audit_events > 0


def test_the_run_states_that_it_does_not_reach_an_actor_node(result: IronTideResult) -> None:
    """The gap is reported on every run rather than left for a reader to infer.

    A persona is not an actor, and this repository has no code that makes one. Saying so on the
    result is the difference between a limitation and a silent overclaim.
    """
    assert "THREAT_ACTOR" in result.actor_gap
    seed = run(result.stores.graph.find_entity(EntityType.IP_ADDRESS, SEED_IP))
    assert seed is not None
    subgraph = run(
        result.stores.graph.neighbourhood(
            GraphQuery(
                entity_id=seed.entity_id,
                max_depth=8,
                min_confidence=0.0,
                exclude_shared_infrastructure=False,
            )
        )
    )
    graph_types = {entity.entity_type for entity in subgraph.entities}
    assert EntityType.THREAT_ACTOR not in graph_types
    assert EntityType.PERSONA in graph_types


def test_the_persona_is_reached_and_is_not_confused_with_an_operator(
    result: IronTideResult,
) -> None:
    """The chain does arrive somewhere. It arrives at a vendor profile, and says so."""
    persona = result.attribute.dimension(AttributionDimension.PERSONA)
    assert PERSONA in persona.hypothesis
    assert persona.band is not ConfidenceBand.INSUFFICIENT_BASIS
    listings = dark_web_fixtures()[(PivotType.MARKETPLACE_LISTING, PERSONA.lower())]
    assert listings.records


def test_every_stage_renders(rendered: str) -> None:
    for name in STAGE_NAMES:
        assert name.upper() in rendered.upper(), f"stage {name} produced no output"
