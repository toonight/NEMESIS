"""Collection-plane tests: the GLASS ANVIL fixtures and the simulated connectors.

Each test here is written to fail if a specific control is removed, not to confirm that the
fixtures parse. The controls under test:

- the two population counts that separate a selective pivot from a worthless one;
- open temporal bounds on observations, pinned bounds only where a registry defines them;
- adversary-authored content arriving as inert data, sandboxed and flagged;
- deception assessments on both planted trails;
- two sensors with one operator collapsing to one source;
- phase-8 material staying invisible to a phase-2 run;
- a failed pivot recorded as a failure rather than as an absence.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from nemesis.collect.base import (
    QUALIFIER_GLOBALLY_UNIQUE,
    QUALIFIER_HOSTILE_CONTENT,
    QUALIFIER_POPULATION_CORPUS,
    QUALIFIER_POPULATION_SIZE,
    QUALIFIER_SHARED_ATTRIBUTE,
    FixtureAnswer,
    FixtureTable,
    ObservationRecord,
)
from nemesis.collect.fixtures.glass_anvil import (
    ACME_EMAIL_GATEWAY,
    ACME_WAF,
    CDN_IP,
    CDN_POPULATION,
    CERT_FINGERPRINT,
    CERTIFICATE_POPULATION,
    CLUSTER_DOMAINS,
    CLUSTER_IP,
    CLUSTER_POPULATION,
    FALSE_FLAG_STRING,
    KIT_SHA256,
    NAMED_PERSON,
    PERSONA_CURRENT,
    PERSONA_HISTORICAL,
    PERSONA_RESURGENT,
    PGP_FINGERPRINT,
    PHISHING_SOURCE_IP,
    PROMPT_INJECTION_POST,
    REGISTRAR,
    RESURGENCE_AS_OF,
    RESURGENCE_IP,
    SCENARIO_PRESENT,
    SEED_DOMAIN,
    WALLET_PRIMARY,
    blockchain_fixtures,
    certificate_fixtures,
    dark_web_fixtures,
    malware_fixtures,
    network_fixtures,
    passive_dns_fixtures,
    phase_one_detection,
    rdap_fixtures,
)
from nemesis.collect.simulated import (
    SimulatedBlockchainConnector,
    SimulatedCertificateConnector,
    SimulatedDarkWebConnector,
    SimulatedMalwareConnector,
    SimulatedNetworkConnector,
    SimulatedPassiveDnsConnector,
    SimulatedRdapConnector,
    simulated_connectors,
)
from nemesis.core.claims import ClaimKind, DerivationKind
from nemesis.core.entities import (
    CATEGORY_OF,
    EntityCategory,
    EntityType,
    NormalizationError,
    normalize_identifier,
)
from nemesis.core.evidence import AdmissibilityDefect, ArtifactKind
from nemesis.core.relationships import IDENTITY_ASSERTING_RELATIONS, Relationship, RelationType
from nemesis.ports.collection import PivotRequest, PivotResult, PivotType
from nemesis.pursuit.materialize import materialize

# Entity types are tried in this order when deciding how to ask for a fixture key: an IPv4
# address is also a syntactically valid domain name, and asking for it as a domain would
# exercise a code path no caller uses.
_TYPE_PREFERENCE = (
    EntityType.IP_ADDRESS,
    EntityType.NETBLOCK,
    EntityType.ASN,
    EntityType.TLS_CERTIFICATE,
    EntityType.MALWARE,
    EntityType.CRYPTO_ADDRESS,
    EntityType.DOMAIN,
    EntityType.PERSONA,
    EntityType.FORUM,
    EntityType.MARKETPLACE,
    EntityType.PHISHING_KIT,
)

_CONNECTORS_AND_FIXTURES = (
    (SimulatedPassiveDnsConnector, passive_dns_fixtures()),
    (SimulatedCertificateConnector, certificate_fixtures()),
    (SimulatedRdapConnector, rdap_fixtures()),
    (SimulatedNetworkConnector, network_fixtures()),
    (SimulatedMalwareConnector, malware_fixtures()),
    (SimulatedDarkWebConnector, dark_web_fixtures()),
    (SimulatedBlockchainConnector, blockchain_fixtures()),
)


def _all_fixture_tables() -> tuple[FixtureTable, ...]:
    return tuple(table for _, table in _CONNECTORS_AND_FIXTURES)


def _all_records() -> Iterator[ObservationRecord]:
    for table in _all_fixture_tables():
        for answer in table.values():
            yield from answer.records


def _entity_type_for(connector: object, key: str) -> EntityType:
    supported = connector.capabilities.supported_entity_types  # type: ignore[attr-defined]
    for candidate in _TYPE_PREFERENCE:
        if candidate not in supported:
            continue
        try:
            if normalize_identifier(candidate, key) == key:
                return candidate
        except NormalizationError:
            continue
    raise AssertionError(f"no supported entity type accepts fixture key {key!r}")


def _pivot(
    connector: object,
    pivot_type: PivotType,
    entity_type: EntityType,
    key: str,
    *,
    reason: str = "test",
) -> PivotResult:
    request = PivotRequest(
        pivot_type=pivot_type, entity_type=entity_type, entity_key=key, reason=reason
    )
    return asyncio.run(connector.pivot(request))  # type: ignore[attr-defined,no-any-return]


def _edges(result: PivotResult) -> tuple[Relationship, ...]:
    materialized = materialize(result.observations, is_synthetic=True)
    assert not materialized.skipped, materialized.skipped
    return materialized.relationships


# --- The two population counts -----------------------------------------------


def test_cluster_reverse_resolution_returns_exactly_four_domains() -> None:
    result = _pivot(
        SimulatedPassiveDnsConnector(),
        PivotType.REVERSE_RESOLUTION,
        EntityType.IP_ADDRESS,
        CLUSTER_IP,
    )

    assert result.succeeded
    assert len(result.observations) == 4
    assert not result.truncated
    subjects = {claim.statement.subject for claim in result.observations}
    assert subjects == {f"domain:{domain}" for domain in CLUSTER_DOMAINS}

    for claim in result.observations:
        qualifiers = claim.statement.qualifiers
        assert qualifiers[QUALIFIER_POPULATION_SIZE] == "4"
        assert qualifiers[QUALIFIER_POPULATION_CORPUS]


def test_cluster_pivot_is_selective_enough_to_carry_a_cluster() -> None:
    result = _pivot(
        SimulatedPassiveDnsConnector(),
        PivotType.REVERSE_RESOLUTION,
        EntityType.IP_ADDRESS,
        CLUSTER_IP,
    )
    edge = _edges(result)[0]

    assert edge.selectivity is not None
    assert edge.selectivity.population_size == CLUSTER_POPULATION
    assert edge.selectivity.population_measured_against is not None
    assert edge.selectivity.is_informative
    assert edge.selectivity.evidential_weight() == pytest.approx(0.5)


def test_cdn_reverse_resolution_is_recorded_as_noise() -> None:
    """The control case. A pivot through 41,700 co-tenants must score as worthless."""
    result = _pivot(
        SimulatedPassiveDnsConnector(), PivotType.REVERSE_RESOLUTION, EntityType.IP_ADDRESS, CDN_IP
    )

    # The sample is a prefix of the population: absence inside it means nothing.
    assert result.truncated

    edge = _edges(result)[0]
    assert edge.selectivity is not None
    assert edge.selectivity.population_size == CDN_POPULATION == 41_700
    assert not edge.selectivity.is_informative
    assert edge.selectivity.evidential_weight() < 0.07

    caveats = " ".join(edge.explain().caveats)
    assert "too many" in caveats


def test_the_selective_pivot_outranks_the_worthless_one() -> None:
    """Same relation, same connector, opposite analytic value."""
    connector = SimulatedPassiveDnsConnector()
    cluster = _edges(
        _pivot(connector, PivotType.REVERSE_RESOLUTION, EntityType.IP_ADDRESS, CLUSTER_IP)
    )[0]
    cdn = _edges(_pivot(connector, PivotType.REVERSE_RESOLUTION, EntityType.IP_ADDRESS, CDN_IP))[0]

    assert cluster.relation is cdn.relation is RelationType.RESOLVES_TO
    assert cluster.confidence.projected_probability > cdn.confidence.projected_probability


def test_no_population_count_travels_without_its_corpus() -> None:
    """A count with no denominator is silently discarded downstream and scores as zero."""
    counted = 0
    for record in _all_records():
        qualifiers = record.statement.qualifiers
        if QUALIFIER_POPULATION_SIZE not in qualifiers:
            continue
        counted += 1
        assert qualifiers.get(QUALIFIER_POPULATION_CORPUS), record.statement.subject
        assert qualifiers.get(QUALIFIER_SHARED_ATTRIBUTE), record.statement.subject
        assert int(qualifiers[QUALIFIER_POPULATION_SIZE]) >= 1
    assert counted >= 8


# --- Temporal honesty ---------------------------------------------------------


def test_passive_dns_extents_leave_both_bounds_open() -> None:
    """First-seen and last-seen bound an interval; they do not define one."""
    result = _pivot(
        SimulatedPassiveDnsConnector(),
        PivotType.RESOLUTION_HISTORY,
        EntityType.DOMAIN,
        SEED_DOMAIN,
    )
    extent = result.observations[0].valid_extent

    assert extent.known_from == datetime(2026, 2, 20, tzinfo=UTC)
    assert extent.known_until == datetime(2026, 3, 10, tzinfo=UTC)
    assert extent.possible_from is None
    assert extent.possible_until is None
    assert extent.is_open_ended


def test_no_observed_sighting_anywhere_claims_a_closed_interval() -> None:
    open_ended = [
        record
        for record in _all_records()
        if record.artifact_kind.value not in {"whois_rdap_record"}
    ]
    assert open_ended
    for record in open_ended:
        assert record.extent.possible_from is None, record.statement.subject
        assert record.extent.possible_until is None, record.statement.subject


def test_registration_pins_only_the_bound_the_registry_defines() -> None:
    """A registry defines when a registration began. Nothing defines when it will end."""
    result = _pivot(
        SimulatedRdapConnector(), PivotType.REGISTRATION_RECORD, EntityType.DOMAIN, SEED_DOMAIN
    )
    extent = result.observations[0].valid_extent

    assert extent.possible_from == extent.known_from
    assert extent.possible_until is not None
    assert extent.possible_until > extent.known_until


def test_registrar_edge_is_justified_by_the_window_not_by_the_registrar() -> None:
    """A registrar links unrelated parties; only the 24-hour window links these four."""
    result = _pivot(
        SimulatedRdapConnector(), PivotType.REGISTRATION_RECORD, EntityType.DOMAIN, SEED_DOMAIN
    )
    edge = _edges(result)[0]

    assert edge.target_type is EntityType.REGISTRAR
    assert edge.shared_infrastructure_justification is not None
    assert "24-hour" in edge.shared_infrastructure_justification
    assert "No justification supplied" not in edge.shared_infrastructure_justification


# --- Hostile content ----------------------------------------------------------


def test_prompt_injection_post_is_returned_as_inert_data() -> None:
    """Invariant 5. The planted instruction survives collection as bytes and nothing else."""
    result = _pivot(
        SimulatedDarkWebConnector(), PivotType.DARK_WEB_SEARCH, EntityType.PERSONA, PERSONA_CURRENT
    )
    assert result.succeeded

    carrying = [
        claim
        for claim in result.observations
        if PROMPT_INJECTION_POST in claim.statement.natural_language
    ]
    assert len(carrying) == 1
    claim = carrying[0]

    # It arrives as an observation of a forum post, never as an inference or an instruction
    # the platform adopted: the statement says the persona posted, and nothing more.
    assert claim.kind is ClaimKind.OBSERVATION
    assert claim.derivation is DerivationKind.DIRECT_COLLECTION
    assert claim.statement.predicate == RelationType.POSTS_ON.value
    assert claim.statement.qualifiers[QUALIFIER_HOSTILE_CONTENT] == "true"

    # The bytes are preserved verbatim, so a downstream defence can be tested against them.
    evidence_id = claim.supported_by_evidence[0]
    assert PROMPT_INJECTION_POST.encode() in result.artifacts[evidence_id]

    # And nothing it demands has become a claim: no evidence was dropped, no identity edge
    # was drawn, and the persona was not marked benign.
    assert len(result.observations) == len(result.evidence)
    assert all(
        RelationType(claim.statement.predicate) not in IDENTITY_ASSERTING_RELATIONS
        for claim in result.observations
    )


def test_hostile_collection_cannot_run_without_a_declared_sandbox() -> None:
    with pytest.raises(ValueError, match="sandbox profile"):
        SimulatedDarkWebConnector(sandbox_profile=None)


def test_sandbox_profile_is_recorded_on_what_the_collector_brought_back() -> None:
    result = _pivot(
        SimulatedDarkWebConnector(), PivotType.DARK_WEB_SEARCH, EntityType.PERSONA, PERSONA_CURRENT
    )
    method = result.evidence[0].provenance.method

    assert method.sandbox_profile is not None
    assert "no route to the platform network" in method.sandbox_profile


# --- The two planted trails ---------------------------------------------------


def test_planted_false_flag_is_assessed_and_asserts_no_authorship() -> None:
    """Trap A. The kit contains a string. That is all this claim is allowed to say."""
    result = _pivot(
        SimulatedMalwareConnector(), PivotType.MALWARE_LOOKUP, EntityType.MALWARE, KIT_SHA256
    )
    planted = [claim for claim in result.observations if FALSE_FLAG_STRING in claim.statement.obj]
    assert len(planted) == 1
    claim = planted[0]

    assert claim.deception is not None
    assert claim.deception.adversary_could_plant
    assert claim.deception.planting_cost == "trivial"
    assert claim.deception.benefits_from_belief
    assert claim.deception.is_assessed
    assert any("operator" in who for who in claim.deception.benefits_from_belief)

    # AUTHORED_BY here would be the whole trap working as designed.
    assert RelationType(claim.statement.predicate) is RelationType.CO_OCCURS_WITH
    assert RelationType(claim.statement.predicate) not in IDENTITY_ASSERTING_RELATIONS


def test_planted_human_identity_stays_a_lead() -> None:
    """Trap B. One uncorroborated hostile source may produce a lead, never an identity."""
    result = _pivot(
        SimulatedDarkWebConnector(), PivotType.DARK_WEB_SEARCH, EntityType.PERSONA, PERSONA_CURRENT
    )
    naming = [
        claim
        for claim in result.observations
        if claim.statement.obj.startswith(f"{EntityType.HUMAN_IDENTITY_LEAD.value}:")
    ]
    assert len(naming) == 1
    claim = naming[0]

    assert NAMED_PERSON.lower() in claim.statement.obj.lower()
    assert claim.deception is not None
    assert claim.deception.adversary_could_plant
    assert claim.deception.planting_cost == "trivial"
    assert claim.deception.benefits_from_belief
    assert RelationType(claim.statement.predicate) not in IDENTITY_ASSERTING_RELATIONS

    lead = next(
        entity
        for entity in materialize(result.observations, is_synthetic=True).entities
        if entity.entity_type is EntityType.HUMAN_IDENTITY_LEAD
    )
    assert CATEGORY_OF[lead.entity_type] is EntityCategory.HUMAN_IDENTITY
    assert lead.is_personal_data


def test_no_fixture_anywhere_asserts_a_natural_person_as_the_operator() -> None:
    """The acceptance criterion of the whole scenario, checked at the source of the data."""
    for record in _all_records():
        if record.statement.obj.startswith(f"{EntityType.HUMAN_IDENTITY_LEAD.value}:"):
            relation = RelationType(record.statement.predicate)
            assert relation not in IDENTITY_ASSERTING_RELATIONS
            assert record.deception is not None


# --- Source independence ------------------------------------------------------


def test_the_two_acme_sensors_are_one_source() -> None:
    """Two sensors, one operator, one event. Fusing them would invent corroboration."""
    assert ACME_EMAIL_GATEWAY.identifier != ACME_WAF.identifier
    assert ACME_EMAIL_GATEWAY.provenance_cluster() == ACME_WAF.provenance_cluster()

    reports = phase_one_detection()
    assert len(reports) == 2
    assert {report.source.identifier for report in reports} == {
        ACME_EMAIL_GATEWAY.identifier,
        ACME_WAF.identifier,
    }
    assert len({report.source.provenance_cluster() for report in reports}) == 1
    assert len({report.record.artifact for report in reports}) == 2


def test_the_fixture_connectors_do_not_present_themselves_as_seven_sources() -> None:
    keys = {
        connector.capabilities.source.provenance_cluster() for connector in simulated_connectors()
    }
    assert len(keys) == 1


# --- Cryptographic identity ---------------------------------------------------


def test_pgp_identity_requires_the_full_fingerprint() -> None:
    assert len(PGP_FINGERPRINT) == 40
    assert normalize_identifier(EntityType.PGP_KEY, PGP_FINGERPRINT) == PGP_FINGERPRINT

    with pytest.raises(NormalizationError):
        normalize_identifier(EntityType.PGP_KEY, PGP_FINGERPRINT[-16:])

    for record in _all_records():
        for token in (record.statement.subject, record.statement.obj):
            prefix = f"{EntityType.PGP_KEY.value}:"
            if token.startswith(prefix):
                assert len(token.removeprefix(prefix)) == 40


def test_shared_pgp_fingerprint_is_unique_by_construction() -> None:
    result = _pivot(
        SimulatedDarkWebConnector(),
        PivotType.PERSONA_ACTIVITY,
        EntityType.PERSONA,
        PERSONA_HISTORICAL,
    )
    claim = result.observations[0]
    assert claim.statement.qualifiers[QUALIFIER_GLOBALLY_UNIQUE] == "true"

    edge = _edges(result)[0]
    assert edge.selectivity is not None
    assert edge.selectivity.is_globally_unique
    assert edge.selectivity.evidential_weight() == 1.0


def test_shared_certificate_is_selective_but_not_unique() -> None:
    """A certificate can be shared by a load-balanced fleet. Population is what informs."""
    result = _pivot(
        SimulatedCertificateConnector(),
        PivotType.CERTIFICATE_REUSE,
        EntityType.TLS_CERTIFICATE,
        CERT_FINGERPRINT,
    )
    assert len(result.observations) == CERTIFICATE_POPULATION

    edge = _edges(result)[0]
    assert edge.selectivity is not None
    assert not edge.selectivity.is_globally_unique
    assert edge.selectivity.population_size == CERTIFICATE_POPULATION
    assert edge.selectivity.is_informative


# --- Transaction-time gating --------------------------------------------------


def test_resurgence_certificate_reuse_is_invisible_before_its_date() -> None:
    """Phase-8 evidence in a phase-2 graph would make the resurgence trivially detectable."""
    phase_two = _pivot(
        SimulatedCertificateConnector(as_of=SCENARIO_PRESENT),
        PivotType.CERTIFICATE_REUSE,
        EntityType.TLS_CERTIFICATE,
        CERT_FINGERPRINT,
    )
    assert len(phase_two.observations) == 3
    assert all(RESURGENCE_IP not in claim.statement.subject for claim in phase_two.observations)

    phase_eight = _pivot(
        SimulatedCertificateConnector(as_of=RESURGENCE_AS_OF),
        PivotType.CERTIFICATE_REUSE,
        EntityType.TLS_CERTIFICATE,
        CERT_FINGERPRINT,
    )
    assert len(phase_eight.observations) == 4
    assert any(RESURGENCE_IP in claim.statement.subject for claim in phase_eight.observations)


def test_resurgent_persona_is_invisible_before_its_date() -> None:
    phase_two = _pivot(
        SimulatedDarkWebConnector(as_of=SCENARIO_PRESENT),
        PivotType.PERSONA_ACTIVITY,
        EntityType.PERSONA,
        PERSONA_RESURGENT,
    )
    assert phase_two.succeeded
    assert phase_two.is_empty

    phase_eight = _pivot(
        SimulatedDarkWebConnector(as_of=RESURGENCE_AS_OF),
        PivotType.PERSONA_ACTIVITY,
        EntityType.PERSONA,
        PERSONA_RESURGENT,
    )
    assert len(phase_eight.observations) == 2
    assert any(PGP_FINGERPRINT in claim.statement.obj for claim in phase_eight.observations)


def test_collection_is_stamped_with_the_scenario_clock_not_the_wall_clock() -> None:
    result = _pivot(
        SimulatedPassiveDnsConnector(),
        PivotType.RESOLUTION_HISTORY,
        EntityType.DOMAIN,
        SEED_DOMAIN,
    )
    assert result.evidence[0].provenance.collected_at == SCENARIO_PRESENT
    assert result.observations[0].asserted_at == SCENARIO_PRESENT


# --- The three answers a source can give --------------------------------------


def test_a_failing_pivot_returns_an_error_rather_than_raising() -> None:
    result = _pivot(
        SimulatedPassiveDnsConnector(),
        PivotType.REVERSE_RESOLUTION,
        EntityType.IP_ADDRESS,
        PHISHING_SOURCE_IP,
    )

    assert not result.succeeded
    assert result.error is not None
    assert "not an observation of absence" in result.error
    assert result.observations == ()
    assert result.evidence == ()
    # "We could not look" must not read as "we looked and found nothing".
    assert not result.is_empty


def test_an_unknown_key_is_an_empty_success_not_a_failure() -> None:
    result = _pivot(
        SimulatedPassiveDnsConnector(),
        PivotType.RESOLUTION_HISTORY,
        EntityType.DOMAIN,
        "nothing-here.example",
    )
    assert result.succeeded
    assert result.is_empty
    assert result.error is None


def test_an_unanswerable_question_is_reported_not_raised() -> None:
    result = _pivot(
        SimulatedRdapConnector(),
        PivotType.REGISTRATION_RECORD,
        EntityType.DOMAIN,
        SEED_DOMAIN,
    )
    assert result.succeeded

    unsupported = asyncio.run(
        SimulatedRdapConnector().pivot(
            PivotRequest(
                pivot_type=PivotType.WALLET_ACTIVITY,
                entity_type=EntityType.CRYPTO_ADDRESS,
                entity_key=WALLET_PRIMARY,
                reason="test",
            )
        )
    )
    assert not unsupported.succeeded
    assert unsupported.error is not None
    assert "does not answer" in unsupported.error


def test_an_unusable_key_is_reported_not_raised() -> None:
    result = _pivot(
        SimulatedPassiveDnsConnector(),
        PivotType.RESOLUTION_HISTORY,
        EntityType.DOMAIN,
        "not a domain",
    )
    assert not result.succeeded
    assert result.error is not None
    assert "unusable entity key" in result.error


def test_truncation_is_reported_when_the_source_had_more_to_say() -> None:
    """max_results is a limit on us, not a statement about the world."""
    connector = SimulatedBlockchainConnector()
    request = PivotRequest(
        pivot_type=PivotType.WALLET_ACTIVITY,
        entity_type=EntityType.CRYPTO_ADDRESS,
        entity_key=WALLET_PRIMARY,
        reason="test",
        max_results=3,
    )
    result = asyncio.run(connector.pivot(request))

    assert result.truncated
    assert len(result.observations) == 3


# --- Simulation, provenance and artifacts, across the whole fixture set --------


def _every_pivot() -> Iterator[tuple[str, PivotResult]]:
    for factory, table in _CONNECTORS_AND_FIXTURES:
        connector = factory(as_of=RESURGENCE_AS_OF)
        for pivot_type, key in table:
            entity_type = _entity_type_for(connector, key)
            yield (
                f"{connector.capabilities.name}/{pivot_type.value}/{key}",
                _pivot(connector, pivot_type, entity_type, key),
            )


def test_every_connector_marks_every_artifact_as_simulated() -> None:
    checked = 0
    for label, result in _every_pivot():
        if not result.succeeded:
            continue
        for evidence in result.evidence:
            checked += 1
            assert evidence.provenance.method.is_simulated, label
            assert evidence.provenance.is_simulated, label
            # Synthetic material is intelligence, never proof.
            assert AdmissibilityDefect.SIMULATED_COLLECTION in evidence.admissibility(), label
            assert not evidence.is_admissible, label
    assert checked > 50

    for connector in simulated_connectors():
        assert connector.capabilities.is_simulated


def test_every_evidence_object_travels_with_the_bytes_it_addresses() -> None:
    """Without the bytes the vault seals nothing and the evidence is unpreserved."""
    for label, result in _every_pivot():
        if not result.succeeded:
            continue
        assert set(result.artifacts) == {evidence.evidence_id for evidence in result.evidence}, (
            label
        )
        for evidence in result.evidence:
            assert evidence.verify_artifact(result.artifacts[evidence.evidence_id]), label


def test_every_fixture_claim_materializes_into_the_graph() -> None:
    """A predicate typo or a malformed reference is skipped silently and lost. It is not."""
    total_edges = 0
    for label, result in _every_pivot():
        if not result.succeeded:
            continue
        materialized = materialize(result.observations, is_synthetic=True)
        assert not materialized.skipped, f"{label}: {materialized.skipped}"
        assert len(materialized.relationships) == len(result.observations), label
        total_edges += len(materialized.relationships)
        for entity in materialized.entities:
            assert entity.is_synthetic, label
    assert total_edges > 50


def test_every_claim_is_a_directly_collected_observation() -> None:
    """A connector reports what a source said. Deciding what it means happens elsewhere."""
    for label, result in _every_pivot():
        for claim in result.observations:
            assert claim.kind is ClaimKind.OBSERVATION, label
            assert claim.derivation is DerivationKind.DIRECT_COLLECTION, label
            assert claim.supported_by_evidence, label
            assert claim.model_identifier is None, label


def test_the_fixture_set_covers_the_scenario_cast() -> None:
    """A missing fixture would make a downstream test pass by finding nothing to fault."""
    passive = passive_dns_fixtures()
    assert all((PivotType.RESOLUTION_HISTORY, domain) in passive for domain in CLUSTER_DOMAINS)
    assert (PivotType.REGISTRATION_RECORD, SEED_DOMAIN) in rdap_fixtures()
    assert (PivotType.CERTIFICATE_REUSE, CERT_FINGERPRINT) in certificate_fixtures()
    assert (PivotType.NETWORK_OWNERSHIP, CLUSTER_IP) in network_fixtures()
    assert (PivotType.MALWARE_LOOKUP, KIT_SHA256) in malware_fixtures()
    assert (PivotType.WALLET_CLUSTERING, WALLET_PRIMARY) in blockchain_fixtures()
    assert (PivotType.PERSONA_ACTIVITY, PERSONA_CURRENT.lower()) in dark_web_fixtures()

    registrars = {
        record.statement.obj for answer in rdap_fixtures().values() for record in answer.records
    }
    assert f"{EntityType.REGISTRAR.value}:{REGISTRAR}" in registrars


def test_the_wallet_clustering_names_its_heuristic_and_how_it_fails() -> None:
    result = _pivot(
        SimulatedBlockchainConnector(),
        PivotType.WALLET_CLUSTERING,
        EntityType.CRYPTO_ADDRESS,
        WALLET_PRIMARY,
    )
    claim = result.observations[0]

    assert claim.statement.qualifiers["heuristic"]
    assert "CoinJoin" in claim.statement.qualifiers["known_failure_mode"]
    assert claim.notes is not None


def test_a_malformed_fixture_costs_one_pivot_not_the_investigation() -> None:
    """A defect in this plane is recorded as a failure to look, never raised at the caller."""

    broken: dict[tuple[PivotType, str], FixtureAnswer] = {
        (PivotType.RESOLUTION_HISTORY, SEED_DOMAIN): FixtureAnswer(
            records=(
                # Validation bypassed on purpose: this is the shape a fixture defect takes,
                # and the question under test is what the pursuit loop sees when one occurs.
                ObservationRecord.model_construct(
                    artifact=b"x",
                    artifact_kind=ArtifactKind.DNS_RECORD,
                    statement=None,  # type: ignore[arg-type]
                    extent=None,  # type: ignore[arg-type]
                ),
            )
        )
    }
    connector = SimulatedPassiveDnsConnector(fixtures=broken)
    result = _pivot(connector, PivotType.RESOLUTION_HISTORY, EntityType.DOMAIN, SEED_DOMAIN)

    assert not result.succeeded
    assert result.error is not None
    assert "while sealing fixture records" in result.error


def test_the_own_sensor_connector_is_the_only_unplantable_channel() -> None:
    """One connector's source class sits in the plantability allowlist, and only one.

    The allowlist is ``{OWN_SENSOR, LAW_ENFORCEMENT}`` and everything else is adversary-
    writable by default. That is not a grading of trustworthiness: an adversary can *cause* an
    observation at a sensor we operate and cannot *author* the record, while they can write
    into a scan corpus, an open-source feed, a commercial feed or a forum at will.

    Pinned as a property of the whole set because the number that matters is *how many*. Before
    this connector existed it was zero, which meant no fact in a run could survive the
    robustness margin however many bridges the graph contained.
    """
    from nemesis.collect.simulated import simulated_connectors
    from nemesis.core.provenance import SourceClass

    connectors = simulated_connectors()
    unplantable = [c for c in connectors if not c.capabilities.source.is_adversary_influenceable]
    assert len(unplantable) == 1
    assert unplantable[0].capabilities.source.source_class is SourceClass.OWN_SENSOR
    assert unplantable[0].capabilities.is_simulated, (
        "the scenario is synthetic and the connector must keep saying so"
    )


def test_the_own_sensor_connector_makes_no_claim_about_a_remote_host() -> None:
    """It reports what arrived, never what it went and looked at.

    A victim's edge sensor does not observe a C2's certificate. A fixture that had it do so
    would be manufacturing an unplantable fact out of a scan — the one move that would make
    every downstream number in this platform meaningless, and the easiest one to make by
    accident.

    Enforced on the pivot vocabulary rather than the prose: the connector supports exactly
    ``OWN_TELEMETRY``, and nothing that involves reaching out.
    """
    from nemesis.collect.simulated import SimulatedOwnSensorConnector
    from nemesis.ports.collection import PivotType

    capabilities = SimulatedOwnSensorConnector().capabilities
    assert capabilities.supported_pivots == frozenset({PivotType.OWN_TELEMETRY})
    reaching_out = {
        PivotType.CERTIFICATE_REUSE,
        PivotType.CERTIFICATE_HISTORY,
        PivotType.SERVICE_FINGERPRINT,
        PivotType.HOSTING_NEIGHBOURS,
        PivotType.RESOLUTION_HISTORY,
    }
    assert not (capabilities.supported_pivots & reaching_out)
