"""Finding the signals in the graph, without inventing the ones that are not there.

The engine scores signals it is handed. This is what hands them to it, and the whole difficulty
is restraint: a graph is a very good place to find resemblances, and most resemblances mean
nothing. Two hosts sharing a registrar is the base rate. Two hosts sharing a private key is a
finding. The assembler's job is to notice both and to score neither.

The load-bearing rule here is that **a population is never counted from our own graph**. We know
of three domains through this registrar; the registrar has forty thousand. A local count is a
lower bound on the world's, and treating a lower bound as the population is precisely how shared
hosting becomes an adversary cluster.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from nemesis.core.confidence import Opinion
from nemesis.core.entities import Entity, EntityType
from nemesis.core.ids import IdPrefix, content_id, new_id
from nemesis.core.provenance import SourceClass, SourceDescriptor, SourceReliability
from nemesis.core.relationships import PivotMethod, Relationship, RelationType
from nemesis.core.temporal import TemporalExtent
from nemesis.graph.memory import InMemoryGraphStore
from nemesis.pursuit.resurgence import ResurgenceEngine, ResurgenceSignalKind
from nemesis.pursuit.watch import assemble_resurgence_signals, signals_by_candidate

NOW = datetime(2026, 6, 1, tzinfo=UTC)
EXTENT = TemporalExtent.at(NOW)


async def node(graph: InMemoryGraphStore, entity_type: EntityType, observed: str) -> Entity:
    return await graph.upsert_entity(
        Entity.create(
            entity_id=new_id(IdPrefix.ENTITY),
            entity_type=entity_type,
            observed_form=observed,
            extent=EXTENT,
            is_synthetic=True,
        )
    )


async def link(
    graph: InMemoryGraphStore,
    source: Entity,
    target: Entity,
    relation: RelationType,
    *,
    justification: str | None = None,
) -> None:
    await graph.add_relationship(
        Relationship(
            edge_id=new_id(IdPrefix.EDGE),
            source_id=source.entity_id,
            target_id=target.entity_id,
            source_type=source.entity_type,
            target_type=target.entity_type,
            relation=relation,
            extent=EXTENT,
            confidence=Opinion(belief=0.9, disbelief=0.0, uncertainty=0.1),
            pivot_method=PivotMethod.DIRECT_OBSERVATION,
            supporting_claims=(content_id(IdPrefix.CLAIM, observed_key(source, target).encode()),),
            shared_infrastructure_justification=justification,
            is_synthetic=True,
        )
    )


def observed_key(source: Entity, target: Entity) -> str:
    return f"{source.natural_key}->{target.natural_key}"


async def own_sensor(_claims: tuple[str, ...]) -> tuple[SourceDescriptor, ...]:
    """A resolver standing in for one that would read the vault's provenance chain."""
    return (
        SourceDescriptor(
            source_class=SourceClass.OWN_SENSOR,
            identifier="nemesis-resurgence-watch",
            reliability=SourceReliability.COMPLETELY_RELIABLE,
        ),
    )


# -- what it finds -----------------------------------------------------------------


@pytest.mark.anyio
async def test_a_shared_certificate_becomes_a_key_control_signal() -> None:
    """The C2 address changed; the private key behind its certificate did not."""
    graph = InMemoryGraphStore()
    old_ip = await node(graph, EntityType.IP_ADDRESS, "198.51.100.23")
    new_ip = await node(graph, EntityType.IP_ADDRESS, "192.0.2.77")
    cert = await node(graph, EntityType.TLS_CERTIFICATE, "3f" * 32)
    await link(graph, old_ip, cert, RelationType.PRESENTS_CERTIFICATE)
    await link(graph, new_ip, cert, RelationType.PRESENTS_CERTIFICATE)

    signals = await assemble_resurgence_signals(
        graph, prior_entity_ids=[old_ip.entity_id], observed_at=NOW
    )

    assert len(signals) == 1
    found = signals[0]
    assert found.kind is ResurgenceSignalKind.SHARED_PRIVATE_KEY
    assert found.new_entity_key == "192.0.2.77"
    assert found.prior_entity_key == "198.51.100.23"
    assert found.selectivity.is_globally_unique


@pytest.mark.anyio
async def test_a_shared_wallet_cluster_becomes_a_financial_signal() -> None:
    graph = InMemoryGraphStore()
    old = await node(graph, EntityType.CRYPTO_ADDRESS, "bc1qold")
    new = await node(graph, EntityType.CRYPTO_ADDRESS, "bc1qnew")
    cluster = await node(graph, EntityType.WALLET_CLUSTER, "anvil-cluster")
    await link(graph, old, cluster, RelationType.CLUSTERED_WITH)
    await link(graph, new, cluster, RelationType.CLUSTERED_WITH)

    signals = await assemble_resurgence_signals(
        graph, prior_entity_ids=[old.entity_id], observed_at=NOW
    )
    assert [s.kind for s in signals] == [ResurgenceSignalKind.SHARED_FINANCIAL_ENDPOINT]


# -- what it refuses to invent -----------------------------------------------------


@pytest.mark.anyio
async def test_a_shared_registrar_never_gets_a_population_from_our_own_graph() -> None:
    """The rule this module exists to hold.

    Our graph knows of two domains through this registrar. The registrar has forty thousand
    customers. Counting two and calling it the population would make a coincidence look like
    the strongest signal in the assessment.
    """
    graph = InMemoryGraphStore()
    old = await node(graph, EntityType.DOMAIN, "acme-invoice-portal.example")
    new = await node(graph, EntityType.DOMAIN, "globex-invoice-portal.example")
    registrar = await node(graph, EntityType.REGISTRAR, "bulletproofreg")
    await link(graph, old, registrar, RelationType.REGISTERED_THROUGH)
    await link(graph, new, registrar, RelationType.REGISTERED_THROUGH)

    signals = await assemble_resurgence_signals(
        graph, prior_entity_ids=[old.entity_id], observed_at=NOW
    )

    assert [s.kind for s in signals] == [ResurgenceSignalKind.PROVIDER_AND_TIMING_PATTERN]
    provider = signals[0]
    assert provider.selectivity.population_size is None
    assert not provider.selectivity.is_globally_unique
    # Uncounted means uninformative, which is the honest answer and not a small number.
    assert provider.evidential_weight == 0.0


@pytest.mark.anyio
async def test_an_entity_already_in_the_prior_cluster_is_not_a_candidate() -> None:
    """An adversary's own two old hosts sharing a key is not a resurgence. It is last month."""
    graph = InMemoryGraphStore()
    old_a = await node(graph, EntityType.IP_ADDRESS, "198.51.100.23")
    old_b = await node(graph, EntityType.IP_ADDRESS, "198.51.100.24")
    cert = await node(graph, EntityType.TLS_CERTIFICATE, "3f" * 32)
    await link(graph, old_a, cert, RelationType.PRESENTS_CERTIFICATE)
    await link(graph, old_b, cert, RelationType.PRESENTS_CERTIFICATE)

    signals = await assemble_resurgence_signals(
        graph,
        prior_entity_ids=[old_a.entity_id, old_b.entity_id],
        observed_at=NOW,
    )
    assert signals == ()


@pytest.mark.anyio
async def test_one_bridge_shared_by_two_prior_entities_yields_one_signal_per_candidate() -> None:
    """Otherwise the same fact arrives twice and looks like corroboration.

    Fusion would collapse them anyway — they share a fact key — but producing them is still
    wrong: the contribution list a human reads would show one observation as two.
    """
    graph = InMemoryGraphStore()
    old_a = await node(graph, EntityType.IP_ADDRESS, "198.51.100.23")
    old_b = await node(graph, EntityType.IP_ADDRESS, "198.51.100.24")
    new_ip = await node(graph, EntityType.IP_ADDRESS, "192.0.2.77")
    cert = await node(graph, EntityType.TLS_CERTIFICATE, "3f" * 32)
    for host in (old_a, old_b, new_ip):
        await link(graph, host, cert, RelationType.PRESENTS_CERTIFICATE)

    signals = await assemble_resurgence_signals(
        graph,
        prior_entity_ids=[old_a.entity_id, old_b.entity_id],
        observed_at=NOW,
    )
    assert len(signals) == 1


@pytest.mark.anyio
async def test_a_bridge_nobody_else_touches_produces_nothing() -> None:
    graph = InMemoryGraphStore()
    old_ip = await node(graph, EntityType.IP_ADDRESS, "198.51.100.23")
    cert = await node(graph, EntityType.TLS_CERTIFICATE, "3f" * 32)
    await link(graph, old_ip, cert, RelationType.PRESENTS_CERTIFICATE)

    signals = await assemble_resurgence_signals(
        graph, prior_entity_ids=[old_ip.entity_id], observed_at=NOW
    )
    assert signals == ()


@pytest.mark.anyio
async def test_an_unknown_prior_entity_is_skipped_rather_than_raising() -> None:
    graph = InMemoryGraphStore()
    signals = await assemble_resurgence_signals(
        graph, prior_entity_ids=[new_id(IdPrefix.ENTITY)], observed_at=NOW
    )
    assert signals == ()


# -- the honest ceiling on what a graph alone can support --------------------------


@pytest.mark.anyio
async def test_without_a_provenance_resolver_the_finding_is_a_lead_not_a_conclusion() -> None:
    """The graph carries no SourceDescriptor, and the assembler does not invent one.

    Provenance lives on the evidence in the vault, reached through a claim; a caller with only
    a graph handle cannot establish that any fact came from a channel an adversary could not
    author. So the default descriptor is plantable and unjudgeable, the robustness margin
    removes everything, and the engine reports a lead.

    This is the correct answer rather than a limitation to work around. A confident resurgence
    finding assembled from a graph whose provenance nobody checked is exactly the output this
    platform exists to refuse.
    """
    graph = InMemoryGraphStore()
    old_ip = await node(graph, EntityType.IP_ADDRESS, "198.51.100.23")
    new_ip = await node(graph, EntityType.IP_ADDRESS, "192.0.2.77")
    cert = await node(graph, EntityType.TLS_CERTIFICATE, "3f" * 32)
    await link(graph, old_ip, cert, RelationType.PRESENTS_CERTIFICATE)
    await link(graph, new_ip, cert, RelationType.PRESENTS_CERTIFICATE)

    signals = await assemble_resurgence_signals(
        graph, prior_entity_ids=[old_ip.entity_id], observed_at=NOW
    )
    result = ResurgenceEngine().assess(
        campaign="GLASS ANVIL",
        signals=signals,
        candidate_population=40,
        assessed_at=NOW,
    )
    assert result.fusion.rests_only_on_plantable_evidence
    assert not result.is_actionable


@pytest.mark.anyio
async def test_a_provenance_resolver_lets_a_finding_stand() -> None:
    """Hand it a resolver that knows the observation was our own sensor's, and it survives.

    Still not actionable on one fact — the single-origin veto holds — but the margin no longer
    strips it, which is the difference the resolver makes.
    """
    graph = InMemoryGraphStore()
    old_ip = await node(graph, EntityType.IP_ADDRESS, "198.51.100.23")
    new_ip = await node(graph, EntityType.IP_ADDRESS, "192.0.2.77")
    cert = await node(graph, EntityType.TLS_CERTIFICATE, "3f" * 32)
    await link(graph, old_ip, cert, RelationType.PRESENTS_CERTIFICATE)
    await link(graph, new_ip, cert, RelationType.PRESENTS_CERTIFICATE)

    signals = await assemble_resurgence_signals(
        graph,
        prior_entity_ids=[old_ip.entity_id],
        observed_at=NOW,
        provenance_of=own_sensor,
    )
    result = ResurgenceEngine().assess(
        campaign="GLASS ANVIL",
        signals=signals,
        candidate_population=40,
        assessed_at=NOW,
    )
    assert not result.fusion.rests_only_on_plantable_evidence
    assert result.is_single_origin
    assert not result.is_actionable


@pytest.mark.anyio
async def test_two_independent_bridges_with_provenance_support_a_resurgence() -> None:
    """The whole chain: graph -> signals -> assessment, saying yes when it should."""
    graph = InMemoryGraphStore()
    old_ip = await node(graph, EntityType.IP_ADDRESS, "198.51.100.23")
    new_ip = await node(graph, EntityType.IP_ADDRESS, "192.0.2.77")
    cert = await node(graph, EntityType.TLS_CERTIFICATE, "3f" * 32)
    await link(graph, old_ip, cert, RelationType.PRESENTS_CERTIFICATE)
    await link(graph, new_ip, cert, RelationType.PRESENTS_CERTIFICATE)

    old_kit = await node(graph, EntityType.MALWARE, "a" * 64)
    new_kit = await node(graph, EntityType.MALWARE, "b" * 64)
    family = await node(graph, EntityType.MALWARE_FAMILY, "anvil-loader")
    await link(graph, old_kit, family, RelationType.BELONGS_TO_FAMILY)
    await link(graph, new_kit, family, RelationType.BELONGS_TO_FAMILY)

    signals = await assemble_resurgence_signals(
        graph,
        prior_entity_ids=[old_ip.entity_id, old_kit.entity_id],
        observed_at=NOW,
        provenance_of=own_sensor,
    )
    kinds = {s.kind for s in signals}
    assert ResurgenceSignalKind.SHARED_PRIVATE_KEY in kinds
    assert ResurgenceSignalKind.SHARED_TOOLING_ARTIFACT in kinds

    result = ResurgenceEngine().assess(
        campaign="GLASS ANVIL",
        signals=signals,
        candidate_population=40,
        assessed_at=NOW,
    )
    assert result.is_actionable
    assert not result.is_single_origin


# -- against the graph the platform actually builds --------------------------------


@pytest.mark.anyio
async def test_the_reference_run_reassembles_its_own_resurgence_from_the_graph() -> None:
    """The scenario's phase 8 is hand-scripted. This finds the same bridge by traversal.

    The assertion worth having is not the score — the scenario's own assessment covers that —
    but that a blind walk of the graph reaches the certificate the narrative reconnects on. If
    it does not, the demonstration is proving something the engine could never find.
    """
    import tempfile
    from pathlib import Path

    from nemesis.collect.fixtures.glass_anvil import CERT_FINGERPRINT, CLUSTER_IP
    from nemesis.slice.scenario import run_glass_anvil_scenario_async

    with tempfile.TemporaryDirectory() as workspace:
        outcome = await run_glass_anvil_scenario_async(workspace=Path(workspace))
        graph = outcome.stores.graph
        prior = await graph.find_entity(EntityType.IP_ADDRESS, CLUSTER_IP)
        assert prior is not None
        signals = await assemble_resurgence_signals(
            graph,
            prior_entity_ids=[prior.entity_id],
            observed_at=outcome.resurgence.as_of,
            provenance_of=own_sensor,
        )

    certificate_signals = [s for s in signals if s.kind is ResurgenceSignalKind.SHARED_PRIVATE_KEY]
    assert certificate_signals, "the traversal did not find the shared certificate"
    assert any(CERT_FINGERPRINT in s.shared_attribute for s in certificate_signals)


@pytest.mark.anyio
async def test_signals_are_groupable_by_the_candidate_they_are_about() -> None:
    """One verdict per candidate, not one verdict over every candidate at once.

    A walk that finds six addresses presenting one certificate has found six separate questions,
    not one well-supported answer. Fusing them together would let six distinct candidates prop
    each other up through a shared fact key and report as a single confident finding.
    """
    graph = InMemoryGraphStore()
    old_ip = await node(graph, EntityType.IP_ADDRESS, "198.51.100.23")
    cert = await node(graph, EntityType.TLS_CERTIFICATE, "3f" * 32)
    await link(graph, old_ip, cert, RelationType.PRESENTS_CERTIFICATE)
    for octet in (77, 78, 79):
        candidate = await node(graph, EntityType.IP_ADDRESS, f"192.0.2.{octet}")
        await link(graph, candidate, cert, RelationType.PRESENTS_CERTIFICATE)

    signals = await assemble_resurgence_signals(
        graph, prior_entity_ids=[old_ip.entity_id], observed_at=NOW
    )
    grouped = signals_by_candidate(signals)

    assert len(signals) == 3
    assert len(grouped) == 3
    assert all(len(members) == 1 for members in grouped.values())
    assert {key for _, key in grouped} == {"192.0.2.77", "192.0.2.78", "192.0.2.79"}
