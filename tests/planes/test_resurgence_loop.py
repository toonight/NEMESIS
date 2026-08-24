"""Closing the loop: a case in resurgence watch that notices a return and resumes.

`DETECT → PURSUE → ... → DISRUPT → WATCH → REAPPEARANCE → PURSUE`. Every piece of that existed
separately — a state to sit in, a walk to find signals, an engine to score them — and nothing
joined the last two. An investigation entered `MONITORING_RESURGENCE` and stayed there, because
the thing that would have noticed a return was never asked.

The property under test is not "it resumes". It is **what it refuses to resume on**. A watch
that reopens a case on a lead is worse than no watch: it burns budget on coincidences, and with
provenance unresolved every graph-assembled signal *is* a lead.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from nemesis.core.confidence import Opinion
from nemesis.core.entities import Entity, EntityType
from nemesis.core.ids import IdPrefix, content_id, new_id
from nemesis.core.provenance import SourceClass, SourceDescriptor, SourceReliability
from nemesis.core.relationships import PivotMethod, Relationship, RelationType
from nemesis.core.temporal import TemporalExtent
from nemesis.graph.memory import InMemoryGraphStore
from nemesis.pursuit.engine import mark_monitoring_resurgence
from nemesis.pursuit.investigation import (
    IncidentSeed,
    Investigation,
    InvestigationBranch,
    InvestigationState,
)
from nemesis.pursuit.watch import resume_pursuit, watch_for_resurgence

NOW = datetime(2026, 6, 1, tzinfo=UTC)
LATER = NOW + timedelta(days=45)
EXTENT = TemporalExtent.at(NOW)


def resolved(_claims: tuple[str, ...]) -> SourceDescriptor:
    """Stands in for a resolver that reads the vault's provenance chain."""
    return SourceDescriptor(
        source_class=SourceClass.OWN_SENSOR,
        identifier="nemesis-resurgence-watch",
        reliability=SourceReliability.COMPLETELY_RELIABLE,
    )


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
    graph: InMemoryGraphStore, source: Entity, target: Entity, relation: RelationType
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
            supporting_claims=(
                content_id(IdPrefix.CLAIM, f"{source.natural_key}->{target.natural_key}".encode()),
            ),
            is_synthetic=True,
        )
    )


def watched(prior: Entity) -> Investigation:
    """A disrupted case, sitting in resurgence watch with one closed branch behind it."""
    investigation = Investigation(
        investigation_id=new_id(IdPrefix.INVESTIGATION),
        seed=IncidentSeed(
            entity_type=EntityType.IP_ADDRESS,
            entity_key=prior.natural_key,
            observed_at=NOW,
            detected_by="waf-fixture",
        ),
        branches=(
            InvestigationBranch(
                branch_id="B0",
                focus_entity_id=prior.entity_id,
                focus_entity_key=prior.natural_key,
                budget_allocated=40.0,
                budget_spent=38.0,
            ),
        ),
        total_budget=100.0,
        budget_spent=38.0,
    )
    return mark_monitoring_resurgence(investigation)


async def world_with_a_return() -> tuple[InMemoryGraphStore, Entity, Entity]:
    """A prior host and a new one, joined by a reused certificate and a shared toolchain."""
    graph = InMemoryGraphStore()
    prior = await node(graph, EntityType.IP_ADDRESS, "198.51.100.23")
    returned = await node(graph, EntityType.IP_ADDRESS, "192.0.2.77")
    cert = await node(graph, EntityType.TLS_CERTIFICATE, "3f" * 32)
    await link(graph, prior, cert, RelationType.PRESENTS_CERTIFICATE)
    await link(graph, returned, cert, RelationType.PRESENTS_CERTIFICATE)

    prior_kit = await node(graph, EntityType.MALWARE, "a" * 64)
    new_kit = await node(graph, EntityType.MALWARE, "b" * 64)
    family = await node(graph, EntityType.MALWARE_FAMILY, "anvil-loader")
    await link(graph, prior_kit, family, RelationType.BELONGS_TO_FAMILY)
    await link(graph, new_kit, family, RelationType.BELONGS_TO_FAMILY)
    return graph, prior, returned


# -- the state is the trigger ------------------------------------------------------


@pytest.mark.anyio
async def test_an_open_investigation_is_not_watched_and_says_so() -> None:
    """Not checked and checked-and-found-nothing are different, and must read differently.

    An empty findings tuple with no reason beside it is the shape of a control that quietly
    stopped running.
    """
    graph, prior, _ = await world_with_a_return()
    open_case = Investigation(
        investigation_id=new_id(IdPrefix.INVESTIGATION),
        seed=IncidentSeed(
            entity_type=EntityType.IP_ADDRESS,
            entity_key=prior.natural_key,
            observed_at=NOW,
            detected_by="waf-fixture",
        ),
    )

    report = await watch_for_resurgence(
        graph, open_case, campaign="GLASS ANVIL", candidate_population=40, now=LATER
    )

    assert report.not_watching_reason is not None
    assert "open" in report.not_watching_reason
    assert report.findings == ()
    assert report.candidates_examined == 0
    assert not report.resumes
    assert "did not" in report.render().lower() or "not watching" in report.render().lower()


@pytest.mark.anyio
async def test_a_watched_investigation_is_examined() -> None:
    graph, prior, _ = await world_with_a_return()
    report = await watch_for_resurgence(
        graph,
        watched(prior),
        campaign="GLASS ANVIL",
        candidate_population=40,
        now=LATER,
        provenance_of=resolved,
    )
    assert report.not_watching_reason is None
    assert report.candidates_examined >= 1


# -- what it refuses to resume on --------------------------------------------------


@pytest.mark.anyio
async def test_a_lead_does_not_reopen_the_case() -> None:
    """The property that matters most.

    With provenance unresolved every assembled signal is plantable, the robustness margin
    removes it, and the verdict is a lead. A watch that reopened on that would spend the
    remaining budget on whatever coincidence the graph happened to contain — and an adversary
    who knows it can arrange coincidences cheaply.
    """
    graph, prior, _ = await world_with_a_return()
    case = watched(prior)

    report = await watch_for_resurgence(
        graph, case, campaign="GLASS ANVIL", candidate_population=40, now=LATER
    )

    assert report.findings, "the walk found no candidate at all, so this proves nothing"
    assert not report.actionable
    assert not report.resumes
    assert all(not finding.assessment.is_actionable for finding in report.findings)


@pytest.mark.anyio
async def test_a_single_origin_finding_does_not_reopen_the_case() -> None:
    """One reused certificate, provenance resolved, and still only a lead."""
    graph = InMemoryGraphStore()
    prior = await node(graph, EntityType.IP_ADDRESS, "198.51.100.23")
    returned = await node(graph, EntityType.IP_ADDRESS, "192.0.2.77")
    cert = await node(graph, EntityType.TLS_CERTIFICATE, "3f" * 32)
    await link(graph, prior, cert, RelationType.PRESENTS_CERTIFICATE)
    await link(graph, returned, cert, RelationType.PRESENTS_CERTIFICATE)

    report = await watch_for_resurgence(
        graph,
        watched(prior),
        campaign="GLASS ANVIL",
        candidate_population=40,
        now=LATER,
        provenance_of=resolved,
    )
    assert report.findings
    assert all(f.assessment.is_single_origin for f in report.findings)
    assert not report.resumes


# -- what it does resume on --------------------------------------------------------


@pytest.mark.anyio
async def test_two_independent_facts_about_one_candidate_reopen_the_case() -> None:
    """Corroboration has to be about the *same* candidate.

    Written after the first version of this test failed, correctly. It gave the world a reused
    certificate on a new address and a shared toolchain on a new malware sample — two
    independent facts, but about two different candidates, so each was assessed alone and each
    was a single-origin lead. Per-candidate grouping is doing exactly what it should: "this
    address is the campaign returning" is not supported by a fact about somebody else.

    So the world here gives one candidate domain two bridges in two different correlation
    groups: the certificate it presents (key control) and the kit it was built with (tooling).
    """
    graph = InMemoryGraphStore()
    prior = await node(graph, EntityType.DOMAIN, "acme-invoice-portal.example")
    returned = await node(graph, EntityType.DOMAIN, "globex-invoice-portal.example")
    cert = await node(graph, EntityType.TLS_CERTIFICATE, "3f" * 32)
    kit = await node(graph, EntityType.PHISHING_KIT, "anvil-kit")
    for domain in (prior, returned):
        await link(graph, domain, cert, RelationType.PRESENTS_CERTIFICATE)
        await link(graph, domain, kit, RelationType.BUILT_WITH)

    case = watched(prior).model_copy(
        update={
            "branches": (
                InvestigationBranch(
                    branch_id="B0",
                    focus_entity_id=prior.entity_id,
                    focus_entity_key=prior.natural_key,
                    budget_allocated=40.0,
                    budget_spent=38.0,
                ),
            )
        }
    )

    report = await watch_for_resurgence(
        graph,
        case,
        campaign="GLASS ANVIL",
        candidate_population=40,
        now=LATER,
        provenance_of=resolved,
    )

    assert report.resumes
    assert report.actionable
    found = next(f for f in report.actionable if f.candidate_key == returned.natural_key)
    assert not found.assessment.is_single_origin
    assert "RESUME" in report.render()


@pytest.mark.anyio
async def test_resuming_keeps_the_investigation_that_was_already_done() -> None:
    """Destroy the adversary's operational continuity, not ours (§9).

    The prior branches, the hypotheses and the budget already spent all survive. An investigation
    that came back as a blank page would have thrown away the reason we recognised the return.
    """
    graph, prior, returned = await world_with_a_return()
    case = watched(prior)
    candidate = await graph.find_entity(EntityType.IP_ADDRESS, returned.natural_key)
    assert candidate is not None

    resumed = resume_pursuit(
        case,
        candidate_entity_id=candidate.entity_id,
        candidate_key=candidate.natural_key,
        reason="reused the historical certificate",
        now=LATER,
        additional_budget=25.0,
    )

    assert resumed.state is InvestigationState.OPEN
    assert len(resumed.branches) == len(case.branches) + 1
    assert resumed.branch("B0") == case.branch("B0")
    assert resumed.budget_spent == case.budget_spent
    new_branch = resumed.branches[-1]
    assert new_branch.focus_entity_key == returned.natural_key
    assert new_branch.is_open
    assert any("resurgence" in note.lower() for note in resumed.notes)


@pytest.mark.anyio
async def test_resuming_grants_a_stated_increment_and_never_resets_the_budget() -> None:
    """A case that reopens with a fresh budget every time is an adversary-controlled tap.

    Returning is cheap for them; the budget is what bounds what it costs us. So resumption adds
    an explicitly stated increment to the ceiling and leaves what was already spent alone.
    """
    graph, prior, returned = await world_with_a_return()
    case = watched(prior)
    candidate = await graph.find_entity(EntityType.IP_ADDRESS, returned.natural_key)
    assert candidate is not None

    resumed = resume_pursuit(
        case,
        candidate_entity_id=candidate.entity_id,
        candidate_key=candidate.natural_key,
        reason="reused the historical certificate",
        now=LATER,
        additional_budget=25.0,
    )

    assert resumed.budget_spent == 38.0
    assert resumed.total_budget == 125.0
    assert resumed.budget_remaining == 87.0

    twice = resume_pursuit(
        resumed,
        candidate_entity_id=candidate.entity_id,
        candidate_key=candidate.natural_key,
        reason="again",
        now=LATER,
        additional_budget=25.0,
    )
    assert twice.total_budget == 150.0
    assert twice.budget_spent == 38.0


@pytest.mark.anyio
async def test_a_negative_increment_is_refused() -> None:
    graph, prior, returned = await world_with_a_return()
    candidate = await graph.find_entity(EntityType.IP_ADDRESS, returned.natural_key)
    assert candidate is not None
    with pytest.raises(ValueError, match="budget"):
        resume_pursuit(
            watched(prior),
            candidate_entity_id=candidate.entity_id,
            candidate_key=candidate.natural_key,
            reason="x",
            now=LATER,
            additional_budget=-1.0,
        )


@pytest.mark.anyio
async def test_the_report_renders_what_it_examined_and_what_it_concluded() -> None:
    graph, prior, _ = await world_with_a_return()
    report = await watch_for_resurgence(
        graph,
        watched(prior),
        campaign="GLASS ANVIL",
        candidate_population=40,
        now=LATER,
        provenance_of=resolved,
    )
    rendered = report.render()
    assert "GLASS ANVIL" in rendered
    assert "candidate" in rendered.lower()
