"""Invariants the defensive-CTI collection module must not be able to violate.

These are the structural promises of the RansomLook tracker reader, the KB-card allowlist adapter
and the local-model output ingester — asserted where they cannot be argued with, not in a docstring.

* **CTI-01** (invariant 1): local-model output enters only as a ``MODEL_ASSERTION`` of kind
  ``HYPOTHESIS`` or ``INFERENCE``. It can never be an ``OBSERVATION`` or a ``FACT``.
* **CTI-02** (invariant 15 / NET-01): the CTI egress connector refuses direct, unconfined network
  collection and is wired into no default connector set.
* **CTI-03** (human-identity wall): no CTI path produces a naming of, or attribution to, a human
  identity — the model ingester refuses it, and neither the tracker nor the KB adapter can express
  one.
* **CTI-04** (content safety): a leak-site KB candidate is ``MANDATORY_REPORT`` (never indexed), and
  a tracker listing naming illegal content is escalated to ``MANDATORY_REPORT``.
* **CTI-05** (least privilege): the pure CTI adapters carry no network capability; only the
  connector does, and it lives in the collection plane.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest

from nemesis.collect.cti_kb import parse_cti_kb
from nemesis.collect.cybertiel import ModelIngestError, ingest_model_assessment
from nemesis.collect.ransomlook import RansomLookConnector
from nemesis.collect.simulated import simulated_connectors
from nemesis.core.claims import Claim, ClaimKind, DerivationKind, Statement
from nemesis.core.entities import EntityType
from nemesis.core.evidence import ContentSafety
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.relationships import RelationType
from nemesis.core.temporal import TemporalExtent
from nemesis.ports.collection import PivotRequest, PivotType

pytestmark = pytest.mark.invariant

NOW = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
PILOT = new_id(IdPrefix.ACTOR)
ONION = "3e7lo3ebsgrjp5wsb6msvoiqrvmrn4mxmtkepmoevgjxqew5ksnftmid.onion"


# --- CTI-01: the local model can never manufacture an observation --------------------------


def _observation_premise() -> Claim:
    return Claim.create(
        kind=ClaimKind.OBSERVATION,
        statement=Statement(
            subject="threat_actor:synthlock",
            predicate=RelationType.HOSTED_ON.value,
            obj="tor_infrastructure:example.onion",
            natural_language="a collected snapshot",
        ),
        derivation=DerivationKind.DIRECT_COLLECTION,
        asserted_by=PILOT,
        asserted_at=NOW,
        valid_extent=TemporalExtent.at(NOW),
        supported_by_evidence=("evd_sha256-" + "b" * 64,),
    )


def test_model_output_can_only_be_a_model_assertion_hypothesis_or_inference() -> None:
    for derived in ((), (_observation_premise(),)):
        claim = ingest_model_assessment(
            model_identifier="CyberTiel",
            subject=(EntityType.THREAT_ACTOR, "SynthLock"),
            predicate=RelationType.ASSOCIATED_WITH,
            obj="intel_type:ransomware_dls",
            asserted_by=PILOT,
            asserted_at=NOW,
            derived_from=derived,
        )
        assert claim.derivation is DerivationKind.MODEL_ASSERTION
        assert claim.kind in {ClaimKind.HYPOTHESIS, ClaimKind.INFERENCE}
        assert claim.kind not in {ClaimKind.OBSERVATION, ClaimKind.FACT}


def test_model_output_cannot_be_inflated_above_its_weakest_premise() -> None:
    """A model assessment may never outrank the claim it rests on (standing dilution)."""
    weak = Claim.create(
        kind=ClaimKind.HYPOTHESIS,
        statement=Statement(
            subject="threat_actor:synthlock",
            predicate=RelationType.ASSOCIATED_WITH.value,
            obj="intel_type:x",
            natural_language="a guess",
        ),
        derivation=DerivationKind.EXTERNAL_REPORT,
        asserted_by=PILOT,
        asserted_at=NOW,
        valid_extent=TemporalExtent.at(NOW),
    )
    with pytest.raises(ModelIngestError):
        ingest_model_assessment(
            model_identifier="CyberTiel",
            subject=(EntityType.THREAT_ACTOR, "SynthLock"),
            predicate=RelationType.ASSOCIATED_WITH,
            obj="intel_type:ransomware_dls",
            asserted_by=PILOT,
            asserted_at=NOW,
            derived_from=(weak,),
        )


def test_the_core_validator_forbids_a_model_observation_directly() -> None:
    """CTI-01 rests on invariant 1 in Claim's own validator; assert it, so the module's guarantee
    is backed by the type and not only by this module's discipline."""
    with pytest.raises(ValueError, match="invariant 1"):
        Claim.create(
            kind=ClaimKind.OBSERVATION,
            statement=Statement(
                subject="threat_actor:x",
                predicate=RelationType.ASSOCIATED_WITH.value,
                obj="y",
                natural_language="a model tried to witness something",
            ),
            derivation=DerivationKind.MODEL_ASSERTION,
            asserted_by=PILOT,
            asserted_at=NOW,
            valid_extent=TemporalExtent.at(NOW),
            supported_by_evidence=("evd_sha256-" + "a" * 64,),
            model_identifier="CyberTiel",
        )


# --- CTI-02: the egress connector refuses unconfined collection and is not wired -----------


def test_the_cti_connector_refuses_direct_unconfined_collection() -> None:
    connector = RansomLookConnector(as_of=NOW)
    result = asyncio.run(
        connector.pivot(
            PivotRequest(
                pivot_type=PivotType.THREAT_INTEL_LOOKUP,
                entity_type=EntityType.THREAT_ACTOR,
                entity_key="SynthLock",
                reason="unconfined attempt must be refused",
            )
        )
    )
    assert not result.succeeded
    assert result.error is not None and "collect_confined" in result.error


def test_the_cti_connector_is_real_hostile_and_isolable() -> None:
    caps = RansomLookConnector(as_of=NOW).capabilities
    assert caps.is_simulated is False
    assert caps.handles_hostile_content is True
    assert caps.isolation_factory == "nemesis.collect.ransomlook:ransomlook_connector"
    assert caps.redistribution_permitted is False


def test_the_cti_connector_is_wired_into_no_default_connector_set() -> None:
    names = {connector.capabilities.name for connector in simulated_connectors()}
    assert "ransomlook-osint" not in names, (
        "the real CTI egress connector must ship off by default, wired into no registry"
    )


# --- CTI-03: no CTI path names a human -----------------------------------------------------


def test_the_model_ingester_refuses_a_human_identity_subject_or_object() -> None:
    for target in ("subject", "obj"):
        with pytest.raises(ModelIngestError):
            ingest_model_assessment(
                model_identifier="CyberTiel",
                subject=(EntityType.HUMAN_IDENTITY_LEAD, "lead")
                if target == "subject"
                else (EntityType.THREAT_ACTOR, "SynthLock"),
                predicate=RelationType.ASSOCIATED_WITH,
                obj=(EntityType.HUMAN_IDENTITY_LEAD, "person")
                if target == "obj"
                else "intel_type:x",
                asserted_by=PILOT,
                asserted_at=NOW,
            )


def test_the_model_ingester_refuses_naming_a_person_through_a_free_string_object() -> None:
    """The free-string object branch is the seam a naming would slip through; it is closed."""
    for obj in ("Jane Doe, Moscow", "human_identity_lead:jane doe"):
        with pytest.raises(ModelIngestError):
            ingest_model_assessment(
                model_identifier="CyberTiel",
                subject=(EntityType.THREAT_ACTOR, "SynthLock"),
                predicate=RelationType.OPERATED_BY,
                obj=obj,
                asserted_by=PILOT,
                asserted_at=NOW,
            )


def test_the_kb_adapter_only_proposes_forum_or_marketplace_targets() -> None:
    card = f"# Site — ransomware_gang\n\n- Live onion/site(s): http://{ONION}\n"
    report = parse_cti_kb([card])
    for service in report.candidates:
        assert service.entity_type in {EntityType.FORUM, EntityType.MARKETPLACE}


# --- CTI-04: leak/illegal material is held, never indexed ----------------------------------


def test_a_leak_site_candidate_is_mandatory_report_and_not_indexed() -> None:
    card = f"# Leaks — ransomware_gang\n\n- Live onion/site(s): http://{ONION}\n"
    report = parse_cti_kb([card])
    assert report.candidates
    assert all(
        service.content_safety is ContentSafety.MANDATORY_REPORT for service in report.candidates
    )


# --- CTI-05: the pure adapters carry no network capability ---------------------------------


def test_only_the_connector_module_holds_network_capability() -> None:
    from nemesis.sandbox.reachability import build_graph

    src = Path(__file__).resolve().parents[2] / "src"
    graph = build_graph(src)
    network = {name for name, cap in graph.capabilities.items() if cap.network}
    for pure in (
        "nemesis.collect.cti_kb",
        "nemesis.collect.cybertiel",
        "nemesis.collect.cti_safety",
    ):
        assert pure not in network, f"{pure} must not hold network capability"
    assert all(name.startswith("nemesis.collect.") for name in network)
