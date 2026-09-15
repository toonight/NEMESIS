"""Ingesting the local model's output as data — never as evidence, never as a naming.

CyberTiel/ct_rag run out of process in the ``cti-toolkit``; this module takes their *output* and
turns it into claims. The properties:

* the claim is a ``MODEL_ASSERTION`` and its kind is ``HYPOTHESIS`` (or ``INFERENCE`` when it
  cites card claims), never an ``OBSERVATION`` or ``FACT`` — invariant 1;
* the model identifier is carried on the claim;
* an attempt to assess a human identity is refused, not scored;
* only the structured assessment is carried — the model's free-text reasoning is not, so nothing an
  adversary planted in a page the model read rides into the graph as instruction or material.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from nemesis.collect.cybertiel import (
    ModelIngestError,
    ingest_model_assessment,
    triage_row_to_assessment,
)
from nemesis.core.claims import Claim, ClaimKind, DerivationKind, Statement
from nemesis.core.entities import EntityType
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.relationships import RelationType
from nemesis.core.temporal import TemporalExtent

NOW = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
MODEL = "CyberTiel-Coder-35B-A3B-MLX-oQ6e (mlx_vlm, MTP-off)"
PILOT = new_id(IdPrefix.ACTOR)


def _card_observation() -> Claim:
    """A strength-4 observation claim, standing in for a knowledge-card claim a model cites."""
    return Claim.create(
        kind=ClaimKind.OBSERVATION,
        statement=Statement(
            subject="threat_actor:synthlock",
            predicate=RelationType.HOSTED_ON.value,
            obj="tor_infrastructure:example.onion",
            natural_language="a collected leak-site snapshot",
        ),
        derivation=DerivationKind.DIRECT_COLLECTION,
        asserted_by=PILOT,
        asserted_at=NOW,
        valid_extent=TemporalExtent.at(NOW),
        supported_by_evidence=("evd_sha256-" + "a" * 64,),
    )


def _card_hypothesis() -> Claim:
    """A strength-1 hypothesis claim — too weak to ground an inference on."""
    return Claim.create(
        kind=ClaimKind.HYPOTHESIS,
        statement=Statement(
            subject="threat_actor:synthlock",
            predicate=RelationType.ASSOCIATED_WITH.value,
            obj="intel_type:ransomware_dls",
            natural_language="a bare guess",
        ),
        derivation=DerivationKind.EXTERNAL_REPORT,
        asserted_by=PILOT,
        asserted_at=NOW,
        valid_extent=TemporalExtent.at(NOW),
    )


def _assess(**overrides: object):  # type: ignore[no-untyped-def]
    kwargs: dict[str, object] = {
        "model_identifier": MODEL,
        "subject": (EntityType.THREAT_ACTOR, "SynthLock"),
        "predicate": RelationType.ASSOCIATED_WITH,
        "obj": "intel_type:ransomware_dls",
        "asserted_by": PILOT,
        "asserted_at": NOW,
    }
    kwargs.update(overrides)
    return ingest_model_assessment(**kwargs)  # type: ignore[arg-type]


def test_model_output_is_a_hypothesis_model_assertion_never_an_observation() -> None:
    claim = _assess()
    assert claim.kind is ClaimKind.HYPOTHESIS
    assert claim.derivation is DerivationKind.MODEL_ASSERTION
    assert claim.model_identifier == MODEL
    assert claim.supported_by_evidence == ()  # model output is never evidence


def test_citing_an_observation_yields_an_inference_still_model_derived() -> None:
    premise = _card_observation()
    claim = _assess(derived_from=(premise,))
    assert claim.kind is ClaimKind.INFERENCE
    assert claim.derivation is DerivationKind.MODEL_ASSERTION
    assert claim.derived_from_claims == (premise.claim_id,)


def test_grounding_on_a_hypothesis_is_refused_not_inflated() -> None:
    # A model assessment cannot outrank its own premise: grounding an INFERENCE on a HYPOTHESIS
    # would launder strength-1 model output into a strength-3 claim. check_derivation forbids it.
    with pytest.raises(ModelIngestError, match="cannot be a inference"):
        _assess(derived_from=(_card_hypothesis(),))


def test_a_free_string_object_that_could_name_a_person_is_refused() -> None:
    with pytest.raises(ModelIngestError):
        _assess(obj="Jane Doe, Moscow")  # bare free-form string, not a namespaced tag
    with pytest.raises(ModelIngestError):
        _assess(obj="human_identity_lead:jane doe")  # a human-identity namespace
    # A namespaced structured tag is accepted.
    assert _assess(obj="intel_type:ransomware_dls").statement.obj == "intel_type:ransomware_dls"


def test_assessing_a_human_identity_is_refused() -> None:
    with pytest.raises(ModelIngestError):
        _assess(subject=(EntityType.HUMAN_IDENTITY_LEAD, "some lead"))
    with pytest.raises(ModelIngestError):
        _assess(obj=(EntityType.HUMAN_IDENTITY_LEAD, "some person"))


def test_a_missing_model_identifier_is_refused() -> None:
    with pytest.raises(ModelIngestError):
        _assess(model_identifier="")


def test_the_statement_prose_names_no_person_and_carries_no_free_text() -> None:
    claim = _assess()
    assert "never a naming of" in claim.statement.natural_language
    assert claim.notes is not None and "not carried into the graph" in claim.notes


def test_structured_qualifiers_are_carried_and_a_naive_time_is_refused() -> None:
    claim = _assess(qualifiers={"cti_value": "5"})
    assert claim.statement.qualifiers["cti_value"] == "5"
    assert claim.statement.qualifiers["model_derived"] == "true"
    with pytest.raises(ValueError, match="asserted_at"):
        _assess(asserted_at=NOW.replace(tzinfo=None))


def test_a_deception_assessment_is_always_attached() -> None:
    claim = _assess()
    assert claim.deception is not None
    assert claim.deception.adversary_could_plant


def test_a_triage_row_becomes_a_hypothesis() -> None:
    row = {
        "id": "markets:0007",
        "intel_type": "access_or_credential_market",
        "cti_value": 4,
        "risk": ["exposes_victim_pii"],
        "note": "active access broker",
        "model": MODEL,
    }
    claim = triage_row_to_assessment(
        row,
        subject=(EntityType.MARKETPLACE, "SomeMarket"),
        asserted_by=PILOT,
        asserted_at=NOW,
    )
    assert claim.kind is ClaimKind.HYPOTHESIS
    assert claim.derivation is DerivationKind.MODEL_ASSERTION
    assert claim.model_identifier == MODEL
    assert claim.statement.qualifiers["cti_value"] == "4"
    assert claim.statement.qualifiers["risk"] == "exposes_victim_pii"
    assert "access_or_credential_market" in claim.statement.obj
    # The free-text triage note is not carried into the claim.
    assert "active access broker" not in str(claim.statement.qualifiers)


def test_a_triage_parse_failure_row_is_refused() -> None:
    row = {"id": "x", "intel_type": None, "cti_value": None, "note": "MODEL_PARSE_FAILURE"}
    with pytest.raises(ModelIngestError):
        triage_row_to_assessment(
            row,
            subject=(EntityType.MARKETPLACE, "X"),
            asserted_by=PILOT,
            asserted_at=NOW,
            model_identifier=MODEL,
        )
