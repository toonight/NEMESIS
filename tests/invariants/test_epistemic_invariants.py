"""Invariants 1, 2 and 4: model output is not evidence, and standing cannot be inflated.

Each test here corresponds to a numbered invariant in CLAUDE.md. They are not unit tests
of convenience — they are the enforcement mechanism. If one of these can be made to pass
by weakening the assertion, the invariant has been lost.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from nemesis.core.claims import (
    Claim,
    ClaimKind,
    DerivationKind,
    EpistemicViolationError,
    Statement,
    check_derivation,
    max_derivable_kind,
)
from nemesis.core.evidence import (
    AdmissibilityDefect,
    ArtifactKind,
    ContentSafety,
    EvidenceObject,
    IntegrityAnchor,
)
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.provenance import (
    CollectionMethod,
    CustodyAction,
    CustodyEvent,
    ProcessingStep,
    ProvenanceChain,
    SourceClass,
    SourceDescriptor,
)
from nemesis.core.temporal import TemporalExtent

pytestmark = pytest.mark.invariant

T0 = datetime(2026, 3, 1, tzinfo=UTC)
T1 = datetime(2026, 6, 1, tzinfo=UTC)
ANALYST = new_id(IdPrefix.ACTOR)


def _statement(text: str = "evil.example resolved to 203.0.113.7") -> Statement:
    return Statement(
        subject="domain:evil.example",
        predicate="resolves_to",
        obj="ipv4:203.0.113.7",
        natural_language=text,
    )


def _evidence_id() -> str:
    from nemesis.core.ids import content_id

    return content_id(IdPrefix.EVIDENCE, b"synthetic-artifact")


def _provenance(*, simulated: bool = False, model_step: bool = False) -> ProvenanceChain:
    processing: tuple[ProcessingStep, ...] = ()
    if model_step:
        processing = (
            ProcessingStep(
                step_name="summarize",
                tool="llm-summarizer",
                tool_version="1.0",
                input_hash="sha256:" + "a" * 64,
                output_hash="sha256:" + "b" * 64,
                is_lossy=True,
                performed_by_model="claude-opus-5",
            ),
        )
    return ProvenanceChain(
        collection_id=new_id(IdPrefix.COLLECTION),
        source=SourceDescriptor(source_class=SourceClass.INTERNET_SCAN, identifier="fixture-pdns"),
        method=CollectionMethod(
            collector_name="fixture",
            collector_version="1.0",
            parameters={"query": "evil.example"},
            is_simulated=simulated,
        ),
        collected_at=T0,
        custody=(
            CustodyEvent(action=CustodyAction.COLLECTED, actor=ANALYST, reason="initial pull"),
        ),
        processing=processing,
    )


# --- Invariant 1: LLM conclusions are not evidence ---------------------------


@pytest.mark.parametrize("kind", [ClaimKind.OBSERVATION, ClaimKind.FACT])
@pytest.mark.parametrize(
    "derivation", [DerivationKind.MODEL_ASSERTION, DerivationKind.STATISTICAL_MODEL]
)
def test_a_model_cannot_produce_an_observation_or_a_fact(
    kind: ClaimKind, derivation: DerivationKind
) -> None:
    with pytest.raises(ValueError, match="never evidence"):
        Claim.create(
            kind=kind,
            statement=_statement(),
            derivation=derivation,
            asserted_by=ANALYST,
            asserted_at=T0,
            valid_extent=TemporalExtent.at(T0),
            supported_by_evidence=(_evidence_id(),),
            model_identifier="claude-opus-5",
        )


def test_a_model_derived_claim_must_name_the_model() -> None:
    with pytest.raises(ValueError, match="must name the model"):
        Claim.create(
            kind=ClaimKind.HYPOTHESIS,
            statement=_statement(),
            derivation=DerivationKind.MODEL_ASSERTION,
            asserted_by=ANALYST,
            asserted_at=T0,
            valid_extent=TemporalExtent.at(T0),
        )


def test_evidence_with_a_model_in_its_derivation_chain_is_inadmissible() -> None:
    obj = EvidenceObject.seal(
        artifact=b"forum post body",
        artifact_kind=ArtifactKind.FORUM_POST,
        provenance=_provenance(model_step=True),
        observed_extent=TemporalExtent.at(T0),
        vault_locator="vault://fixture/1",
    )
    assert AdmissibilityDefect.MODEL_IN_DERIVATION_CHAIN in obj.admissibility()
    assert not obj.is_admissible


# --- Invariant 2: observations and facts must rest on preserved material -----


def test_an_observation_without_evidence_is_rejected() -> None:
    with pytest.raises(ValueError, match="must cite at least one evidence object"):
        Claim.create(
            kind=ClaimKind.OBSERVATION,
            statement=_statement(),
            derivation=DerivationKind.DIRECT_COLLECTION,
            asserted_by=ANALYST,
            asserted_at=T0,
            valid_extent=TemporalExtent.at(T0),
        )


def test_simulated_collection_is_never_admissible() -> None:
    obj = EvidenceObject.seal(
        artifact=b"synthetic dns answer",
        artifact_kind=ArtifactKind.DNS_RECORD,
        provenance=_provenance(simulated=True),
        observed_extent=TemporalExtent.at(T0),
        vault_locator="vault://fixture/2",
    )
    assert AdmissibilityDefect.SIMULATED_COLLECTION in obj.admissibility()


def test_mandatory_report_content_is_never_indexed_or_admitted() -> None:
    obj = EvidenceObject.seal(
        artifact=b"redacted",
        artifact_kind=ArtifactKind.DOCUMENT,
        provenance=_provenance(),
        observed_extent=TemporalExtent.at(T0),
        content_safety=ContentSafety.MANDATORY_REPORT,
        vault_locator="quarantine://sealed/3",
    )
    assert obj.must_not_be_indexed
    assert AdmissibilityDefect.RESTRICTED_CONTENT in obj.admissibility()


# --- Standing cannot be inflated through a derivation chain ------------------


def _claim_of(kind: ClaimKind) -> Claim:
    """Build a minimal well-formed claim of the requested kind."""
    if kind in {ClaimKind.OBSERVATION, ClaimKind.FACT}:
        return Claim.create(
            kind=kind,
            statement=_statement(f"a {kind.value}"),
            derivation=DerivationKind.DIRECT_COLLECTION
            if kind is ClaimKind.OBSERVATION
            else DerivationKind.AUTHORITATIVE_RECORD,
            asserted_by=ANALYST,
            asserted_at=T0,
            valid_extent=TemporalExtent.at(T0),
            supported_by_evidence=(_evidence_id(),),
        )
    return Claim.create(
        kind=kind,
        statement=_statement(f"a {kind.value}"),
        derivation=DerivationKind.HUMAN_ANALYST,
        asserted_by=ANALYST,
        asserted_at=T0,
        valid_extent=TemporalExtent.at(T0),
    )


def test_a_fact_cannot_be_derived_from_a_hypothesis() -> None:
    premises = (_claim_of(ClaimKind.OBSERVATION), _claim_of(ClaimKind.HYPOTHESIS))
    with pytest.raises(EpistemicViolationError, match="weakest premise is a hypothesis"):
        check_derivation(ClaimKind.FACT, premises)


def test_a_correlation_premise_caps_the_conclusion_at_a_correlation() -> None:
    premises = (_claim_of(ClaimKind.FACT), _claim_of(ClaimKind.CORRELATION))
    assert max_derivable_kind(premises) is ClaimKind.CORRELATION
    with pytest.raises(EpistemicViolationError):
        check_derivation(ClaimKind.INFERENCE, premises)


def test_derivation_from_observations_yields_an_inference_not_an_observation() -> None:
    """Nothing was witnessed here — it was reasoned. That distinction must survive."""
    premises = (_claim_of(ClaimKind.OBSERVATION), _claim_of(ClaimKind.FACT))
    assert max_derivable_kind(premises) is ClaimKind.INFERENCE
    with pytest.raises(EpistemicViolationError):
        check_derivation(ClaimKind.OBSERVATION, premises)


def test_a_claim_resting_on_nothing_is_a_hypothesis() -> None:
    assert max_derivable_kind(()) is ClaimKind.HYPOTHESIS
    with pytest.raises(EpistemicViolationError, match="there are no premises"):
        check_derivation(ClaimKind.INFERENCE, ())


def test_nothing_stronger_than_a_hypothesis_derives_from_an_attribution() -> None:
    """An attribution is a conclusion. Building facts on top of it launders judgment."""
    assert max_derivable_kind((_claim_of(ClaimKind.ATTRIBUTION),)) is ClaimKind.HYPOTHESIS


# --- Invariant 3: provenance is unbroken -------------------------------------


def test_a_broken_processing_chain_is_rejected() -> None:
    with pytest.raises(ValueError, match="processing chain is broken"):
        ProvenanceChain(
            collection_id=new_id(IdPrefix.COLLECTION),
            source=SourceDescriptor(source_class=SourceClass.OPEN_SOURCE, identifier="x"),
            method=CollectionMethod(collector_name="c", collector_version="1"),
            collected_at=T0,
            processing=(
                ProcessingStep(
                    step_name="decode",
                    tool="t",
                    tool_version="1",
                    input_hash="sha256:" + "a" * 64,
                    output_hash="sha256:" + "b" * 64,
                ),
                ProcessingStep(
                    step_name="parse",
                    tool="t",
                    tool_version="1",
                    input_hash="sha256:" + "c" * 64,  # does not match the previous output
                    output_hash="sha256:" + "d" * 64,
                ),
            ),
        )


def test_an_inference_must_name_a_replayable_rule() -> None:
    with pytest.raises(ValueError, match="must name its rule"):
        Claim.create(
            kind=ClaimKind.INFERENCE,
            statement=_statement(),
            derivation=DerivationKind.DETERMINISTIC_RULE,
            asserted_by=ANALYST,
            asserted_at=T0,
            valid_extent=TemporalExtent.at(T0),
            derived_from_claims=(_claim_of(ClaimKind.OBSERVATION).claim_id,),
        )


# --- Invariant 10: an internal anchor proves nothing against an insider ------


def test_a_self_issued_anchor_does_not_satisfy_the_external_anchor_requirement() -> None:
    internal = IntegrityAnchor(
        anchor_type="merkle_inclusion_proof",
        anchored_at=T0,
        authority="nemesis",
        proof="deadbeef",
        covers_hash="a" * 64,
    )
    assert not internal.is_externally_held

    obj = EvidenceObject.seal(
        artifact=b"artifact",
        artifact_kind=ArtifactKind.LOG_RECORD,
        provenance=_provenance(),
        observed_extent=TemporalExtent.at(T0),
        vault_locator="vault://x",
        anchors=(internal,),
    )
    assert AdmissibilityDefect.NO_EXTERNAL_ANCHOR in obj.admissibility()


# --- Deduplication: identical claims must not look like corroboration --------


def test_the_same_claim_derived_identically_has_one_identity() -> None:
    kwargs = {
        "kind": ClaimKind.OBSERVATION,
        "statement": _statement(),
        "derivation": DerivationKind.DIRECT_COLLECTION,
        "asserted_by": ANALYST,
        "valid_extent": TemporalExtent.at(T0),
        "supported_by_evidence": (_evidence_id(),),
    }
    first = Claim.create(asserted_at=T0, **kwargs)  # type: ignore[arg-type]
    second = Claim.create(asserted_at=T1, **kwargs)  # type: ignore[arg-type]
    assert first.claim_id == second.claim_id, (
        "restating a claim at a different time must not mint a second identity, "
        "or a pursuit loop manufactures its own corroboration"
    )


def test_the_same_artifact_collected_twice_is_one_evidence_object() -> None:
    artifact = b"identical bytes from two independent collectors"
    first = EvidenceObject.seal(
        artifact=artifact,
        artifact_kind=ArtifactKind.TLS_CERTIFICATE,
        provenance=_provenance(),
        observed_extent=TemporalExtent.at(T0),
    )
    second = EvidenceObject.seal(
        artifact=artifact,
        artifact_kind=ArtifactKind.TLS_CERTIFICATE,
        provenance=_provenance(),
        observed_extent=TemporalExtent.at(T1),
    )
    assert first.evidence_id == second.evidence_id


def test_evidence_id_must_address_its_own_content() -> None:
    """Guards against a forged object claiming an identity that is not its content.

    Without this check, an insider could keep a legitimate evidence_id — already cited by
    claims and already anchored — while swapping the content hash underneath it.
    """
    obj = EvidenceObject.seal(
        artifact=b"real",
        artifact_kind=ArtifactKind.DOCUMENT,
        provenance=_provenance(),
        observed_extent=TemporalExtent.at(T0),
    )
    forged = obj.model_dump(by_alias=True) | {"content_hash": "f" * 64}
    with pytest.raises(ValueError, match="does not address its content"):
        EvidenceObject.model_validate(forged)


def test_verify_artifact_detects_substitution() -> None:
    obj = EvidenceObject.seal(
        artifact=b"original",
        artifact_kind=ArtifactKind.DOCUMENT,
        provenance=_provenance(),
        observed_extent=TemporalExtent.at(T0),
    )
    assert obj.verify_artifact(b"original")
    assert not obj.verify_artifact(b"tampered")
