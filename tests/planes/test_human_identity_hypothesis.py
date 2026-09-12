"""ADR-0015: human identity may be *hypothesised* — never asserted, never exported.

The strong-shape gate and its ``SCORED``/``WITHHELD`` outcomes are unchanged and are covered
in ``test_attribute.py``. These tests pin the new third disposition: a name-free operator
*profile*, offered by a pilot with ``is_profile=True``, is emitted as an explicitly
low-confidence, deception-discounted ``HYPOTHESIS`` that names no natural person and cannot
reach an external product.

The safety line these tests defend: a hypothesis is a lead in the Intelligence Graph, not an
accusation. ``names_a_person`` stays False for it, and ``redact_for_disclosure`` still drops
the whole dimension. A profile whose support is too thin to estimate degrades honestly to
WITHHELD rather than being dressed as a low hypothesis.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from nemesis.attribute.dimensions import (
    AttributionDimension,
    IdentityDisposition,
)
from nemesis.attribute.disclosure import redact_for_disclosure
from nemesis.attribute.engine import (
    AttributionEngine,
    AttributionEvidence,
    AttributionRequest,
    DimensionInput,
)
from nemesis.core.claims import Claim, ClaimKind, DeceptionAssessment, DerivationKind, Statement
from nemesis.core.confidence import ConfidenceBand, Opinion
from nemesis.core.ids import IdPrefix, content_id, new_id
from nemesis.core.provenance import SourceClass, SourceDescriptor, SourceReliability
from nemesis.core.temporal import TemporalExtent

pytestmark = pytest.mark.invariant

ASSESSED_AT = datetime(2026, 9, 12, 9, 0, tzinfo=UTC)
WINDOW = TemporalExtent.between(
    datetime(2026, 8, 26, tzinfo=UTC), datetime(2026, 9, 11, tzinfo=UTC)
)
ANALYST = new_id(IdPrefix.ACTOR)

# A profile that names no natural person — what a responsible pilot authors.
PROFILE = (
    "Likely a single operator working human-in-the-loop with AI tooling; no natural person "
    "is identified."
)


def _source(identifier: str, *, source_class: SourceClass) -> SourceDescriptor:
    return SourceDescriptor(
        source_class=source_class,
        identifier=identifier,
        reliability=SourceReliability.USUALLY_RELIABLE,
        operator=identifier,
    )


RESEARCH = _source("threat-research-firm", source_class=SourceClass.COMMERCIAL_FEED)
RESEARCH_2 = _source("second-research-firm", source_class=SourceClass.OPEN_SOURCE)
RESEARCH_3 = _source("peer-csirt", source_class=SourceClass.PARTNER)
OWN_MODEL = _source("local-pilot-inference", source_class=SourceClass.OWN_SENSOR)


def _claim(
    *,
    predicate: str,
    obj: str,
    text: str,
    kind: ClaimKind = ClaimKind.OBSERVATION,
    derivation: DerivationKind = DerivationKind.DIRECT_COLLECTION,
    model_identifier: str | None = None,
    deception: DeceptionAssessment | None = None,
) -> Claim:
    evidence_backed = kind in {ClaimKind.OBSERVATION, ClaimKind.FACT}
    return Claim.create(
        kind=kind,
        statement=Statement(
            subject="operation:papercut-agentic",
            predicate=predicate,
            obj=obj,
            natural_language=text,
        ),
        derivation=derivation,
        asserted_by=ANALYST,
        asserted_at=ASSESSED_AT,
        valid_extent=WINDOW,
        supported_by_evidence=(
            (content_id(IdPrefix.EVIDENCE, f"{predicate}|{obj}".encode()),)
            if evidence_backed
            else ()
        ),
        model_identifier=model_identifier,
        deception=deception,
    )


def _supports(
    claim: Claim, source: SourceDescriptor, belief: float, label: str
) -> AttributionEvidence:
    return AttributionEvidence(
        claim=claim,
        source=source,
        opinion=Opinion(belief=belief, disbelief=0.0, uncertainty=1.0 - belief),
        label=label,
    )


# A realistic name-free profile: three independent OSINT origins each describing one facet of
# the operator, the way a PaperCut profile would rest on GreyNoise + a DFIR firm + a peer CSIRT.
def _profile_evidence() -> tuple[AttributionEvidence, ...]:
    return (
        _supports(
            _claim(
                predicate="operator_profile",
                obj="single operator",
                text="A research report describes one operator directing the agents.",
            ),
            RESEARCH,
            0.7,
            "research report",
        ),
        _supports(
            _claim(
                predicate="operating_mode",
                obj="human-in-the-loop",
                text="A recovered working directory shows human-in-the-loop markers.",
            ),
            RESEARCH_2,
            0.7,
            "recovered directory",
        ),
        _supports(
            _claim(
                predicate="operator_profile",
                obj="single operator",
                text="A peer CSIRT independently profiles a single operator.",
            ),
            RESEARCH_3,
            0.7,
            "peer CSIRT",
        ),
    )


def _engine() -> AttributionEngine:
    return AttributionEngine(assessed_by=new_id(IdPrefix.ACTOR))


def _profile_input(*evidence: AttributionEvidence) -> DimensionInput:
    return DimensionInput(
        dimension=AttributionDimension.HUMAN_IDENTITY,
        hypothesis=PROFILE,
        is_profile=True,
        evidence=tuple(evidence),
    )


def _assess(item: DimensionInput):
    result = _engine().assess(
        AttributionRequest(subject="Operation PAPERCUT (agentic)", dimensions=(item,)),
        assessed_at=ASSESSED_AT,
    )
    return result, result.for_dimension(AttributionDimension.HUMAN_IDENTITY)


# --- the new disposition -----------------------------------------------------


def test_a_profile_lead_is_emitted_as_a_hypothesis_not_withheld() -> None:
    result, human = _assess(_profile_input(*_profile_evidence()))

    assert human.identity_disposition is IdentityDisposition.HYPOTHESIS
    assert human.is_hypothesis
    assert not human.is_refused
    assert human.band is not ConfidenceBand.INSUFFICIENT_BASIS
    # A hypothesis is a lead, not an accusation.
    assert result.names_a_person is False


def test_a_human_identity_hypothesis_names_no_person() -> None:
    result, human = _assess(_profile_input(*_profile_evidence()))

    assert result.names_a_person is False
    assert human.identity_disposition is not IdentityDisposition.SCORED


def test_a_thin_profile_degrades_to_withheld_rather_than_a_dressed_up_estimate() -> None:
    """One weak source is not enough to estimate. Honest: WITHHELD, not a low hypothesis."""
    thin = _claim(
        predicate="operator_profile",
        obj="single operator",
        text="A single low-reliability mention profiles one operator.",
    )
    _, human = _assess(_profile_input(_supports(thin, RESEARCH, 0.3, "single weak mention")))

    assert human.identity_disposition is IdentityDisposition.WITHHELD
    assert human.band is ConfidenceBand.INSUFFICIENT_BASIS


def test_a_human_identity_hypothesis_carries_explicit_low_confidence_and_a_caveat() -> None:
    _, human = _assess(_profile_input(*_profile_evidence()))

    # Explicit confidence, not a refusal to estimate — and never near-certain for a profile.
    assert human.band is not ConfidenceBand.INSUFFICIENT_BASIS
    assert human.band is not ConfidenceBand.ALMOST_CERTAIN
    assert any("hypothesis" in warning.casefold() for warning in human.warnings)


def test_a_cheaply_plantable_profile_signal_is_deception_discounted() -> None:
    plantable = _claim(
        predicate="likely_nationality",
        obj="russophone",
        text="A do-not-hit list of CIS states is read as a nationality tell.",
        deception=DeceptionAssessment(
            adversary_could_plant=True,
            planting_cost="trivial",
            benefits_from_belief=("the actual operator",),
        ),
    )
    evidence = (*_profile_evidence(), _supports(plantable, RESEARCH, 0.7, "CIS exclusion list"))
    _, human = _assess(_profile_input(*evidence))

    # The inversion machinery runs on the hypothesis path too: a trivially plantable support
    # is recorded as a planting alternative rather than raising the estimate.
    assert any(alt.is_deception_hypothesis for alt in human.alternatives)
    assert human.is_hypothesis


def test_a_model_authored_profile_is_a_hypothesis_never_a_naming() -> None:
    """Invariant 1: a model may propose a lead, never produce a scored identification."""
    inferred = _claim(
        predicate="operator_profile",
        obj="single operator",
        text="The local pilot infers a single-operator profile from tooling telemetry.",
        kind=ClaimKind.INFERENCE,
        derivation=DerivationKind.STATISTICAL_MODEL,
        model_identifier="local-ollama-pilot",
    )
    evidence = (_supports(inferred, OWN_MODEL, 0.8, "pilot inference"), *_profile_evidence())
    result, human = _assess(_profile_input(*evidence))

    assert human.identity_disposition is IdentityDisposition.HYPOTHESIS
    assert result.names_a_person is False


# --- the export wall is unchanged --------------------------------------------


def test_a_human_identity_hypothesis_is_withheld_from_an_external_product() -> None:
    result, human = _assess(_profile_input(*_profile_evidence()))
    assert human.is_hypothesis  # precondition: this run really produced a hypothesis
    product = redact_for_disclosure(result)

    withheld = {item.dimension for item in product.withheld}
    shipped = {item.dimension for item in product.dimensions}
    assert AttributionDimension.HUMAN_IDENTITY in withheld
    assert AttributionDimension.HUMAN_IDENTITY not in shipped
    assert product.names_a_person is False
    # The dimension name legitimately appears as a *withheld* label (the recipient is told it
    # was withheld) — but the profile's content must not ride out in the product.
    payload = product.model_dump_json()
    assert "human-in-the-loop" not in payload
    assert "single operator" not in payload
