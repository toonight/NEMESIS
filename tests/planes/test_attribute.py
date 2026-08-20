"""Attribution engine: the two controls that decide whether this platform is safe to run.

The scenario under test is Operation GLASS ANVIL (`docs/architecture/DEMO_SCENARIO.md`).
Two of its acceptance criteria are encoded here as tests that fail if the control is
removed rather than merely weakened:

- **No attribution names a natural person.** The human-identity gate is structural and runs
  before any scoring, so the tests attack it the way an adversary would — by raising the
  score, by raising the prior, and by restating one source until it looks like a crowd.
  A gate that could be cleared that way would pass a threshold test and fail these.
- **The planted "RedOctober Team" string is contradicting evidence.** The test asserts both
  halves: where the claim lands, and that removing the deception assessment moves it to the
  other side. A test that only checked the first half would pass against an engine that
  files everything as contradicting.

The band expectations for the five dimensions are the ones in phase 7 of the scenario.
They are asserted as ordering plus band membership rather than as exact point estimates:
the point estimates depend on calibration constants that are explicitly provisional, and a
test pinned to them would break on a recalibration that changed nothing about the controls.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from nemesis.attribute.dimensions import (
    AttributionDimension,
    RefusalReason,
)
from nemesis.attribute.engine import (
    REFUSED_IDENTITY_HYPOTHESIS,
    AttributionEngine,
    AttributionEvidence,
    AttributionRequest,
    DimensionInput,
    EvidenceDirection,
    run_identity_gate,
)
from nemesis.core.claims import Claim, ClaimKind, DeceptionAssessment, DerivationKind, Statement
from nemesis.core.confidence import ConfidenceBand, Opinion
from nemesis.core.ids import IdPrefix, content_id, new_id
from nemesis.core.provenance import SourceClass, SourceDescriptor, SourceReliability
from nemesis.core.temporal import TemporalExtent

ASSESSED_AT = datetime(2026, 3, 12, 9, 0, tzinfo=UTC)
CAMPAIGN_WINDOW = TemporalExtent.between(
    datetime(2026, 2, 18, tzinfo=UTC), datetime(2026, 3, 10, tzinfo=UTC)
)
ANALYST = new_id(IdPrefix.ACTOR)

PLANTED_NAME = "John Doe"
"""The innocent person the scenario plants. It must not appear in any rendered output."""

HIGH_BANDS = frozenset(
    {ConfidenceBand.LIKELY, ConfidenceBand.VERY_LIKELY, ConfidenceBand.ALMOST_CERTAIN}
)


# --- fixtures ----------------------------------------------------------------


def _source(
    identifier: str,
    *,
    source_class: SourceClass,
    reliability: SourceReliability,
    operator: str | None = None,
) -> SourceDescriptor:
    return SourceDescriptor(
        source_class=source_class,
        identifier=identifier,
        reliability=reliability,
        operator=operator or identifier,
    )


PASSIVE_DNS = _source(
    "passivedns-feed",
    source_class=SourceClass.COMMERCIAL_FEED,
    reliability=SourceReliability.USUALLY_RELIABLE,
    operator="PassiveDNSCo",
)
PASSIVE_DNS_RESELLER = _source(
    "threat-portal",
    source_class=SourceClass.COMMERCIAL_FEED,
    reliability=SourceReliability.USUALLY_RELIABLE,
    operator="PassiveDNSCo",
)
CT_LOGS = _source(
    "ct-log-archive",
    source_class=SourceClass.INTERNET_SCAN,
    reliability=SourceReliability.COMPLETELY_RELIABLE,
)
RDAP = _source(
    "rdap-mirror",
    source_class=SourceClass.COMMERCIAL_FEED,
    reliability=SourceReliability.USUALLY_RELIABLE,
)
OWN_ANALYSIS = _source(
    "kit-analysis-sandbox",
    source_class=SourceClass.OWN_SENSOR,
    reliability=SourceReliability.COMPLETELY_RELIABLE,
)
OPEN_KIT = _source(
    "open-directory-retrieval",
    source_class=SourceClass.OPEN_SOURCE,
    reliability=SourceReliability.USUALLY_RELIABLE,
)
PARTNER = _source(
    "peer-csirt",
    source_class=SourceClass.PARTNER,
    reliability=SourceReliability.USUALLY_RELIABLE,
)
DARK_ARCHIVE = _source(
    "darkbazaar-archive",
    source_class=SourceClass.COMMERCIAL_FEED,
    reliability=SourceReliability.USUALLY_RELIABLE,
    operator="DarkArchiveCo",
)
CHAIN = _source(
    "chain-analysis",
    source_class=SourceClass.BLOCKCHAIN,
    reliability=SourceReliability.COMPLETELY_RELIABLE,
)
DARK_POST = _source(
    "darkbazaar-post-helpful_anon",
    source_class=SourceClass.DARK_WEB,
    reliability=SourceReliability.CANNOT_BE_JUDGED,
)
DARK_POST_MIRROR = _source(
    "darkbazaar-mirror-helpful_anon",
    source_class=SourceClass.DARK_WEB,
    reliability=SourceReliability.CANNOT_BE_JUDGED,
    operator="darkbazaar-post-helpful_anon",
)
LAW_ENFORCEMENT = _source(
    "lea-referral",
    source_class=SourceClass.LAW_ENFORCEMENT,
    reliability=SourceReliability.COMPLETELY_RELIABLE,
)


def _claim(
    *,
    subject: str,
    predicate: str,
    obj: str,
    text: str,
    deception: DeceptionAssessment | None = None,
    kind: ClaimKind = ClaimKind.OBSERVATION,
    derivation: DerivationKind = DerivationKind.DIRECT_COLLECTION,
    model_identifier: str | None = None,
    extent: TemporalExtent = CAMPAIGN_WINDOW,
) -> Claim:
    evidence_backed = kind in {ClaimKind.OBSERVATION, ClaimKind.FACT}
    return Claim.create(
        kind=kind,
        statement=Statement(subject=subject, predicate=predicate, obj=obj, natural_language=text),
        derivation=derivation,
        asserted_by=ANALYST,
        asserted_at=ASSESSED_AT,
        valid_extent=extent,
        supported_by_evidence=(
            (content_id(IdPrefix.EVIDENCE, f"{subject}|{predicate}|{obj}".encode()),)
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


def _contradicts(
    claim: Claim, source: SourceDescriptor, disbelief: float, label: str
) -> AttributionEvidence:
    return AttributionEvidence(
        claim=claim,
        source=source,
        opinion=Opinion(belief=0.0, disbelief=disbelief, uncertainty=1.0 - disbelief),
        direction=EvidenceDirection.CONTRADICTS,
        label=label,
    )


FALSE_FLAG_DECEPTION = DeceptionAssessment(
    adversary_could_plant=True,
    planting_cost="trivial",
    benefits_from_belief=("the actual operator",),
)

FALSE_FLAG_CLAIM = _claim(
    subject="artifact:phishing-kit",
    predicate="contains_string",
    obj="Coded by DmitryK, RedOctober Team",
    text="The recovered kit archive contains the string 'Coded by DmitryK, RedOctober Team'.",
    deception=FALSE_FLAG_DECEPTION,
)

IDENTITY_CLAIM = _claim(
    subject="persona:GlassAnvil",
    predicate="is_natural_person",
    obj=PLANTED_NAME,
    text=f"A DarkBazaar post by helpful_anon asserts that GlassAnvil is {PLANTED_NAME}.",
)


def _engine() -> AttributionEngine:
    return AttributionEngine(assessed_by=new_id(IdPrefix.ACTOR))


def _glass_anvil_request() -> AttributionRequest:
    """The five dimensions of the scenario, as an investigation would hand them over."""
    cluster = _claim(
        subject="ip:198.51.100.23",
        predicate="hosts_domains",
        obj="4 domains",
        text="198.51.100.23 hosts four domains across three victim brands.",
    )
    cdn = _claim(
        subject="ip:192.0.2.10",
        predicate="hosts_domains",
        obj="41700 domains",
        text="192.0.2.10 is a shared CDN address hosting 41,700 domains.",
    )
    certificate = _claim(
        subject="cert:3f8a1c",
        predicate="presented_by",
        obj="198.51.100.23, 198.51.100.24, 203.0.113.88",
        text="One TLS certificate fingerprint is presented by three addresses.",
    )
    registration = _claim(
        subject="registrar:BulletproofReg",
        predicate="registered_within",
        obj="24 hours",
        text="All four domains were created inside a 24-hour window.",
    )
    kit = _claim(
        subject="artifact:phishing-kit",
        predicate="deployed_on",
        obj="198.51.100.24",
        text="A single phishing kit build is deployed across the cluster.",
    )
    ttp = _claim(
        subject="campaign:glass-anvil",
        predicate="uses_ttp_set",
        obj="invoice-lure/credential-harvest",
        text="One invoice-lure and credential-harvest TTP set across all sightings.",
    )
    tempo = _claim(
        subject="campaign:glass-anvil",
        predicate="shows_division_of_labour",
        obj="kit development separate from operation",
        text="Kit development and operation appear to be separate roles.",
    )
    vendor = _claim(
        subject="persona:GlassAnvil",
        predicate="operates_as",
        obj="vendor with escrow and support",
        text="The persona runs an escrow-backed vendor operation with customer support.",
    )
    pgp = _claim(
        subject="persona:GlassAnvil",
        predicate="publishes_pgp_fingerprint",
        obj="9f2c4e1a" + "0" * 32,
        text="GlassAnvil and AnvilWorks publish the same 160-bit PGP fingerprint.",
    )
    alias = _claim(
        subject="persona:GlassAnvil",
        predicate="shares_alias_stem",
        obj="anvil",
        text="Both personas carry the alias stem 'anvil'.",
    )
    hours = _claim(
        subject="persona:GlassAnvil",
        predicate="posts_within",
        obj="06:00-15:00 UTC",
        text="Both personas post within the same UTC window.",
    )
    telegram = _claim(
        subject="artifact:phishing-kit",
        predicate="references_channel",
        obj="@glassanvil",
        text="The kit references the same Telegram channel the persona advertises.",
    )
    wallet = _claim(
        subject="wallet:bc1qglassanvil",
        predicate="clusters_with",
        obj="bc1qanvil2nd",
        text="Multi-input clustering links the escrow wallet to a second address.",
    )

    return AttributionRequest(
        subject="the actor behind Operation GLASS ANVIL",
        dimensions=(
            DimensionInput(
                dimension=AttributionDimension.INFRASTRUCTURE,
                hypothesis=(
                    "The four domains, 198.51.100.23 and the shared certificate were under "
                    "common control."
                ),
                evidence=(
                    _supports(cluster, PASSIVE_DNS, 0.65, "4-domain reverse resolution"),
                    _supports(cdn, PASSIVE_DNS_RESELLER, 0.06, "41,700-domain CDN pivot"),
                    _supports(certificate, CT_LOGS, 0.85, "shared TLS certificate"),
                    _supports(registration, RDAP, 0.50, "24-hour registration window"),
                ),
            ),
            DimensionInput(
                dimension=AttributionDimension.CAMPAIGN,
                hypothesis="All observed activity belongs to one campaign.",
                evidence=(
                    _supports(kit, OWN_ANALYSIS, 0.80, "one kit build"),
                    _supports(ttp, PARTNER, 0.60, "one TTP set"),
                    _supports(registration, RDAP, 0.55, "24-hour registration window"),
                ),
            ),
            DimensionInput(
                dimension=AttributionDimension.ORGANIZATION,
                hypothesis="An organized group, not a lone operator, stands behind it.",
                evidence=(
                    _supports(tempo, PARTNER, 0.50, "division of labour"),
                    _supports(vendor, DARK_ARCHIVE, 0.45, "escrow-backed vendor operation"),
                ),
            ),
            DimensionInput(
                dimension=AttributionDimension.PERSONA,
                hypothesis="GlassAnvil and AnvilWorks are one operator.",
                evidence=(
                    _supports(pgp, DARK_ARCHIVE, 0.95, "shared full PGP fingerprint"),
                    _supports(alias, DARK_ARCHIVE, 0.15, "shared alias stem"),
                    _supports(hours, DARK_ARCHIVE, 0.10, "overlapping posting hours"),
                    _supports(telegram, OWN_ANALYSIS, 0.60, "Telegram handle in the kit"),
                    _supports(wallet, CHAIN, 0.50, "wallet cluster overlap"),
                ),
            ),
            DimensionInput(
                dimension=AttributionDimension.HUMAN_IDENTITY,
                hypothesis=f"The operator behind GlassAnvil is {PLANTED_NAME}, of Minsk.",
                evidence=(
                    _supports(
                        IDENTITY_CLAIM,
                        DARK_POST,
                        0.40,
                        f"DarkBazaar post naming {PLANTED_NAME}",
                    ),
                ),
            ),
        ),
    )


# --- the five dimensions stay five -------------------------------------------


def test_all_five_dimensions_are_reported_separately() -> None:
    result = _engine().assess(_glass_anvil_request(), assessed_at=ASSESSED_AT)

    assert [item.dimension for item in result.assessments] == list(AttributionDimension)
    assert len({item.dimension for item in result.assessments}) == 5


def test_a_dimension_with_no_input_is_still_reported() -> None:
    """Silence about a dimension reads as agreement. "Nobody looked" must be visible."""
    request = AttributionRequest(subject="a bare case")
    result = _engine().assess(request, assessed_at=ASSESSED_AT)

    infrastructure = result.for_dimension(AttributionDimension.INFRASTRUCTURE)
    assert infrastructure.band is ConfidenceBand.INSUFFICIENT_BASIS
    assert infrastructure.opinion.is_vacuous
    assert infrastructure.supporting_claims == ()
    assert "nobody looked" in infrastructure.reasoning


def test_the_result_offers_no_way_to_collapse_the_dimensions() -> None:
    """Anyone who wants one number must write the collapse themselves and own it."""
    result = _engine().assess(_glass_anvil_request(), assessed_at=ASSESSED_AT)

    forbidden = (
        "overall",
        "overall_confidence",
        "score",
        "combined",
        "aggregate",
        "total",
        "confidence",
        "collapse",
    )
    assert [name for name in forbidden if hasattr(result, name)] == []


# --- phase 7 of the scenario --------------------------------------------------


def test_glass_anvil_dimensions_land_where_the_scenario_says() -> None:
    result = _engine().assess(_glass_anvil_request(), assessed_at=ASSESSED_AT)

    infrastructure = result.for_dimension(AttributionDimension.INFRASTRUCTURE)
    campaign = result.for_dimension(AttributionDimension.CAMPAIGN)
    organization = result.for_dimension(AttributionDimension.ORGANIZATION)
    persona = result.for_dimension(AttributionDimension.PERSONA)
    identity = result.for_dimension(AttributionDimension.HUMAN_IDENTITY)

    # The reported figures sit below what the evidence alone gives, because the robustness
    # margin drops the most load-bearing plantable fact before reporting. The threshold here
    # encoded the pre-margin policy; it is corrected rather than the dimension exempted,
    # because the whole point is that these dimensions are margined too.
    for high in (infrastructure, campaign, persona):
        assert high.band in HIGH_BANDS, high.render()
        assert high.opinion.projected_probability > 0.55

    # "Moderate": a coherent operation with no organizational evidence must not come out
    # looking like the infrastructure finding, which is the one with real artifacts behind it.
    # ORGANIZATION is an ACTOR_ATTRIBUTION and therefore margined, so it now lands lower than
    # it did — the intent of this assertion is unchanged and its bound is widened downward.
    assert organization.band in {
        ConfidenceBand.UNLIKELY,
        ConfidenceBand.ROUGHLY_EVEN,
        ConfidenceBand.LIKELY,
    }
    for high in (infrastructure, campaign, persona):
        assert organization.opinion.projected_probability < high.opinion.projected_probability

    assert identity.band is ConfidenceBand.INSUFFICIENT_BASIS


def test_the_worthless_cdn_pivot_contributes_nothing() -> None:
    """A 41,700-domain shared address must not add confidence just by being present."""
    result = _engine().assess(_glass_anvil_request(), assessed_at=ASSESSED_AT)
    infrastructure = result.for_dimension(AttributionDimension.INFRASTRUCTURE)

    cdn = next(
        item
        for item in infrastructure.signal_contributions
        if item.label == "41,700-domain CDN pivot"
    )
    assert cdn.delta_projected <= 0.0


def test_two_feeds_from_one_operator_are_one_origin() -> None:
    """Feed count is not source count, and the engine must not recount it itself."""
    result = _engine().assess(_glass_anvil_request(), assessed_at=ASSESSED_AT)
    diversity = result.for_dimension(AttributionDimension.INFRASTRUCTURE).source_diversity

    assert diversity.total_signals == 4
    assert diversity.independent_source_count == 3
    assert any("threat-portal" in group for group in diversity.collapsed_groups)


# --- invariant 4: the base rate belongs to the proposition --------------------


@pytest.mark.invariant
def test_a_source_cannot_smuggle_in_its_own_base_rate() -> None:
    """A generous prior attached to a source must not buy confidence out of nothing.

    Jøsang flags this as the failure of base-rate-sensitive discounting: an unknown source
    with ``a=0.99`` asserting something confidently derives near-total belief. The engine
    stamps the dimension's prior over whatever the caller attached, so the attack is not
    available at this layer either.
    """
    claim = _claim(
        subject="ip:198.51.100.23",
        predicate="hosts_domains",
        obj="4 domains",
        text="198.51.100.23 hosts four domains.",
    )
    modest = AttributionEvidence(
        claim=claim,
        source=PASSIVE_DNS,
        opinion=Opinion(belief=0.3, disbelief=0.0, uncertainty=0.7, base_rate=0.01),
        label="reverse resolution",
    )
    greedy = modest.model_copy(
        update={"opinion": modest.opinion.model_copy(update={"base_rate": 0.99})}
    )

    def run(evidence: AttributionEvidence) -> float:
        request = AttributionRequest(
            subject="s",
            dimensions=(
                DimensionInput(
                    dimension=AttributionDimension.INFRASTRUCTURE,
                    hypothesis="common control",
                    evidence=(evidence,),
                ),
            ),
        )
        result = _engine().assess(request, assessed_at=ASSESSED_AT)
        return result.for_dimension(
            AttributionDimension.INFRASTRUCTURE
        ).opinion.projected_probability

    assert run(modest) == run(greedy)


# --- invariant 13: deception is a first-class alternative ---------------------


def _red_october_request(deception: DeceptionAssessment | None) -> AttributionRequest:
    """The counter-attribution the false flag was planted to produce."""
    claim = _claim(
        subject="artifact:phishing-kit",
        predicate="contains_string",
        obj="Coded by DmitryK, RedOctober Team",
        text="The recovered kit contains a RedOctober author marker.",
        deception=deception,
    )
    # The deception assessment is not part of the content address, so both variants are the
    # same claim: the only thing that differs between the two runs is the control itself.
    assert claim.claim_id == FALSE_FLAG_CLAIM.claim_id
    elsewhere = _claim(
        subject="artifact:phishing-kit",
        predicate="exfiltrates_to",
        obj="dropbox_ivan@mail.example, @glassanvil",
        text="The kit's exfiltration address and Telegram channel belong to GlassAnvil.",
    )
    return AttributionRequest(
        subject="the RedOctober Team as the actor behind GLASS ANVIL",
        dimensions=(
            DimensionInput(
                dimension=AttributionDimension.ORGANIZATION,
                hypothesis="The RedOctober Team conducted Operation GLASS ANVIL.",
                evidence=(
                    _supports(claim, OPEN_KIT, 0.70, "RedOctober author string"),
                    _contradicts(
                        elsewhere, OWN_ANALYSIS, 0.70, "kit exfiltration ties to GlassAnvil"
                    ),
                ),
            ),
        ),
    )


@pytest.mark.invariant
def test_the_planted_false_flag_becomes_contradicting_evidence() -> None:
    result = _engine().assess(_red_october_request(FALSE_FLAG_DECEPTION), assessed_at=ASSESSED_AT)
    organization = result.for_dimension(AttributionDimension.ORGANIZATION)

    assert organization.supporting_claims == ()
    assert FALSE_FLAG_CLAIM.claim_id in organization.contradicting_claims
    assert organization.band in {
        ConfidenceBand.ALMOST_NO_CHANCE,
        ConfidenceBand.VERY_UNLIKELY,
        ConfidenceBand.UNLIKELY,
    }
    assert organization.opinion.belief == 0.0
    assert any(alternative.is_deception_hypothesis for alternative in organization.alternatives)
    assert any("plant" in warning for warning in organization.warnings)


@pytest.mark.invariant
def test_the_deception_control_is_what_moves_the_string() -> None:
    """Without the deception assessment the same string supports RedOctober.

    This is the half of the test that fails if the control is deleted: an engine that filed
    everything as contradicting would pass the assertion above and fail this one.
    """
    with_control = (
        _engine()
        .assess(_red_october_request(FALSE_FLAG_DECEPTION), assessed_at=ASSESSED_AT)
        .for_dimension(AttributionDimension.ORGANIZATION)
    )
    without_control = (
        _engine()
        .assess(_red_october_request(None), assessed_at=ASSESSED_AT)
        .for_dimension(AttributionDimension.ORGANIZATION)
    )

    assert without_control.supporting_claims == (FALSE_FLAG_CLAIM.claim_id,)
    assert FALSE_FLAG_CLAIM.claim_id not in without_control.contradicting_claims
    # Compared on the evidential opinion, not the reported one. The reported figure is what
    # survives losing a plantable fact, and with the control removed there is only one fact
    # left to lose — so both arms would read 0.0 and the differential would measure the
    # margin rather than the deception control it is named for.
    assert without_control.evidential_opinion is not None
    assert without_control.evidential_opinion.belief > 0.0
    assert with_control.evidential_opinion is not None
    assert (
        with_control.evidential_opinion.projected_probability
        < without_control.evidential_opinion.projected_probability
    )
    assert not any(
        alternative.is_deception_hypothesis
        for alternative in without_control.alternatives
        if alternative.name.startswith("Planted")
    )


@pytest.mark.invariant
def test_the_planting_alternative_is_weighed_and_argued() -> None:
    """An alternative recorded without a number is one nobody will weigh."""
    result = _engine().assess(_red_october_request(FALSE_FLAG_DECEPTION), assessed_at=ASSESSED_AT)
    organization = result.for_dimension(AttributionDimension.ORGANIZATION)

    planted = next(
        alternative
        for alternative in organization.alternatives
        if alternative.name.startswith("Planted to mislead")
    )
    assert planted.opinion.belief > 0.0
    assert not planted.opinion.is_vacuous
    assert "the actual operator" in planted.description
    assert "double bluff" in planted.argument_against or "naming itself" in (
        planted.argument_against
    )


def test_an_expensive_marker_is_not_inverted() -> None:
    """The inversion is about cost. An adversary who must burn infrastructure is trading."""
    claim = _claim(
        subject="artifact:phishing-kit",
        predicate="signed_by",
        obj="a certificate issued to a real RedOctober front company",
        text="The kit is signed by a certificate issued to a RedOctober front company.",
        deception=DeceptionAssessment(
            adversary_could_plant=True,
            planting_cost="high",
            benefits_from_belief=("the actual operator",),
        ),
    )
    request = AttributionRequest(
        subject="s",
        dimensions=(
            DimensionInput(
                dimension=AttributionDimension.ORGANIZATION,
                hypothesis="RedOctober conducted it.",
                evidence=(_supports(claim, OPEN_KIT, 0.7, "code-signing certificate"),),
            ),
        ),
    )
    organization = (
        _engine()
        .assess(request, assessed_at=ASSESSED_AT)
        .for_dimension(AttributionDimension.ORGANIZATION)
    )

    assert organization.supporting_claims == (claim.claim_id,)


# --- the human-identity gate --------------------------------------------------


@pytest.mark.invariant
def test_human_identity_returns_insufficient_basis() -> None:
    result = _engine().assess(_glass_anvil_request(), assessed_at=ASSESSED_AT)
    identity = result.for_dimension(AttributionDimension.HUMAN_IDENTITY)

    assert identity.band is ConfidenceBand.INSUFFICIENT_BASIS
    assert identity.is_refused
    assert identity.supporting_claims == ()
    assert result.names_a_person is False

    gate = identity.identity_gate
    assert gate is not None
    assert set(gate.reasons) == {
        RefusalReason.SINGLE_SOURCED,
        RefusalReason.ONLY_ADVERSARY_INFLUENCEABLE,
        RefusalReason.NO_CORROBORATION,
    }
    assert gate.refused_claims == (IDENTITY_CLAIM.claim_id,)
    assert identity.missing_evidence  # the refusal says what would change it


@pytest.mark.invariant
def test_a_refusal_does_not_restate_the_name_it_refused() -> None:
    """The refusal document is the artifact that gets forwarded onward.

    The caller's hypothesis and the analyst's signal label both carry the planted name, as
    they would in real use. Neither may survive into the output.
    """
    result = _engine().assess(_glass_anvil_request(), assessed_at=ASSESSED_AT)
    identity = result.for_dimension(AttributionDimension.HUMAN_IDENTITY)

    assert identity.hypothesis == REFUSED_IDENTITY_HYPOTHESIS
    assert PLANTED_NAME not in identity.render()
    assert PLANTED_NAME not in result.render()
    assert PLANTED_NAME not in identity.reasoning


@pytest.mark.invariant
def test_the_gate_cannot_be_bypassed_by_raising_the_score() -> None:
    """The attack the gate exists to defeat: make the number big enough.

    Near-certain belief from every signal, a prior of 0.99, and the same dark-web post
    restated through a dozen mirrors. Every one of those is cheap for the adversary who
    wrote the original post, and none of them changes the shape of the evidence.
    """
    restatements = tuple(
        AttributionEvidence(
            claim=IDENTITY_CLAIM,
            source=DARK_POST_MIRROR.model_copy(update={"identifier": f"mirror-{index}"}),
            opinion=Opinion(belief=0.99, disbelief=0.0, uncertainty=0.01, base_rate=0.99),
            label=f"restatement {index}",
        )
        for index in range(12)
    )
    request = AttributionRequest(
        subject="the operator behind GlassAnvil",
        dimensions=(
            DimensionInput(
                dimension=AttributionDimension.HUMAN_IDENTITY,
                hypothesis=f"The operator is {PLANTED_NAME}.",
                base_rate=0.99,
                evidence=(
                    _supports(IDENTITY_CLAIM, DARK_POST, 0.99, "the original post"),
                    *restatements,
                ),
            ),
        ),
    )
    identity = (
        _engine()
        .assess(request, assessed_at=ASSESSED_AT)
        .for_dimension(AttributionDimension.HUMAN_IDENTITY)
    )

    assert identity.band is ConfidenceBand.INSUFFICIENT_BASIS
    assert identity.is_refused
    assert identity.supporting_claims == ()
    assert identity.signal_contributions == ()
    gate = identity.identity_gate
    assert gate is not None
    assert RefusalReason.SINGLE_SOURCED in gate.reasons
    assert gate.independent_origin_count == 1


@pytest.mark.invariant
def test_two_hostile_channels_disagreeing_is_not_corroboration() -> None:
    """Two origins asserting two different names confirm nothing about either."""
    second_name = _claim(
        subject="persona:GlassAnvil",
        predicate="is_natural_person",
        obj="Richard Roe",
        text="A second forum post asserts a different name for the operator.",
    )
    other_forum = _source(
        "nightport-post",
        source_class=SourceClass.DARK_WEB,
        reliability=SourceReliability.FAIRLY_RELIABLE,
    )
    request = AttributionRequest(
        subject="the operator",
        dimensions=(
            DimensionInput(
                dimension=AttributionDimension.HUMAN_IDENTITY,
                hypothesis="The operator has been identified.",
                evidence=(
                    _supports(IDENTITY_CLAIM, DARK_POST, 0.6, "first post"),
                    _supports(second_name, other_forum, 0.6, "second post"),
                ),
            ),
        ),
    )
    identity = (
        _engine()
        .assess(request, assessed_at=ASSESSED_AT)
        .for_dimension(AttributionDimension.HUMAN_IDENTITY)
    )

    gate = identity.identity_gate
    assert gate is not None
    assert gate.passed is False
    assert RefusalReason.NO_CORROBORATION in gate.reasons
    assert RefusalReason.ONLY_ADVERSARY_INFLUENCEABLE in gate.reasons
    assert RefusalReason.SINGLE_SOURCED not in gate.reasons


@pytest.mark.invariant
def test_a_model_assertion_can_never_carry_an_identification() -> None:
    """Invariant 1, at the one place where breaking it does the most damage."""
    inferred = _claim(
        subject="persona:GlassAnvil",
        predicate="is_natural_person",
        obj="a named person",
        text="A model concluded an identity from writing style.",
        kind=ClaimKind.INFERENCE,
        derivation=DerivationKind.STATISTICAL_MODEL,
        model_identifier="stylometry-v3",
    )
    corroborating = _claim(
        subject="persona:GlassAnvil",
        predicate="is_natural_person",
        obj="a named person",
        text="A lawful-process return names the same person.",
    )
    evidence = (
        _supports(corroborating, LAW_ENFORCEMENT, 0.8, "lawful-process return"),
        _supports(corroborating, PARTNER, 0.6, "peer CSIRT attestation"),
        _supports(inferred, OWN_ANALYSIS, 0.9, "stylometric identification"),
    )
    request = AttributionRequest(
        subject="the operator",
        dimensions=(
            DimensionInput(
                dimension=AttributionDimension.HUMAN_IDENTITY,
                hypothesis="The operator has been identified.",
                evidence=evidence,
            ),
        ),
    )
    identity = (
        _engine()
        .assess(request, assessed_at=ASSESSED_AT)
        .for_dimension(AttributionDimension.HUMAN_IDENTITY)
    )

    gate = identity.identity_gate
    assert gate is not None
    assert gate.reasons == (RefusalReason.MODEL_DERIVED_SUPPORT,)
    assert identity.band is ConfidenceBand.INSUFFICIENT_BASIS


def test_the_gate_can_be_passed() -> None:
    """A gate that always refuses would satisfy every test above and be worthless.

    Two independent origins, one of them outside any channel the adversary can write into,
    attesting the *same* statement, with no model in the support. This is the shape the
    gate is looking for — and passing it still produces a band, not a name.
    """
    statement = _claim(
        subject="persona:GlassAnvil",
        predicate="is_natural_person",
        obj="a named person",
        text="Two independent records name the same person as the account holder.",
    )
    request = AttributionRequest(
        subject="the operator",
        dimensions=(
            DimensionInput(
                dimension=AttributionDimension.HUMAN_IDENTITY,
                hypothesis="The operator has been identified.",
                evidence=(
                    _supports(statement, LAW_ENFORCEMENT, 0.85, "lawful-process return"),
                    _supports(statement, PARTNER, 0.70, "peer CSIRT attestation"),
                ),
            ),
        ),
    )
    identity = (
        _engine()
        .assess(request, assessed_at=ASSESSED_AT)
        .for_dimension(AttributionDimension.HUMAN_IDENTITY)
    )

    gate = identity.identity_gate
    assert gate is not None
    assert gate.passed is True
    assert gate.corroborated_statements == 1
    assert identity.band is not ConfidenceBand.INSUFFICIENT_BASIS
    assert identity.supporting_claims == (statement.claim_id,)


def test_run_identity_gate_refuses_an_empty_evidence_set() -> None:
    gate = run_identity_gate(())

    assert gate.passed is False
    assert gate.reasons == (RefusalReason.NO_EVIDENCE,)


# --- input hygiene ------------------------------------------------------------


def test_a_claim_cannot_be_offered_in_both_directions() -> None:
    claim = _claim(
        subject="ip:198.51.100.23",
        predicate="hosts_domains",
        obj="4 domains",
        text="198.51.100.23 hosts four domains.",
    )
    with pytest.raises(ValidationError, match="both supporting and contradicting"):
        DimensionInput(
            dimension=AttributionDimension.INFRASTRUCTURE,
            hypothesis="common control",
            evidence=(
                _supports(claim, PASSIVE_DNS, 0.6, "as support"),
                _contradicts(claim, PARTNER, 0.6, "as contradiction"),
            ),
        )


def test_a_declared_direction_must_match_the_mass_it_carries() -> None:
    claim = _claim(
        subject="ip:198.51.100.23",
        predicate="hosts_domains",
        obj="4 domains",
        text="198.51.100.23 hosts four domains.",
    )
    with pytest.raises(ValidationError, match="declared as contradicting"):
        AttributionEvidence(
            claim=claim,
            source=PASSIVE_DNS,
            opinion=Opinion(belief=0.7, disbelief=0.0, uncertainty=0.3),
            direction=EvidenceDirection.CONTRADICTS,
            label="mislabelled",
        )


def test_a_dimension_cannot_be_supplied_twice() -> None:
    with pytest.raises(ValidationError, match="more than once"):
        AttributionRequest(
            subject="s",
            dimensions=(
                DimensionInput(dimension=AttributionDimension.PERSONA, hypothesis="one operator"),
                DimensionInput(dimension=AttributionDimension.PERSONA, hypothesis="two operators"),
            ),
        )


def test_temporal_incoherence_is_reported_not_absorbed() -> None:
    """Facts that cannot all have been true at once are a signal about the evidence."""
    early = _claim(
        subject="domain:acme-invoice-portal.example",
        predicate="resolved_to",
        obj="198.51.100.23",
        text="Resolution observed in February.",
        extent=TemporalExtent.between(
            datetime(2026, 2, 20, tzinfo=UTC), datetime(2026, 2, 21, tzinfo=UTC)
        ),
    )
    late = _claim(
        subject="domain:acme-invoice-portal.example",
        predicate="registered_on",
        obj="2026-06-01",
        text="Registration record dated June, months after the phishing it enabled.",
        extent=TemporalExtent.between(
            datetime(2026, 6, 1, tzinfo=UTC), datetime(2026, 6, 2, tzinfo=UTC)
        ),
    )
    request = AttributionRequest(
        subject="s",
        dimensions=(
            DimensionInput(
                dimension=AttributionDimension.INFRASTRUCTURE,
                hypothesis="common control",
                evidence=(
                    _supports(early, PASSIVE_DNS, 0.6, "resolution"),
                    _supports(late, RDAP, 0.6, "registration"),
                ),
            ),
        ),
    )
    infrastructure = (
        _engine()
        .assess(request, assessed_at=ASSESSED_AT)
        .for_dimension(AttributionDimension.INFRASTRUCTURE)
    )

    assert infrastructure.temporal_consistency.is_coherent is False
    assert infrastructure.temporal_consistency.discontinuities
    assert "connected stretch of time" in infrastructure.reasoning


def test_a_wider_tolerance_can_be_configured() -> None:
    """The gap tolerance encodes how sparsely we collect, not how the adversary behaved."""
    engine = AttributionEngine(
        assessed_by=new_id(IdPrefix.ACTOR), temporal_tolerance=timedelta(days=200)
    )
    early = _claim(
        subject="d",
        predicate="resolved_to",
        obj="198.51.100.23",
        text="February sighting.",
        extent=TemporalExtent.between(
            datetime(2026, 2, 20, tzinfo=UTC), datetime(2026, 2, 21, tzinfo=UTC)
        ),
    )
    late = _claim(
        subject="d",
        predicate="resolved_to",
        obj="198.51.100.24",
        text="June sighting.",
        extent=TemporalExtent.between(
            datetime(2026, 6, 1, tzinfo=UTC), datetime(2026, 6, 2, tzinfo=UTC)
        ),
    )
    request = AttributionRequest(
        subject="s",
        dimensions=(
            DimensionInput(
                dimension=AttributionDimension.INFRASTRUCTURE,
                hypothesis="common control",
                evidence=(
                    _supports(early, PASSIVE_DNS, 0.6, "february"),
                    _supports(late, RDAP, 0.6, "june"),
                ),
            ),
        ),
    )

    infrastructure = engine.assess(request, assessed_at=ASSESSED_AT).for_dimension(
        AttributionDimension.INFRASTRUCTURE
    )
    assert infrastructure.temporal_consistency.is_coherent is True
