"""Recognising an adversary whose indicators have all changed.

A disruption that works destroys the adversary's operational continuity. It must not destroy
ours. When the C2 goes dark, the domain lapses and the persona stops posting, the question is
not "is this IOC on a list" — every IOC is new by construction — but "does the combined
evidence support, and how strongly, that this new cluster is the campaign we already know".

The failure mode that matters is not missing a return. It is **false resurgence**: deciding two
unrelated operations are one because they share a registrar, a hosting provider or a TLS stack.
That mistake compounds — a wrongly merged cluster makes the next link look better supported —
and it is the reason most of the tests here are about refusing to conclude.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from nemesis.core.confidence import ConfidenceBand
from nemesis.core.disclosure import DisclosureClass
from nemesis.core.entities import EntityType
from nemesis.core.ids import IdPrefix, content_id
from nemesis.core.provenance import SourceClass, SourceDescriptor, SourceReliability
from nemesis.core.relationships import PivotSelectivity
from nemesis.core.temporal import TemporalExtent
from nemesis.pursuit.resurgence import (
    ACTIONABLE_FLOOR,
    ResurgenceAssessment,
    ResurgenceEngine,
    ResurgenceSignal,
    ResurgenceSignalKind,
    SuccessionGroup,
    base_rate_for_campaign_population,
)

NOW = datetime(2026, 6, 1, tzinfo=UTC)
EXTENT = TemporalExtent.at(NOW)
CAMPAIGN = "GLASS ANVIL"

# A corpus of tracked campaigns. Small on purpose: a large one would make every prior tiny and
# hide whether the signals are doing any work.
POPULATION = 40


def sensor(identifier: str, *, operator: str | None = None) -> SourceDescriptor:
    return SourceDescriptor(
        source_class=SourceClass.OWN_SENSOR,
        identifier=identifier,
        reliability=SourceReliability.USUALLY_RELIABLE,
        operator=operator,
    )


def unplantable(identifier: str) -> SourceDescriptor:
    """A channel an adversary cannot author into, so a fact it attests survives the margin.

    ``OWN_SENSOR`` — infrastructure we operate, observing traffic sent to us. An adversary can
    cause an observation and cannot author the record.

    Written as a named helper because the obvious choice is wrong: a HONEYPOT is *ours* and is
    still plantable, since an adversary writing into it is the entire point of deploying one.
    Ownership is not unplantability. The allowlist is exactly ``{OWN_SENSOR, LAW_ENFORCEMENT}``
    and everything else is plantable by default.
    """
    return SourceDescriptor(
        source_class=SourceClass.OWN_SENSOR,
        identifier=identifier,
        reliability=SourceReliability.COMPLETELY_RELIABLE,
    )


def open_source(identifier: str) -> SourceDescriptor:
    """A channel an adversary can write into — which is nearly all of them."""
    return SourceDescriptor(
        source_class=SourceClass.OPEN_SOURCE,
        identifier=identifier,
        reliability=SourceReliability.USUALLY_RELIABLE,
    )


def signal(
    kind: ResurgenceSignalKind,
    *,
    attribute: str,
    observed_by: SourceDescriptor | None = None,
    population: int | None = None,
    corpus: str | None = "passive DNS, 2026-06 snapshot",
    globally_unique: bool = False,
    new_entity_type: EntityType = EntityType.IP_ADDRESS,
    new_entity_key: str = "203.0.113.88",
    match_strength: float = 1.0,
) -> ResurgenceSignal:
    return ResurgenceSignal(
        kind=kind,
        shared_attribute=attribute,
        selectivity=PivotSelectivity(
            attribute=attribute,
            population_size=population,
            population_measured_against=corpus if population is not None else None,
            is_globally_unique=globally_unique,
        ),
        observed_by=observed_by or sensor(f"sensor-{attribute[:8]}"),
        new_entity_type=new_entity_type,
        new_entity_key=new_entity_key,
        prior_entity_key="198.51.100.23",
        match_strength=match_strength,
        extent=EXTENT,
        supporting_claims=(content_id(IdPrefix.CLAIM, attribute.encode()),),
    )


def assess(*signals: ResurgenceSignal, population: int = POPULATION) -> ResurgenceAssessment:
    return ResurgenceEngine().assess(
        campaign=CAMPAIGN,
        signals=signals,
        candidate_population=population,
        assessed_at=NOW,
    )


# -- the prior does most of the work -----------------------------------------------


def test_the_prior_falls_as_the_tracked_corpus_grows() -> None:
    """Base-rate neglect is how a moderate resemblance becomes a confident identification."""
    small = base_rate_for_campaign_population(10)
    large = base_rate_for_campaign_population(10_000)
    assert small > large
    assert 0.0 < large < small < 1.0


def test_a_corpus_of_one_campaign_has_no_pair_to_assess() -> None:
    with pytest.raises(ValueError, match="two"):
        base_rate_for_campaign_population(1)


# -- false resurgence: the failure that matters ------------------------------------


def test_a_shared_registrar_alone_establishes_nothing() -> None:
    """§31: shared hosting mistaken for dedicated infrastructure.

    Forty thousand domains went through this registrar. Two of them being ours is the base
    rate, not a finding.
    """
    result = assess(
        signal(
            ResurgenceSignalKind.PROVIDER_AND_TIMING_PATTERN,
            attribute="registrar:BulletproofReg",
            population=41_698,
        )
    )
    assert result.band is ConfidenceBand.INSUFFICIENT_BASIS
    assert not result.is_actionable


def test_an_uncounted_population_contributes_nothing_rather_than_a_guess() -> None:
    """Nobody counted is not the same as the population being small.

    Assuming a pivot is selective when nobody counted is precisely how shared-hosting
    artefacts become adversary clusters.
    """
    result = assess(
        signal(
            ResurgenceSignalKind.SHARED_TOOLING_ARTIFACT,
            attribute="user-agent:Mozilla/5.0",
            population=None,
            corpus=None,
        )
    )
    assert result.opinion.is_vacuous
    assert result.band is ConfidenceBand.INSUFFICIENT_BASIS


def test_a_naming_resemblance_alone_is_not_a_resurgence() -> None:
    """Cheap to imitate, and cheaper to frame somebody with."""
    result = assess(
        signal(
            ResurgenceSignalKind.NAMING_PATTERN,
            attribute="pattern:<brand>-invoice-<word>",
            population=180,
            new_entity_type=EntityType.DOMAIN,
            new_entity_key="globex-invoice-portal.example",
        )
    )
    assert not result.is_actionable


def test_one_plantable_fact_cannot_carry_a_resurgence_finding() -> None:
    """The robustness margin, on the proposition it was built for.

    An adversary who copies a certificate onto their own host and lets an honest collector
    find it has manufactured exactly this claim. One arranged fact must not produce a band
    anyone would act on, however many collectors reported it.
    """
    cert = "cert:3f8a1c7d9e4b2a6058c31df24e97b0a5"
    result = assess(
        signal(
            ResurgenceSignalKind.SHARED_PRIVATE_KEY,
            attribute=cert,
            globally_unique=True,
            observed_by=open_source("ct-log-watcher"),
        ),
        signal(
            ResurgenceSignalKind.SHARED_PRIVATE_KEY,
            attribute=cert,
            globally_unique=True,
            observed_by=open_source("scan-fleet"),
        ),
    )
    assert result.fusion.rests_only_on_plantable_evidence
    assert not result.is_actionable


# -- true resurgence ---------------------------------------------------------------


def test_two_independent_unplantable_facts_support_a_resurgence() -> None:
    """The engine must be able to say yes, or it is not a detector.

    Two different things about the world — a private key the operator reused and a build
    artefact from their toolchain — each attested by a channel an adversary cannot write into.
    """
    result = assess(
        signal(
            ResurgenceSignalKind.SHARED_PRIVATE_KEY,
            attribute="cert:3f8a1c7d9e4b2a6058c31df24e97b0a5",
            globally_unique=True,
            observed_by=unplantable("tls-honeypot"),
        ),
        signal(
            ResurgenceSignalKind.SHARED_TOOLING_ARTIFACT,
            attribute="build:pdb-path-D:\\anvil\\loader",
            population=3,
            observed_by=unplantable("malware-sandbox"),
        ),
    )
    assert result.is_actionable
    assert result.band not in {ConfidenceBand.INSUFFICIENT_BASIS, ConfidenceBand.ALMOST_NO_CHANCE}
    assert not result.fusion.rests_only_on_plantable_evidence


def test_signals_from_one_generating_process_do_not_accumulate() -> None:
    """Two certificates from one key are one choice of the operator's, not two facts.

    Collapsed by correlation group, exactly as persona linkage collapses two self-presentation
    signals. Otherwise an adversary who reuses one key across five hosts produces five
    'independent' confirmations of their own return.
    """
    many = assess(
        *(
            signal(
                ResurgenceSignalKind.SHARED_PRIVATE_KEY,
                attribute=f"cert:{n:032x}",
                globally_unique=True,
                observed_by=unplantable(f"sensor-{n}"),
            )
            for n in range(5)
        )
    )
    one = assess(
        signal(
            ResurgenceSignalKind.SHARED_PRIVATE_KEY,
            attribute="cert:00000000000000000000000000000000",
            globally_unique=True,
            observed_by=unplantable("sensor-0"),
        )
    )
    assert many.opinion.projected_probability == pytest.approx(
        one.opinion.projected_probability, abs=0.15
    )


# -- the §31 scenarios -------------------------------------------------------------


def test_c2_migration_is_recognised_through_a_reused_key() -> None:
    """The C2 address changed; the private key behind its certificate did not."""
    result = assess(
        signal(
            ResurgenceSignalKind.SHARED_PRIVATE_KEY,
            attribute="cert:3f8a1c7d9e4b2a6058c31df24e97b0a5",
            globally_unique=True,
            observed_by=unplantable("tls-honeypot"),
            new_entity_type=EntityType.C2_INFRASTRUCTURE,
            new_entity_key="203.0.113.88",
        ),
        signal(
            ResurgenceSignalKind.SHARED_TOOLING_ARTIFACT,
            attribute="beacon-config:jitter=37,sleep=900",
            population=2,
            observed_by=unplantable("malware-sandbox"),
            new_entity_type=EntityType.C2_INFRASTRUCTURE,
            new_entity_key="203.0.113.88",
        ),
    )
    assert result.is_actionable
    assert result.disclosure is DisclosureClass.DELIVERABLE


def test_wallet_reuse_is_a_financial_signal_and_stays_deliverable() -> None:
    result = assess(
        signal(
            ResurgenceSignalKind.SHARED_FINANCIAL_ENDPOINT,
            attribute="wallet:bc1qanvilcluster",
            population=2,
            corpus="clustered addresses, 2026-06",
            observed_by=unplantable("chain-analytics"),
            new_entity_type=EntityType.CRYPTO_ADDRESS,
            new_entity_key="bc1qnewreceiver",
        ),
        signal(
            ResurgenceSignalKind.SHARED_PRIVATE_KEY,
            attribute="cert:3f8a1c7d9e4b2a6058c31df24e97b0a5",
            globally_unique=True,
            observed_by=unplantable("tls-honeypot"),
        ),
    )
    assert result.is_actionable
    assert result.disclosure is DisclosureClass.DELIVERABLE


def test_persona_reuse_makes_the_finding_internal_rather_than_deliverable() -> None:
    """Founder decision D1, enforced where a resurgence finding would otherwise launder it.

    Persona linkage is an investigative lead and never a deliverable. A resurgence assessment
    resting on a persona signal takes the persona's classification — the wrapper does not get
    to publish what its contents may not say.
    """
    result = assess(
        signal(
            ResurgenceSignalKind.SHARED_PUBLISHED_FINGERPRINT,
            attribute="pgp:9F1C4A2E8B7D6053A1F2C3D4E5B6A70819283746",
            globally_unique=True,
            observed_by=unplantable("forum-watcher"),
            new_entity_type=EntityType.PERSONA,
            new_entity_key="quiet-anvil",
        ),
        signal(
            ResurgenceSignalKind.SHARED_PRIVATE_KEY,
            attribute="cert:3f8a1c7d9e4b2a6058c31df24e97b0a5",
            globally_unique=True,
            observed_by=unplantable("tls-honeypot"),
        ),
    )
    assert result.disclosure is DisclosureClass.INTERNAL_LEAD
    assert result.rests_on_internal_material


# -- what the assessment must always say -------------------------------------------


def test_an_assessment_always_offers_a_competing_explanation() -> None:
    """A finding with no alternative on the page is an argument, not an assessment."""
    result = assess(
        signal(
            ResurgenceSignalKind.SHARED_PRIVATE_KEY,
            attribute="cert:3f8a1c7d9e4b2a6058c31df24e97b0a5",
            globally_unique=True,
            observed_by=unplantable("tls-honeypot"),
        )
    )
    assert result.alternatives
    assert any(
        "copy" in a.hypothesis.lower() or "stag" in a.hypothesis.lower()
        for a in result.alternatives
    )


def test_no_signals_is_a_prior_not_a_finding() -> None:
    result = assess()
    assert result.opinion.is_vacuous
    assert result.band is ConfidenceBand.INSUFFICIENT_BASIS
    assert not result.is_actionable
    assert "no signal" in result.render().lower()


def test_the_assessment_names_the_campaign_it_is_about() -> None:
    result = assess(
        signal(
            ResurgenceSignalKind.SHARED_PRIVATE_KEY,
            attribute="cert:abc",
            globally_unique=True,
            observed_by=unplantable("tls-honeypot"),
        )
    )
    assert CAMPAIGN in result.render()
    assert result.campaign == CAMPAIGN


def test_every_signal_kind_has_a_ceiling_and_a_group() -> None:
    """A new kind must be placed deliberately, not defaulted into being persuasive."""
    for kind in ResurgenceSignalKind:
        probe = signal(kind, attribute="x", globally_unique=True)
        assert 0.0 < probe.belief_ceiling <= 1.0
        assert isinstance(probe.correlation_group, SuccessionGroup)


def test_the_ceilings_are_ordered_by_how_hard_the_signal_is_to_stage() -> None:
    """The ordering is the argument. A signal an adversary can fake cheaply must not
    outrank one they would have to steal a private key to produce."""
    order = [
        ResurgenceSignalKind.SHARED_PRIVATE_KEY,
        # An exfiltration endpoint has to work for the operator: copying it to frame somebody
        # means sending your victims' credentials to the party you are framing.
        ResurgenceSignalKind.SHARED_EXFILTRATION_ENDPOINT,
        ResurgenceSignalKind.SHARED_PUBLISHED_FINGERPRINT,
        ResurgenceSignalKind.SHARED_TOOLING_ARTIFACT,
        ResurgenceSignalKind.SHARED_FINANCIAL_ENDPOINT,
        ResurgenceSignalKind.PROVIDER_AND_TIMING_PATTERN,
        ResurgenceSignalKind.NAMING_PATTERN,
    ]
    ceilings = [signal(k, attribute="x", globally_unique=True).belief_ceiling for k in order]
    assert ceilings == sorted(ceilings, reverse=True)


def test_a_honeypot_is_ours_and_still_plantable() -> None:
    """Ownership is not unplantability, and getting this backwards is easy.

    An adversary writing into a honeypot is the entire point of deploying one, so a fact
    attested only by one is a fact an adversary may have arranged. Pinned here because the
    first draft of this file used a honeypot as its example of an unplantable channel and the
    engine correctly refused every finding built on it.
    """
    result = assess(
        signal(
            ResurgenceSignalKind.SHARED_PRIVATE_KEY,
            attribute="cert:3f8a1c7d9e4b2a6058c31df24e97b0a5",
            globally_unique=True,
            observed_by=SourceDescriptor(
                source_class=SourceClass.HONEYPOT,
                identifier="tls-honeypot",
                reliability=SourceReliability.COMPLETELY_RELIABLE,
            ),
        )
    )
    assert result.fusion.rests_only_on_plantable_evidence
    assert not result.is_actionable


def test_a_single_origin_is_a_lead_however_confident_it_looks() -> None:
    """One unplantable fact from one origin projects high and is still not actionable.

    Measured before this rule existed: a single certificate match attested by one own-sensor
    projected 0.811 and read as *very likely*, because the robustness margin leaves an
    unplantable fact standing. The margin defends against arranged evidence; it says nothing
    about fragility. A confident single source and three corroborating ones project the same
    number, and only the second is safe to re-open a case on.
    """
    result = assess(
        signal(
            ResurgenceSignalKind.SHARED_PRIVATE_KEY,
            attribute="cert:3f8a1c7d9e4b2a6058c31df24e97b0a5",
            globally_unique=True,
            observed_by=unplantable("own-tls-sensor"),
        )
    )
    assert result.opinion.projected_probability > ACTIONABLE_FLOOR
    assert result.band is ConfidenceBand.VERY_LIKELY
    assert result.is_single_origin
    assert not result.is_actionable
    assert "one independent origin" in result.render()
