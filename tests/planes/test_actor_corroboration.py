"""Cross-source actor corroboration must not turn two feeds of one origin into agreement.

The load-bearing test is the first: ransomware.live and deepdarkCTI both referencing an actor,
when both trace to the actor's own leak site, collapse to ONE independent origin — enrichment,
not corroboration. Only sources with genuinely distinct upstreams reduce uncertainty.
"""

from __future__ import annotations

from nemesis.core.claims import ClaimKind
from nemesis.core.confidence import Opinion
from nemesis.core.fusion import DependenceHandling
from nemesis.core.provenance import SourceClass, SourceDescriptor, SourceReliability
from nemesis.resolve.actor_corroboration import (
    SourceView,
    corroborate_actor,
)

ACTOR = "synthlock"


def _src(
    identifier: str,
    *,
    upstream: str,
    reliability: SourceReliability = SourceReliability.FAIRLY_RELIABLE,
) -> SourceDescriptor:
    return SourceDescriptor(
        source_class=SourceClass.OPEN_SOURCE,
        identifier=identifier,
        reliability=reliability,
        upstream_of_record=upstream,
    )


def _believing(n: int) -> Opinion:
    return Opinion.from_evidence(supporting=float(n), contradicting=0.0)


def _disbelieving(n: int) -> Opinion:
    return Opinion.from_evidence(supporting=0.0, contradicting=float(n))


def _ransomware_live(upstream: str, victims: int = 12) -> SourceView:
    return SourceView(
        source=_src("ransomware.live", upstream=upstream),
        opinion=_believing(victims),
        detail=f"claims {victims} victims",
    )


def _deepdarkcti(upstream: str, *, online: bool = True) -> SourceView:
    return SourceView(
        source=_src("deepdarkCTI", upstream=upstream),
        opinion=_believing(6) if online else _disbelieving(6),
        detail="leak site listed ONLINE" if online else "leak site listed OFFLINE",
    )


def test_two_feeds_of_one_leak_site_are_enrichment_not_corroboration() -> None:
    shared = f"leak-site:{ACTOR}"
    result = corroborate_actor(
        ACTOR,
        [_ransomware_live(shared), _deepdarkcti(shared)],
    )

    assert len(result.contributing_sources) == 2
    assert result.independent_origins == 1
    assert result.independently_corroborated is False
    assert result.fusion.dependence_handling in {
        DependenceHandling.DEPENDENT_COLLAPSED,
        DependenceHandling.SINGLE_SOURCE,
    }
    assert any("feeds resolved to" in w for w in result.warnings)


def test_genuinely_independent_origins_reduce_uncertainty() -> None:
    dependent = corroborate_actor(
        ACTOR,
        [_ransomware_live(f"leak-site:{ACTOR}"), _deepdarkcti(f"leak-site:{ACTOR}")],
    )
    independent = corroborate_actor(
        ACTOR,
        [
            _ransomware_live(f"scrape:ransomware.live:{ACTOR}"),
            _deepdarkcti(f"community-probe:deepdarkcti:{ACTOR}"),
        ],
    )

    assert independent.independent_origins == 2
    assert independent.independently_corroborated is True
    # CBF over two real origins leaves less uncertainty than WBF over one collapsed origin.
    assert independent.fusion.opinion.uncertainty < dependent.fusion.opinion.uncertainty
    assert independent.deception.contra_indicators  # notes what independence buys


def test_a_single_source_is_reported_as_such() -> None:
    result = corroborate_actor(ACTOR, [_ransomware_live(f"leak-site:{ACTOR}")])
    assert result.independent_origins == 1
    assert result.independently_corroborated is False
    assert any("single-sourced" in d for d in result.discrepancies)


def test_disagreement_between_independent_sources_surfaces_as_a_discrepancy() -> None:
    result = corroborate_actor(
        ACTOR,
        [
            _ransomware_live(f"scrape:ransomware.live:{ACTOR}", victims=12),
            _deepdarkcti(f"community-probe:deepdarkcti:{ACTOR}", online=False),
        ],
    )
    # One says active, the other says the leak site is down: a discrepancy worth an analyst.
    assert result.discrepancies
    assert result.fusion.max_conflict > 0.0


def test_it_is_intelligence_not_evidence_and_always_carries_a_deception_hypothesis() -> None:
    result = corroborate_actor(ACTOR, [_ransomware_live(f"leak-site:{ACTOR}")])
    assert result.claim_kind is ClaimKind.INFERENCE
    assert result.deception.adversary_could_plant is True
    assert result.deception.benefits_from_belief


def test_no_sources_is_a_prior_not_a_finding() -> None:
    result = corroborate_actor(ACTOR, [])
    assert result.independent_origins == 0
    assert result.contributing_sources == ()
    assert result.fusion.dependence_handling is DependenceHandling.NO_SOURCES


def test_render_states_the_verdict_and_origin_count() -> None:
    shared = f"leak-site:{ACTOR}"
    line = corroborate_actor(ACTOR, [_ransomware_live(shared), _deepdarkcti(shared)]).render()
    assert ACTOR in line
    assert "1 independent origin" in line
    assert "not corroboration" in line
