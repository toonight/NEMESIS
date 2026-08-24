"""Following a claim back to who actually saw the thing.

The graph records that two hosts present one certificate. It does not record *who observed
that*, and it cannot: ``Relationship`` and ``Claim`` carry no
:class:`~nemesis.core.provenance.SourceDescriptor`. Provenance lives on the evidence in the
vault, one hop further back.

Everything downstream of that hop depends on making it. Without provenance the robustness
margin treats every fact as plantable, and the resurgence watch was structurally incapable of
producing anything but a lead — 0.007 against an analyst-grade 0.811 on the reference run. This
is the hop.

The tests are mostly about what it refuses to conclude. A resolver that guesses at provenance
would hand the margin an unplantable fact it never verified, and the margin is the control that
stops one planted artifact from producing a confident finding.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from nemesis.core.claims import Claim, ClaimKind, DerivationKind, Statement
from nemesis.core.evidence import ArtifactKind, EvidenceObject
from nemesis.core.ids import IdPrefix, content_id, new_id
from nemesis.core.provenance import (
    CollectionMethod,
    ProvenanceChain,
    SourceClass,
    SourceDescriptor,
    SourceReliability,
)
from nemesis.core.temporal import TemporalExtent
from nemesis.evidence.lineage import UNRESOLVED_SOURCE, resolve_lineage, resolve_sources
from nemesis.graph.memory import InMemoryClaimStore

NOW = datetime(2026, 6, 1, tzinfo=UTC)
EXTENT = TemporalExtent.at(NOW)


class FakeVault:
    """A vault that only has to answer ``get``. The resolver reads nothing else."""

    def __init__(self) -> None:
        self._objects: dict[str, EvidenceObject] = {}

    def hold(self, evidence: EvidenceObject) -> EvidenceObject:
        self._objects[evidence.evidence_id] = evidence
        return evidence

    async def get(self, evidence_id: str) -> EvidenceObject | None:
        return self._objects.get(evidence_id)


def descriptor(cls: SourceClass, identifier: str, operator: str | None = None) -> SourceDescriptor:
    return SourceDescriptor(
        source_class=cls,
        identifier=identifier,
        reliability=SourceReliability.USUALLY_RELIABLE,
        operator=operator,
    )


def sealed(vault: FakeVault, source: SourceDescriptor, payload: bytes) -> EvidenceObject:
    evidence = EvidenceObject(
        evidence_id=content_id(IdPrefix.EVIDENCE, payload),
        artifact_kind=ArtifactKind.TLS_CERTIFICATE,
        content_hash=__import__("hashlib").sha256(payload).hexdigest(),
        size_bytes=len(payload),
        provenance=ProvenanceChain(
            collection_id=new_id(IdPrefix.COLLECTION),
            source=source,
            method=CollectionMethod(
                collector_name="test-collector",
                collector_version="1.0",
                technique="passive collection",
                is_simulated=True,
            ),
            collected_at=NOW,
        ),
        observed_extent=EXTENT,
    )
    return vault.hold(evidence)


def observation(*evidence: EvidenceObject) -> Claim:
    return Claim.create(
        kind=ClaimKind.OBSERVATION,
        statement=Statement(
            subject="ip_address:192.0.2.77",
            predicate="presents_certificate",
            obj="tls_certificate:3f",
            natural_language="The address presented the certificate.",
        ),
        derivation=DerivationKind.DIRECT_COLLECTION,
        asserted_by=new_id(IdPrefix.ACTOR),
        asserted_at=NOW,
        valid_extent=EXTENT,
        supported_by_evidence=tuple(item.evidence_id for item in evidence),
    )


def model_belief() -> Claim:
    return Claim.create(
        kind=ClaimKind.HYPOTHESIS,
        statement=Statement(
            subject="ip_address:192.0.2.77",
            predicate="belongs_to",
            obj="campaign:glass-anvil",
            natural_language="The pilot believes this is the same campaign.",
        ),
        derivation=DerivationKind.MODEL_ASSERTION,
        asserted_by=new_id(IdPrefix.ACTOR),
        asserted_at=NOW,
        valid_extent=EXTENT,
        model_identifier="gpt-5-cyber",
    )


# -- the hop it exists to make -----------------------------------------------------


@pytest.mark.anyio
async def test_a_claim_resolves_to_the_source_that_observed_its_evidence() -> None:
    vault = FakeVault()
    claims = InMemoryClaimStore()
    sensor = descriptor(SourceClass.OWN_SENSOR, "tls-watcher")
    claim = observation(sealed(vault, sensor, b"a sealed capture"))
    await claims.record(claim)

    lineage = await resolve_lineage(claims, vault, (claim.claim_id,))

    assert lineage.sources == (sensor,)
    assert lineage.resolved_claims == 1
    assert lineage.unresolved_claims == 0
    assert not lineage.is_unresolved


@pytest.mark.anyio
async def test_distinct_origins_are_all_returned() -> None:
    """One fact seen by two sources is two attestations, not one averaged one.

    Returned as a sequence rather than collapsed, because ``establish_fact`` is what decides
    whether two origins accumulate or fold together — and it needs both to do that. Picking one
    here would make that decision silently and in the wrong place.
    """
    vault = FakeVault()
    claims = InMemoryClaimStore()
    a = descriptor(SourceClass.OWN_SENSOR, "tls-watcher")
    b = descriptor(SourceClass.OPEN_SOURCE, "ct-log")
    claim = observation(sealed(vault, a, b"first"), sealed(vault, b, b"second"))
    await claims.record(claim)

    lineage = await resolve_lineage(claims, vault, (claim.claim_id,))
    assert set(lineage.sources) == {a, b}


@pytest.mark.anyio
async def test_an_identical_source_seen_twice_is_returned_once() -> None:
    vault = FakeVault()
    claims = InMemoryClaimStore()
    sensor = descriptor(SourceClass.OWN_SENSOR, "tls-watcher")
    claim = observation(sealed(vault, sensor, b"first"), sealed(vault, sensor, b"second"))
    await claims.record(claim)

    lineage = await resolve_lineage(claims, vault, (claim.claim_id,))
    assert lineage.sources == (sensor,)


# -- what it refuses to conclude ---------------------------------------------------


@pytest.mark.anyio
async def test_an_unknown_claim_yields_the_unresolved_source_and_is_counted() -> None:
    """Unresolved is a reported state, never an absent one.

    A resolver that returned nothing for a claim it could not find would let the caller build a
    signal with no source at all, and an empty source list reads downstream as "no adversary-
    influenceable origin" — which is the exact opposite of what not knowing means.
    """
    vault = FakeVault()
    claims = InMemoryClaimStore()

    lineage = await resolve_lineage(claims, vault, (content_id(IdPrefix.CLAIM, b"never recorded"),))

    assert lineage.sources == (UNRESOLVED_SOURCE,)
    assert lineage.unresolved_claims == 1
    assert lineage.is_unresolved
    assert UNRESOLVED_SOURCE.is_adversary_influenceable


@pytest.mark.anyio
async def test_evidence_missing_from_the_vault_is_unresolved_not_trusted() -> None:
    vault = FakeVault()
    claims = InMemoryClaimStore()
    # A claim citing evidence the vault does not hold. An observation with *no* evidence at
    # all is refused by Claim itself, so the realistic failure is a citation that dangles —
    # after a retention sweep, or across a vault the caller does not have.
    claim = Claim.create(
        kind=ClaimKind.OBSERVATION,
        statement=Statement(
            subject="ip_address:192.0.2.77",
            predicate="presents_certificate",
            obj="tls_certificate:3f",
            natural_language="The address presented the certificate.",
        ),
        derivation=DerivationKind.DIRECT_COLLECTION,
        asserted_by=new_id(IdPrefix.ACTOR),
        asserted_at=NOW,
        valid_extent=EXTENT,
        supported_by_evidence=(content_id(IdPrefix.EVIDENCE, b"sealed somewhere else"),),
    )
    await claims.record(claim)

    lineage = await resolve_lineage(claims, vault, (claim.claim_id,))
    assert lineage.sources == (UNRESOLVED_SOURCE,)
    assert lineage.unresolved_claims == 1


@pytest.mark.anyio
async def test_a_model_derived_claim_contributes_no_provenance() -> None:
    """Invariant 1 at the hop where a model belief could have acquired a source.

    A pilot's belief cites no evidence and has no observer. Letting it fall through to the
    unresolved descriptor would be nearly harmless; letting it inherit a source from elsewhere
    in the same call would not be. It is counted separately so a reader sees it was refused
    rather than simply absent.
    """
    vault = FakeVault()
    claims = InMemoryClaimStore()
    belief = model_belief()
    await claims.record(belief)

    lineage = await resolve_lineage(claims, vault, (belief.claim_id,))

    assert lineage.model_derived_claims == 1
    assert lineage.resolved_claims == 0
    assert lineage.sources == (UNRESOLVED_SOURCE,)


@pytest.mark.anyio
async def test_one_resolved_claim_does_not_launder_an_unresolved_one() -> None:
    """Both are returned. The trusted half does not vouch for the half nobody checked."""
    vault = FakeVault()
    claims = InMemoryClaimStore()
    sensor = descriptor(SourceClass.OWN_SENSOR, "tls-watcher")
    good = observation(sealed(vault, sensor, b"a sealed capture"))
    await claims.record(good)

    lineage = await resolve_lineage(
        claims, vault, (good.claim_id, content_id(IdPrefix.CLAIM, b"missing"))
    )

    assert sensor in lineage.sources
    assert UNRESOLVED_SOURCE in lineage.sources
    assert lineage.resolved_claims == 1
    assert lineage.unresolved_claims == 1


@pytest.mark.anyio
async def test_no_claims_at_all_is_unresolved_rather_than_empty() -> None:
    vault = FakeVault()
    claims = InMemoryClaimStore()
    lineage = await resolve_lineage(claims, vault, ())
    assert lineage.sources == (UNRESOLVED_SOURCE,)
    assert lineage.is_unresolved


# -- the derivation chain ----------------------------------------------------------


@pytest.mark.anyio
async def test_an_inference_resolves_through_the_claims_it_rests_on() -> None:
    """An inference cites no evidence of its own; its provenance is its inputs'.

    Without this the resolver would report every derived claim as unresolved, and a platform
    whose conclusions are mostly derived would never establish provenance for anything.
    """
    vault = FakeVault()
    claims = InMemoryClaimStore()
    sensor = descriptor(SourceClass.OWN_SENSOR, "tls-watcher")
    base = observation(sealed(vault, sensor, b"a sealed capture"))
    await claims.record(base)

    inference = Claim.create(
        kind=ClaimKind.INFERENCE,
        statement=Statement(
            subject="ip_address:192.0.2.77",
            predicate="succeeded_by",
            obj="ip_address:198.51.100.23",
            natural_language="The new address succeeded the old one.",
        ),
        derivation=DerivationKind.DETERMINISTIC_RULE,
        asserted_by=new_id(IdPrefix.ACTOR),
        asserted_at=NOW,
        valid_extent=EXTENT,
        derived_from_claims=(base.claim_id,),
        rule_name="resurgence.shared-artifact-reconnection",
        rule_version="1",
    )
    await claims.record(inference)

    lineage = await resolve_lineage(claims, vault, (inference.claim_id,))
    assert lineage.sources == (sensor,)
    assert lineage.resolved_claims == 1


# -- the callable the watch consumes ------------------------------------------------


@pytest.mark.anyio
async def test_resolve_sources_is_the_hook_shape_the_watch_expects() -> None:
    vault = FakeVault()
    claims = InMemoryClaimStore()
    sensor = descriptor(SourceClass.OWN_SENSOR, "tls-watcher")
    claim = observation(sealed(vault, sensor, b"a sealed capture"))
    await claims.record(claim)

    hook = resolve_sources(claims, vault)
    sources = await hook((claim.claim_id,))
    assert sources == (sensor,)
