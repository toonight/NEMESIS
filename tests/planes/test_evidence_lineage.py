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

Registers EVID-09 (an origin is inherited only across a link a procedure made, never across one
somebody chose) and EVID-10 (resolving provenance is linear in the claims reachable, not in the
routes to them). Both are in `docs/security/INVARIANTS.md`, and EVID-09's row states the limit
this file cannot test away: the gate reads `derivation`, which the claim's own author writes.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from nemesis.core.claims import Claim, ClaimKind, DerivationKind, Statement
from nemesis.core.evidence import ArtifactKind, EvidenceObject
from nemesis.core.fusion import trust_of_source
from nemesis.core.ids import IdPrefix, content_id, new_id
from nemesis.core.provenance import (
    RELIABILITY_CONSERVATISM,
    CollectionMethod,
    ProvenanceChain,
    SourceClass,
    SourceDescriptor,
    SourceReliability,
    merge_source_records,
)
from nemesis.core.temporal import TemporalExtent
from nemesis.evidence.lineage import (
    ASSERTED_BACKING_PREFIX,
    COLLECTING_DERIVATIONS,
    INHERITING_DERIVATIONS,
    UNRESOLVED_SOURCE,
    resolve_lineage,
    resolve_sources,
)
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


# -- standing: who is entitled to have their own citation establish an origin -------


def analyst_hypothesis(*evidence: EvidenceObject, **overrides: object) -> Claim:
    """A named person's leap, pointing at material they chose.

    The statement is about a natural person and the evidence is a TLS certificate. Nothing in
    the schema relates the two, and nothing ever could: ``EvidenceObject`` names no claim, no
    entity and no statement, so "is this artifact about this assertion" is not a question this
    platform can ask. That is why the control has to be about standing rather than relevance.
    """
    return Claim.create(
        kind=overrides.pop("kind", ClaimKind.HYPOTHESIS),  # type: ignore[arg-type]
        statement=Statement(
            subject="human_identity_lead:Jean Dupont",
            predicate="operates",
            obj="organization:GLASS ANVIL",
            natural_language="Jean Dupont is the operator behind GLASS ANVIL.",
        ),
        derivation=overrides.pop("derivation", DerivationKind.HUMAN_ANALYST),  # type: ignore[arg-type]
        asserted_by=new_id(IdPrefix.ACTOR),
        asserted_at=NOW,
        valid_extent=EXTENT,
        supported_by_evidence=tuple(item.evidence_id for item in evidence),
        **overrides,  # type: ignore[arg-type]
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("kind", "derivation"),
    [
        (ClaimKind.HYPOTHESIS, DerivationKind.HUMAN_ANALYST),
        (ClaimKind.ATTRIBUTION, DerivationKind.HUMAN_ANALYST),
        (ClaimKind.HYPOTHESIS, DerivationKind.EXTERNAL_REPORT),
        (ClaimKind.CORRELATION, DerivationKind.EXTERNAL_REPORT),
    ],
)
async def test_a_guess_pointing_at_an_own_sensor_artifact_does_not_become_unplantable(
    kind: ClaimKind, derivation: DerivationKind
) -> None:
    """THE TEST THIS SECTION EXISTS FOR.

    ``UNPLANTABLE_SOURCE_CLASSES`` is ``{OWN_SENSOR, LAW_ENFORCEMENT}``, and the robustness
    margin keeps a fact only when some attesting origin is one of them. So an origin handed
    back for a claim nobody collected is not a cosmetic error: it is the margin's input, and
    the margin is the control that stops one planted artifact producing a confident finding.

    A hypothesis is a *guess*. Whoever wrote it chose which artifact to cite, and that choice
    is precisely the lever an adversary — or an honest analyst having a bad day — pulls. The
    origin of the artifact is not the origin of the assertion.
    """
    vault = FakeVault()
    claims = InMemoryClaimStore()
    sensor = descriptor(SourceClass.OWN_SENSOR, "tls-watcher")
    cert = sealed(vault, sensor, b"-----BEGIN CERTIFICATE----- evil.example")
    claim = analyst_hypothesis(cert, kind=kind, derivation=derivation)
    await claims.record(claim)

    lineage = await resolve_lineage(claims, vault, (claim.claim_id,))

    assert not any(not source.is_adversary_influenceable for source in lineage.sources), (
        f"a {kind.value} derived by {derivation.value} laundered its author's choice of "
        f"artifact into an unplantable origin: {lineage.sources}"
    )


# -- the walk is bounded in breadth, not only in depth ------------------------------


@pytest.mark.anyio
async def test_resolving_a_lattice_does_not_multiply_store_lookups() -> None:
    """The bound that was measured and the bound that was missing.

    ``MAX_DERIVATION_DEPTH`` exists, its docstring says, because "an unbounded walk over a
    store an adversary can grow is a way to make a watch pass take forever". It bounds *depth*.
    Nothing bounded *breadth*: with no visited set, a claim reachable by many paths is fetched
    once per path, so a shallow lattice costs one lookup per distinct route rather than per
    distinct claim.

    Measured before the visited set: nineteen claims in the store, three queried, **1,821**
    lookups. Against an I/O-backed claim store that is 1,821 round trips, and ``resolve_sources``
    is wired into the resurgence watch. The ceiling here is deliberately generous — this asserts
    the difference between linear and exponential, not a particular constant.
    """
    vault = FakeVault()
    lookups = 0

    class CountingStore(InMemoryClaimStore):
        async def get(self, claim_id: str) -> Claim | None:
            nonlocal lookups
            lookups += 1
            return await super().get(claim_id)

    claims = CountingStore()
    sensor = descriptor(SourceClass.OWN_SENSOR, "tls-watcher")
    base = observation(sealed(vault, sensor, b"a sealed capture"))
    await claims.record(base)

    layer = [base]
    stored = 1
    for depth in range(6):
        successors = []
        for index in range(3):
            node = Claim.create(
                kind=ClaimKind.INFERENCE,
                statement=Statement(
                    subject=f"ip_address:192.0.2.{depth}",
                    predicate="succeeded_by",
                    obj=f"ip_address:198.51.100.{index}",
                    natural_language=f"Layer {depth}, node {index}.",
                ),
                derivation=DerivationKind.DETERMINISTIC_RULE,
                asserted_by=new_id(IdPrefix.ACTOR),
                asserted_at=NOW,
                valid_extent=EXTENT,
                derived_from_claims=tuple(parent.claim_id for parent in layer),
                rule_name="resurgence.shared-artifact-reconnection",
                rule_version="1",
            )
            await claims.record(node)
            successors.append(node)
            stored += 1
        layer = successors

    lookups = 0
    lineage = await resolve_lineage(claims, vault, tuple(node.claim_id for node in layer))

    assert lineage.sources == (sensor,), "the lattice must still resolve to its one origin"
    assert lookups <= 4 * stored, (
        f"resolving {len(layer)} claims over a {stored}-claim lattice cost {lookups} store "
        f"lookups; the walk is counting paths, not claims"
    )


# -- the hop the gate must not break, and the hop it must -------------------------


@pytest.mark.anyio
async def test_a_guess_that_names_an_observation_as_its_parent_does_not_inherit_its_sensor() -> (
    None
):
    """The bottom-only rule is not enough, and this is the case that proves it.

    This guess cites no evidence at all. It names a real, honestly collected observation as its
    premise, and a check made where the walk *ends* cannot see anything wrong: the claim it
    returns is a genuine ``OBSERVATION``/``DIRECT_COLLECTION`` and passes. Choosing which parent
    matters is the same act as choosing which artifact to cite, so the standing test has to be
    applied at every hop of the walk rather than at the bottom of it.
    """
    vault = FakeVault()
    claims = InMemoryClaimStore()
    sensor = descriptor(SourceClass.OWN_SENSOR, "tls-watcher")
    honest = observation(sealed(vault, sensor, b"a sealed capture"))
    await claims.record(honest)

    guess = Claim.create(
        kind=ClaimKind.ATTRIBUTION,
        statement=Statement(
            subject="human_identity_lead:Jean Dupont",
            predicate="operates",
            obj="organization:GLASS ANVIL",
            natural_language="Jean Dupont is the operator behind GLASS ANVIL.",
        ),
        derivation=DerivationKind.HUMAN_ANALYST,
        asserted_by=new_id(IdPrefix.ACTOR),
        asserted_at=NOW,
        valid_extent=EXTENT,
        derived_from_claims=(honest.claim_id,),
    )
    await claims.record(guess)

    lineage = await resolve_lineage(claims, vault, (guess.claim_id,))

    assert not any(not source.is_adversary_influenceable for source in lineage.sources), (
        f"a judgement inherited its premise's sensor by naming it: {lineage.sources}"
    )
    assert lineage.asserted_backing_claims == 1
    assert lineage.resolved_claims == 0


@pytest.mark.anyio
async def test_a_deterministic_rule_chain_still_inherits_the_origin_its_inputs_established() -> (
    None
):
    """The value the module exists to deliver, asserted directly rather than assumed.

    This is the over-gating guard. It is green before this change and green after, by design —
    its job is to turn red the moment someone tightens the standing rule far enough to strip a
    replayable rule of its inputs' provenance, which is the failure that would take the
    reference run's resurgence finding back to the base rate.
    """
    vault = FakeVault()
    claims = InMemoryClaimStore()
    sensor = descriptor(SourceClass.OWN_SENSOR, "tls-watcher")
    base = observation(sealed(vault, sensor, b"a sealed capture"))
    await claims.record(base)

    lower = Claim.create(
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
    await claims.record(lower)
    upper = Claim.create(
        kind=ClaimKind.INFERENCE,
        statement=Statement(
            subject="ip_address:198.51.100.23",
            predicate="belongs_to",
            obj="campaign:glass-anvil",
            natural_language="The successor belongs to the campaign.",
        ),
        derivation=DerivationKind.DETERMINISTIC_RULE,
        asserted_by=new_id(IdPrefix.ACTOR),
        asserted_at=NOW,
        valid_extent=EXTENT,
        derived_from_claims=(lower.claim_id,),
        rule_name="resurgence.campaign-attachment",
        rule_version="1",
    )
    await claims.record(upper)

    lineage = await resolve_lineage(claims, vault, (upper.claim_id,))

    assert lineage.sources == (sensor,), "two rule hops must not lose the sensor underneath"
    assert lineage.resolved_claims == 1
    assert lineage.asserted_backing_claims == 0


@pytest.mark.anyio
async def test_a_correlation_a_collector_recorded_still_names_the_sensor_that_saw_it() -> None:
    """The reason the line is drawn on ``derivation`` and not on ``kind``.

    A gate on ``ClaimKind`` would refuse this — a ``CORRELATION`` is weak — while waving through
    a ``FACT`` derived from an ``EXTERNAL_REPORT``, which carries the joint-maximum
    ``EPISTEMIC_STRENGTH`` with no observer anywhere behind it. A collector really did record
    this one, in the same act that produced the artifact.
    """
    vault = FakeVault()
    claims = InMemoryClaimStore()
    sensor = descriptor(SourceClass.OWN_SENSOR, "tls-watcher")
    evidence = sealed(vault, sensor, b"a sealed capture")
    recorded = Claim.create(
        kind=ClaimKind.CORRELATION,
        statement=Statement(
            subject="domain:a.example",
            predicate="shares_certificate_with",
            obj="domain:b.example",
            natural_language="Both domains presented the same certificate.",
        ),
        derivation=DerivationKind.DIRECT_COLLECTION,
        asserted_by=new_id(IdPrefix.ACTOR),
        asserted_at=NOW,
        valid_extent=EXTENT,
        supported_by_evidence=(evidence.evidence_id,),
    )
    await claims.record(recorded)

    lineage = await resolve_lineage(claims, vault, (recorded.claim_id,))

    assert lineage.sources == (sensor,)
    assert lineage.resolved_claims == 1


@pytest.mark.anyio
async def test_a_claim_reachable_by_two_routes_keeps_the_standing_of_the_better_one() -> None:
    """What a visited set keyed on the claim id alone would silently destroy.

    The observation is reachable twice: once across a chain of replayable rules, and once across
    a judgement somebody made. Both are true, and the first is what entitles this claim to the
    sensor's origin. A walk that recorded "seen" against the claim id would take whichever route
    the store yielded first — the judgement is listed first here, deliberately — and the honest
    origin would vanish depending on tuple order.

    Keying the visited set on ``(claim_id, inherited)`` is what makes the answer independent of
    that ordering, at a cost of at most two visits per claim.
    """
    vault = FakeVault()
    claims = InMemoryClaimStore()
    sensor = descriptor(SourceClass.OWN_SENSOR, "tls-watcher")
    base = observation(sealed(vault, sensor, b"a sealed capture"))
    await claims.record(base)

    def over(kind: ClaimKind, derivation: DerivationKind, label: str, **extra: object) -> Claim:
        return Claim.create(
            kind=kind,
            statement=Statement(
                subject="ip_address:192.0.2.77",
                predicate="succeeded_by",
                obj=f"ip_address:198.51.100.{label}",
                natural_language=f"Route {label}.",
            ),
            derivation=derivation,
            asserted_by=new_id(IdPrefix.ACTOR),
            asserted_at=NOW,
            valid_extent=EXTENT,
            derived_from_claims=(base.claim_id,),
            **extra,  # type: ignore[arg-type]
        )

    judged = over(ClaimKind.HYPOTHESIS, DerivationKind.HUMAN_ANALYST, "1")
    ruled = over(
        ClaimKind.INFERENCE,
        DerivationKind.DETERMINISTIC_RULE,
        "2",
        rule_name="resurgence.shared-artifact-reconnection",
        rule_version="1",
    )
    await claims.record(judged)
    await claims.record(ruled)

    root = Claim.create(
        kind=ClaimKind.INFERENCE,
        statement=Statement(
            subject="campaign:glass-anvil",
            predicate="resurged_as",
            obj="ip_address:198.51.100.23",
            natural_language="The campaign resurged.",
        ),
        derivation=DerivationKind.DETERMINISTIC_RULE,
        asserted_by=new_id(IdPrefix.ACTOR),
        asserted_at=NOW,
        valid_extent=EXTENT,
        # The judged route first: a claim-id-keyed visited set would consume the observation here.
        derived_from_claims=(judged.claim_id, ruled.claim_id),
        rule_name="resurgence.campaign-attachment",
        rule_version="1",
    )
    await claims.record(root)

    lineage = await resolve_lineage(claims, vault, (root.claim_id,))

    assert sensor in lineage.sources, (
        "the rule route to the observation was lost because the judged route reached it first: "
        f"{lineage.sources}"
    )
    assert lineage.resolved_claims == 1


# -- a design that was built, measured and rejected -------------------------------


@pytest.mark.anyio
async def test_a_second_collector_of_the_same_artifact_is_not_demoted() -> None:
    """THE REGRESSION PIN FOR A CONTROL THAT LOOKED RIGHT AND WAS AN OUTAGE.

    A custody conjunct was implemented here — demote unless the artifact's chain of custody names
    the party that wrote the claim — and removed after measurement. Three properties combine to
    make it a release trigger rather than a control:

    - ``evidence_id`` is a content address over the artifact bytes alone, so two collectors of
      the same bytes yield one evidence object, deliberately;
    - the vault returns the *stored* object on a re-seal, so the first sealer's metadata wins;
    - ``CustodyEvent`` is constructed at exactly one site in the tree, inside
      ``build_observation``, so the tuple holds one event forever.

    So the conjunct did not ask what its docstring said. It asked whether this claim's author was
    the first party ever to seal these bytes — and ``connector_actor_id`` hashes a connector's
    name *and version*. Bumping one connector's version over a durable vault demoted 34 of 34
    honest observations, took every reference-run finding to the base rate, and flipped the
    resurgence watch's ``resumes`` from True to False. No adversary required.

    This test reproduces the two-collector case with no version change at all. It is here so that
    re-adding the conjunct turns something red instead of shipping.
    """
    vault = FakeVault()
    claims = InMemoryClaimStore()
    payload = b"one artifact, two honest collectors"
    first = sealed(vault, descriptor(SourceClass.OWN_SENSOR, "acme-ct-watcher"), payload)

    # A second collector reaches the same bytes. Content addressing collapses them to one object
    # and the vault keeps the first sealer's provenance, so the later claim's author appears
    # nowhere in the custody the resolver can see.
    later = Claim.create(
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
        supported_by_evidence=(first.evidence_id,),
    )
    await claims.record(later)

    lineage = await resolve_lineage(claims, vault, (later.claim_id,))

    assert lineage.resolved_claims == 1, "an honest second collector was demoted"
    assert lineage.asserted_backing_claims == 0
    assert any(not source.is_adversary_influenceable for source in lineage.sources), (
        f"the later collector lost the sensor's standing: {lineage.sources}"
    )


# -- tripwires on the two dials ---------------------------------------------------


def test_every_derivation_kind_is_placed_on_one_side_of_the_standing_line() -> None:
    """An eighth ``DerivationKind`` must not acquire standing by being forgotten.

    Both sets are allowlists, so a new member defaults to no standing and this test would still
    pass — which is exactly why the assertion is on the *placement being considered* rather than
    on the behaviour. Adding a derivation forces a decision here.
    """
    granted = COLLECTING_DERIVATIONS | INHERITING_DERIVATIONS
    withheld = {kind for kind in DerivationKind if kind not in granted}

    assert granted == {
        DerivationKind.DIRECT_COLLECTION,
        DerivationKind.AUTHORITATIVE_RECORD,
        DerivationKind.DETERMINISTIC_RULE,
    }
    assert withheld == {
        DerivationKind.MODEL_ASSERTION,
        DerivationKind.STATISTICAL_MODEL,
        DerivationKind.HUMAN_ANALYST,
        DerivationKind.EXTERNAL_REPORT,
    }
    assert granted | withheld == set(DerivationKind), "a derivation kind was placed nowhere"


def test_no_model_derivation_is_ever_granted_standing() -> None:
    """Invariant 1 asserted against the dials themselves.

    Deliberately not a behavioural test: the walk refuses a model-derived claim in three separate
    places, so a behavioural assertion here would pass because of a different control. This one
    can only fail by someone editing a frozenset, which is the change it exists to catch.
    """
    for derivation in (DerivationKind.MODEL_ASSERTION, DerivationKind.STATISTICAL_MODEL):
        assert derivation not in COLLECTING_DERIVATIONS
        assert derivation not in INHERITING_DERIVATIONS


@pytest.mark.anyio
async def test_a_demoted_origin_still_names_the_artifact_it_pointed_at() -> None:
    """The demotion has to reach the analyst's page, not just the arithmetic.

    "Nobody could establish an origin" and "somebody asserted a link nothing can check" are
    different states with different fixes. Collapsing the second into ``UNRESOLVED_SOURCE`` would
    leave an on-call engineer hunting a retention sweep for an attempted laundering.
    """
    vault = FakeVault()
    claims = InMemoryClaimStore()
    sensor = descriptor(SourceClass.OWN_SENSOR, "tls-watcher")
    cert = sealed(vault, sensor, b"-----BEGIN CERTIFICATE----- evil.example")
    claim = analyst_hypothesis(cert)
    await claims.record(claim)

    lineage = await resolve_lineage(claims, vault, (claim.claim_id,))
    marked = [s for s in lineage.sources if s.identifier.startswith(ASSERTED_BACKING_PREFIX)]

    assert len(marked) == 1, f"the chosen pairing was not marked as one: {lineage.sources}"
    demoted = marked[0]
    assert "tls-watcher" in demoted.identifier, "the analyst cannot see what was pointed at"
    assert demoted.source_class is SourceClass.HUMAN_ANALYST
    assert demoted.reliability is SourceReliability.CANNOT_BE_JUDGED
    assert demoted.is_adversary_influenceable
    assert UNRESOLVED_SOURCE not in lineage.sources, (
        "a demoted origin is not the same state as an unresolved one"
    )


# --- two records of one source -------------------------------------------------


def _source(
    *,
    reliability: SourceReliability = SourceReliability.USUALLY_RELIABLE,
    upstream: str | None = None,
    restrictions: tuple[str, ...] = (),
) -> SourceDescriptor:
    """One identity — same class, identifier and operator — recorded differently."""
    return SourceDescriptor(
        source_class=SourceClass.OPEN_SOURCE,
        identifier="feed-alpha",
        operator="AlphaCorp",
        reliability=reliability,
        upstream_of_record=upstream,
        handling_restrictions=restrictions,
    )


def test_merging_two_records_of_one_source_does_not_depend_on_which_came_first() -> None:
    """THE ORDER DEPENDENCE THE WALK ABOVE HAD ALREADY REMOVED FROM ITSELF.

    `resolve_sources` deduplicated on `(source_class, identifier, operator)` with
    `setdefault`, so the first record encountered won and the other's `reliability`,
    `upstream_of_record` and `handling_restrictions` were discarded — inside the function
    whose walk was made breadth-first *precisely* so its result would not depend on the order
    the store happened to yield. `reliability` is not inert on that path: it reaches
    `fusion.trust_of_source`, so which record arrived first could move a fused number.
    """
    graded = _source(reliability=SourceReliability.USUALLY_RELIABLE, upstream="osint:alpha")
    ungraded = _source(
        reliability=SourceReliability.CANNOT_BE_JUDGED, restrictions=("no redistribution",)
    )

    assert merge_source_records(graded, ungraded) == merge_source_records(ungraded, graded)


def test_a_merged_source_never_claims_more_than_either_record_did() -> None:
    """Conservative on the axis that decides, and `CANNOT_BE_JUDGED` is not a middling grade.

    Admiralty `F` maps to a **vacuous** opinion in `trust_of_source` — 0.00/0.00, which
    nullifies whatever the source claims — so it is the *least* believing value, not the worst
    one after `E`. Merging by the letter would have read `F` as "worse than E" and, on the
    other side, let `A` win over `F`; both are wrong. The order is written out by belief.
    """
    graded = _source(reliability=SourceReliability.COMPLETELY_RELIABLE)
    ungraded = _source(reliability=SourceReliability.CANNOT_BE_JUDGED)

    merged = merge_source_records(graded, ungraded)

    assert merged.reliability is SourceReliability.CANNOT_BE_JUDGED, (
        "one record says nobody judged this source and the merge asserted a grade anyway"
    )
    assert trust_of_source(merged).belief <= trust_of_source(graded).belief
    assert trust_of_source(merged).belief <= trust_of_source(ungraded).belief


def test_a_merged_source_keeps_every_handling_restriction() -> None:
    """Restrictions are unioned rather than picked between. Nothing reads them today, which
    is a separate finding — but a field that looks like a dissemination limit must not lose
    entries to a dictionary insertion order while it waits for a reader."""
    restricted = _source(restrictions=("no redistribution",))
    tlp = _source(restrictions=("TLP:RED",))

    merged = merge_source_records(restricted, tlp)

    assert merged.handling_restrictions == ("TLP:RED", "no redistribution")


def test_two_records_naming_different_origins_assert_neither() -> None:
    """A single-valued field cannot hold a disagreement, so it holds nothing.

    Asserting one of two contradictory origins is the worse error: `upstream_of_record` is
    what collapses two feeds into one independent origin, and a *wrong* one silently destroys
    corroboration that was real. `None` records that none was established, which is what
    happened.
    """
    alpha = _source(upstream="osint:alpha")
    beta = _source(upstream="osint:beta-reseller")

    assert merge_source_records(alpha, beta).upstream_of_record is None
    assert merge_source_records(alpha, _source()).upstream_of_record == "osint:alpha"


def test_the_conservatism_order_agrees_with_the_beliefs_fusion_actually_uses() -> None:
    """The anti-drift pin, and the reason the table is written out at all.

    `core.fusion` imports `core.provenance`, so the ordering cannot be derived from
    `trust_of_source` without a cycle. Written out, it can disagree — and the disagreement
    would be silent and in the worst direction: a merge that kept the *more* believing of two
    records while the table said otherwise. So the two are asserted against each other here,
    and re-grading a letter in one has to move the other or the build says so.
    """
    by_belief = sorted(
        SourceReliability,
        key=lambda grade: trust_of_source(_source(reliability=grade)).belief,
    )
    by_table = sorted(SourceReliability, key=lambda grade: RELIABILITY_CONSERVATISM[grade])

    assert by_table == by_belief, (
        f"the conservatism order says {[g.value for g in by_table]} and fusion believes "
        f"{[g.value for g in by_belief]}"
    )
