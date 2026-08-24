"""The seven simulated connectors the vertical slice runs on.

**Status: `SIMULATED`.** Each class below answers from the GLASS ANVIL fixture table and
nothing else. There is no network code in this module and none is reachable from it, which
is what makes invariant 15 a property of the build rather than a promise: CI fails on a
network import outside this package, and this package does not have one.

Every connector declares ``is_simulated``, and :class:`~nemesis.collect.base.SimulatedConnector`
refuses to construct one that does not. The flag reaches every artifact through
:class:`~nemesis.core.provenance.CollectionMethod`, where
:meth:`~nemesis.core.evidence.EvidenceObject.admissibility` reads it: synthetic material is
usable as intelligence and can never be presented as proof.

Costs are relative and only their ratios matter. They order the Pursuit Engine's queue, so
they encode operational reality rather than money: a dark-web collection means driving an
isolated collector through Tor and is the most expensive thing here, while an RDAP lookup
is nearly free. Nothing in a confidence figure reads them.

:attr:`~nemesis.ports.collection.ConnectorCapabilities.handles_hostile_content` is set on
exactly one connector. It is not a description — the base class turns it into a
requirement that a sandbox profile be declared, and that profile is recorded in the
provenance of everything the connector collects.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Final

from nemesis.collect.base import (
    CONNECTOR_VERSION,
    FixtureTable,
    SimulatedConnector,
)
from nemesis.collect.fixtures.glass_anvil import (
    SCENARIO_PRESENT,
    blockchain_fixtures,
    certificate_fixtures,
    dark_web_fixtures,
    malware_fixtures,
    network_fixtures,
    own_sensor_fixtures,
    passive_dns_fixtures,
    rdap_fixtures,
)
from nemesis.core.entities import EntityType
from nemesis.core.provenance import SourceClass, SourceDescriptor, SourceReliability
from nemesis.ports.collection import (
    ConnectorCapabilities,
    IntelligenceConnector,
    PivotType,
)

FIXTURE_OPERATOR: Final = "NEMESIS GLASS ANVIL fixture set"
"""Operator recorded on every simulated source.

Deliberately identical across all seven. They are one origin wearing seven hats, so
:meth:`~nemesis.core.provenance.SourceDescriptor.provenance_cluster` collapses them and no
pair of them can ever be fused as independent corroboration. A fixture set that presented
itself as seven independent sources would inflate every confidence figure in the demo.
"""

TOR_SANDBOX_PROFILE: Final = (
    "isolated-tor-collector-v1: dedicated VM, no route to the platform network, no host "
    "filesystem, snapshot-reverted after each collection, output treated as untrusted data"
)


def _source(
    source_class: SourceClass,
    identifier: str,
    reliability: SourceReliability,
) -> SourceDescriptor:
    return SourceDescriptor(
        source_class=source_class,
        identifier=identifier,
        reliability=reliability,
        operator=FIXTURE_OPERATOR,
    )


class SimulatedPassiveDnsConnector(SimulatedConnector):
    """Resolution history and reverse resolution, with the population counts."""

    def __init__(
        self, *, as_of: datetime = SCENARIO_PRESENT, fixtures: FixtureTable | None = None
    ) -> None:
        super().__init__(
            capabilities=ConnectorCapabilities(
                name="simulated-passive-dns",
                version=CONNECTOR_VERSION,
                source=_source(
                    SourceClass.INTERNET_SCAN,
                    "SIMULATED passive-DNS corpus",
                    SourceReliability.USUALLY_RELIABLE,
                ),
                supported_pivots=frozenset(
                    {PivotType.RESOLUTION_HISTORY, PivotType.REVERSE_RESOLUTION}
                ),
                supported_entity_types=frozenset({EntityType.DOMAIN, EntityType.IP_ADDRESS}),
                is_simulated=True,
                cost_per_call=1.0,
            ),
            fixtures=passive_dns_fixtures() if fixtures is None else fixtures,
            as_of=as_of,
        )


class SimulatedCertificateConnector(SimulatedConnector):
    """Certificate transparency: what a host presented, and where else that key appears."""

    def __init__(
        self, *, as_of: datetime = SCENARIO_PRESENT, fixtures: FixtureTable | None = None
    ) -> None:
        super().__init__(
            capabilities=ConnectorCapabilities(
                name="simulated-certificate-transparency",
                version=CONNECTOR_VERSION,
                source=_source(
                    SourceClass.INTERNET_SCAN,
                    "SIMULATED certificate-transparency corpus",
                    SourceReliability.USUALLY_RELIABLE,
                ),
                supported_pivots=frozenset(
                    {PivotType.CERTIFICATE_HISTORY, PivotType.CERTIFICATE_REUSE}
                ),
                supported_entity_types=frozenset(
                    {EntityType.DOMAIN, EntityType.IP_ADDRESS, EntityType.TLS_CERTIFICATE}
                ),
                is_simulated=True,
                cost_per_call=1.2,
            ),
            fixtures=certificate_fixtures() if fixtures is None else fixtures,
            as_of=as_of,
        )


class SimulatedRdapConnector(SimulatedConnector):
    """Registration records.

    Reliability is ``COMPLETELY_RELIABLE`` because a registry is authoritative about its
    own registrations. That grades the source, not the information: a registrar's record
    can still carry a registrant field the registrant lied about.
    """

    def __init__(
        self, *, as_of: datetime = SCENARIO_PRESENT, fixtures: FixtureTable | None = None
    ) -> None:
        super().__init__(
            capabilities=ConnectorCapabilities(
                name="simulated-rdap",
                version=CONNECTOR_VERSION,
                source=_source(
                    SourceClass.OPEN_SOURCE,
                    "SIMULATED RDAP service",
                    SourceReliability.COMPLETELY_RELIABLE,
                ),
                supported_pivots=frozenset({PivotType.REGISTRATION_RECORD}),
                supported_entity_types=frozenset({EntityType.DOMAIN}),
                is_simulated=True,
                cost_per_call=0.8,
            ),
            fixtures=rdap_fixtures() if fixtures is None else fixtures,
            as_of=as_of,
        )


class SimulatedNetworkConnector(SimulatedConnector):
    """BGP and RIR data: which network announces an address, and who holds it."""

    def __init__(
        self, *, as_of: datetime = SCENARIO_PRESENT, fixtures: FixtureTable | None = None
    ) -> None:
        super().__init__(
            capabilities=ConnectorCapabilities(
                name="simulated-network-ownership",
                version=CONNECTOR_VERSION,
                source=_source(
                    SourceClass.OPEN_SOURCE,
                    "SIMULATED BGP/RIR feed",
                    SourceReliability.USUALLY_RELIABLE,
                ),
                supported_pivots=frozenset({PivotType.NETWORK_OWNERSHIP}),
                supported_entity_types=frozenset(
                    {EntityType.IP_ADDRESS, EntityType.NETBLOCK, EntityType.ASN}
                ),
                is_simulated=True,
                cost_per_call=0.6,
            ),
            fixtures=network_fixtures() if fixtures is None else fixtures,
            as_of=as_of,
        )


class SimulatedMalwareConnector(SimulatedConnector):
    """Phishing-kit analysis. Everything it returns is quarantined, never executed."""

    def __init__(
        self, *, as_of: datetime = SCENARIO_PRESENT, fixtures: FixtureTable | None = None
    ) -> None:
        super().__init__(
            capabilities=ConnectorCapabilities(
                name="simulated-malware-analysis",
                version=CONNECTOR_VERSION,
                source=_source(
                    SourceClass.COMMERCIAL_FEED,
                    "SIMULATED malware analysis service",
                    SourceReliability.USUALLY_RELIABLE,
                ),
                supported_pivots=frozenset({PivotType.MALWARE_LOOKUP, PivotType.C2_EXTRACTION}),
                supported_entity_types=frozenset({EntityType.MALWARE, EntityType.PHISHING_KIT}),
                is_simulated=True,
                cost_per_call=2.0,
                redistribution_permitted=False,
            ),
            fixtures=malware_fixtures() if fixtures is None else fixtures,
            as_of=as_of,
        )


class SimulatedDarkWebConnector(SimulatedConnector):
    """The one connector that handles adversary-authored content.

    ``handles_hostile_content`` forces a sandbox profile: the base class will not construct
    this connector without one, because collecting hostile content without stated isolation
    is a policy violation rather than a configuration gap.

    Reliability grades **the collector**, not the personas whose text it retrieves. The
    identifier below names our own isolated Tor collector, and what it asserts is "this
    string was present in this listing at this time" — something it does reliably. Grading
    it ``CANNOT_BE_JUDGED`` conflates the channel with the author and has a consequence
    that is easy to miss and total: ``trust_of_source`` maps that grade to a *vacuous*
    trust opinion, and uncertainty-favouring discounting turns every claim from such a
    source into a vacuous one. The whole dark-web plane then contributes nothing to any
    fusion — including the full PGP fingerprint the demonstration scenario makes decisive
    (DEMO_SCENARIO.md §3 and phase 5). No plane test caught it because the resolution and
    attribution tests build their own source descriptors.

    The hostility of the *content* is carried where it belongs and is unaffected by this
    grade: ``SourceClass.DARK_WEB`` makes every one of these sources
    adversary-influenceable, each planted record carries a
    :class:`~nemesis.core.claims.DeceptionAssessment`, and the human-identity gate refuses
    structurally rather than on a reliability threshold — so an anonymous post still cannot
    become a named suspect, whatever this grade says.
    """

    def __init__(
        self,
        *,
        as_of: datetime = SCENARIO_PRESENT,
        fixtures: FixtureTable | None = None,
        sandbox_profile: str | None = TOR_SANDBOX_PROFILE,
    ) -> None:
        super().__init__(
            capabilities=ConnectorCapabilities(
                name="simulated-dark-web",
                version=CONNECTOR_VERSION,
                source=_source(
                    SourceClass.DARK_WEB,
                    "SIMULATED isolated Tor collector",
                    SourceReliability.USUALLY_RELIABLE,
                ),
                supported_pivots=frozenset(
                    {
                        PivotType.DARK_WEB_SEARCH,
                        PivotType.PERSONA_ACTIVITY,
                        PivotType.MARKETPLACE_LISTING,
                    }
                ),
                supported_entity_types=frozenset(
                    {EntityType.PERSONA, EntityType.FORUM, EntityType.MARKETPLACE}
                ),
                is_simulated=True,
                handles_hostile_content=True,
                isolation_factory="nemesis.collect.simulated:dark_web_connector",
                cost_per_call=4.0,
                redistribution_permitted=False,
            ),
            fixtures=dark_web_fixtures() if fixtures is None else fixtures,
            as_of=as_of,
            sandbox_profile=sandbox_profile,
        )


class SimulatedBlockchainConnector(SimulatedConnector):
    """Ledger reads and one heuristic clustering, with its failure mode recorded."""

    def __init__(
        self, *, as_of: datetime = SCENARIO_PRESENT, fixtures: FixtureTable | None = None
    ) -> None:
        super().__init__(
            capabilities=ConnectorCapabilities(
                name="simulated-blockchain",
                version=CONNECTOR_VERSION,
                source=_source(
                    SourceClass.BLOCKCHAIN,
                    "SIMULATED ledger and clustering service",
                    SourceReliability.COMPLETELY_RELIABLE,
                ),
                supported_pivots=frozenset(
                    {
                        PivotType.WALLET_ACTIVITY,
                        PivotType.WALLET_CLUSTERING,
                        PivotType.TRANSACTION_TRACE,
                    }
                ),
                supported_entity_types=frozenset({EntityType.CRYPTO_ADDRESS}),
                is_simulated=True,
                cost_per_call=2.5,
            ),
            fixtures=blockchain_fixtures() if fixtures is None else fixtures,
            as_of=as_of,
        )


class SimulatedOwnSensorConnector(SimulatedConnector):
    """Our own edge, reporting traffic that was sent to us.

    The only connector here whose source class sits in the plantability allowlist, and the
    reason is a real difference rather than a grading: an adversary can *cause* an observation
    at a sensor we operate and cannot *author* the record. Every other connector in this module
    reads a channel they can write into.

    ``is_simulated`` is true and says so in the identifier, exactly like its neighbours. The
    scenario is synthetic; what is not synthetic is the provenance semantics, and an evidence
    object sealed from this still carries ``AdmissibilityDefect.SIMULATED_COLLECTION`` — which
    is the label that keeps a demonstration from reading as a case.

    No egress. It answers from what arrived, which is what places the pivot on the right side
    of invariant 15.
    """

    def __init__(
        self, *, as_of: datetime = SCENARIO_PRESENT, fixtures: FixtureTable | None = None
    ) -> None:
        super().__init__(
            capabilities=ConnectorCapabilities(
                name="simulated-own-edge-telemetry",
                version=CONNECTOR_VERSION,
                source=_source(
                    SourceClass.OWN_SENSOR,
                    "SIMULATED ACME edge sensors",
                    SourceReliability.COMPLETELY_RELIABLE,
                ),
                supported_pivots=frozenset({PivotType.OWN_TELEMETRY}),
                supported_entity_types=frozenset({EntityType.DOMAIN}),
                is_simulated=True,
                cost_per_call=0.5,
            ),
            fixtures=own_sensor_fixtures() if fixtures is None else fixtures,
            as_of=as_of,
        )


def simulated_connectors(
    *, as_of: datetime = SCENARIO_PRESENT
) -> tuple[IntelligenceConnector, ...]:
    """Every GLASS ANVIL connector, answering as of one instant.

    A single ``as_of`` for the whole set on purpose: connectors that disagreed about what
    time it is would let phase-8 material into a phase-2 graph through whichever one was
    set later, and the resurgence detection would then be reading evidence that did not
    exist when it claims to have collected it.
    """
    return (
        SimulatedOwnSensorConnector(as_of=as_of),
        SimulatedPassiveDnsConnector(as_of=as_of),
        SimulatedCertificateConnector(as_of=as_of),
        SimulatedRdapConnector(as_of=as_of),
        SimulatedNetworkConnector(as_of=as_of),
        SimulatedMalwareConnector(as_of=as_of),
        SimulatedDarkWebConnector(as_of=as_of),
        SimulatedBlockchainConnector(as_of=as_of),
    )


def dark_web_connector(
    as_of: str, config: Mapping[str, str] | None = None
) -> IntelligenceConnector:
    """Factory for the confined collector, addressed by name across a process boundary.

    :class:`~nemesis.collect.isolation.IsolatedCollector` takes a ``module:function`` string
    rather than an object, because an object cannot cross a pipe and pickling one would hand
    the child a deserialization surface — the very class of bug the boundary exists to
    contain. This is the one connector that declares `handles_hostile_content`, so it is the
    one that must not run in the main process.
    """
    if config:
        raise ValueError("the simulated dark-web connector accepts no runtime configuration")
    return SimulatedDarkWebConnector(as_of=datetime.fromisoformat(as_of))
