"""Machinery shared by every simulated connector.

**Status: `SIMULATED`.** Nothing here reaches a network. A connector built on this base
answers from a fixture table and says so, in the only place that survives every downstream
transformation: :attr:`CollectionMethod.is_simulated`, set here rather than passed in, so a
subclass cannot construct itself out of the flag.

Three separations are worth stating, because a shorter implementation would lose them.

**A fixture answer is not a pivot result.** :class:`FixtureAnswer` is inert data: bytes and
a statement. :meth:`SimulatedConnector.pivot` is what seals it into evidence and mints a
claim, which means every fixture goes through the same provenance path and none can arrive
with provenance somebody hand-wrote.

**"Nothing there", "could not look" and "more than we could carry" are three answers.**
A missing fixture key is an empty success — the source was asked and held nothing. A
fixture carrying ``error`` is a failure: we did not see, and downstream must not read that
as absence. ``truncated`` is a third state: what we did see is a prefix, so absence within
it means nothing at all. The port models all three and this base never collapses them.

**Population counts travel as statement qualifiers.** A connector returns claims, not
edges, so it cannot fill in :class:`~nemesis.core.relationships.PivotSelectivity` itself.
It records the count and the corpus it was measured against under the qualifier keys below,
and the graph plane builds selectivity from them. Both keys or neither: a count with no
stated denominator is not a count, and the core model rejects one anyway.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from nemesis.core.claims import (
    Claim,
    ClaimKind,
    DeceptionAssessment,
    DerivationKind,
    Statement,
)
from nemesis.core.entities import NormalizationError, normalize_identifier
from nemesis.core.evidence import ArtifactKind, ContentSafety, EvidenceObject
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.provenance import (
    CollectionMethod,
    CustodyAction,
    CustodyEvent,
    ProvenanceChain,
    SourceDescriptor,
)
from nemesis.core.temporal import TemporalExtent
from nemesis.ports.collection import (
    ConnectorCapabilities,
    PivotRequest,
    PivotResult,
    PivotType,
)

CONNECTOR_VERSION: Final = "0.1.0"
"""Version stamped into every :class:`CollectionMethod`. An artifact collected by a
different version of the collector is a different artifact, so this moves when the
fixture set or the sealing logic changes."""

FIXTURE_SET: Final = "glass-anvil"

# --- Statement qualifier keys -------------------------------------------------
# The contract between this plane and the graph plane. Both sides import these names
# rather than repeating the literals, because a typo here silently degrades a selective
# pivot into an uncounted one — which reads as "nobody counted" and is scored as noise.

QUALIFIER_SHARED_ATTRIBUTE: Final = "shared_attribute"
"""What the pivot selected on. Its absence means no selectivity is recorded at all, so a
count supplied without it is silently ignored on the graph side."""

QUALIFIER_POPULATION_SIZE: Final = "population_size"
QUALIFIER_POPULATION_CORPUS: Final = "population_measured_against"
QUALIFIER_GLOBALLY_UNIQUE: Final = "globally_unique"
QUALIFIER_PIVOT_METHOD: Final = "pivot_method"
QUALIFIER_SHARED_INFRASTRUCTURE_JUSTIFICATION: Final = "shared_infrastructure_justification"
"""Why co-location on a registrar, an exchange or an ASN means anything here. Without one
the graph plane records the edge as carrying no weight, which is the correct default."""

QUALIFIER_HOSTILE_CONTENT: Final = "content_is_hostile"
"""Set on any statement quoting adversary-authored text. The quoted span is data: it was
written by someone who wants a reader to act on it, and a reader that acts on it has been
instructed by the adversary (invariant 5)."""

QUALIFIER_QUOTED_VERBATIM: Final = "quoted_verbatim"
QUALIFIER_HEURISTIC: Final = "heuristic"
QUALIFIER_HEURISTIC_FAILURE_MODE: Final = "known_failure_mode"


class ObservationRecord(BaseModel):
    """One thing a source said, with the bytes that prove it said it.

    The same extent serves as the evidence object's ``observed_extent`` and the claim's
    ``valid_extent``: for a directly collected record these are the same interval — when
    the artifact's content was true of the world. They diverge only once something derives
    a claim whose validity is narrower than the artifact it came from, which no connector
    does.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact: bytes
    """Preserved byte-for-byte. Its SHA-256 becomes the evidence identifier, so two
    connectors that independently retrieve this record collapse to one evidence object
    instead of looking like two corroborating sources."""

    artifact_kind: ArtifactKind
    statement: Statement
    extent: TemporalExtent

    media_type: str = "text/plain; charset=utf-8"
    content_safety: ContentSafety = ContentSafety.ROUTINE
    summary: str | None = None
    deception: DeceptionAssessment | None = None
    notes: str | None = None

    available_from: datetime | None = Field(
        default=None,
        description="Transaction-time gate: the earliest scenario date at which this "
        "record could have been collected. None means it is part of the historical record "
        "from the start. Resurgence material carries a date so a phase-2 run cannot see "
        "evidence that did not exist yet.",
    )


class FixtureAnswer(BaseModel):
    """What one connector returns for one (pivot type, entity key) question.

    ``extra="forbid"`` rather than pydantic's default, and it is a control rather than
    tidiness. ``available_from`` is a field of :class:`ObservationRecord` and not of this
    model; the reference fixture passed it here for as long as its docstring had been
    claiming a transaction-time gate, and the default ``extra="ignore"`` discarded it in
    silence. Both phase-8 own-sensor records came back ungated, so a connector answering as
    of phase 2 returned evidence dated forty-five days in its own future.

    A misplaced keyword on a fixture model is always a control that is not there. It should
    cost a traceback where it is written, not a wrong answer where it is read.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    records: tuple[ObservationRecord, ...] = ()
    truncated: bool = False
    error: str | None = None


FixtureKey = tuple[PivotType, str]
FixtureTable = Mapping[FixtureKey, FixtureAnswer]
"""Keyed by the *normalized* natural key, so a caller's casing does not decide whether a
fixture is found."""


def connector_actor_id(name: str, version: str) -> str:
    """Derive a stable actor identifier for a connector.

    Deliberately deterministic rather than freshly minted. Claims are content-addressed
    over their asserting actor, so a connector that received a new actor id on every
    construction would produce a distinct claim each time the same pivot ran — and a
    pursuit loop that revisits a pivot would manufacture apparent corroboration for itself
    out of one underlying observation.

    The cost, stated because it is a real one: the identifier is shaped like a UUIDv7 but
    carries no timestamp, so :func:`~nemesis.core.ids.timestamp_of` returns a meaningless
    number for it. Nothing reads a connector's actor id as a time.
    """
    digest = hashlib.sha256(f"connector:{name}@{version}".encode()).hexdigest()
    return f"{IdPrefix.ACTOR.value}_{digest[:32]}"


def build_observation(
    *,
    record: ObservationRecord,
    source: SourceDescriptor,
    method: CollectionMethod,
    collected_at: datetime,
    asserted_by: str,
    reason: str,
) -> tuple[EvidenceObject, Claim]:
    """Seal one record into evidence and mint the observation claim that cites it.

    The claim is an ``OBSERVATION`` derived by ``DIRECT_COLLECTION`` and nothing else. A
    connector reports what a source said; deciding what that means is the job of planes
    that have contradicting-evidence machinery and a deception model, and neither exists
    inside the collection boundary.

    ``vault_locator`` is left unset on purpose. This plane holds bytes, not storage: the
    locator is assigned when the vault seals the artifact. Claiming one here would make an
    unpreserved artifact look preserved, which is the one admissibility defect an analyst
    cannot detect by reading the object.
    """
    content_hash = hashlib.sha256(record.artifact).hexdigest()
    custody = CustodyEvent(
        action=CustodyAction.COLLECTED,
        actor=asserted_by,
        occurred_at=collected_at,
        reason=reason,
        artifact_hash_before=content_hash,
        artifact_hash_after=content_hash,
    )
    provenance = ProvenanceChain(
        # Each call is a distinct collection event and gets a distinct id. Evidence and
        # claim identity are content-addressed and therefore unaffected: re-collecting the
        # same artifact yields the same evidence object with a new collection event.
        collection_id=new_id(IdPrefix.COLLECTION),
        source=source,
        method=method,
        collected_at=collected_at,
        custody=(custody,),
    )
    evidence = EvidenceObject.seal(
        artifact=record.artifact,
        artifact_kind=record.artifact_kind,
        provenance=provenance,
        observed_extent=record.extent,
        media_type=record.media_type,
        content_safety=record.content_safety,
        summary=record.summary,
    )
    claim = Claim.create(
        kind=ClaimKind.OBSERVATION,
        statement=record.statement,
        derivation=DerivationKind.DIRECT_COLLECTION,
        asserted_by=asserted_by,
        asserted_at=collected_at,
        valid_extent=record.extent,
        supported_by_evidence=(evidence.evidence_id,),
        deception=record.deception,
        notes=record.notes,
    )
    return evidence, claim


class SimulatedConnector:
    """A fixture-backed :class:`~nemesis.ports.collection.IntelligenceConnector`.

    Subclasses supply capabilities and a fixture table; everything else — normalization,
    the three failure modes, sealing, the simulation flag — happens here, once.
    """

    def __init__(
        self,
        *,
        capabilities: ConnectorCapabilities,
        fixtures: FixtureTable,
        as_of: datetime,
        sandbox_profile: str | None = None,
        fixture_set: str = FIXTURE_SET,
    ) -> None:
        if not capabilities.is_simulated:
            raise ValueError(
                f"{capabilities.name} is built on SimulatedConnector and must declare "
                "is_simulated: synthetic data that does not announce itself corrupts every "
                "confidence figure downstream of it"
            )
        if capabilities.handles_hostile_content and sandbox_profile is None:
            raise ValueError(
                f"{capabilities.name} retrieves adversary-controlled content and must "
                "declare a sandbox profile; collecting hostile content without stated "
                "isolation is a policy violation, not a configuration gap"
            )
        if as_of.tzinfo is None:
            raise ValueError("as_of must be timezone-aware")

        self._capabilities = capabilities
        self._fixtures = fixtures
        self._as_of = as_of
        self._sandbox_profile = sandbox_profile
        # Recorded in every CollectionMethod. A second operation's fixtures answering under
        # the first operation's name would make two synthetic worlds indistinguishable in
        # provenance, which is the one field a reader uses to tell them apart.
        self._fixture_set = fixture_set
        self._actor = connector_actor_id(capabilities.name, capabilities.version)

    @property
    def capabilities(self) -> ConnectorCapabilities:
        return self._capabilities

    @property
    def as_of(self) -> datetime:
        """The scenario instant this connector answers as of.

        Collection is stamped with this rather than the wall clock, so a demo run in 2027
        does not produce evidence claiming to have been collected in 2027 about events in
        2026 — and so material that only exists after a later phase stays invisible until
        a caller explicitly asks from that date.
        """
        return self._as_of

    @property
    def actor_id(self) -> str:
        return self._actor

    def _method(self, request: PivotRequest) -> CollectionMethod:
        return CollectionMethod(
            collector_name=self._capabilities.name,
            collector_version=self._capabilities.version,
            parameters={
                "pivot_type": request.pivot_type.value,
                "entity_type": request.entity_type.value,
                "entity_key": request.entity_key,
                "max_results": str(request.max_results),
                "as_of": self._as_of.isoformat(),
                "fixture_set": self._fixture_set,
            },
            # Set here, never taken from a parameter: there is no code path by which a
            # subclass or a caller can produce an unflagged synthetic artifact.
            is_simulated=True,
            sandbox_profile=self._sandbox_profile,
        )

    def _failed(self, request: PivotRequest, error: str) -> PivotResult:
        return PivotResult(
            request=request,
            connector_name=self._capabilities.name,
            observations=(),
            evidence=(),
            error=error,
        )

    async def pivot(self, request: PivotRequest) -> PivotResult:
        """Answer one question. Never raises for a failure the caller should record."""
        if not self._capabilities.can_answer(request):
            return self._failed(
                request,
                f"{self._capabilities.name} does not answer {request.pivot_type.value} "
                f"for {request.entity_type.value}",
            )

        try:
            key = normalize_identifier(request.entity_type, request.entity_key)
        except NormalizationError as exc:
            return self._failed(request, f"unusable entity key: {exc}")

        answer = self._fixtures.get((request.pivot_type, key))
        if answer is None:
            # The source was asked and held nothing. Distinct from a failure: this one IS
            # evidence of absence, within the limits of what the source covers.
            return PivotResult(
                request=request,
                connector_name=self._capabilities.name,
                observations=(),
                evidence=(),
            )
        if answer.error is not None:
            return self._failed(request, answer.error)

        visible = tuple(
            record
            for record in answer.records
            if record.available_from is None or record.available_from <= self._as_of
        )
        truncated = answer.truncated or len(visible) > request.max_results
        visible = visible[: request.max_results]

        method = self._method(request)
        observations: list[Claim] = []
        evidence: list[EvidenceObject] = []
        # The bytes travel with the result because this plane cannot write to the vault.
        # Omitting them would leave every sealed object describing an artifact nobody
        # preserved — inadmissible, and invisible to an analyst reading the object.
        artifacts: dict[str, bytes] = {}
        try:
            for record in visible:
                sealed, claim = build_observation(
                    record=record,
                    source=self._capabilities.source,
                    method=method,
                    collected_at=self._as_of,
                    asserted_by=self._actor,
                    reason=request.reason,
                )
                evidence.append(sealed)
                artifacts[sealed.evidence_id] = record.artifact
                observations.append(claim)
        except Exception as exc:
            # A malformed fixture is a defect in this plane, but it must not propagate as
            # an exception into the pursuit loop: one bad record would abort an entire
            # investigation instead of costing it one pivot. Recorded as a failure, which
            # is what it is from the caller's side — we could not look.
            return self._failed(
                request, f"{type(exc).__name__} while sealing fixture records: {exc}"
            )

        return PivotResult(
            request=request,
            connector_name=self._capabilities.name,
            observations=tuple(observations),
            evidence=tuple(evidence),
            artifacts=artifacts,
            truncated=truncated,
        )

    async def health(self) -> bool:
        """Always usable: the fixture table is in memory and cannot be unreachable."""
        return True
