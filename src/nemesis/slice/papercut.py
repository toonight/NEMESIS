"""Operation PAPER SWARM — a sealed, verifiable run over the agentic PaperCut campaign.

The founder's ask: use NEMESIS, with an external pilot, to investigate and trace the Aug/Sep
2026 PaperCut NG/MF campaign (CVE-2026-81578 + CVE-2026-82078), and produce a sealed,
`nemesis verify`-able package — as the public-IOC POC did, but offline.

**What this run is.** The pilot (Claude, then the local Ollama pilot for one specific step) did
the OSINT reading; NEMESIS contacts nothing. The verified public observations
(:mod:`nemesis.collect.fixtures.papercut`) are sealed into a hash-chained vault, cited by
claims, recorded in a hash-chained audit trail with a published anchor, and run through the
five-dimension attribution engine. Nothing external is touched — invariant 15 holds because
there is no egress path, not because anyone promised restraint.

**The human-identity step is the point of ADR-0015.** The dimension is offered as a *name-free
operator profile* (``is_profile=True``), authored by the local pilot (a fixture author offline).
It is emitted as a deception-discounted ``HYPOTHESIS`` that names no natural person and can never
reach an external product — a lead in the Intelligence Graph, not an accusation.

Run it:

```bash
uv run nemesis papercut
uv run nemesis verify --workspace <the workspace it prints>
```
"""

from __future__ import annotations

import asyncio
import tempfile
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final

from nemesis.attribute.dimensions import AttributionDimension
from nemesis.attribute.engine import (
    AttributionEngine,
    AttributionEvidence,
    AttributionRequest,
    AttributionResult,
    DimensionInput,
)
from nemesis.audit.trail import ActorKind, AppendOnlyAuditTrail, make_event
from nemesis.authz.anchor import FileAnchorStore, LocalAnchorSigner
from nemesis.authz.audit_anchor import (
    ANCHOR_FILE,
    ANCHOR_PUBLIC_KEY_FILE,
    anchor_audit_trail,
    retain_epoch,
)
from nemesis.authz.keys import CapabilitySigningKey
from nemesis.collect.base import (
    CONNECTOR_VERSION,
    ObservationRecord,
    build_observation,
    connector_actor_id,
)
from nemesis.collect.fixtures.papercut import (
    COLLECTION_METHOD,
    ORCHESTRATION_IP,
    PAYLOAD_HOST,
    PROFILE_BRIEF,
    WINDOW,
    PaperSwarmObservation,
    default_profile_author,
    paper_swarm_observations,
)
from nemesis.core.authorization import LegalBasis, OperationClass
from nemesis.core.confidence import Opinion
from nemesis.core.entities import EntityType
from nemesis.core.ids import IdPrefix, new_id
from nemesis.disrupt.options import (
    AdversaryRecovery,
    DisruptionTarget,
    ImpactLevel,
    OwnershipEvidence,
    ProviderDisposition,
    RecoveryDifficulty,
)
from nemesis.disrupt.planner import DisruptionLever, DisruptionPlan, DisruptionPlanner
from nemesis.evidence.vault import FileSystemEvidenceVault

# A profile author takes the name-free brief and returns a name-free profile string. The
# default is deterministic and offline; the live path passes an Ollama-backed author.
ProfileAuthor = Callable[[str], str]

SUBJECT: Final = "Operation PAPER SWARM (agentic PaperCut NG/MF exploitation, Aug-Sep 2026)"

_DIMENSION_HYPOTHESIS: Final[dict[AttributionDimension, str]] = {
    AttributionDimension.INFRASTRUCTURE: (
        f"The orchestration nodes ({ORCHESTRATION_IP} and one peer) were under common control "
        "and drove the campaign."
    ),
    AttributionDimension.CAMPAIGN: (
        "The ~440-instance activity is one coordinated campaign from a single orchestration "
        "stack (Codex harness + DeepSeek model + AionUi + Hindsight + Netlas)."
    ),
    AttributionDimension.ORGANIZATION: (
        "An organized Russian-speaking crew stands behind the operation."
    ),
    AttributionDimension.PERSONA: (
        "The recovered operator working directory resolves to one operator footprint."
    ),
}

# What the run cannot reach, stated on every result rather than left for a reader to infer.
ACTOR_GAP: Final = (
    "This run ends at a name-free operator PROFILE hypothesis. No natural person is identified, "
    "and none is nameable from the public sources: attribution rests entirely on soft, forgeable "
    "indicators (a copyable CIS do-not-hit list, commodity tooling, rented infrastructure). "
    "Naming an individual is REQUIRES_EXTERNAL_DATA and would require unplantable, corroborated "
    "evidence — the SCORED gate (ADR-0015), which this run does not clear."
)


@dataclass(frozen=True)
class PaperSwarmResult:
    """What one PAPER SWARM run produced."""

    workspace: Path
    attribution: AttributionResult
    disruption: DisruptionPlan
    profile_hypothesis: str
    sealed_objects: int
    audit_events: int
    audit_chain_intact: bool
    vault_chain_intact: bool
    anchored_epoch: int
    any_external_contact: bool
    actor_gap: str = ACTOR_GAP

    def dimension(self, dimension: AttributionDimension) -> object:
        return self.attribution.for_dimension(dimension)


def _levers() -> tuple[DisruptionLever, ...]:
    """A small, honest lever set: what NEMESIS may draft, and what it may only propose.

    Ownership is deliberately thin (single-sourced, rented range), so the executable options
    are drafts and the infrastructure options that would need legal authority are declared
    with no adapter behind them.
    """
    ip_target = DisruptionTarget(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type=EntityType.IP_ADDRESS,
        natural_key=ORCHESTRATION_IP,
        display=f"orchestration node {ORCHESTRATION_IP}",
    )
    payload_target = DisruptionTarget(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type=EntityType.DOMAIN,
        natural_key=PAYLOAD_HOST,
        display=f"payload host {PAYLOAD_HOST}",
    )
    thin_ownership = OwnershipEvidence(
        opinion=Opinion(belief=0.5, disbelief=0.0, uncertainty=0.5),
        independent_source_count=1,
        basis=(
            "Single OSINT origin (GreyNoise) ties the IP to the campaign; the range is rented "
            "and abuse-prone, so control is observed use, not established ownership."
        ),
    )
    payload_ownership = OwnershipEvidence(
        opinion=Opinion(belief=0.6, disbelief=0.0, uncertainty=0.4),
        independent_source_count=1,
        basis="The payload URL was actor-staged; hosting is a third-party file-sharing service.",
    )
    return (
        DisruptionLever(
            key="notify-orchestration-host",
            operation=OperationClass.PROVIDER_NOTIFICATION,
            title=f"Draft an abuse notification to the host of {ORCHESTRATION_IP}",
            description=(
                "Factual abuse report to the hosting provider of the orchestration node. "
                "Drafted, never sent."
            ),
            targets=(ip_target,),
            unconstrained_impact=ImpactLevel.LOW,
            impact_note=(
                "Rented, reassignable node in an abuse-prone range; disruption is temporary."
            ),
            provider_disposition=ProviderDisposition.UNRESPONSIVE,
            provider_name="(abuse-prone hosting range)",
            recovery=AdversaryRecovery(
                path="Rent a fresh VPS in the same or another abuse-prone range.",
                difficulty=RecoveryDifficulty.TRIVIAL,
                estimated_time="under an hour",
            ),
            ownership=thin_ownership,
            legal_basis=LegalBasis.PROVIDER_TERMS_OF_SERVICE,
            jurisdictions=("XX",),
        ),
        DisruptionLever(
            key="takedown-payload-host",
            operation=OperationClass.TAKEDOWN_REQUEST_DRAFT,
            title=f"Draft a takedown request for the {PAYLOAD_HOST} payload staging URL",
            description=(
                "Takedown request with its evidence bundle for the payload URL. Drafted, not sent."
            ),
            targets=(payload_target,),
            unconstrained_impact=ImpactLevel.MODERATE,
            impact_note="Removes one staging URL; the operator can re-stage elsewhere.",
            provider_disposition=ProviderDisposition.SLOW,
            provider_name=PAYLOAD_HOST,
            recovery=AdversaryRecovery(
                path="Re-upload the loader to another file-sharing host.",
                difficulty=RecoveryDifficulty.EASY,
                estimated_time="minutes",
            ),
            ownership=payload_ownership,
            legal_basis=LegalBasis.PROVIDER_TERMS_OF_SERVICE,
            jurisdictions=("XX",),
        ),
        DisruptionLever(
            key="terminate-orchestration-host",
            operation=OperationClass.HOSTING_TERMINATION,
            title=f"Terminate hosting of {ORCHESTRATION_IP}",
            description=(
                "Declared operation class with no adapter: NEMESIS can propose it and cannot "
                "execute it. REQUIRES_LEGAL_AUTHORITY."
            ),
            targets=(ip_target,),
            unconstrained_impact=ImpactLevel.MODERATE,
            impact_note="Would need a cooperating host and legal authority NEMESIS does not hold.",
            provider_disposition=ProviderDisposition.BULLETPROOF,
            recovery=AdversaryRecovery(
                path="Move orchestration to another bulletproof provider.",
                difficulty=RecoveryDifficulty.EASY,
                estimated_time="hours",
            ),
            ownership=thin_ownership,
            legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
            jurisdictions=("XX",),
        ),
    )


async def run_paper_swarm_async(
    *,
    workspace: Path | None = None,
    profile_author: ProfileAuthor = default_profile_author,
    as_of: datetime | None = None,
) -> PaperSwarmResult:
    """Seal the verified OSINT, attribute across five dimensions, and plan disruption.

    ``profile_author`` authors the name-free human-identity profile. It defaults to the
    offline deterministic fixture; the opt-in live test passes a local-Ollama-backed author.
    """
    root = (
        Path(workspace)
        if workspace is not None
        else Path(tempfile.mkdtemp(prefix="nemesis-paperswarm-"))
    )
    vault = FileSystemEvidenceVault(root / "vault")
    audit = AppendOnlyAuditTrail(root / "audit.jsonl")
    assessed_at = as_of if as_of is not None else COLLECTION_METHOD_MOMENT
    operator = new_id(IdPrefix.ACTOR)

    per_dimension: dict[AttributionDimension, list[AttributionEvidence]] = defaultdict(list)
    profile_supports: list[AttributionEvidence] = []
    sealed = 0

    for obs in paper_swarm_observations():
        record = ObservationRecord(
            artifact=obs.artifact,
            artifact_kind=obs.artifact_kind,
            statement=obs.statement,
            extent=WINDOW,
            summary=obs.label,
            deception=obs.deception,
        )
        connector = connector_actor_id(obs.source.identifier, CONNECTOR_VERSION)
        evidence, claim = build_observation(
            record=record,
            source=obs.source,
            method=COLLECTION_METHOD,
            collected_at=assessed_at,
            asserted_by=connector,
            reason=obs.reason,
        )
        await vault.seal(evidence, obs.artifact)
        sealed += 1
        await audit.record(
            make_event(
                actor=operator,
                actor_kind=ActorKind.HUMAN,
                action="collect.observation",
                subject=obs.statement.subject,
                outcome=f"sealed evidence {evidence.evidence_id}",
                inputs={
                    "source": obs.source.identifier,
                    "dimension": obs.dimension,
                    "simulated": "true",
                },
            )
        )
        opinion = Opinion(belief=obs.belief, disbelief=0.0, uncertainty=1.0 - obs.belief)
        attribution_evidence = AttributionEvidence(
            claim=claim, source=obs.source, opinion=opinion, label=obs.label
        )
        per_dimension[AttributionDimension(obs.dimension)].append(attribution_evidence)
        if obs.is_profile_support:
            profile_supports.append(attribution_evidence)

    profile_hypothesis = profile_author(PROFILE_BRIEF)

    dimensions = [
        DimensionInput(
            dimension=dimension,
            hypothesis=_DIMENSION_HYPOTHESIS[dimension],
            evidence=tuple(per_dimension[dimension]),
        )
        for dimension in (
            AttributionDimension.INFRASTRUCTURE,
            AttributionDimension.CAMPAIGN,
            AttributionDimension.ORGANIZATION,
            AttributionDimension.PERSONA,
        )
    ]
    dimensions.append(
        DimensionInput(
            dimension=AttributionDimension.HUMAN_IDENTITY,
            hypothesis=profile_hypothesis,
            is_profile=True,
            evidence=tuple(profile_supports),
        )
    )

    result = AttributionEngine(assessed_by=operator).assess(
        AttributionRequest(subject=SUBJECT, dimensions=tuple(dimensions)),
        assessed_at=assessed_at,
    )
    await audit.record(
        make_event(
            actor=operator,
            actor_kind=ActorKind.HUMAN,
            action="attribute.assess",
            subject=SUBJECT,
            outcome=(
                "five dimensions assessed; human identity emitted as a name-free HYPOTHESIS; "
                f"names_a_person={result.names_a_person}"
            ),
            inputs={"names_a_person": str(result.names_a_person)},
        )
    )

    disruption = DisruptionPlanner().plan(_levers(), now=assessed_at)

    signer = LocalAnchorSigner(CapabilitySigningKey.generate())
    # The public half is written so `nemesis verify` in another process can check the anchor;
    # the private half is ephemeral, so this run cannot re-anchor a trail edited afterwards.
    (root / ANCHOR_PUBLIC_KEY_FILE).write_bytes(signer.verifying_key.public_pem())
    published = await anchor_audit_trail(
        audit, store=FileAnchorStore(root / ANCHOR_FILE), signer=signer
    )
    # Retain the published epoch so a later verify has a baseline to refuse a rollback against.
    retain_epoch(root, published.epoch)

    vault_report = await vault.verify_integrity()
    chain = await audit.verify()

    return PaperSwarmResult(
        workspace=root,
        attribution=result,
        disruption=disruption,
        profile_hypothesis=profile_hypothesis,
        sealed_objects=sealed,
        audit_events=await audit.entry_count(),
        audit_chain_intact=chain.intact,
        vault_chain_intact=vault_report.is_intact,
        anchored_epoch=published.epoch,
        # Structural: every connector here reads a fixture; nothing has a network path.
        any_external_contact=False,
    )


# Fixed moment for a reproducible run (no wall clock in the sealed content).
COLLECTION_METHOD_MOMENT: Final = datetime.fromisoformat("2026-09-12T12:00:00+00:00")


def run_paper_swarm(
    *,
    workspace: Path | None = None,
    profile_author: ProfileAuthor = default_profile_author,
    as_of: datetime | None = None,
) -> PaperSwarmResult:
    """Synchronous entry point for the CLI and tests."""
    return asyncio.run(
        run_paper_swarm_async(workspace=workspace, profile_author=profile_author, as_of=as_of)
    )


__all__ = [
    "SUBJECT",
    "PaperSwarmObservation",
    "PaperSwarmResult",
    "ProfileAuthor",
    "run_paper_swarm",
    "run_paper_swarm_async",
]
