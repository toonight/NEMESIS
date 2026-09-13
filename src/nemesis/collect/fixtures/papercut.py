"""Operation PAPER SWARM — the Aug/Sep 2026 agentic PaperCut NG/MF campaign, as fixtures.

**Status: `SIMULATED` collection of real public OSINT.** Every observation below is transcribed
from a public first-party report on the CVE-2026-81578 / CVE-2026-82078 campaign and sealed as a
*third-party report of what a source said* — never as a confirmed fact about the world. The
identifiers (CVEs, the orchestration IP, the payload host, the RAT names) are real public IOCs;
nothing here is contacted, resolved, or probed. The collection is simulated because the pilot —
not a NEMESIS connector — did the reading; invariant 15 holds because there is no egress.

This is the executable seed for :mod:`nemesis.slice.papercut`. Where the two disagree, the slice's
sealed run wins, because it is the thing that actually produced the vault.

The counter-verified reading behind these numbers (confirmed / unverifiable / not-in-source ratio,
and why "Russian-speaking" and "fully autonomous" do not survive) lives in
``docs/evaluation/papercut-2026-09/REPORT.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from nemesis.collect.base import CONNECTOR_VERSION
from nemesis.core.claims import DeceptionAssessment, Statement
from nemesis.core.evidence import ArtifactKind
from nemesis.core.provenance import (
    CollectionMethod,
    SourceClass,
    SourceDescriptor,
    SourceReliability,
)
from nemesis.core.temporal import TemporalExtent

# Plane-neutral dimension keys. The collection plane may not import the attribution plane, so
# an observation is tagged with a string; the slice maps it to an AttributionDimension.
DIM_INFRASTRUCTURE = "infrastructure"
DIM_CAMPAIGN = "campaign"
DIM_ORGANIZATION = "organization"
DIM_PERSONA = "persona"
DIM_HUMAN_IDENTITY = "human_identity"

FIXTURE_SET = "paper-swarm-2026-09"

# The campaign window: PaperCut's urgent advisory (27 Aug) through the maintenance releases and
# the bulk of GreyNoise's observed activity (early-mid Sep 2026).
WINDOW = TemporalExtent.between(
    datetime(2026, 8, 26, tzinfo=UTC), datetime(2026, 9, 11, tzinfo=UTC)
)
COLLECTED_AT = datetime(2026, 9, 12, 12, 0, tzinfo=UTC)

# Real public identifiers (documentation-safe: no egress touches any of them).
CVE_AUTH_BYPASS = "CVE-2026-81578"
CVE_UNSAFE_REFLECTION = "CVE-2026-82078"
ORCHESTRATION_IP = "45.142.193.132"
SECONDARY_IP = "45.158.196.75"
PAYLOAD_HOST = "sendit.sh"

COLLECTION_METHOD = CollectionMethod(
    collector_name="pilot-osint-transcription",
    collector_version=CONNECTOR_VERSION,
    parameters={"fixture_set": FIXTURE_SET, "mode": "public-report-transcription"},
    is_simulated=True,
)

# A name-free operator *profile* brief handed to the profile author (the local pilot in the
# live path, a deterministic fixture otherwise). It carries NO natural-person identifier by
# construction — the author is asked to characterise, never to name.
PROFILE_BRIEF = (
    "Characterise the operator behind Operation PAPER SWARM as a NAME-FREE profile only. "
    "Do not name, guess, or invent any natural person. Facts available: one coordinated "
    "orchestration stack (an OpenAI Codex harness driving a DeepSeek model, with AionUi "
    "orchestration, Hindsight persistent memory, and Netlas.io target sourcing); ~440 "
    "compromised PaperCut instances across ~395 organisations in 48 countries; a recovered "
    "working directory showing human-in-the-loop markers ('requested by user', 'interrupted "
    "by user'); a 28-country CIS-heavy do-not-hit list the agents partially ignored; "
    "commodity post-exploitation tooling (SimpleHelp, AnyDesk, Meterpreter). The nationality "
    "read ('likely Russian-speaking') rests solely on the copyable do-not-hit list and is "
    "high false-flag risk. Objective is unclear (access brokering vs data theft vs ransomware)."
)

# The default, offline, deterministic profile a pilot would author from the brief. It names no
# natural person; it is a characterisation held as a hypothesis. The live path replaces this with
# the local Ollama pilot's own text (see tests/planes/test_papercut_live_pilot.py).
DEFAULT_OPERATOR_PROFILE = (
    "Hypothesis (name-free): a single operator or small team running an AI-orchestrated "
    "access-development operation human-in-the-loop, not a fully autonomous system. Tradecraft "
    "is commodity and the 'Russian-speaking' read is a copyable do-not-hit-list artifact, so "
    "nationality is held at low confidence and treated as plantable. No natural person is "
    "identified; the objective (access brokering, data theft, or ransomware) is undetermined."
)


@dataclass(frozen=True)
class PaperSwarmObservation:
    """One public-report observation, ready to seal and to offer to one attribution dimension."""

    key: str
    source: SourceDescriptor
    artifact: bytes
    artifact_kind: ArtifactKind
    statement: Statement
    dimension: str
    """Plane-neutral dimension key (see ``DIM_*``); the slice maps it to an AttributionDimension."""
    belief: float
    label: str
    reason: str
    deception: DeceptionAssessment | None = None
    is_profile_support: bool = False


def _src(
    identifier: str, cls: SourceClass, reliability: SourceReliability, operator: str
) -> SourceDescriptor:
    return SourceDescriptor(
        source_class=cls, identifier=identifier, reliability=reliability, operator=operator
    )


# First-party sources, kept in distinct provenance clusters so two reports of one fact do not
# masquerade as independent corroboration when they trace to the same upstream.
_GREYNOISE = _src(
    "greynoise-agents-gone-wild",
    SourceClass.COMMERCIAL_FEED,
    SourceReliability.USUALLY_RELIABLE,
    "GreyNoise",
)
_BLACKPOINT = _src(
    "blackpoint-thousand-papercuts",
    SourceClass.COMMERCIAL_FEED,
    SourceReliability.USUALLY_RELIABLE,
    "BlackpointCyber",
)
_HUNTRESS = _src(
    "huntress-papercut-actively-exploited",
    SourceClass.COMMERCIAL_FEED,
    SourceReliability.USUALLY_RELIABLE,
    "Huntress",
)
_ARCTIC_WOLF = _src(
    "arctic-wolf-papercut-credential-theft",
    SourceClass.COMMERCIAL_FEED,
    SourceReliability.USUALLY_RELIABLE,
    "ArcticWolf",
)
_VENDOR = _src(
    "papercut-security-bulletin-27aug2026",
    SourceClass.OPEN_SOURCE,
    SourceReliability.USUALLY_RELIABLE,
    "PaperCutSoftware",
)

# The plantable nationality tell: an adversary of any nationality can paste a CIS-heavy
# do-not-hit list. Trivial to stage, so the engine inverts it out of ORGANIZATION support.
_CIS_FALSE_FLAG = DeceptionAssessment(
    adversary_could_plant=True,
    planting_cost="trivial",
    benefits_from_belief=("an actor of any nationality seeking a Russian false flag",),
    contra_indicators=(),
)
# Commodity tooling carries no discriminating attribution value and is maximally plantable.
_COMMODITY = DeceptionAssessment(
    adversary_could_plant=True,
    planting_cost="low",
    benefits_from_belief=("anyone blending in with common intrusion tooling",),
    contra_indicators=(),
)


def paper_swarm_observations() -> tuple[PaperSwarmObservation, ...]:
    """The verified public-OSINT observations that seed Operation PAPER SWARM."""
    return (
        PaperSwarmObservation(
            key="orchestration-ip",
            source=_GREYNOISE,
            artifact=(
                f"GreyNoise: {ORCHESTRATION_IP} (and {SECONDARY_IP}) drove the agentic PaperCut "
                f"campaign, tracked since early July probing Palo Alto/Citrix/SonicWall before "
                f"pivoting to PaperCut on 2026-08-31. Rented/abuse-prone range."
            ).encode(),
            artifact_kind=ArtifactKind.DOCUMENT,
            statement=Statement(
                subject=f"ip:{ORCHESTRATION_IP}",
                predicate="orchestrated",
                obj="operation:paper-swarm",
                natural_language=(
                    f"GreyNoise reports {ORCHESTRATION_IP} as the orchestration node for the "
                    "agentic PaperCut campaign."
                ),
            ),
            dimension=DIM_INFRASTRUCTURE,
            belief=0.6,
            label="GreyNoise orchestration IP",
            reason="public-report transcription: GreyNoise 'Agents Gone Wild'",
        ),
        PaperSwarmObservation(
            key="campaign-scope",
            source=_GREYNOISE,
            artifact=(
                b"GreyNoise: at least 440 PaperCut instances across 395 identified organisations "
                b"in 48 countries, one orchestration stack (Codex harness + DeepSeek model + "
                b"AionUi + Hindsight + Netlas.io). Education most affected (204)."
            ),
            artifact_kind=ArtifactKind.DOCUMENT,
            statement=Statement(
                subject="operation:paper-swarm",
                predicate="is_one_coordinated_campaign",
                obj="440 instances / 395 orgs / 48 countries",
                natural_language=(
                    "One orchestration stack, one target list and one tempo across 440 "
                    "compromised instances — GreyNoise assesses a single coordinated campaign."
                ),
            ),
            dimension=DIM_CAMPAIGN,
            belief=0.72,
            label="GreyNoise campaign scope",
            reason="public-report transcription: GreyNoise campaign scope",
        ),
        PaperSwarmObservation(
            key="operator-directory",
            source=_BLACKPOINT,
            artifact=(
                b"Blackpoint 'Death by a Thousand PaperCuts': recovered the operator's exposed "
                b"working directory; human-in-the-loop markers ('requested by user', "
                b"'interrupted by user'); 'not evidence of fully autonomous exploitation'; "
                b"'we cannot confirm the exact end goal'."
            ),
            artifact_kind=ArtifactKind.DOCUMENT,
            statement=Statement(
                subject="operation:paper-swarm",
                predicate="run_by_single_operator_footprint",
                obj="recovered working directory",
                natural_language=(
                    "Blackpoint recovered one operator working directory with human-in-the-loop "
                    "markers, corroborating a single coordinated operation run by one operator "
                    "footprint — not full autonomy."
                ),
            ),
            dimension=DIM_CAMPAIGN,
            belief=0.66,
            label="Blackpoint recovered operator directory",
            reason="public-report transcription: Blackpoint recovered directory",
        ),
        PaperSwarmObservation(
            key="persona-footprint",
            source=_BLACKPOINT,
            artifact=(
                b"Blackpoint: the recovered directory is one operator footprint; no marketplace "
                b"or forum persona is resolved to it, and no natural person is named."
            ),
            artifact_kind=ArtifactKind.DOCUMENT,
            statement=Statement(
                subject="persona:paper-swarm-operator",
                predicate="resolves_to_one_footprint",
                obj="recovered directory",
                natural_language=(
                    "The recovered working directory is a single operator footprint; it is not "
                    "resolved to any named persona."
                ),
            ),
            dimension=DIM_PERSONA,
            belief=0.55,
            label="single operator footprint",
            reason="public-report transcription: Blackpoint operator footprint",
        ),
        PaperSwarmObservation(
            key="nationality-tell",
            source=_GREYNOISE,
            artifact=(
                b"GreyNoise: 'likely Russian-speaking', sole stated basis a 28-country CIS-heavy "
                b"do-not-hit list the agents partially ignored. No Cyrillic/timezone/prompt-"
                b"language artifact published."
            ),
            artifact_kind=ArtifactKind.DOCUMENT,
            statement=Statement(
                subject="operation:paper-swarm",
                predicate="attributed_to_organization",
                obj="a Russian-speaking crew",
                natural_language=(
                    "A CIS-heavy do-not-hit list is read as a Russian-speaking tell — the most "
                    "copyable false-flag convention there is."
                ),
            ),
            dimension=DIM_ORGANIZATION,
            belief=0.5,
            label="CIS do-not-hit-list nationality read",
            reason="public-report transcription: GreyNoise 'likely Russian-speaking'",
            deception=_CIS_FALSE_FLAG,
        ),
        PaperSwarmObservation(
            key="commodity-tooling",
            source=_ARCTIC_WOLF,
            artifact=(
                b"Arctic Wolf / PaperCut: post-exploitation used SimpleHelp + AnyDesk RATs, "
                b"Meterpreter Java payloads, lsa_collect.exe (BootKey->SAM), attempted "
                b"'Administrator17' account. All commodity."
            ),
            artifact_kind=ArtifactKind.DOCUMENT,
            statement=Statement(
                subject="operation:paper-swarm",
                predicate="attributed_to_organization",
                obj="operators of SimpleHelp/AnyDesk/Meterpreter",
                natural_language=(
                    "Commodity RATs and offensive tooling — used by nearly every intrusion set, "
                    "criminal and state alike."
                ),
            ),
            dimension=DIM_ORGANIZATION,
            belief=0.45,
            label="commodity tooling",
            reason="public-report transcription: Arctic Wolf tooling",
            deception=_COMMODITY,
        ),
        # --- human-identity profile supports (name-free) --------------------------------
        PaperSwarmObservation(
            key="profile-greynoise",
            source=_GREYNOISE,
            artifact=(
                b"GreyNoise: hundreds of AI agents (Codex harness + DeepSeek model), empty "
                b"workspace to first RCE in <4h, human-directed campaign; objective unclear."
            ),
            artifact_kind=ArtifactKind.DOCUMENT,
            statement=Statement(
                subject="operation:paper-swarm",
                predicate="operator_profile",
                obj="AI-orchestrated access-development operation",
                natural_language=(
                    "An AI-orchestrated access-development operation moving at machine speed, "
                    "directed by an operator — a profile, not a person."
                ),
            ),
            dimension=DIM_HUMAN_IDENTITY,
            belief=0.6,
            label="GreyNoise operator profile",
            reason="public-report transcription: GreyNoise operator profile",
            is_profile_support=True,
        ),
        PaperSwarmObservation(
            key="profile-blackpoint",
            source=_BLACKPOINT,
            artifact=(
                "Blackpoint: human-in-the-loop markers in the recovered directory — the operator "
                "steered the agents; not a fully autonomous system."
            ).encode(),
            artifact_kind=ArtifactKind.DOCUMENT,
            statement=Statement(
                subject="operation:paper-swarm",
                predicate="operating_mode",
                obj="human-in-the-loop",
                natural_language=(
                    "Human-in-the-loop operation: an operator directed the AI tooling rather "
                    "than a fully autonomous system running alone."
                ),
            ),
            dimension=DIM_HUMAN_IDENTITY,
            belief=0.6,
            label="Blackpoint human-in-the-loop markers",
            reason="public-report transcription: Blackpoint HITL markers",
            is_profile_support=True,
        ),
        PaperSwarmObservation(
            key="profile-huntress",
            source=_HUNTRESS,
            artifact=(
                b"Huntress: limited, brief hands-on activity in observed incidents (whoami & ver), "
                b"consistent with a single directing operator rather than a large crew."
            ),
            artifact_kind=ArtifactKind.DOCUMENT,
            statement=Statement(
                subject="operation:paper-swarm",
                predicate="operator_profile",
                obj="small directing footprint",
                natural_language=(
                    "Brief, deliberate hands-on activity is consistent with a small directing "
                    "operator footprint."
                ),
            ),
            dimension=DIM_HUMAN_IDENTITY,
            belief=0.55,
            label="Huntress hands-on footprint",
            reason="public-report transcription: Huntress observed activity",
            is_profile_support=True,
        ),
    )


def default_profile_author(brief: str) -> str:
    """Offline, deterministic stand-in for the local pilot's profile authorship.

    Takes the same name-free brief the live Ollama pilot receives and returns a fixed,
    name-free profile so the reference run is reproducible without a model. The live path
    (opt-in test) substitutes the pilot's own text through this same one-argument contract.
    """
    return DEFAULT_OPERATOR_PROFILE
