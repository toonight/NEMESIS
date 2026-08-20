"""What to look at next, and when to stop looking.

The MVP policy is **rule-based and deterministic**, not model-driven. That is a choice, and
it is worth stating why, because "use an LLM to decide the next pivot" is the obvious move.

Invariant 11 requires that agent actions be replayable. A deterministic policy replays
exactly: given the same graph state and the same budget, it proposes the same pivots in the
same order, so an audit can reconstruct not just what the engine did but what it was
choosing between. A model-driven policy cannot offer that, and an investigation whose
branching cannot be reproduced is one whose conclusions cannot be defended.

The second reason is adversarial. A model deciding where to look next is a model whose
decisions can be steered by content the adversary wrote. Under a rule policy, collected
content influences *what is in the graph*, never *what the engine does next*. That removes
a whole class of manipulation without relying on the model resisting it.

:class:`PursuitPolicy` is the extension point. A model-assisted policy is a legitimate
future component — for hypothesis generation especially, where breadth matters more than
reproducibility. It would need its own audit story, and it must not be the thing that
decides where to spend.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from nemesis.core.entities import SHARED_INFRASTRUCTURE_TYPES, Entity, EntityType
from nemesis.ports.collection import PivotType
from nemesis.pursuit.investigation import (
    BranchState,
    Hypothesis,
    InvestigationBranch,
    PivotCandidate,
)

PIVOTS_FOR_ENTITY: dict[EntityType, tuple[tuple[PivotType, float, str], ...]] = {
    EntityType.DOMAIN: (
        (PivotType.RESOLUTION_HISTORY, 0.80, "Where the domain pointed, and when."),
        (PivotType.REGISTRATION_RECORD, 0.55, "Who registered it and when."),
        (PivotType.CERTIFICATE_HISTORY, 0.65, "Certificates presented, a strong reuse signal."),
        (PivotType.SUBDOMAIN_DISCOVERY, 0.40, "Sibling hostnames under the same control."),
    ),
    EntityType.IP_ADDRESS: (
        (PivotType.REVERSE_RESOLUTION, 0.75, "What else resolved here, and how crowded it is."),
        (PivotType.NETWORK_OWNERSHIP, 0.50, "Which network announces it."),
        (PivotType.SERVICE_FINGERPRINT, 0.45, "Services and fingerprints that pivot further."),
        (PivotType.PROXY_CLASSIFICATION, 0.60, "Whether this is a proxy, VPN or Tor exit."),
    ),
    EntityType.TLS_CERTIFICATE: (
        (PivotType.CERTIFICATE_REUSE, 0.85, "Where else this exact key is presented."),
    ),
    EntityType.MALWARE: (
        (PivotType.MALWARE_LOOKUP, 0.70, "What is known about this sample."),
        (PivotType.C2_EXTRACTION, 0.80, "Command-and-control and exfiltration endpoints."),
        (PivotType.MALWARE_SIMILARITY, 0.55, "Related samples by code similarity."),
    ),
    EntityType.PHISHING_KIT: (
        (PivotType.MALWARE_LOOKUP, 0.70, "Kit provenance and reuse."),
        (PivotType.C2_EXTRACTION, 0.85, "Exfiltration endpoints embedded in the kit."),
    ),
    EntityType.PERSONA: (
        (PivotType.PERSONA_ACTIVITY, 0.75, "Posting history, contacts and habits."),
        (PivotType.MARKETPLACE_LISTING, 0.60, "What this persona sells and where."),
        (PivotType.KEY_LOOKUP, 0.85, "Published keys — the strongest persona link there is."),
    ),
    EntityType.PGP_KEY: (
        (PivotType.KEY_LOOKUP, 0.90, "Every persona that has published this fingerprint."),
    ),
    EntityType.EMAIL_ADDRESS: (
        (PivotType.OSINT_SEARCH, 0.50, "Public appearances of this address."),
    ),
    EntityType.CRYPTO_ADDRESS: (
        (PivotType.WALLET_ACTIVITY, 0.70, "Transactions in and out."),
        (PivotType.WALLET_CLUSTERING, 0.65, "Addresses under common control, heuristically."),
        (PivotType.TRANSACTION_TRACE, 0.60, "Where the funds went."),
    ),
    EntityType.ASN: ((PivotType.NETWORK_OWNERSHIP, 0.30, "Who operates this network."),),
}
"""Which questions are worth asking of which entity type, and how much each usually pays.

The gains are prior expectations, not measurements. They order the queue; they do not
appear in any confidence figure, so a badly tuned prior costs time rather than correctness.
"""

MAX_CONSECUTIVE_UNINFORMATIVE = 3
MAX_BRANCH_DEPTH = 4


@runtime_checkable
class PursuitPolicy(Protocol):
    """Decides what to pursue and when to stop."""

    def propose(
        self, branch: InvestigationBranch, entity: Entity, hypotheses: tuple[Hypothesis, ...]
    ) -> tuple[PivotCandidate, ...]: ...

    def should_abandon(self, branch: InvestigationBranch) -> tuple[BranchState, str] | None: ...

    def should_branch_on(self, entity: Entity, depth: int) -> bool: ...


class RuleBasedPursuitPolicy:
    """Deterministic policy. Same inputs, same decisions, every time."""

    def __init__(
        self,
        *,
        connector_costs: dict[PivotType, float] | None = None,
        max_depth: int = MAX_BRANCH_DEPTH,
    ) -> None:
        self._costs = connector_costs or {}
        self._max_depth = max_depth

    def propose(
        self, branch: InvestigationBranch, entity: Entity, hypotheses: tuple[Hypothesis, ...]
    ) -> tuple[PivotCandidate, ...]:
        already_run = {pivot.candidate.pivot_type for pivot in branch.executed}
        open_hypothesis = next((h for h in hypotheses if not h.is_settled), None)

        candidates: list[PivotCandidate] = []
        for pivot_type, gain, rationale in PIVOTS_FOR_ENTITY.get(entity.entity_type, ()):
            if pivot_type in already_run:
                continue

            through_shared = entity.entity_type in SHARED_INFRASTRUCTURE_TYPES

            # A pivot on shared infrastructure is not forbidden — sometimes the CDN address
            # really is the answer — but its expected value collapses, so it sinks below
            # everything else and only runs when nothing better is left.
            effective_gain = gain * 0.1 if through_shared else gain

            candidates.append(
                PivotCandidate(
                    pivot_type=pivot_type,
                    entity_id=entity.entity_id,
                    entity_type=entity.entity_type,
                    entity_key=entity.natural_key,
                    addresses_hypothesis=open_hypothesis.hypothesis_id if open_hypothesis else None,
                    expected_information_gain=effective_gain,
                    estimated_cost=self._costs.get(pivot_type, 1.0),
                    rationale=rationale
                    + (
                        " Discounted: this entity type is shared by unrelated parties."
                        if through_shared
                        else ""
                    ),
                    would_pivot_through_shared_infrastructure=through_shared,
                )
            )

        # Sorted by value per cost, then by pivot type so ties break deterministically.
        # A stable order is what makes the engine's choices reproducible for audit.
        candidates.sort(key=lambda c: (-c.value_per_cost, c.pivot_type.value))
        return tuple(candidates)

    def should_abandon(self, branch: InvestigationBranch) -> tuple[BranchState, str] | None:
        if not branch.is_open:
            return None

        if branch.consecutive_uninformative >= MAX_CONSECUTIVE_UNINFORMATIVE:
            return (
                BranchState.ABANDONED_UNINFORMATIVE,
                f"{branch.consecutive_uninformative} consecutive pivots returned nothing "
                "that moved an open hypothesis.",
            )

        if branch.budget_allocated > 0 and branch.budget_remaining <= 0:
            return (
                BranchState.ABANDONED_BUDGET,
                f"Branch budget of {branch.budget_allocated:.1f} is exhausted.",
            )

        if branch.depth > self._max_depth:
            return (
                BranchState.ABANDONED_UNINFORMATIVE,
                f"Depth {branch.depth} exceeds the limit of {self._max_depth}; links this "
                "far from the seed are rarely defensible.",
            )

        return None

    def should_branch_on(self, entity: Entity, depth: int) -> bool:
        """Whether a newly discovered entity deserves a line of enquiry of its own.

        Shared infrastructure never does. Branching on a CDN address expands into every
        unrelated party behind it, and the resulting cluster is large, fast to compute and
        entirely meaningless.
        """
        if depth > self._max_depth:
            return False
        if entity.entity_type in SHARED_INFRASTRUCTURE_TYPES:
            return False
        return entity.entity_type in PIVOTS_FOR_ENTITY
