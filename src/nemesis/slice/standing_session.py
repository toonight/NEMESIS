"""A demonstration envelope that reaches the infrastructure role gate.

The gate in :func:`nemesis.effects.registry.preflight` decides *whose* a target is before it
decides whether an operation may run against it, and it is the rule the mission turns on:
observing an adversary use a piece of infrastructure establishes nothing about who owns it, so
malicious use alone never authorizes disruption. It has 12 tests in
``tests/invariants/test_infrastructure_gate.py``, all of which construct a capability and call
the registry directly.

**What was missing was a path.** The reference demonstration in :mod:`nemesis.slice.pilot_session`
holds a capability permitting exactly one operation class, ``SIMULATION`` — and ``SIMULATION`` is
in :data:`~nemesis.core.infrastructure.OBSERVE_AND_PRESERVE_OPERATIONS`, which every role is
eligible for including ``UNKNOWN``. So the gate was silent for the whole of that run, not because
it agreed but because nothing it governs was ever requested. A control with unit tests and no
end-to-end path is a control whose *wiring* is untested: nothing proved that a role derived by
the producer reaches the enforcement point at all, through the mediator, through the envelope,
through the signature.

This module is that path. It requests two operations against five targets and reports which the
gate refused, driving the same :class:`~nemesis.pilot.mediator.PilotMediator` the reference
demonstration drives.

**Nothing here contacts anything.** The two operations it exercises are the two the MVP
implements outside the observe-and-preserve tier, and both only produce text::

    TAKEDOWN_REQUEST_DRAFT   DISRUPTIVE            eligible: actor_owned, actor_controlled
    PROVIDER_NOTIFICATION    THIRD_PARTY_ENGAGE.   eligible: every role except unknown

:mod:`nemesis.effects.drafting` has no transport and none below it; a draft is returned to the
caller and getting it in front of a registrar is a human act performed outside NEMESIS. Every
document opens with the same ``SIMULATED`` banner, which is a constant no caller can weaken.

**The roles are derived, not written.** A demonstration that hand-placed
``infrastructure_role`` on each entity would prove the gate reads an attribute and nothing about
whether anything produces one. So the graph is built, :func:`nemesis.pursuit.standing.
reassess_standing` classifies it, and the capability is signed against *what the producer
concluded* — which is also the real order of events: an analyst classifies, then an approver
signs against that classification.

**The legal basis is not ``none_simulation_only``**, because it cannot be: a capability
permitting anything beyond ``SIMULATION`` is refused at construction without a stated basis and
a reference. The basis here is ``PROVIDER_TERMS_OF_SERVICE`` — the honest one for a draft that
asks a provider to apply its own terms — and :data:`SYNTHETIC_AUTHORITY_REFERENCE` says in the
reference field itself that no real authority stands behind it. That string travels into every
drafted document, which is where somebody reading one would need to see it.

Labelled `SIMULATED`: the code is real and the refusals are real; the targets, the claims and
the campaign behind them are synthetic fixtures.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

from nemesis.audit.trail import AppendOnlyAuditTrail
from nemesis.authz.envelope import AutonomyEnvelope
from nemesis.authz.gateway import RevocationRegistry
from nemesis.authz.keys import CapabilitySigningKey
from nemesis.authz.store import SqliteAuthorizationStore
from nemesis.collect.simulated import simulated_connectors
from nemesis.core.authorization import (
    Approval,
    AuthorizationCapability,
    LegalBasis,
    OperationClass,
    StopCondition,
    TargetFingerprint,
)
from nemesis.core.claims import Claim, ClaimKind, DerivationKind, Statement
from nemesis.core.confidence import Opinion
from nemesis.core.entities import Entity, EntityType
from nemesis.core.identity import Role
from nemesis.core.ids import IdPrefix, content_id, new_id
from nemesis.core.infrastructure import (
    OBSERVE_AND_PRESERVE_OPERATIONS,
    OWNERSHIP_PREDICATE,
    ROLE_ATTRIBUTE,
    InfrastructureRole,
    eligible_roles,
)
from nemesis.core.relationships import PivotMethod, Relationship, RelationType
from nemesis.core.temporal import TemporalExtent
from nemesis.effects.isolation import IsolatedEffectsExecutor
from nemesis.evidence.vault import FileSystemEvidenceVault
from nemesis.graph.memory import InMemoryClaimStore, InMemoryGraphStore
from nemesis.pilot.mediator import PilotMediator
from nemesis.pilot.moves import Briefing, PilotMove, RequestEffect, RulingStatus
from nemesis.pilot.stagnation import SessionStagnationDetector, SessionStagnationPolicy
from nemesis.ports.authorization import TrustAnchor
from nemesis.pursuit.engine import ConnectorRegistry, PursuitEngine
from nemesis.pursuit.investigation import IncidentSeed
from nemesis.pursuit.standing import reassess_standing

SCENARIO_NOW: Final = datetime(2026, 3, 2, 9, 30, tzinfo=UTC)
EXTENT: Final = TemporalExtent.at(SCENARIO_NOW)

SYNTHETIC_AUTHORITY_REFERENCE: Final = (
    "SIMULATED/NO-REAL-AUTHORITY — synthetic exercise of the infrastructure role gate. "
    "No provider has been contacted and no instrument exists behind this reference."
)
"""What stands in the ``legal_authority_reference`` field, and why it is loud.

A capability permitting anything beyond ``SIMULATION`` must state a legal basis and cite an
authority, or it is refused at construction. Those two fields exist so that a document drafted
under the capability can say what it rests on — the takedown draft renders the basis into its own
body — so leaving them plausible-looking would put an unfounded authority claim into an artifact
designed to be read by somebody outside this system. The string says the opposite instead.
"""

EFFECT_BUDGET: Final = 12
"""One per request the demonstration makes, plus headroom.

Refused effects debit the budget exactly as accepted ones do (a counter that decrements only on
success is one an adversary empties by failing), and this demonstration is mostly refusals — so
a budget sized to the *accepted* effects would end the run halfway through and look like the
gate had stopped working.
"""

OPERATIONS: Final[tuple[OperationClass, ...]] = (
    OperationClass.TAKEDOWN_REQUEST_DRAFT,
    OperationClass.PROVIDER_NOTIFICATION,
)
"""The two implemented operations the role gate governs.

Deliberately both, because one alone cannot show the distinction the gate makes. A run that only
requested takedown drafts would show protected targets being refused and could not distinguish
"the gate blocks this role" from "the gate blocks everything"; the provider notification is
accepted against the very same targets, so the refusals are visibly about the *tier*, not about
the target being unpopular.
"""


# -- the campaign ----------------------------------------------------------------------

ACTOR_HANDLE: Final = "GLASS ANVIL"
LEGITIMATE_OWNER: Final = "organization:northwind-logistics"

ACTOR_CONTROLLED_DOMAIN: Final = "anvil-payments-secure.example"
COMPROMISED_DOMAIN: Final = "shipping.northwind-logistics.example"
SHARED_REGISTRAR: Final = "bulletproofreg"
UNCLASSIFIED_DOMAIN: Final = "anvil-invoice-mirror.example"
UNBOUND_DOMAIN: Final = "anvil-billing-portal.example"

SEED_DOMAIN: Final = ACTOR_CONTROLLED_DOMAIN


@dataclass(frozen=True)
class StandingCase:
    """One target, and what the demonstration expects the gate to make of it."""

    natural_key: str
    entity_type: EntityType
    why: str
    bind_role: bool = True
    """Whether the approver bound the classification into the target fingerprint.

    ``False`` is not an oversight in the fixture; it is the case being demonstrated. An approver
    who names a target without saying what it was found to be has authorized an operation against
    a standing nobody recorded, and the gate refuses that separately from refusing a role it
    dislikes — because "nobody looked" and "somebody looked and it is a victim's" are different
    failures and a control that conflated them would teach the wrong lesson.
    """


CASES: Final[tuple[StandingCase, ...]] = (
    StandingCase(
        natural_key=ACTOR_CONTROLLED_DOMAIN,
        entity_type=EntityType.DOMAIN,
        why="a persona controls it and no admissible record names an owner — rented, not owned",
    ),
    StandingCase(
        natural_key=COMPROMISED_DOMAIN,
        entity_type=EntityType.DOMAIN,
        why=(
            "an admissible record names a legitimate owner AND the persona controls it: the "
            "compromised-legitimate case, which malicious use alone would have marked as the "
            "adversary's"
        ),
    ),
    StandingCase(
        natural_key=SHARED_REGISTRAR,
        entity_type=EntityType.REGISTRAR,
        why="a node type unrelated parties share; adversary traffic through it is not a finding",
    ),
    StandingCase(
        natural_key=UNCLASSIFIED_DOMAIN,
        entity_type=EntityType.DOMAIN,
        why="observed in the campaign and nothing more; the honest answer is that nobody knows",
    ),
    StandingCase(
        natural_key=UNBOUND_DOMAIN,
        entity_type=EntityType.DOMAIN,
        why=(
            "the same standing as the target that drafted — the persona controls it and no "
            "record names an owner — refused solely because the approval did not say so"
        ),
        bind_role=False,
    ),
)


# -- what the run reports --------------------------------------------------------------


@dataclass(frozen=True)
class GateOutcome:
    """One (target, operation) pair, and what happened to it."""

    natural_key: str
    role: str
    """As the producer derived it. ``"(unbound)"`` when the approver did not bind it, which is
    what the gate saw — not what the graph knew."""

    operation: OperationClass
    status: RulingStatus
    detail: str

    external_contact_made: bool | None
    """What the Effects plane reported about reaching outside, carried up so the demonstration
    can *measure* containment instead of asserting it.

    ``None`` means no effect ran, or one ran and did not say. :meth:`left_the_platform` treats
    the second case as contact, because a control that reads silence as safety is the one that
    fails quietly."""

    @property
    def left_the_platform(self) -> bool:
        """Fail-closed: an accepted effect that came back without saying counts as having left."""
        return self.accepted and self.external_contact_made is not False

    @property
    def accepted(self) -> bool:
        return self.status is RulingStatus.ACCEPTED

    @property
    def refused_by_the_role_gate(self) -> bool:
        """Whether *this* control refused, as opposed to some earlier one.

        Keyed on the gate's own wording rather than on the status, because
        ``REFUSED_OUT_OF_ENVELOPE`` is also what a revoked capability, an unmatched fingerprint
        and an uncleared stop condition produce. A demonstration that counted every refusal as
        the gate's would report success while the gate sat unreached — the exact failure it
        exists to rule out.
        """
        return not self.accepted and (
            "may run only against" in self.detail
            or f"no {ROLE_ATTRIBUTE} is bound into this capability" in self.detail
            or f"the bound {ROLE_ATTRIBUTE}" in self.detail
        )


@dataclass(frozen=True)
class StandingDemonstration:
    """The matrix, the envelope it spent, and where the drafts were written."""

    outcomes: tuple[GateOutcome, ...]
    roles: dict[str, InfrastructureRole]
    envelope: AutonomyEnvelope
    workspace: Path

    @property
    def gate_refusals(self) -> tuple[GateOutcome, ...]:
        return tuple(item for item in self.outcomes if item.refused_by_the_role_gate)

    @property
    def accepted(self) -> tuple[GateOutcome, ...]:
        return tuple(item for item in self.outcomes if item.accepted)

    def render(self) -> str:
        lines = [
            "Infrastructure role gate — exercised end to end",
            "",
            "  SIMULATED. Synthetic targets, synthetic claims, no external contact. The two",
            "  operations below are the only implemented ones the gate governs; both produce",
            "  text and neither can send it.",
            "",
        ]
        for operation in OPERATIONS:
            permitted = sorted(role.value for role in eligible_roles(operation))
            tier = (
                "observe-and-preserve"
                if operation in OBSERVE_AND_PRESERVE_OPERATIONS
                else "governed by the gate"
            )
            lines.append(f"  {operation.value} ({tier})")
            lines.append(f"      may run against: {', '.join(permitted)}")
        lines.append("")

        width = max(len(item.natural_key) for item in self.outcomes)
        roles = max(len(item.role) for item in self.outcomes)
        header = f"  {'target':{width}}  {'derived role':{roles}}  "
        header += "  ".join(f"{op.value:24}" for op in OPERATIONS)
        lines.extend([header, "  " + "-" * (len(header) - 2)])

        for case in CASES:
            row = [item for item in self.outcomes if item.natural_key == case.natural_key]
            if not row:
                continue
            cells = []
            for operation in OPERATIONS:
                found = next((r for r in row if r.operation is operation), None)
                if found is None:
                    cells.append("—")
                elif found.accepted:
                    cells.append("drafted")
                elif found.refused_by_the_role_gate:
                    cells.append("REFUSED by the gate")
                else:
                    cells.append(f"refused ({found.status.value})")
            lines.append(
                f"  {case.natural_key:{width}}  {row[0].role:{roles}}  "
                + "  ".join(f"{cell:24}" for cell in cells)
            )

        lines.extend(
            [
                "",
                f"  {len(self.accepted)} drafted, {len(self.gate_refusals)} refused by the role "
                f"gate, of {len(self.outcomes)} requested. External contact reported by the "
                f"Effects plane on {sum(1 for o in self.outcomes if o.left_the_platform)} of "
                f"them.",
                "",
                "  Why each target came out as it did:",
            ]
        )
        lines.extend(f"    {case.natural_key}: {case.why}" for case in CASES)
        lines.extend(
            [
                "",
                "  The refusals are not the capability's doing. Every target here was named by",
                "  the approver, every signature verifies and every fingerprint matches; the",
                "  budget was available and no stop condition blocked. What refused is the",
                "  answer to whose the target is — which is the mission's rule, made",
                "  deterministic: malicious use is not ownership.",
                "",
                "  Not shown here, because it is refused earlier: an entity typed VICTIM never",
                "  reaches this gate at all. The mediator's disclosure wall stops it first, so",
                "  the two kinds of third party are protected by two different controls.",
            ]
        )
        return "\n".join(lines)


# -- the pilot -------------------------------------------------------------------------


class _StandingProbePilot:
    """Requests every operation against every target, in order, then concludes.

    Scripted rather than a model, and this is the one demonstration where that is not a
    limitation: what is under test is the enforcement path, and a pilot that chose its own moves
    would exercise a different subset each run. The mediator cannot tell a scripted pilot from a
    model — it validates the move, never the mover — so the path this walks is the path a model
    walks.
    """

    name = "standing-probe (SIMULATED)"

    def __init__(self, targets: dict[str, str]) -> None:
        self._targets = targets
        self._plan: list[tuple[str, OperationClass]] = [
            (case.natural_key, operation) for case in CASES for operation in OPERATIONS
        ]
        self._turn = 0

    @property
    def plan(self) -> tuple[tuple[str, OperationClass], ...]:
        return tuple(self._plan)

    async def propose(self, briefing: Briefing) -> PilotMove | dict[str, Any]:
        if self._turn >= len(self._plan):
            return {
                "kind": "conclude",
                "summary": (
                    "Requested both governed operations against every target. What was refused "
                    "was refused on standing, not on authority."
                ),
            }
        natural_key, operation = self._plan[self._turn]
        self._turn += 1
        return RequestEffect(
            entity_id=self._targets[natural_key],
            operation=operation,
            parameters={
                "recipient": "abuse@example-registrar.invalid (SIMULATED, never contacted)",
                "observed_activity": (
                    "Credential-harvesting pages imitating a payments portal, observed in "
                    "synthetic fixtures."
                ),
            },
            rationale=f"Probing the role gate for {natural_key} with {operation.value}.",
        )


# -- construction ----------------------------------------------------------------------


def _claim(*, subject: Entity, owner: str) -> Claim:
    """An admissible ownership record naming a legitimate owner.

    ``AUTHORITATIVE_RECORD`` because that is what makes it move a node's standing at all —
    :data:`~nemesis.core.infrastructure.ADMISSIBLE_OWNERSHIP_DERIVATIONS` excludes a model's
    assertion and a vendor report, and a demonstration built on an inadmissible claim would show
    the producer declining to classify rather than the gate declining to act.
    """
    return Claim.create(
        kind=ClaimKind.FACT,
        statement=Statement(
            subject=f"{subject.entity_type.value}:{subject.natural_key}",
            predicate=OWNERSHIP_PREDICATE,
            obj=owner,
            natural_language=(
                f"{subject.natural_key} is registered to {owner} in a corporate register "
                f"(SIMULATED)."
            ),
        ),
        derivation=DerivationKind.AUTHORITATIVE_RECORD,
        asserted_by=new_id(IdPrefix.ACTOR),
        asserted_at=SCENARIO_NOW,
        valid_extent=EXTENT,
        supported_by_evidence=(content_id(IdPrefix.EVIDENCE, b"a sealed corporate record"),),
    )


def _entity(natural_key: str, entity_type: EntityType) -> Entity:
    return Entity.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type=entity_type,
        observed_form=natural_key,
        # Positively recorded, not assumed: the mediator clears the blocking stop condition only
        # when it can *see* this, and an absent attribute is a target nobody checked.
        attributes={"ownership_contested": "false"},
        extent=EXTENT,
        is_synthetic=True,
    )


def _control_edge(*, actor: Entity, target: Entity, claim: Claim) -> Relationship:
    return Relationship(
        edge_id=new_id(IdPrefix.EDGE),
        source_id=actor.entity_id,
        target_id=target.entity_id,
        source_type=actor.entity_type,
        target_type=target.entity_type,
        relation=RelationType.CONTROLS,
        extent=EXTENT,
        confidence=Opinion(belief=0.8, disbelief=0.05, uncertainty=0.15),
        pivot_method=PivotMethod.DIRECT_OBSERVATION,
        supporting_claims=(claim.claim_id,),
        is_synthetic=True,
    )


def _control_claim(*, actor: Entity, target: Entity) -> Claim:
    return Claim.create(
        kind=ClaimKind.OBSERVATION,
        statement=Statement(
            subject=f"{actor.entity_type.value}:{actor.natural_key}",
            predicate="controls",
            obj=f"{target.entity_type.value}:{target.natural_key}",
            natural_language=(
                f"{actor.natural_key} operates {target.natural_key}: the same deployment "
                f"tooling and operator key appear on both (SIMULATED)."
            ),
        ),
        derivation=DerivationKind.DIRECT_COLLECTION,
        asserted_by=new_id(IdPrefix.ACTOR),
        asserted_at=SCENARIO_NOW,
        valid_extent=EXTENT,
        supported_by_evidence=(content_id(IdPrefix.EVIDENCE, b"a sealed deployment artifact"),),
    )


def signed_envelope(
    signer: CapabilitySigningKey,
    targets: dict[str, Entity],
    *,
    now: datetime,
) -> AuthorizationCapability:
    """The demonstration's capability: five named targets, two permitted operations.

    Deliberately *broad in targets and narrow in operations*, which is the shape that makes the
    gate the load-bearing control. Every target here was named by the approver and every one
    matches its fingerprint, so nothing downstream can refuse on authority — whatever refuses is
    refusing on what the target turned out to be.

    The classification goes into ``bound_attributes``, which is what puts it inside the signed
    digest and re-observed at execution. Checking a role at approval and trusting it later is the
    thing this avoids: a node reclassified after signing stops matching its own fingerprint, and
    nobody has to remember to revoke anything.
    """
    fingerprints = []
    for case in CASES:
        entity = targets[case.natural_key]
        bound = dict(entity.attributes)
        if not case.bind_role:
            bound.pop(ROLE_ATTRIBUTE, None)
        fingerprints.append(
            TargetFingerprint.create(
                entity_id=entity.entity_id,
                entity_type=entity.entity_type.value,
                natural_key=entity.natural_key,
                bound_attributes=bound,
            )
        )

    unsigned = AuthorizationCapability(
        capability_id=new_id(IdPrefix.CAPABILITY),
        case_id=new_id(IdPrefix.CASE),
        audit_id=new_id(IdPrefix.AUDIT),
        issued_at=now - timedelta(minutes=1),
        not_before=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=4),
        targets=tuple(fingerprints),
        permitted_operations=frozenset(OPERATIONS),
        forbidden_operations=frozenset(
            {
                OperationClass.REGISTRAR_SUSPENSION,
                OperationClass.HOSTING_TERMINATION,
                OperationClass.DOMAIN_SEIZURE,
                OperationClass.SINKHOLE,
                OperationClass.ASSET_FREEZE_REQUEST,
            }
        ),
        jurisdictions=("FR", "NL"),
        legal_basis=LegalBasis.PROVIDER_TERMS_OF_SERVICE,
        legal_authority_reference=SYNTHETIC_AUTHORITY_REFERENCE,
        max_targets=len(CASES),
        max_effect_description=(
            "Drafts only. Each operation returns a document the caller may read; none is sent, "
            "and no adapter in this registry declares external contact."
        ),
        stop_conditions=(
            StopCondition(
                condition="target_ownership_contested",
                description="Abort if anyone has contested ownership of the target since approval.",
            ),
        ),
        approvals=(
            Approval(
                approver=new_id(IdPrefix.ACTOR),
                approver_roles=frozenset({Role.INVESTIGATION_LEAD}),
                decided_at=now,
                decision=True,
                rationale=(
                    "Drafting delegated in advance across the campaign's nodes. The classification "
                    "of each node is bound into its fingerprint; what may be done to each follows "
                    "from that rather than from my having named it."
                ),
            ),
        ),
        required_approvals=1,
    )
    return unsigned.model_copy(update={"signature": signer.sign(unsigned.signing_payload())})


async def run_standing_demonstration(*, workspace: Path | None = None) -> StandingDemonstration:
    """Build the campaign, let the producer classify it, then ask for what it forbids."""
    root = Path(workspace or tempfile.mkdtemp(prefix="nemesis-standing-"))
    root.mkdir(parents=True, exist_ok=True)

    graph = InMemoryGraphStore()
    claims = InMemoryClaimStore()
    vault = FileSystemEvidenceVault(root / "vault")
    audit = AppendOnlyAuditTrail(root / "audit.jsonl")

    actor = Entity.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type=EntityType.PERSONA,
        observed_form=ACTOR_HANDLE,
        extent=EXTENT,
        is_synthetic=True,
    )
    await graph.upsert_entity(actor)

    targets = {case.natural_key: _entity(case.natural_key, case.entity_type) for case in CASES}
    for entity in targets.values():
        await graph.upsert_entity(entity)

    # Adversary control over three of them, and an admissible owner over exactly one. Those two
    # facts, and the order of the producer's rules, are the whole difference between
    # ACTOR_CONTROLLED and COMPROMISED_LEGITIMATE.
    #
    # UNBOUND_DOMAIN gets the same control edge as ACTOR_CONTROLLED_DOMAIN deliberately: the two
    # come out of the producer identically classified, so when one drafts and the other is
    # refused, the difference cannot be read as anything but the approval having omitted the
    # classification. A target that was both unclassified and unbound would have demonstrated
    # nothing about the unbound branch, because the unclassified one would explain the refusal
    # on its own.
    recorded: list[Claim] = []
    for natural_key in (ACTOR_CONTROLLED_DOMAIN, COMPROMISED_DOMAIN, UNBOUND_DOMAIN):
        control = _control_claim(actor=actor, target=targets[natural_key])
        recorded.append(control)
        await claims.record(control)
        await graph.add_relationship(
            _control_edge(actor=actor, target=targets[natural_key], claim=control)
        )

    ownership = _claim(subject=targets[COMPROMISED_DOMAIN], owner=LEGITIMATE_OWNER)
    recorded.append(ownership)
    await claims.record(ownership)

    roles = await reassess_standing(
        graph,
        [entity.entity_id for entity in targets.values()],
        claims=recorded,
        assessed_at=SCENARIO_NOW,
    )
    # Re-read: `record_standing` wrote the role onto each entity, and the capability must be
    # signed against what is *on the graph*, not against what this function believes it asked
    # for. A fingerprint built from the pre-assessment attributes would diverge at execution and
    # every target would refuse for the wrong reason.
    stored = {key: await graph.get_entity(entity.entity_id) for key, entity in targets.items()}
    resolved = {key: entity for key, entity in stored.items() if entity is not None}
    if len(resolved) != len(CASES):
        missing = sorted(set(targets) - set(resolved))
        raise RuntimeError(f"the graph lost {missing} between assessment and approval")

    signer = CapabilitySigningKey.generate()
    store = SqliteAuthorizationStore(root / "authorization.sqlite3")
    envelope = AutonomyEnvelope(
        # The wall clock, not the scenario clock: the Effects plane reads `utcnow()` itself,
        # because a caller-supplied "now" is all an attacker needs to revive an expired grant.
        signed_envelope(signer, resolved, now=datetime.now(UTC)),
        max_autonomous_effects=EFFECT_BUDGET,
        ledger=store,
    )

    engine = PursuitEngine(
        graph=graph,
        claims=claims,
        vault=vault,
        audit=audit,
        connectors=ConnectorRegistry(simulated_connectors(as_of=SCENARIO_NOW)),
    )
    mediator = PilotMediator(
        engine=engine,
        graph=graph,
        envelope=envelope,
        effects=IsolatedEffectsExecutor(
            TrustAnchor(verifying_key=signer.verifying_key, revocations=RevocationRegistry()),
            # The workspace holds the evidence vault, the audit trail and the
            # authorization ledger. Reading any of them off disk needs no import, so the
            # import contracts alone would not keep a worker out of the investigation it
            # is acting for.
            # Named, because the default now refuses. This is a demonstration that runs on
            # whatever platform the reader has, including the Linux CI where `sandbox-exec`
            # does not exist — a refusal there would hide the thing being demonstrated. A
            # deployment says nothing here and gets the refusal.
            allow_unsandboxed=True,
            read_denied=(root,),
        ),
        claims=claims,
        audit=audit,
        max_moves=len(CASES) * len(OPERATIONS) + 2,
        # A matrix probe looks exactly like a stall, because in production it would be one: the
        # scripted pilot requests every operation against every target and most are refused. The
        # point of this demonstration is the cell-by-cell refusal table, and stopping at the
        # sixth cell would demonstrate the stagnation detector instead of the role gate. The
        # stall is still detected and recorded; only the stopping is declined. See
        # `SessionStagnationPolicy.halt_on_stall`.
        stagnation=SessionStagnationDetector(SessionStagnationPolicy(halt_on_stall=False)),
    )

    pilot = _StandingProbePilot({key: entity.entity_id for key, entity in resolved.items()})
    seed = IncidentSeed(
        entity_type=EntityType.DOMAIN,
        entity_key=SEED_DOMAIN,
        observed_at=SCENARIO_NOW,
        detected_by="acme-waf (SIMULATED)",
    )
    session = await mediator.drive(pilot, seed, total_budget=60.0)

    by_key = {entity.entity_id: key for key, entity in resolved.items()}
    role_of = {by_key[entity_id]: role for entity_id, role in roles.items() if entity_id in by_key}
    bound = {case.natural_key: case.bind_role for case in CASES}

    outcomes = []
    effect_rulings = [r for r in session.rulings if r.move_kind == "request_effect"]
    for (natural_key, operation), ruling in zip(pilot.plan, effect_rulings, strict=False):
        role = role_of.get(natural_key, InfrastructureRole.UNKNOWN)
        outcomes.append(
            GateOutcome(
                natural_key=natural_key,
                role=role.value if bound[natural_key] else f"{role.value} (unbound)",
                operation=operation,
                status=ruling.status,
                detail=ruling.reason,
                external_contact_made=ruling.external_contact_made,
            )
        )

    return StandingDemonstration(
        outcomes=tuple(outcomes),
        roles=role_of,
        envelope=envelope,
        workspace=root,
    )


__all__ = [
    "CASES",
    "EFFECT_BUDGET",
    "OPERATIONS",
    "SYNTHETIC_AUTHORITY_REFERENCE",
    "GateOutcome",
    "StandingCase",
    "StandingDemonstration",
    "run_standing_demonstration",
    "signed_envelope",
]
