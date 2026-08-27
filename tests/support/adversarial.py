"""One place to stand up a hostile pilot session, so eight test modules do not each rebuild it.

The fixture `tests/invariants/test_pilot_containment.py` builds is the right one and is
deliberately left where it is: it is the test of record for the seam, it predates everything in
this hardening pass, and moving it would put a refactor between a reader and the tests that
established the original claims.

What lives here instead is the *same shape*, built for the modules added by the
agent-collective pass, plus the two things those modules all need and the original does not:
a before/after :class:`~nemesis.authz.monotonicity.AuthoritySnapshot`, and a second entity
nobody approved so an attack has somewhere illegitimate to point.

**Why not import the Breaker's arena.** :mod:`nemesis.breaker` is forbidden from being imported
by any plane, and a test suite reaching into it would make the harness a dependency of the
thing it attacks in everything but the letter of the contract. The duplication between this
module and `breaker/arena.py` is real, small, and the price of that separation — and it is
watched by `test_the_breaker_and_the_test_harness_agree_about_the_envelope`, which asserts the
two describe the same authority rather than trusting them to.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, cast

from nemesis.audit.trail import AppendOnlyAuditTrail
from nemesis.authz.envelope import AutonomyEnvelope
from nemesis.authz.gateway import RevocationRegistry
from nemesis.authz.keys import CapabilitySigningKey
from nemesis.authz.monotonicity import AuthoritySnapshot, snapshot
from nemesis.collect.simulated import simulated_connectors
from nemesis.core.authorization import (
    Approval,
    AuthorizationCapability,
    LegalBasis,
    OperationClass,
    StopCondition,
    TargetFingerprint,
)
from nemesis.core.entities import Entity, EntityType
from nemesis.core.identity import Role
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.temporal import TemporalExtent
from nemesis.effects.registry import default_registry
from nemesis.evidence.vault import FileSystemEvidenceVault
from nemesis.graph.memory import InMemoryClaimStore, InMemoryGraphStore
from nemesis.pilot.mediator import PilotMediator, PilotSession
from nemesis.pilot.moves import Briefing, Conclude
from nemesis.pilot.pilot import AutonomousPilot
from nemesis.pursuit.engine import ConnectorRegistry, PursuitEngine
from nemesis.pursuit.investigation import IncidentSeed

NOW: Final = datetime(2026, 3, 14, 9, 0, tzinfo=UTC)
APPROVED_DOMAIN: Final = "harness-approved.example"
UNAPPROVED_DOMAIN: Final = "harness-unapproved.example"
SEED_DOMAIN: Final = "harness-seed.example"

APPROVED_STATE: Final[Mapping[str, str]] = {
    "registrar": "example-registrar",
    "resolves_to": "203.0.113.10",
    "ownership_contested": "false",
}


class Scripted:
    """A pilot that plays a fixed list and then concludes.

    Entries may be moves, mappings, or anything else at all — a bare string, an object with a
    lying ``__str__``. A double that could only return valid moves could not attack the
    validator, which is why this is typed loosely and cast once, in :meth:`Harness.drive`.
    """

    def __init__(self, name: str, script: Sequence[object]) -> None:
        self.name = name
        self._script = list(script)
        self._turn = 0

    async def propose(self, briefing: Briefing) -> object:
        if self._turn >= len(self._script):
            return Conclude(summary="script exhausted")
        item = self._script[self._turn]
        self._turn += 1
        return item(briefing) if callable(item) else item


@dataclass
class Harness:
    """One isolated NEMESIS and the handles a hostile test needs."""

    workspace: Path
    graph: InMemoryGraphStore
    claims: InMemoryClaimStore
    audit: AppendOnlyAuditTrail
    envelope: AutonomyEnvelope
    mediator: PilotMediator
    approved: Entity
    unapproved: Entity
    seed: IncidentSeed
    signer: CapabilitySigningKey

    def authority(self) -> AuthoritySnapshot:
        """Snapshot the **mediator's** envelope, not our own reference to it.

        These differ, and an adversarial review found that they do. Reading ``self.envelope``
        measures the object this fixture happens to hold; a mediator that swapped its own
        envelope for a strictly wider one — the exact event these assertions exist to detect —
        was invisible, because the fixture kept comparing the old object with itself.

        A private attribute, deliberately and with the reason stated: the mediator does not
        expose its envelope and should not, since that would be a handle. What a test needs is
        not a handle but a *measurement*, and taking it from the enforcing object is the whole
        point of taking it at all.
        """
        envelope = self.mediator._envelope
        return snapshot(envelope.capability, envelope)

    async def drive(self, pilot: object, *, total_budget: float = 100.0) -> PilotSession:
        """Run a pilot. The cast is declared here, once, with the reason.

        Every double these modules use breaks the
        :class:`~nemesis.pilot.pilot.AutonomousPilot` contract deliberately. Scattering
        ``# type: ignore`` at each call site would read as noise and would hide the day one of
        them stopped being deliberate; the mediator's own signature stays strict, so production
        code cannot pass one by accident.
        """
        return await self.mediator.drive(
            cast(AutonomousPilot, pilot), self.seed, total_budget=total_budget
        )


async def harness(tmp_path: Path, *, effect_budget: int = 4, **mediator: Any) -> Harness:
    """Stand up an isolated NEMESIS with one approved target and one nobody approved."""
    graph = InMemoryGraphStore()
    claims = InMemoryClaimStore()
    audit = AppendOnlyAuditTrail(tmp_path / "audit.jsonl")
    extent = TemporalExtent.at(NOW)

    approved = Entity.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type=EntityType.DOMAIN,
        observed_form=APPROVED_DOMAIN,
        attributes=dict(APPROVED_STATE),
        extent=extent,
        is_synthetic=True,
    )
    unapproved = Entity.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type=EntityType.DOMAIN,
        observed_form=UNAPPROVED_DOMAIN,
        attributes={"registrar": "other-registrar"},
        extent=extent,
        is_synthetic=True,
    )
    await graph.upsert_entity(approved)
    await graph.upsert_entity(unapproved)

    signer = CapabilitySigningKey.generate()
    envelope = AutonomyEnvelope(_capability(signer, approved), max_autonomous_effects=effect_budget)
    engine = PursuitEngine(
        graph=graph,
        claims=claims,
        vault=FileSystemEvidenceVault(tmp_path / "vault"),
        audit=audit,
        connectors=ConnectorRegistry(simulated_connectors(as_of=NOW)),
    )
    mediator.setdefault("max_moves", 12)
    return Harness(
        workspace=tmp_path,
        graph=graph,
        claims=claims,
        audit=audit,
        envelope=envelope,
        mediator=PilotMediator(
            engine=engine,
            graph=graph,
            envelope=envelope,
            registry=default_registry(
                verifying_key=signer.verifying_key, revocations=RevocationRegistry()
            ),
            claims=claims,
            audit=audit,
            clock=lambda: NOW,
            **mediator,
        ),
        approved=approved,
        unapproved=unapproved,
        seed=IncidentSeed(
            entity_type=EntityType.DOMAIN,
            entity_key=SEED_DOMAIN,
            observed_at=NOW,
            detected_by="harness fixture (SIMULATED)",
        ),
        signer=signer,
    )


def _capability(signer: CapabilitySigningKey, approved: Entity) -> AuthorizationCapability:
    """One reversible class, one approved target, the irreversible class explicitly forbidden.

    The validity window brackets the **real** wall clock, not ``NOW``: ``preflight`` reads
    ``utcnow()`` itself and deliberately refuses a caller-supplied instant, because a
    caller-supplied "now" is all an attacker needs to revive an expired grant.
    """
    real = datetime.now(UTC)
    target = TargetFingerprint.create(
        entity_id=approved.entity_id,
        entity_type="domain",
        natural_key=approved.natural_key,
        bound_attributes=dict(approved.attributes),
    )
    unsigned = AuthorizationCapability(
        capability_id=new_id(IdPrefix.CAPABILITY),
        case_id=new_id(IdPrefix.CASE),
        audit_id=new_id(IdPrefix.AUDIT),
        issued_at=real - timedelta(minutes=1),
        not_before=real - timedelta(minutes=1),
        expires_at=real + timedelta(hours=4),
        targets=(target,),
        permitted_operations=frozenset({OperationClass.SIMULATION}),
        forbidden_operations=frozenset({OperationClass.REGISTRAR_SUSPENSION}),
        jurisdictions=("FR",),
        legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
        legal_authority_reference=None,
        max_targets=2,
        max_effect_description="One rehearsed suspension that suspends nothing. No contact.",
        stop_conditions=(
            StopCondition(
                condition="target_ownership_contested",
                is_blocking=True,
                description="Abort if anyone has contested ownership since approval.",
            ),
        ),
        approvals=(
            Approval(
                approver=new_id(IdPrefix.ACTOR),
                approver_roles=frozenset({Role.INVESTIGATION_LEAD}),
                decided_at=real,
                decision=True,
                rationale="Reversible rehearsal class; one synthetic target.",
            ),
        ),
        required_approvals=1,
    )
    return unsigned.model_copy(update={"signature": signer.sign(unsigned.signing_payload())})


__all__ = [
    "APPROVED_DOMAIN",
    "APPROVED_STATE",
    "NOW",
    "SEED_DOMAIN",
    "UNAPPROVED_DOMAIN",
    "Harness",
    "Scripted",
    "harness",
]
