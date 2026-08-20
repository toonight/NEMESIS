"""Authorization capabilities: the object that stands between a plan and an effect.

Invariant 7 says no consequential real-world action happens because an agent asked for it.
That is not enforceable by telling a model to be careful. It is enforceable by making the
Effects plane structurally incapable of acting without a signed object it cannot mint,
that names exactly what it may do, and that expires.

Four properties do the work:

**Target binding.** A capability names not just *which* entities may be acted on, but a
fingerprint of their state at the moment of approval. Between approval and execution, a
domain can be transferred, an IP reassigned, a server rebuilt for a legitimate customer.
If the target has changed, the capability no longer matches and execution fails closed.
Approving an action against "evil.example" is not approving an action against whatever
evil.example happens to point at next Tuesday.

**Explicit denial.** Forbidden operations are listed and always win over permitted ones.
A capability that grants a class through some future widening of an enum still cannot
perform what was explicitly denied.

**Expiry and stop conditions.** Authority is temporary and has abort criteria. A
capability with no expiry is a standing permission, which is the thing invariant 9 exists
to prevent.

**Dual control.** Consequential classes require more than one approver, and the approvers
must be distinct people. Configurable, because the right threshold differs between a draft
abuse email and a seizure package.

This module defines the *structure* and the *canonical bytes to sign*. Key handling and
signature verification live in :mod:`nemesis.authz`, so the domain model stays free of
cryptographic dependencies and the signing key never becomes reachable from here.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Final, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from nemesis.core.canonical import canonical_bytes
from nemesis.core.identity import AssuranceLevel, Role
from nemesis.core.ids import ActorId, AuditId, CapabilityId, CaseId, EntityId
from nemesis.core.temporal import require_utc, utcnow


class OperationClass(StrEnum):
    """What kind of effect an operation is.

    The MVP implements only the first group. Everything below ``EVIDENCE_EXPORT`` is a
    declared class with no adapter behind it, so the planner can reason about options that
    NEMESIS is not permitted to perform — which is the point. A planner that can only
    propose what it can execute will silently narrow an investigation to whatever happens
    to be implemented.
    """

    # --- IMPLEMENTED in the MVP -------------------------------------------------
    SIMULATION = "simulation"
    """Executes nothing. Exercises the full authorization path against a synthetic world."""

    PROVIDER_NOTIFICATION = "provider_notification"
    """Drafts a factual abuse notification to a provider. Drafted, not sent."""

    TAKEDOWN_REQUEST_DRAFT = "takedown_request_draft"
    """Drafts a takedown request with its evidence bundle. Drafted, not sent."""

    EVIDENCE_EXPORT = "evidence_export"
    """Produces a sealed, verifiable evidence package for an external recipient."""

    # --- REQUIRES_LEGAL_AUTHORITY — declared, never implemented here ------------
    REGISTRAR_SUSPENSION = "registrar_suspension"
    HOSTING_TERMINATION = "hosting_termination"
    ACCOUNT_SUSPENSION = "account_suspension"
    EXCHANGE_NOTIFICATION = "exchange_notification"
    ASSET_FREEZE_REQUEST = "asset_freeze_request"
    DOMAIN_SEIZURE = "domain_seizure"
    SINKHOLE = "sinkhole"
    LAW_ENFORCEMENT_REFERRAL = "law_enforcement_referral"
    JUDICIAL_SEIZURE_PACKAGE = "judicial_seizure_package"


MVP_IMPLEMENTED_OPERATIONS: frozenset[OperationClass] = frozenset(
    {
        OperationClass.SIMULATION,
        OperationClass.PROVIDER_NOTIFICATION,
        OperationClass.TAKEDOWN_REQUEST_DRAFT,
        OperationClass.EVIDENCE_EXPORT,
    }
)
"""Operation classes with a real adapter. Everything else raises on execution.

Kept as data rather than as a comment so the Effects plane can refuse by lookup, and so a
test can assert that the set has not quietly grown.
"""

IRREVERSIBLE_OPERATIONS: frozenset[OperationClass] = frozenset(
    {
        OperationClass.REGISTRAR_SUSPENSION,
        OperationClass.HOSTING_TERMINATION,
        OperationClass.ACCOUNT_SUSPENSION,
        OperationClass.ASSET_FREEZE_REQUEST,
        OperationClass.DOMAIN_SEIZURE,
        OperationClass.SINKHOLE,
    }
)
"""Operations whose effects cannot be undone by us. Always require dual control."""


class LegalBasis(StrEnum):
    """Under what authority an operation would be performed."""

    NONE_SIMULATION_ONLY = "none_simulation_only"
    PROVIDER_TERMS_OF_SERVICE = "provider_terms_of_service"
    """A provider acting on its own ToS after being notified. We only supply facts."""

    VOLUNTARY_PROVIDER_ACTION = "voluntary_provider_action"
    STATUTORY_NOTICE_AND_ACTION = "statutory_notice_and_action"
    """e.g. an EU DSA Article 16 notice. Verify the current regime before relying on this."""

    COURT_ORDER = "court_order"
    LAW_ENFORCEMENT_REQUEST = "law_enforcement_request"
    REGULATORY_AUTHORITY = "regulatory_authority"


class TargetFingerprint(BaseModel):
    """A target, bound to the state in which it was approved.

    The digest covers the attributes that made this entity the right target. If any of
    them changed since approval, the operation is no longer the one that was authorized,
    and it must not proceed on the strength of a stale decision.
    """

    model_config = ConfigDict(frozen=True)

    entity_id: EntityId
    entity_type: str
    natural_key: Annotated[str, Field(min_length=1)]

    bound_attributes: dict[str, str]
    """The attributes whose change invalidates the approval: current resolution, hosting
    provider, registrar, certificate fingerprint. Chosen per operation class."""

    fingerprint: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]

    @model_validator(mode="after")
    def _check_fingerprint(self) -> Self:
        expected = self.compute(
            entity_id=self.entity_id,
            entity_type=self.entity_type,
            natural_key=self.natural_key,
            bound_attributes=self.bound_attributes,
        )
        if self.fingerprint != expected:
            raise ValueError("target fingerprint does not match the bound attributes")
        return self

    @staticmethod
    def compute(
        *,
        entity_id: str,
        entity_type: str,
        natural_key: str,
        bound_attributes: dict[str, str],
    ) -> str:
        payload = json.dumps(
            {
                "entity_id": entity_id,
                "entity_type": entity_type,
                "natural_key": natural_key,
                "bound": dict(sorted(bound_attributes.items())),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
        return f"sha256:{hashlib.sha256(payload).hexdigest()}"

    @classmethod
    def create(
        cls,
        *,
        entity_id: str,
        entity_type: str,
        natural_key: str,
        bound_attributes: dict[str, str],
    ) -> TargetFingerprint:
        return cls(
            entity_id=entity_id,
            entity_type=entity_type,
            natural_key=natural_key,
            bound_attributes=bound_attributes,
            fingerprint=cls.compute(
                entity_id=entity_id,
                entity_type=entity_type,
                natural_key=natural_key,
                bound_attributes=bound_attributes,
            ),
        )

    def matches_current_state(self, current_attributes: dict[str, str]) -> bool:
        """Whether the target is still in the state that was approved.

        Compares only the bound attributes. Attributes nobody bound are free to change:
        binding everything would make every capability expire on the first unrelated
        observation, which trains operators to re-approve without reading.
        """
        return all(
            current_attributes.get(key) == value for key, value in self.bound_attributes.items()
        )


GENESIS_HASH: Final = "0" * 64
"""The predecessor of the first revocation in a store."""

NO_CAPABILITY: Final = "cap_" + "0" * 32
"""The capability id recorded when no grant was authenticated.

Well-formed so it validates, and unmistakable so nobody chases it. The alternative — echoing
the id off an unverified capability — writes an attacker-chosen identifier into the audit
trail and points whoever investigates at a grant with nothing to do with the event.
"""

UNSIGNED_FIELDS: Final[set[str]] = {"signature", "revoked_at", "revocation_reason"}
"""The only capability fields outside the signed payload.

The signature cannot cover itself. The revocation fields are excluded so that revoking a
capability leaves its signature intact and a revoked grant stays cryptographically
distinguishable from a forged one.
"""


class Approval(BaseModel):
    """One human's decision. Dual control means more than one of these, from distinct people."""

    model_config = ConfigDict(frozen=True)

    approver: ActorId
    approver_roles: frozenset[Role]
    """The roles the identity provider vouched for, as roles rather than as prose.

    Structured because :func:`~nemesis.authz.rbac.check_legal_basis_reviewed` reads it at
    issuance to decide whether anyone qualified reviewed the legal instrument, and a policy
    check that has to parse a display string back into roles is a policy check waiting to be
    fooled by a comma."""

    approver_assurance: AssuranceLevel = AssuranceLevel.DEVELOPMENT
    """How well the approver's identity was established, per the provider that vouched.

    Signed, so the record of *what an approval was worth* cannot be edited afterwards. A
    reader six months later must be able to see that a grant rests on a development fixture
    rather than on a hardware-backed login, and that is not something the approver should be
    able to restate more favourably."""

    authenticated_by: Annotated[str, Field(min_length=1)] = "unauthenticated"
    """The identity provider. ``unauthenticated`` is the honest default for a caller that
    supplied a name rather than presenting a principal."""

    decided_at: datetime
    decision: bool
    """True approves, False rejects. A rejection is recorded, never deleted — the record
    of what was refused is as operationally important as the record of what was allowed."""

    rationale: Annotated[str, Field(min_length=1, max_length=4000)]
    """Why. An approval with no stated reasoning cannot be reviewed after the fact."""

    reviewed_evidence: tuple[str, ...] = ()
    """Evidence ids the approver states they examined. Distinguishes a considered decision
    from a rubber stamp, and makes the difference auditable."""

    signature: str | None = None

    @property
    def approver_role(self) -> str:
        """One line for a human reader. Never the input to a decision."""
        return ", ".join(sorted(role.value for role in self.approver_roles)) or "no roles"


class Revocation(BaseModel):
    """A withdrawal of an authority already granted, signed and chained.

    Two different attacks, two different defences, and conflating them is how a store ends
    up defending against neither.

    **Forgery** — anyone who can write the store withdrawing a capability they dislike — is a
    denial of service on lawful action, and is stopped by the signature: a revocation is
    minted by the gateway with the same key that issues capabilities, and a reader checks it.

    **Suppression** — deleting a revocation so a withdrawn capability works again — is the
    more dangerous one, and a signature does nothing about it: an attacker who can add a row
    can remove one. That is what ``previous_hash`` is for. Revocations form a chain, so a
    missing one breaks every link after it and the gap is visible rather than silent.
    """

    model_config = ConfigDict(frozen=True)

    capability_id: CapabilityId
    revoked_at: Annotated[datetime, AfterValidator(lambda v: require_utc(v, "revoked_at"))]
    """Normalised to UTC here rather than trusted from the caller.

    A store that keeps this as text orders it lexicographically, and that is only correct on
    UTC-normalised values. Left unnormalised, a withdrawal recorded as ``12:00+02:00`` — ten
    o'clock, and earlier — compared as *later* than ``11:00Z`` and lost the earliest-wins
    rule, which exists precisely so a second revocation cannot narrow the window the first
    applied to. A naive datetime was accepted outright."""
    revoked_by: ActorId
    reason: Annotated[str, Field(min_length=1)]
    """Why the authority was withdrawn. A revocation with no reason cannot be reviewed, and
    a pattern of unexplained revocations is itself a signal worth being able to read."""

    sequence: Annotated[int, Field(ge=0)] = 0
    previous_hash: str = GENESIS_HASH
    """The hash of the previous revocation in this store.

    Makes deletion detectable. Without it, a revocation store is a set of independent rows
    and removing one leaves nothing behind — the capability simply works again, and the
    reader cannot tell that from never having been revoked."""

    signature: str | None = None
    """Ed25519 over :meth:`signing_payload`, minted by the gateway.

    ``None`` on a revocation nobody signed, which a verifying store refuses. The signature
    covers the chain position, so it cannot be lifted onto a different link."""

    def signing_payload(self) -> bytes:
        """The exact bytes a signature covers: this withdrawal, whole, including its link."""
        return canonical_bytes(self.model_dump(mode="json", exclude={"signature"}))

    def chain_hash(self) -> str:
        """This link's hash, over its own contents and its predecessor's."""
        return hashlib.sha256(self.signing_payload()).hexdigest()


class StopCondition(BaseModel):
    """A condition that aborts the operation, checked before and during execution."""

    model_config = ConfigDict(frozen=True)

    condition: Annotated[str, Field(min_length=1)]
    description: Annotated[str, Field(min_length=1)]
    is_blocking: bool = True


class AuthorizationCapability(BaseModel):
    """A narrowly scoped, expiring, signed grant of authority to perform one operation.

    Cannot be minted by an agent: issuance requires the signing key, which lives outside
    the agent execution plane. The Effects plane verifies this object offline and holds no
    other authority (invariant 8).
    """

    model_config = ConfigDict(frozen=True)

    capability_id: CapabilityId
    case_id: CaseId
    audit_id: AuditId

    issued_at: datetime
    not_before: datetime
    expires_at: datetime

    targets: tuple[TargetFingerprint, ...]
    permitted_operations: frozenset[OperationClass]
    forbidden_operations: frozenset[OperationClass] = frozenset()
    """Explicit denials. Always win over permissions, including permissions added later."""

    jurisdictions: tuple[str, ...]
    """ISO 3166-1 alpha-2 codes of every jurisdiction touched: where the target sits, where
    the provider sits, where we sit. An operation spanning jurisdictions needs authority in
    each, and listing them is what makes that reviewable."""

    legal_basis: LegalBasis
    legal_authority_reference: str | None = Field(
        default=None,
        description="Case number, court order reference, statutory provision. Required for "
        "anything beyond simulation.",
    )

    max_targets: Annotated[int, Field(ge=1)]
    """Ceiling on how many targets may be acted on, independent of the target list. A
    second, blunter limit that survives a bug in target expansion."""

    max_effect_description: Annotated[str, Field(min_length=1)]
    """What the worst permitted outcome is, in plain language, as approved."""

    stop_conditions: tuple[StopCondition, ...] = ()
    approvals: tuple[Approval, ...]
    required_approvals: Annotated[int, Field(ge=1)] = 1

    revoked_at: datetime | None = None
    revocation_reason: str | None = None

    signature: str | None = Field(
        default=None,
        description="Detached signature over signing_payload(). Unsigned capabilities are "
        "valid only for SIMULATION, and are marked as such wherever they appear.",
    )

    @model_validator(mode="after")
    def _enforce_capability_rules(self) -> Self:
        if self.expires_at <= self.not_before:
            raise ValueError("a capability must expire after it becomes valid")
        if self.expires_at <= self.issued_at:
            raise ValueError("a capability must expire after it is issued")

        if not self.targets:
            raise ValueError("a capability must name at least one target")
        if len(self.targets) > self.max_targets:
            raise ValueError(
                f"capability names {len(self.targets)} targets but max_targets is "
                f"{self.max_targets}"
            )

        if not self.permitted_operations:
            raise ValueError("a capability that permits nothing is not a capability")

        overlap = self.permitted_operations & self.forbidden_operations
        if overlap:
            raise ValueError(
                f"operations both permitted and forbidden: {sorted(op.value for op in overlap)}"
            )

        # Dual control for anything that cannot be undone.
        irreversible = self.permitted_operations & IRREVERSIBLE_OPERATIONS
        if irreversible and self.required_approvals < 2:
            raise ValueError(
                f"{sorted(op.value for op in irreversible)} cannot be undone and require "
                "at least two approvers"
            )

        granted = [approval for approval in self.approvals if approval.decision]
        if len(granted) < self.required_approvals:
            raise ValueError(
                f"{self.required_approvals} approval(s) required, {len(granted)} granted"
            )

        approvers = {approval.approver for approval in granted}
        if len(approvers) < self.required_approvals:
            raise ValueError(
                "dual control requires distinct approvers; the same person cannot supply "
                "two of the required approvals"
            )

        # Anything beyond simulation needs a stated legal basis.
        beyond_simulation = self.permitted_operations - {OperationClass.SIMULATION}
        if beyond_simulation:
            if self.legal_basis is LegalBasis.NONE_SIMULATION_ONLY:
                raise ValueError(
                    f"{sorted(op.value for op in beyond_simulation)} require a legal basis "
                    "other than none_simulation_only"
                )
            if not self.legal_authority_reference:
                raise ValueError(
                    "a legal_authority_reference is required for any operation beyond simulation"
                )

        return self

    # -- verification ---------------------------------------------------------

    def signing_payload(self) -> bytes:
        """The exact bytes a signature covers: this capability, whole.

        Excludes only the signature itself and the revocation fields. Revocation happens
        after issuance and must not invalidate the original signature, or a revoked
        capability would become indistinguishable from a forged one — which is why the
        Effects plane asks the issuing authority rather than asking the object.

        Everything else is included by construction rather than by enumeration. The version
        that enumerated — signing ``op.value`` while deciding on ``operation in
        permitted_operations`` — was defeated by an object that rendered as ``simulation``
        and compared as ``provider_notification``: identical bytes, valid signature, and a
        provider notification drafted from a rehearsal grant. See
        :mod:`nemesis.core.canonical`.
        """
        return canonical_bytes(self.model_dump(mode="json", exclude=UNSIGNED_FIELDS))

    @classmethod
    def from_signed_payload(cls, payload: bytes) -> Self:
        """Reconstruct what the authorizer actually signed.

        The counterpart to :meth:`signing_payload`, and the reason the pair exists. A
        signature proves an authorizer produced *these bytes*; what the bytes say is decided
        by parsing them through the model's own validators, never by trusting the object
        that arrived beside them. Every enum here is a real member and every timestamp a
        real ``datetime``, because both were built from text.

        The reconstruction carries no revocation state — those fields are outside the
        signature by design — so a caller must still ask the revocation oracle.
        """
        rebuilt = cls.model_validate(json.loads(payload))
        if rebuilt.signing_payload() != payload:
            # The bytes parse, but they are not the canonical encoding of what they parse
            # to. Today no such bytes exist — the only source of a valid signature is
            # `signing_payload()` on a validated model — and the day a signature arrives
            # from a second implementation, a wire format or an HSM that signs a
            # caller-supplied buffer, this is what stops `{"max_targets":1,"max_targets":9999}`
            # from parsing as 9999 while the reader believed it signed 1.
            raise ValueError(
                "signed bytes are not the canonical encoding of the capability they parse to; "
                "duplicate keys, unknown fields or a non-canonical ordering would let two "
                "readers disagree about what was signed"
            )
        return rebuilt

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def time_status(self, now: datetime | None = None) -> str:
        moment = now or utcnow()
        if moment < self.not_before:
            return "not_yet_valid"
        if moment >= self.expires_at:
            return "expired"
        return "valid"

    def remaining(self, now: datetime | None = None) -> timedelta:
        return self.expires_at - (now or utcnow())

    def authorizes(
        self,
        *,
        operation: OperationClass,
        target_fingerprint: str,
        now: datetime | None = None,
    ) -> AuthorizationDecision:
        """Whether this capability permits this operation against this exact target.

        Returns a decision object rather than a boolean so a refusal can be logged with
        its reason. "Denied" and "denied because the target changed since approval" are
        very different events for an operator.
        """
        moment = now or utcnow()
        reasons: list[str] = []

        if self.is_revoked:
            reasons.append(f"capability revoked at {self.revoked_at}: {self.revocation_reason}")
        status = self.time_status(moment)
        if status == "expired":
            reasons.append(f"capability expired at {self.expires_at.isoformat()}")
        elif status == "not_yet_valid":
            reasons.append(f"capability is not valid until {self.not_before.isoformat()}")

        if operation in self.forbidden_operations:
            reasons.append(f"{operation.value} is explicitly forbidden by this capability")
        elif operation not in self.permitted_operations:
            reasons.append(
                f"{operation.value} is not among the permitted operations "
                f"({sorted(op.value for op in self.permitted_operations)})"
            )

        if target_fingerprint not in {target.fingerprint for target in self.targets}:
            reasons.append(
                "target fingerprint does not match any approved target: either this target "
                "was never approved, or its state changed since approval"
            )

        blocking = [c for c in self.stop_conditions if c.is_blocking]
        return AuthorizationDecision(
            permitted=not reasons,
            capability_id=self.capability_id,
            operation=operation,
            target_fingerprint=target_fingerprint,
            evaluated_at=moment,
            denial_reasons=tuple(reasons),
            stop_conditions_to_check=tuple(c.condition for c in blocking),
        )


class AuthorizationDecision(BaseModel):
    """The outcome of checking a capability. Always recorded, permitted or not."""

    model_config = ConfigDict(frozen=True)

    permitted: bool
    capability_id: CapabilityId
    operation: OperationClass
    target_fingerprint: str
    evaluated_at: datetime
    denial_reasons: tuple[str, ...] = ()
    stop_conditions_to_check: tuple[str, ...] = ()

    def render(self) -> str:
        if self.permitted:
            checks = (
                f" Stop conditions to verify: {', '.join(self.stop_conditions_to_check)}."
                if self.stop_conditions_to_check
                else ""
            )
            return f"PERMITTED: {self.operation.value} under {self.capability_id}.{checks}"
        return f"DENIED: {self.operation.value} — " + "; ".join(self.denial_reasons)
