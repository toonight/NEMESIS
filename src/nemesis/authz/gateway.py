"""The Human Authorization Gateway: where a proposed effect becomes an authorized one.

Invariant 7 says no real-world effect happens because an agent asked for it. This module is
the seam where that is decided. It holds the four-step lifecycle — request, decide, issue,
revoke — and it is the only place a signature over a capability is produced.

The shape of the API carries the control. An agent can construct an
:class:`ApprovalRequest`; that is the point, since the planner must be able to propose
options it is not permitted to perform. It cannot produce an
:class:`~nemesis.core.authorization.AuthorizationCapability` that survives verification,
because :meth:`AuthorizationGateway.issue` needs a
:class:`~nemesis.authz.keys.CapabilitySigner`, and a capability signed by any other key is
rejected by the Effects plane's public key with a reason naming the wrong key.

**Verification is offline; revocation is not.** :func:`verify_capability` takes a
capability, a public key and a clock, and decides authenticity and structural validity from
those three alone — no store, no gateway instance, no network. That is what lets the Effects
plane verify while holding nothing else (invariant 8). Revocation cannot work that way:
withdrawing an authority already granted is new information created after signing, so it
necessarily lives in state, and a holder of the signed bytes will keep verifying them
forever. This is precisely why the revocation fields are excluded from
:meth:`~nemesis.core.authorization.AuthorizationCapability.signing_payload` — if revoking
changed the signed bytes, a revoked capability would become cryptographically
indistinguishable from a forged one, and the operator investigating a refused operation
could no longer tell "we withdrew this" from "someone made this up". The cost of that
choice is the asymmetry: anything consulting a capability must check
:class:`RevocationRegistry` separately, and a component that cannot reach the registry
cannot honour a revocation at all. Short expiries are the mitigation, not the registry.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Final, Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.authz.attestation import PrincipalVerifier
from nemesis.authz.keys import CapabilitySigner, CapabilitySigningKey, CapabilityVerifyingKey
from nemesis.authz.rbac import (
    check_dual_control,
    check_legal_basis_reviewed,
    check_may_approve,
    check_may_reject,
    check_may_request,
)
from nemesis.authz.verification import CapabilityVerification, verify_capability
from nemesis.core.authorization import (
    GENESIS_HASH,
    IRREVERSIBLE_OPERATIONS,
    Approval,
    AuthorizationCapability,
    LegalBasis,
    OperationClass,
    Revocation,
    StopCondition,
    TargetFingerprint,
)
from nemesis.core.identity import IdentityAssertion, Principal
from nemesis.core.ids import ActorId, AuditId, CapabilityId, CaseId, IdPrefix, new_id
from nemesis.core.temporal import utcnow
from nemesis.ports.authorization import ChainTip, RevocationLedger

MAX_CAPABILITY_LIFETIME: Final = timedelta(hours=24)
"""Ceiling on how long any capability may live.

A capability that outlives the situation that justified it is a standing permission wearing
an expiry date, which is the thing invariant 9 exists to prevent. Twenty-four hours is a
policy choice, not a derived number: it is short enough that a forgotten grant lapses within
one working day, and the demonstration scenario asks for four hours.
"""


def required_approvals_for(operations: Iterable[OperationClass]) -> int:
    """How many distinct humans must agree before these operations may be authorized.

    Two for anything we cannot undo. One approver plus one mistake is a permanent effect on
    infrastructure that may turn out to belong to someone else — the failure this threshold
    exists to make expensive.
    """
    return 2 if set(operations) & IRREVERSIBLE_OPERATIONS else 1


class AuthorizationError(Exception):
    """Refusal by the gateway. Raised, not returned: none of these is a normal outcome."""


class UnknownRequestError(AuthorizationError):
    """No such approval request. Issuing against an id the gateway never saw is forgery."""


class DuplicateApproverError(AuthorizationError):
    """One person supplying more than one decision on the same request."""


class SelfApprovalError(AuthorizationError):
    """The requester approving their own request."""


class InsufficientApprovalsError(AuthorizationError):
    """Issuance attempted before the approval threshold was met."""


class AlreadyDecidedError(AuthorizationError):
    """A decision arriving after the request was rejected or already issued."""


class RequestState(StrEnum):
    """Where a request stands. Rejection and issuance are both terminal."""

    PENDING = "pending"
    APPROVED = "approved"
    """Threshold met, nothing signed yet. A separate state because approving and issuing are
    separate acts: the human decides, the key mints, and the gap between them is auditable."""

    REJECTED = "rejected"
    ISSUED = "issued"


class ApprovalRequest(BaseModel):
    """What is being asked for, by whom, and on what grounds.

    Frozen: the thing approvers read must be the thing that was approved. A request that
    could be edited between the reading and the decision would make every approval a
    signature on unknown terms.

    Carries the identifier the capability will be issued under. One id spans the proposal,
    the decisions and the grant, so the audit trail joins without a correlation table, and a
    second issuance under the same id is detectable as a replay rather than looking like an
    unrelated capability.
    """

    model_config = ConfigDict(frozen=True)

    capability_id: CapabilityId
    case_id: CaseId
    audit_id: AuditId

    requested_by: ActorId
    """Who asked. Usually an agent — the disruption planner proposing an option. Recorded
    because "an agent requested this" and "an analyst requested this" are different facts
    about how much independent thought preceded the request."""

    requested_at: datetime
    justification: Annotated[str, Field(min_length=1, max_length=8000)]
    """Why this operation, against these targets, now. What the approver actually reads."""

    targets: tuple[TargetFingerprint, ...]
    requested_operations: frozenset[OperationClass]
    forbidden_operations: frozenset[OperationClass] = frozenset()

    jurisdictions: tuple[str, ...]
    legal_basis: LegalBasis
    legal_authority_reference: str | None = None

    max_targets: Annotated[int, Field(ge=1)]
    max_effect_description: Annotated[str, Field(min_length=1)]
    lifetime: timedelta
    stop_conditions: tuple[StopCondition, ...] = ()

    supporting_evidence: tuple[str, ...] = ()
    """Evidence ids offered to the approver. An approval citing no evidence at all is
    visible as such rather than being assumed to have rested on something."""

    required_approvals: Annotated[int, Field(ge=1)] = 1

    @model_validator(mode="after")
    def _check_request_can_be_granted(self) -> Self:
        """Reject at request time whatever could never be issued.

        These checks mirror :class:`~nemesis.core.authorization.AuthorizationCapability`'s
        own validation deliberately. Discovering at issuance that a request was unissuable
        means a human has already spent attention approving something impossible, and the
        habit of approving requests that then fail is how approval becomes a formality.
        """
        if not self.targets:
            raise ValueError("a request must name at least one target")
        if len(self.targets) > self.max_targets:
            raise ValueError(
                f"request names {len(self.targets)} targets but max_targets is {self.max_targets}"
            )
        if not self.requested_operations:
            raise ValueError("a request that asks for nothing is not a request")

        overlap = self.requested_operations & self.forbidden_operations
        if overlap:
            raise ValueError(
                f"operations both requested and forbidden: {sorted(op.value for op in overlap)}"
            )

        if self.lifetime <= timedelta(0):
            raise ValueError("a capability must be valid for a positive interval")

        minimum = required_approvals_for(self.requested_operations)
        if self.required_approvals < minimum:
            raise ValueError(
                f"{sorted(op.value for op in self.requested_operations & IRREVERSIBLE_OPERATIONS)} "
                f"require at least {minimum} approvers"
            )

        beyond_simulation = self.requested_operations - {OperationClass.SIMULATION}
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


class RequestStatus(BaseModel):
    """A readable snapshot of one request: what was asked, what was decided, what was issued.

    Rejections are carried here alongside approvals and are never dropped. The record of
    what an analyst refused, and why, is as operationally important as the record of what
    they allowed — the demonstration scenario turns on exactly that.
    """

    model_config = ConfigDict(frozen=True)

    request: ApprovalRequest
    decisions: tuple[Approval, ...]
    state: RequestState
    capability: AuthorizationCapability | None = None

    @property
    def granted(self) -> tuple[Approval, ...]:
        return tuple(decision for decision in self.decisions if decision.decision)

    @property
    def refused(self) -> tuple[Approval, ...]:
        return tuple(decision for decision in self.decisions if not decision.decision)


class RevocationOracle(Protocol):
    """The revocation check the Effects plane consults before acting.

    Separate from verification because it is the one part that cannot be answered from the
    capability's own bytes. Kept as a protocol so a deployment can back it with a shared
    store: an in-memory registry that only the issuing process can see would let a revoked
    capability stay usable everywhere else.
    """

    def is_revoked(self, capability_id: CapabilityId) -> bool: ...

    def revocation_of(self, capability_id: CapabilityId) -> Revocation | None: ...


class RevocationRegistry:
    """In-memory revocation list. `IMPLEMENTED`, and process-local.

    Adequate for the MVP, where issuance and execution share a process. A deployment that
    splits them needs a shared, replicated implementation of :class:`RevocationOracle`;
    until then, expiry rather than revocation is what actually bounds a capability, which is
    the reason lifetimes are capped at :data:`MAX_CAPABILITY_LIFETIME`.
    """

    __slots__ = ("_revocations",)

    def __init__(self) -> None:
        self._revocations: dict[str, Revocation] = {}

    def tip(self) -> ChainTip:
        """Where the next revocation attaches."""
        if not self._revocations:
            return ChainTip(0, GENESIS_HASH)
        last = max(self._revocations.values(), key=lambda r: r.sequence)
        return ChainTip(last.sequence + 1, last.chain_hash())

    def record(self, revocation: Revocation) -> Revocation:
        """Record a withdrawal. The earliest one wins.

        Re-revoking must not move the effective time later: if it did, a second revocation
        could be used to narrow the window in which the first one applied, and an operation
        performed in between would retroactively look authorized.
        """
        existing = self._revocations.get(revocation.capability_id)
        if existing is not None and existing.revoked_at <= revocation.revoked_at:
            return existing
        self._revocations[revocation.capability_id] = revocation
        return revocation

    def is_revoked(self, capability_id: CapabilityId) -> bool:
        return capability_id in self._revocations

    def revocation_of(self, capability_id: CapabilityId) -> Revocation | None:
        return self._revocations.get(capability_id)

    def revocations(self) -> tuple[Revocation, ...]:
        return tuple(self._revocations.values())


class AuthorizationGateway:
    """The control-plane service that turns human decisions into signed capabilities.

    Construction requires a :class:`~nemesis.authz.keys.CapabilitySigner`. There is no
    default, no lazily-generated key and no unsigned issuance path, so a caller that has not
    been handed signing authority cannot mint anything, and the question "who can issue?"
    reduces to "who was given the signer?" — a question about deployment rather than about
    what a model was told.
    """

    __slots__ = (
        "_capabilities",
        "_clock",
        "_decisions",
        "_identity",
        "_max_lifetime",
        "_requests",
        "_revocations",
        "_signer",
        "_verifying_key",
    )

    def __init__(
        self,
        signer: CapabilitySigner,
        *,
        identity: PrincipalVerifier,
        verifying_key: CapabilityVerifyingKey | None = None,
        max_lifetime: timedelta = MAX_CAPABILITY_LIFETIME,
        clock: Callable[[], datetime] = utcnow,
        revocations: RevocationLedger | None = None,
    ) -> None:
        if verifying_key is None:
            if not isinstance(signer, CapabilitySigningKey):
                raise ValueError(
                    "an out-of-process signer must be paired with its verifying key; the "
                    "gateway cannot derive a public key it was not given"
                )
            verifying_key = signer.verifying_key
        if verifying_key.key_id != signer.key_id:
            raise ValueError(
                f"verifying key {verifying_key.key_id!r} does not match signer "
                f"{signer.key_id!r}: capabilities would be issued that nobody can verify"
            )

        self._signer = signer
        self._identity = identity
        self._verifying_key = verifying_key
        self._max_lifetime = max_lifetime
        self._clock = clock
        self._requests: dict[str, ApprovalRequest] = {}
        self._decisions: dict[str, list[Approval]] = {}
        self._capabilities: dict[str, AuthorizationCapability] = {}
        self._revocations = revocations if revocations is not None else RevocationRegistry()

    @property
    def verifying_key(self) -> CapabilityVerifyingKey:
        """The public key to hand to the Effects plane. Deliberately the only key exposed."""
        return self._verifying_key

    @property
    def revocations(self) -> RevocationLedger:
        return self._revocations

    def _establish(self, assertion: IdentityAssertion) -> Principal:
        """The only door identities come through.

        A :class:`~nemesis.core.identity.Principal` is an ordinary model: any caller could
        build one claiming hardware-backed assurance from an issuer named ``corporate-sso``,
        and an audit did exactly that and received a genuine signed capability in return.
        The capability was authentic; the identity behind it had never been checked. So the
        gateway no longer accepts one. It accepts a signed assertion and asks the verifier —
        which knows the issuer allowlist, the audience, the validity window and the ceiling
        this deployment puts on each issuer — what that assertion actually establishes.
        """
        return self._identity.verify(assertion, now=self._clock())

    # -- request ---------------------------------------------------------------

    def request(
        self,
        *,
        case_id: CaseId,
        audit_id: AuditId,
        requested_by: IdentityAssertion,
        justification: str,
        targets: Sequence[TargetFingerprint],
        operations: Iterable[OperationClass],
        jurisdictions: Sequence[str],
        legal_basis: LegalBasis,
        max_effect_description: str,
        lifetime: timedelta,
        legal_authority_reference: str | None = None,
        forbidden_operations: Iterable[OperationClass] = (),
        max_targets: int | None = None,
        stop_conditions: Sequence[StopCondition] = (),
        supporting_evidence: Sequence[str] = (),
        requested_at: datetime | None = None,
    ) -> ApprovalRequest:
        """Record what is being asked for and why. Grants nothing.

        ``requested_by`` is a :class:`Principal` rather than an identifier, because an
        identifier is a claim and this record is supposed to say who asked.

        Raises if the principal holds no role entitled to request one.

        ``max_targets`` defaults to the number of targets named. Widening it is a
        deliberate act by the requester and is visible to the approver, which is the point
        of having a ceiling independent of the target list.
        """
        requester = self._establish(requested_by)
        check_may_request(requester)
        if lifetime > self._max_lifetime:
            raise AuthorizationError(
                f"requested lifetime {lifetime} exceeds the ceiling {self._max_lifetime}: "
                "an authority that outlives the situation justifying it is a standing "
                "permission"
            )

        requested = frozenset(operations)
        request = ApprovalRequest(
            capability_id=new_id(IdPrefix.CAPABILITY),
            case_id=case_id,
            audit_id=audit_id,
            requested_by=requester.actor_id,
            requested_at=requested_at or self._clock(),
            justification=justification,
            targets=tuple(targets),
            requested_operations=requested,
            forbidden_operations=frozenset(forbidden_operations),
            jurisdictions=tuple(jurisdictions),
            legal_basis=legal_basis,
            legal_authority_reference=legal_authority_reference,
            max_targets=max_targets if max_targets is not None else len(targets),
            max_effect_description=max_effect_description,
            lifetime=lifetime,
            stop_conditions=tuple(stop_conditions),
            supporting_evidence=tuple(supporting_evidence),
            required_approvals=required_approvals_for(requested),
        )
        # A deep copy is retained and a separate object is returned. The two must not be
        # the same instance: `request()` hands its result to the caller who asked for the
        # authority, and `issue()` reads the retained record afterwards. When both were one
        # object, a requester could have a rehearsal approved and then edit the record the
        # approver had signed off on — an adversarial review turned an approved `SIMULATION`
        # into a `PROVIDER_NOTIFICATION` capability that drafted a document, without
        # touching a key. Frozen models are no defence: `__dict__` is still there.
        self._requests[request.capability_id] = request.model_copy(deep=True)
        self._decisions[request.capability_id] = []
        return request

    # -- decide ----------------------------------------------------------------

    def approve(
        self,
        capability_id: CapabilityId,
        *,
        approver: IdentityAssertion,
        rationale: str,
        reviewed_evidence: Sequence[str] = (),
        decided_at: datetime | None = None,
    ) -> Approval:
        """Record one human's assent."""
        return self._decide(
            capability_id,
            approver=approver,
            rationale=rationale,
            reviewed_evidence=reviewed_evidence,
            decided_at=decided_at,
            decision=True,
        )

    def reject(
        self,
        capability_id: CapabilityId,
        *,
        approver: IdentityAssertion,
        rationale: str,
        reviewed_evidence: Sequence[str] = (),
        decided_at: datetime | None = None,
    ) -> Approval:
        """Record one human's refusal, which ends the request.

        A rejection is terminal rather than something a later approval can outvote. If a
        refusal could be overridden by finding another approver, dual control would become a
        search for the most permissive reviewer.
        """
        return self._decide(
            capability_id,
            approver=approver,
            rationale=rationale,
            reviewed_evidence=reviewed_evidence,
            decided_at=decided_at,
            decision=False,
        )

    def _decide(
        self,
        capability_id: CapabilityId,
        *,
        approver: IdentityAssertion,
        rationale: str,
        reviewed_evidence: Sequence[str],
        decided_at: datetime | None,
        decision: bool,
    ) -> Approval:
        request = self._require(capability_id)
        decisions = self._decisions[capability_id]
        # Establish the identity before anything is decided with it. Everything below reads
        # roles, assurance and an actor id off `principal`; read off the assertion instead
        # and the decision rests on what the caller wrote rather than on what was checked.
        principal = self._establish(approver)

        if capability_id in self._capabilities:
            raise AlreadyDecidedError(
                f"{capability_id} has already been issued; a decision arriving afterwards "
                "cannot change a capability that is already in circulation"
            )
        if any(not existing.decision for existing in decisions):
            raise AlreadyDecidedError(f"{capability_id} was rejected; the request is closed")

        # Entitlement first, and asymmetric: approving needs the role and the assurance for
        # this operation class, rejecting needs only standing to review. Both are checked
        # against what the provider vouched for, never against a role the caller named.
        if decision:
            check_may_approve(principal, frozenset(request.requested_operations))
        else:
            check_may_reject(principal)

        if principal.actor_id == request.requested_by:
            raise SelfApprovalError(
                f"{principal.describe()} raised this request and cannot also decide it: a "
                "requester who can approve their own request is a requester who can issue "
                "capabilities"
            )
        if any(existing.approver == principal.actor_id for existing in decisions):
            raise DuplicateApproverError(
                f"{principal.describe()} has already decided on {capability_id}: one person "
                "cannot supply two of the required approvals"
            )

        approval = Approval(
            approver=principal.actor_id,
            approver_roles=principal.roles,
            approver_assurance=principal.assurance,
            authenticated_by=principal.authenticated_by,
            decided_at=decided_at or self._clock(),
            decision=decision,
            rationale=rationale,
            reviewed_evidence=tuple(reviewed_evidence),
        )
        # Retained separately from what the caller gets back, for the same reason as the
        # request above: adding `legal_reviewer` to a returned `Approval` used to change
        # what `issue()` saw, and produced a court-order capability nobody qualified had
        # reviewed.
        decisions.append(approval.model_copy(deep=True))
        return approval

    # -- issue -----------------------------------------------------------------

    def issue(
        self,
        capability_id: CapabilityId,
        *,
        issued_at: datetime | None = None,
        not_before: datetime | None = None,
    ) -> AuthorizationCapability:
        """Mint and sign the capability. The only path to a usable grant.

        Reachable only with the signer supplied at construction: an agent holding a request
        id and every field of the approval record still cannot produce bytes that verify.
        """
        request = self._require(capability_id)
        decisions = self._decisions[capability_id]

        if capability_id in self._capabilities:
            raise AlreadyDecidedError(
                f"{capability_id} has already been issued; re-issuing would put two live "
                "capabilities into circulation from one human decision"
            )
        if any(decision.decision is False for decision in decisions):
            raise AlreadyDecidedError(f"{capability_id} was rejected and cannot be issued")

        granted = [decision for decision in decisions if decision.decision]
        if len(granted) < request.required_approvals:
            raise InsufficientApprovalsError(
                f"{capability_id} needs {request.required_approvals} approval(s), has "
                f"{len(granted)}"
            )
        # Counted over distinct approvers rather than over decisions. `_decide` already
        # refuses a duplicate approver, so this is the second lock on the same door — and
        # the door is dual control, which is worth two locks. It also gives the refusal a
        # message that names the irreversible classes involved.
        check_dual_control(
            frozenset(decision.approver for decision in granted),
            request.required_approvals,
            frozenset(request.requested_operations),
        )
        # Asked of the assembled set rather than of each approver in turn, because the
        # question is whether anybody qualified read the instrument — which is not a
        # question any single decision can answer. It sat unwired until an audit noticed:
        # a court-order capability could be issued with no legal reviewer anywhere near it.
        check_legal_basis_reviewed(
            frozenset().union(*(decision.approver_roles for decision in granted)),
            request.legal_basis,
        )

        moment = issued_at or self._clock()
        start = not_before or moment
        # Measured against the clock, never against `issued_at`. Both `issued_at` and
        # `not_before` are caller-supplied, so bounding one by the other bounds nothing: a
        # review issued a capability stamped ten years in the future and got a grant valid
        # 3650 days after the real clock, past a ceiling documented as "one working day".
        # The window that matters is how long this authority is usable starting now.
        window = (start + request.lifetime) - self._clock()
        if window > self._max_lifetime:
            raise AuthorizationError(
                f"this grant would remain usable for {window}, beyond the "
                f"{self._max_lifetime} ceiling. An authority that outlives the situation "
                "justifying it is a standing permission, and a capability that becomes valid "
                "long after the decision authorizing it will not act in the situation the "
                "approver reviewed"
            )
        unsigned = AuthorizationCapability(
            capability_id=request.capability_id,
            case_id=request.case_id,
            audit_id=request.audit_id,
            issued_at=moment,
            not_before=start,
            expires_at=start + request.lifetime,
            targets=request.targets,
            permitted_operations=request.requested_operations,
            forbidden_operations=request.forbidden_operations,
            jurisdictions=request.jurisdictions,
            legal_basis=request.legal_basis,
            legal_authority_reference=request.legal_authority_reference,
            max_targets=request.max_targets,
            max_effect_description=request.max_effect_description,
            stop_conditions=request.stop_conditions,
            approvals=tuple(decisions),
            required_approvals=request.required_approvals,
        )
        # The signature is not part of what it covers, so attaching it afterwards cannot
        # invalidate it. Everything else in this object went through the model's validators
        # a line above; ``model_copy`` skips them, and adding one excluded field is the only
        # thing it is used for here.
        capability = unsigned.model_copy(
            update={"signature": self._signer.sign(unsigned.signing_payload())}
        )
        self._capabilities[capability_id] = capability
        return capability

    # -- verify ----------------------------------------------------------------

    def verify(
        self, capability: AuthorizationCapability, *, now: datetime | None = None
    ) -> CapabilityVerification:
        """Check a capability against this gateway's public key.

        Consults none of the gateway's state, by delegation to :func:`verify_capability`.
        A capability issued by one gateway verifies against any other holding the same
        public key, and against a bare key with no gateway at all.
        """
        return verify_capability(capability, self._verifying_key, now=now or self._clock())

    # -- revoke ----------------------------------------------------------------

    def revoke(
        self,
        capability_id: CapabilityId,
        reason: str,
        *,
        revoked_by: ActorId,
        revoked_at: datetime | None = None,
    ) -> Revocation:
        """Withdraw an authority already granted.

        The stored capability is replaced by a revoked view so that anything reading it from
        this gateway sees the withdrawal. Bytes already handed out are unaffected and keep
        verifying — deliberately, so that a revoked capability stays distinguishable from a
        forged one — which is why holders must consult :attr:`revocations` and not merely
        their own copy.
        """
        request = self._requests.get(capability_id)
        if request is None:
            raise UnknownRequestError(f"{capability_id} was never requested through this gateway")

        moment = revoked_at or self._clock()
        # Signed with the same key that issues capabilities, and chained onto whatever the
        # store already holds. The signature stops a forged withdrawal — a denial of service
        # on lawful action by anyone who can write the store. The chain stops the opposite
        # attack, which a signature does nothing about: an attacker who can add a row can
        # remove one, and a deleted revocation silently re-enables a withdrawn capability.
        tip = self._revocations.tip()
        unsigned = Revocation(
            sequence=tip.sequence,
            previous_hash=tip.hash,
            capability_id=capability_id,
            revoked_at=moment,
            revoked_by=revoked_by,
            reason=reason,
        )
        revocation = self._revocations.record(
            unsigned.model_copy(update={"signature": self._signer.sign(unsigned.signing_payload())})
        )

        issued = self._capabilities.get(capability_id)
        if issued is not None:
            self._capabilities[capability_id] = issued.model_copy(
                update={
                    "revoked_at": revocation.revoked_at,
                    "revocation_reason": revocation.reason,
                }
            )
        return revocation

    def is_revoked(self, capability_id: CapabilityId) -> bool:
        """The check the Effects plane consults. Needs state; cannot be answered offline."""
        return self._revocations.is_revoked(capability_id)

    # -- reading ---------------------------------------------------------------
    #
    # Every reader below hands out copies. The gateway's own records are what `issue()`
    # reads, so a reference escaping through a read method is the same defect as one
    # escaping through `request()`: a caller could hold the record, wait for the approval,
    # and edit what gets signed. Copying on read costs a little and removes the whole
    # question of who else has a reference.

    def status(self, capability_id: CapabilityId) -> RequestStatus:
        request = self._require(capability_id)
        decisions = tuple(
            decision.model_copy(deep=True) for decision in self._decisions[capability_id]
        )
        capability = self._capabilities.get(capability_id)
        if capability is not None:
            capability = capability.model_copy(deep=True)

        if capability is not None:
            state = RequestState.ISSUED
        elif any(not decision.decision for decision in decisions):
            state = RequestState.REJECTED
        elif sum(decision.decision for decision in decisions) >= request.required_approvals:
            state = RequestState.APPROVED
        else:
            state = RequestState.PENDING

        return RequestStatus(
            request=request.model_copy(deep=True),
            decisions=decisions,
            state=state,
            capability=capability,
        )

    def pending(self) -> tuple[ApprovalRequest, ...]:
        """Requests still waiting on a human. The analyst's queue."""
        return tuple(
            request.model_copy(deep=True)
            for capability_id, request in self._requests.items()
            if self.status(capability_id).state is RequestState.PENDING
        )

    def capability(self, capability_id: CapabilityId) -> AuthorizationCapability | None:
        capability = self._capabilities.get(capability_id)
        return None if capability is None else capability.model_copy(deep=True)

    def _require(self, capability_id: CapabilityId) -> ApprovalRequest:
        """The retained record, for internal use only. Never returned to a caller as-is."""
        request = self._requests.get(capability_id)
        if request is None:
            raise UnknownRequestError(
                f"{capability_id} was never requested through this gateway; a decision or "
                "issuance against an unknown id is a fabricated approval trail"
            )
        return request
