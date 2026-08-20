"""Who may approve what, and how well they must be known to do it.

Two independent gates, and they answer different questions:

**Permission** — does this person's role entitle them to approve this class of operation?
A lead may authorize a rehearsal; a lead alone may not authorize something that needs a
legal basis. Checked against the roles the *provider* attached to the principal, never
against a role string the caller supplied.

**Assurance** — is the identity established well enough for a decision this consequential?
This is the gate that matters most in the current state of the system, because there is no
real identity provider yet. A development principal can approve a simulation and nothing
else. That is what turns "we have not built authentication" from a documented gap into a
runtime refusal, and it is the difference between a caveat somebody has to read and a
control that cannot be forgotten.

Neither gate replaces dual control; both compose with it. Two authenticated people at
adequate assurance with the right roles is the bar, and previously the bar was two distinct
strings.
"""

from __future__ import annotations

from nemesis.core.authorization import IRREVERSIBLE_OPERATIONS, LegalBasis, OperationClass
from nemesis.core.identity import AssuranceLevel, Principal, Role

APPROVAL_ROLES: dict[OperationClass, frozenset[Role]] = {
    OperationClass.SIMULATION: frozenset({Role.INVESTIGATION_LEAD}),
    OperationClass.PROVIDER_NOTIFICATION: frozenset({Role.INVESTIGATION_LEAD}),
    OperationClass.TAKEDOWN_REQUEST_DRAFT: frozenset({Role.INVESTIGATION_LEAD}),
    OperationClass.EVIDENCE_EXPORT: frozenset({Role.INVESTIGATION_LEAD, Role.LEGAL_REVIEWER}),
    # Everything below needs a legal basis, so a lead alone cannot authorize it. The
    # separation is the point: the person who wants the operation and the person who
    # judges whether we are entitled to it should not be the same role.
    OperationClass.REGISTRAR_SUSPENSION: frozenset({Role.LEGAL_REVIEWER}),
    OperationClass.HOSTING_TERMINATION: frozenset({Role.LEGAL_REVIEWER}),
    OperationClass.ACCOUNT_SUSPENSION: frozenset({Role.LEGAL_REVIEWER}),
    OperationClass.EXCHANGE_NOTIFICATION: frozenset({Role.LEGAL_REVIEWER}),
    OperationClass.ASSET_FREEZE_REQUEST: frozenset({Role.LEGAL_REVIEWER}),
    OperationClass.DOMAIN_SEIZURE: frozenset({Role.LEGAL_REVIEWER}),
    OperationClass.SINKHOLE: frozenset({Role.LEGAL_REVIEWER}),
    OperationClass.LAW_ENFORCEMENT_REFERRAL: frozenset({Role.LEGAL_REVIEWER}),
    OperationClass.JUDICIAL_SEIZURE_PACKAGE: frozenset({Role.LEGAL_REVIEWER}),
}
"""Roles entitled to approve each operation class.

``ANALYST`` appears nowhere: an analyst requests, and requesting is not approving. Nor does
``AUDITOR``, so that oversight never requires the ability to authorize, or ``OPERATOR``, so
that the person who executes is not by default the person who decided.
"""

REQUEST_ROLES: frozenset[Role] = frozenset(
    {Role.ANALYST, Role.INVESTIGATION_LEAD, Role.LEGAL_REVIEWER}
)

MINIMUM_ASSURANCE: dict[OperationClass, AssuranceLevel] = {
    # A rehearsal touches nothing, so a development identity may authorize one. This single
    # entry is what keeps the demonstration runnable without pretending it is authenticated.
    OperationClass.SIMULATION: AssuranceLevel.DEVELOPMENT,
    # A draft touches nothing by itself, and exists so that a human can send it. The floor
    # therefore tracks whether the artifact is meant to leave the platform, not whether the
    # adapter makes contact — every adapter here makes none, and that will not always hold.
    OperationClass.PROVIDER_NOTIFICATION: AssuranceLevel.SINGLE_FACTOR,
    OperationClass.TAKEDOWN_REQUEST_DRAFT: AssuranceLevel.SINGLE_FACTOR,
    OperationClass.EVIDENCE_EXPORT: AssuranceLevel.MULTI_FACTOR,
}
"""The floor an approver's identity must clear, per operation class.

Anything not listed falls to :data:`DEFAULT_MINIMUM_ASSURANCE`. That default is deliberately
the strictest level: an operation class added later inherits the tightest bar rather than
the loosest, so forgetting to add an entry fails closed.
"""

DEFAULT_MINIMUM_ASSURANCE: AssuranceLevel = AssuranceLevel.HARDWARE_BACKED
"""What an unlisted operation class requires.

Set at the top because the operations that are unlisted today are seizures, sinkholes and
asset freezes. If somebody implements one and forgets the table, the failure should be that
nobody can authorize it.
"""


def minimum_assurance_for(operation: OperationClass) -> AssuranceLevel:
    return MINIMUM_ASSURANCE.get(operation, DEFAULT_MINIMUM_ASSURANCE)


class AuthorizationPolicyError(PermissionError):
    """A principal was not entitled to the decision they attempted.

    A ``PermissionError`` rather than a ``ValueError``: this is not a malformed argument to
    be corrected and retried, it is a person being told no.
    """


def check_may_request(principal: Principal) -> None:
    """Requesting is not approving, and needs only a role that runs investigations."""
    if not principal.roles & REQUEST_ROLES:
        raise AuthorizationPolicyError(
            f"{principal.describe()} holds no role entitled to request an authorization; "
            f"one of {sorted(role.value for role in REQUEST_ROLES)} is required"
        )


def check_may_reject(principal: Principal) -> None:
    """Refusing is deliberately less restricted than approving.

    Anyone entitled to look at a request may kill it. Requiring the approval role to refuse
    would leave a request that nobody qualified can review sitting open rather than closed,
    and it would stop an investigation lead from stopping something they can see is wrong
    merely because the class needs a lawyer to *permit*. Refusal is the safe direction, and
    controls should not be symmetric about a direction that is not.
    """
    if not principal.roles & (REQUEST_ROLES | {Role.AUDITOR}):
        raise AuthorizationPolicyError(
            f"{principal.describe()} holds no role entitled to review this request"
        )


def check_may_approve(principal: Principal, operations: frozenset[OperationClass]) -> None:
    """Whether this principal may approve a request for these operation classes.

    Every class must be permitted. A capability naming several operations is approved once,
    so the approver must be entitled to the whole of it — approving the reversible half of a
    grant that also carries a seizure is not a partial approval, it is an approval.
    """
    for operation in sorted(operations, key=lambda item: item.value):
        permitted = APPROVAL_ROLES.get(operation, frozenset())
        if not principal.roles & permitted:
            raise AuthorizationPolicyError(
                f"{principal.describe()} may not approve {operation.value}; "
                f"it requires one of {sorted(role.value for role in permitted)}"
                + (
                    " — this class needs a legal basis, which is a separate judgement from "
                    "whether the investigation wants it"
                    if operation
                    not in {
                        OperationClass.SIMULATION,
                        OperationClass.PROVIDER_NOTIFICATION,
                        OperationClass.TAKEDOWN_REQUEST_DRAFT,
                    }
                    else ""
                )
            )

        floor = minimum_assurance_for(operation)
        if principal.assurance < floor:
            raise AuthorizationPolicyError(
                f"{principal.describe()} is not established well enough to approve "
                f"{operation.value}: it requires {floor.name.lower()} and this identity is "
                f"{principal.assurance.name.lower()}."
                + (
                    " This platform has no real identity provider yet, so development "
                    "principals can authorize a rehearsal and nothing else. That refusal "
                    "is the control, not a configuration problem to work around."
                    if principal.is_development_identity
                    else ""
                )
            )


def check_dual_control(
    approvers: frozenset[str], required: int, operations: frozenset[OperationClass]
) -> None:
    """Distinct *authenticated* identities, not distinct strings.

    The gateway already refuses a requester who approves their own request. This adds the
    count, checked against subjects a registered issuer asserted rather than names a caller
    typed.

    **What that is worth today, stated precisely.** This counts distinct subjects, so it is
    exactly as strong as the guarantee that one human cannot obtain two subjects. The only
    issuer registered in this repository is a development fixture that mints a fresh subject
    for any display name presented, checking no credential — so one person enrolling twice
    clears dual control. That is not a defect in this function; it is what "we have no
    identity provider" means at this layer, and no code here can fix it.

    It is also unreachable for anything NEMESIS can currently perform:
    ``required_approvals_for`` returns 1 for every class in ``MVP_IMPLEMENTED_OPERATIONS``,
    so the two-approver path exists only for ``REQUIRES_LEGAL_AUTHORITY`` classes that have
    no adapter. Kept and called anyway, because the day a class needs two people is not the
    day to be writing this.
    """
    if len(approvers) < required:
        irreversible = operations & IRREVERSIBLE_OPERATIONS
        raise AuthorizationPolicyError(
            f"{required} distinct authenticated approver(s) required, {len(approvers)} "
            "supplied"
            + (
                f"; {sorted(op.value for op in irreversible)} cannot be undone by us"
                if irreversible
                else ""
            )
        )


def check_legal_basis_reviewed(approvers: frozenset[Role], legal_basis: LegalBasis) -> None:
    """Anything resting on a legal instrument needs somebody qualified to read it.

    A court order or a statutory notice is a document with conditions in it. An
    investigation lead confirming that they want the outcome is not the same as somebody
    confirming that we are entitled to it.
    """
    needs_review = legal_basis in {
        LegalBasis.COURT_ORDER,
        LegalBasis.LAW_ENFORCEMENT_REQUEST,
        LegalBasis.REGULATORY_AUTHORITY,
        LegalBasis.STATUTORY_NOTICE_AND_ACTION,
    }
    if needs_review and Role.LEGAL_REVIEWER not in approvers:
        raise AuthorizationPolicyError(
            f"a capability resting on {legal_basis.value} requires a legal reviewer among "
            "its approvers; no approver holds that role"
        )
