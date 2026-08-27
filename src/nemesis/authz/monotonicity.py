"""Authority, made into an object you can measure before and after.

NEMESIS already refuses, in a dozen separate places, to let an untrusted party gain authority:
the move vocabulary has no verb for it, the collaboration plane cannot reach the gateway, a
challenger's whole verdict set only subtracts, a supervisor's directive vocabulary does nothing,
a research hint is redacted, an approval reply is an *intent*. Each of those is enforced where it
lives, and each has its own test.

What did not exist was the property they are all instances of, stated once and checkable
directly:

    **Peer-originated information can never increase authority.**
    ``authority_after_untrusted_input ⊑ authority_before_untrusted_input``

This module makes that comparison mechanical. :func:`snapshot` reduces the live authorization
state — the signed capability plus the envelope's remaining autonomy — to a frozen, comparable
value, and :meth:`AuthoritySnapshot.widenings_from` names every way one snapshot grants more than
another. A test can then feed the platform any hostile input at all and assert an empty tuple,
without knowing which of the dozen controls was the one that held.

**Why that is worth a module rather than an assertion in each test.** The controls are
individually strong and collectively unstated, and the failure mode this architecture keeps
finding in itself is exactly that shape: a refusal produced by a *different* control than the one
under test, which looks like the control working right up until the other one moves. An audit of
the effects verb found precisely that — the disclosure wall was missing from one branch and
target binding was refusing those requests for an unrelated reason. A property over the whole
authority state does not care which control refused; it cares that nothing got wider.

**What a snapshot deliberately does not include.** Anything a model can change legitimately:
what the graph holds, what claims exist, what an investigation believes, how much *pursuit*
budget is left. Those are supposed to move — an investigation that learns nothing is a failed
investigation. Authority is the closed set below, and it is closed because every member of it is
something no untrusted party may ever move in the permissive direction.

**Not an enforcement point.** Nothing in the production path consults this module before acting:
the capability, the envelope ledger and the effects registry do the enforcing, and adding a
fourth gate that reads a summary of the other three would be a control derived from the controls
it is meant to check. This is an *observation* instrument — for tests, for the Breaker
(:mod:`nemesis.breaker`), and for an operator asking "did that session change what we are
allowed to do". A measurement that could itself permit something would be the wrong shape.

Status: `IMPLEMENTED`. Invariants AUTH-01 … AUTH-04, EFFECT-03 and MODEL-03 in
`docs/security/INVARIANTS.md` are stated in terms of it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from nemesis.core.authorization import AuthorizationCapability


class RemainingAutonomy(Protocol):
    """The half of authority that lives in a ledger rather than in the signed grant.

    A Protocol so this module does not import :class:`~nemesis.authz.envelope.AutonomyEnvelope`
    and become a dependency of it. Anything with these two members satisfies it, which is what
    lets a test snapshot a bare capability with no envelope at all.
    """

    @property
    def budget(self) -> int: ...

    @property
    def remaining(self) -> int: ...


class AuthoritySnapshot(BaseModel):
    """Everything an untrusted party could conceivably want more of, in one comparable value.

    Frozen, hashable-by-value and cheap: two snapshots taken either side of a hostile input are
    compared field by field, and any difference in the permissive direction is a defect with a
    name. Field order below is the order defects are reported in, deliberately — the grant comes
    before the ledger, because a widened grant is a design failure and a widened ledger is a
    counting failure, and an operator reading a list wants the first one first.
    """

    model_config = ConfigDict(frozen=True)

    capability_id: str
    permitted_operations: frozenset[str]
    forbidden_operations: frozenset[str]
    target_fingerprints: frozenset[str]
    """The bound fingerprints, not the entity ids. An entity id names *which* thing; a
    fingerprint names which thing *in which state*, and a stale approval respent against a
    target that has since changed hands is the attack this field exists to make visible."""

    not_before: datetime
    expires_at: datetime
    max_targets: int
    required_approvals: int
    approver_subjects: frozenset[str]
    """Who approved, by verified subject. Included because removing an approver is a widening
    even when nothing else changes: a two-approver grant re-presented as a one-approver grant
    authorizes the same operation on strictly less agreement."""

    revoked: bool
    autonomy_budget: int
    autonomy_remaining: int

    def widenings_from(self, earlier: AuthoritySnapshot) -> tuple[str, ...]:
        """Every way this snapshot grants more than ``earlier``. Empty means it does not.

        Returns findings rather than a boolean, for the reason
        :func:`~nemesis.evolution.memory.reads_as_an_instruction` and
        :func:`~nemesis.authz.anchor.verify_against_anchor` do: a control that answers "no" and
        cannot say why is a control nobody can act on or argue with.

        Narrowings are **not** reported. An investigation that spends autonomy, a grant that is
        revoked, an approver whose assertion expired — each makes the snapshot smaller, and each
        is the system working. Only the permissive direction is a finding.
        """
        defects: list[str] = []

        if self.capability_id != earlier.capability_id:
            defects.append(
                f"the capability changed identity: {earlier.capability_id} became "
                f"{self.capability_id}. A different grant is not a narrower one, and nothing "
                "untrusted may cause a substitution"
            )

        gained = self.permitted_operations - earlier.permitted_operations
        if gained:
            defects.append(f"operations newly permitted: {sorted(gained)}")

        dropped = earlier.forbidden_operations - self.forbidden_operations
        if dropped:
            defects.append(
                f"denials removed: {sorted(dropped)}. A forbidden operation always wins over a "
                "permission, so deleting one is the cheapest possible widening"
            )

        new_targets = self.target_fingerprints - earlier.target_fingerprints
        if new_targets:
            defects.append(
                f"{len(new_targets)} target binding(s) appeared that no approval covered"
            )

        if self.expires_at > earlier.expires_at:
            defects.append(
                f"the expiry moved later: {earlier.expires_at.isoformat()} became "
                f"{self.expires_at.isoformat()}"
            )
        if self.not_before < earlier.not_before:
            defects.append(
                f"the grant became valid earlier: {earlier.not_before.isoformat()} became "
                f"{self.not_before.isoformat()}"
            )
        if self.max_targets > earlier.max_targets:
            defects.append(
                f"the target ceiling rose from {earlier.max_targets} to {self.max_targets}"
            )
        if self.required_approvals < earlier.required_approvals:
            defects.append(
                f"the required approvals fell from {earlier.required_approvals} to "
                f"{self.required_approvals}: the same operation now needs less agreement"
            )

        lost_approvers = earlier.approver_subjects - self.approver_subjects
        if lost_approvers:
            defects.append(
                f"{len(lost_approvers)} approver(s) no longer appear on the grant, so it rests "
                "on less human agreement than it was issued with"
            )

        if earlier.revoked and not self.revoked:
            defects.append("a revoked capability came back: a withdrawal was undone")

        if self.autonomy_remaining > earlier.autonomy_remaining:
            defects.append(
                f"autonomous effects remaining rose from {earlier.autonomy_remaining} to "
                f"{self.autonomy_remaining}: spent budget was returned"
            )
        if self.autonomy_budget > earlier.autonomy_budget:
            defects.append(
                f"the autonomy budget itself rose from {earlier.autonomy_budget} to "
                f"{self.autonomy_budget}"
            )

        return tuple(defects)

    def is_no_wider_than(self, earlier: AuthoritySnapshot) -> bool:
        """The property in one word. Prefer :meth:`widenings_from` when reporting."""
        return not self.widenings_from(earlier)


def snapshot(
    capability: AuthorizationCapability, autonomy: RemainingAutonomy | None = None
) -> AuthoritySnapshot:
    """Reduce the live authorization state to a comparable value.

    ``autonomy`` is optional because authority exists without an envelope: a capability issued
    for one human-driven operation has no ledger, and a snapshot of it should not have to invent
    a budget of zero and then be indistinguishable from an exhausted one. Absent, both counters
    read ``-1`` — a value no real budget can take, so a comparison between a snapshot with an
    envelope and one without produces the ``capability changed identity`` style of loud
    disagreement rather than a silent apparent widening.
    """
    return AuthoritySnapshot(
        capability_id=capability.capability_id,
        permitted_operations=frozenset(op.value for op in capability.permitted_operations),
        forbidden_operations=frozenset(op.value for op in capability.forbidden_operations),
        target_fingerprints=frozenset(target.fingerprint for target in capability.targets),
        not_before=capability.not_before,
        expires_at=capability.expires_at,
        max_targets=capability.max_targets,
        required_approvals=capability.required_approvals,
        approver_subjects=frozenset(approval.approver for approval in capability.approvals),
        revoked=capability.revoked_at is not None,
        autonomy_budget=-1 if autonomy is None else autonomy.budget,
        autonomy_remaining=-1 if autonomy is None else autonomy.remaining,
    )


__all__ = ["AuthoritySnapshot", "RemainingAutonomy", "snapshot"]
