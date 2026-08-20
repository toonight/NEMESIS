"""When the platform incurs a legal obligation, and why it cannot discharge one itself.

:class:`~nemesis.core.evidence.ContentSafety.MANDATORY_REPORT` says the material "triggers a
legal reporting obligation" and that "escalation is a human decision, immediately". The
quarantine now enforces the first half — such material has no automated exit. This is the
other half, and it is the part that is not really about software:

    **The platform cannot discharge its own legal obligation.**

An obligation is opened by the platform and closed only by a named human holding the role that
makes their signature mean something. Nothing here closes one on its own, on a timer, or as a
side effect of anything being cleaned up. A system that could mark its own legal duty complete
would be a system whose compliance record is a record of its own convenience.

**The failure this is actually built against is silence.** An obligation nobody actively
refuses is not the dangerous case; an obligation that lands in a queue nobody reads is. So an
open obligation becomes *more* visible as it ages rather than less: :meth:`Register.overdue`
exists, :meth:`Register.render` leads with the oldest, and there is no way to acknowledge one
without recording who did it and when.

**What "closed" means here, stated narrowly.** It means a named person recorded that they
discharged the obligation, with a reference to the channel they used. It does **not** mean
NEMESIS verified the report was filed, accepted, or acted on — the platform cannot see any of
that, and a status that implied otherwise would be worse than none. The record is a record of
what a human said they did, which is exactly what an audit of a reporting obligation needs and
no more than the platform can honestly hold.

Status: `IMPLEMENTED` as a register and a refusal. The *procedure* — which authority, which
channel, which deadline in which jurisdiction — is a legal question this repository cannot
answer and must not guess at; a deployment configures :class:`Obligation.authority` and
:data:`DEFAULT_DEADLINE` from advice, and the defaults here are deliberately conservative
placeholders rather than a claim about any regime.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from nemesis.core.identity import Principal, Role
from nemesis.core.temporal import utcnow

MAY_DISCHARGE: Final[frozenset[Role]] = frozenset({Role.LEGAL_REVIEWER})
"""Who may record an obligation as discharged.

One role, deliberately. An investigation lead can decide what to investigate; whether a legal
duty has been met is a different competence, and letting the person who found the material
also close the obligation removes the only second pair of eyes in the process.
"""

DEFAULT_DEADLINE: Final = timedelta(hours=72)
"""How long an obligation may stay open before it is overdue.

**A placeholder, not legal advice.** Reporting windows vary by regime, material and
jurisdiction, and this repository cannot answer that question — 72 hours is chosen because it
is short enough to be uncomfortable, which is the correct direction for a default nobody has
reviewed yet. A deployment sets this from advice.
"""


class ObligationState(StrEnum):
    OPEN = "open"
    """Incurred and not yet discharged. The only state the platform can put one in."""

    DISCHARGED = "discharged"
    """A named human recorded that they reported it. **Not** a claim that the report was
    filed, accepted or acted on — the platform cannot see any of that."""


class EscalationError(RuntimeError):
    """The register refused. Its own type because a compliance refusal is not an outage."""


class Obligation(BaseModel):
    """One legal duty the platform has incurred and cannot itself satisfy."""

    model_config = ConfigDict(frozen=True)

    obligation_id: str
    artifact_id: str
    incurred_at: datetime
    deadline: datetime
    authority: str = Field(
        min_length=1,
        description="Who must be told. Deployment configuration, because which authority is "
        "owed a report is a question of jurisdiction and material, not of software.",
    )
    reason: str = Field(min_length=1)

    state: ObligationState = ObligationState.OPEN
    discharged_by: str | None = None
    discharged_at: datetime | None = None
    channel_reference: str | None = None
    """How the report was made — a case number, a submission id. Required to discharge, so
    "we handled it" cannot be recorded without something an auditor could follow."""

    def is_overdue(self, now: datetime) -> bool:
        return self.state is ObligationState.OPEN and now >= self.deadline

    def age(self, now: datetime) -> timedelta:
        return now - self.incurred_at

    def render(self, now: datetime) -> str:
        if self.state is ObligationState.DISCHARGED:
            return (
                f"{self.obligation_id}: discharged by {self.discharged_by} "
                f"({self.channel_reference}) — reported, not verified as filed"
            )
        marker = "OVERDUE" if self.is_overdue(now) else "open"
        return (
            f"{self.obligation_id}: {marker}, {self.age(now).days}d — owed to "
            f"{self.authority} — {self.reason}"
        )


class Register:
    """Every obligation the platform has incurred, and the refusal to close its own.

    Deliberately not a queue with a worker. Nothing drains this: an obligation leaves only
    when a named human says they discharged it, and the absence of an automated consumer is
    the control rather than a missing feature.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] = utcnow,
        deadline: timedelta = DEFAULT_DEADLINE,
    ) -> None:
        self._clock = clock
        self._deadline = deadline
        self._obligations: dict[str, Obligation] = {}

    def incur(self, *, artifact_id: str, authority: str, reason: str) -> Obligation:
        """Record that the platform now owes a report. The only thing it may do alone."""
        now = self._clock()
        obligation = Obligation(
            obligation_id=f"obl_{artifact_id}",
            artifact_id=artifact_id,
            incurred_at=now,
            deadline=now + self._deadline,
            authority=authority,
            reason=reason,
        )
        # Re-incurring on the same artifact must not restart its clock: an obligation whose
        # deadline moves every time the material is re-examined is an obligation that never
        # becomes overdue.
        self._obligations.setdefault(obligation.obligation_id, obligation)
        return self._obligations[obligation.obligation_id]

    def discharge(
        self, obligation_id: str, principal: Principal, *, channel_reference: str
    ) -> Obligation:
        """Record that a named human reported it. The platform cannot do this for itself."""
        if not (principal.roles & MAY_DISCHARGE):
            held = ", ".join(sorted(role.value for role in principal.roles)) or "no roles"
            raise EscalationError(
                f"{principal.describe()} holds {held}; discharging a reporting obligation "
                "needs a legal reviewer. Letting whoever found the material also close the "
                "duty removes the only second pair of eyes in the process"
            )
        if not channel_reference.strip():
            raise EscalationError(
                "a channel reference is required: 'we handled it' with nothing an auditor "
                "could follow is not a discharge record"
            )
        existing = self._obligations.get(obligation_id)
        if existing is None:
            raise EscalationError(f"no obligation {obligation_id!r} was ever incurred")
        if existing.state is ObligationState.DISCHARGED:
            raise EscalationError(
                f"{obligation_id} was already discharged by {existing.discharged_by}; "
                "re-closing it would overwrite the record of who actually did"
            )

        discharged = existing.model_copy(
            update={
                "state": ObligationState.DISCHARGED,
                "discharged_by": principal.actor_id,
                "discharged_at": self._clock(),
                "channel_reference": channel_reference.strip(),
            }
        )
        self._obligations[obligation_id] = discharged
        return discharged

    def open_obligations(self) -> tuple[Obligation, ...]:
        """Oldest first, because the dangerous one is the one that has been waiting."""
        return tuple(
            sorted(
                (o for o in self._obligations.values() if o.state is ObligationState.OPEN),
                key=lambda o: o.incurred_at,
            )
        )

    def overdue(self) -> tuple[Obligation, ...]:
        now = self._clock()
        return tuple(o for o in self.open_obligations() if o.is_overdue(now))

    def render(self) -> str:
        """Leads with what is overdue, because a report nobody reads is the failure mode."""
        now = self._clock()
        overdue = self.overdue()
        lines: list[str] = []
        if overdue:
            lines.append(
                f"!! {len(overdue)} REPORTING OBLIGATION(S) OVERDUE. NEMESIS cannot discharge "
                "these; a legal reviewer must."
            )
            lines += [f"   {o.render(now)}" for o in overdue]
        remaining = [o for o in self.open_obligations() if not o.is_overdue(now)]
        lines.append(f"{len(remaining)} obligation(s) open and within their window.")
        lines += [f"   {o.render(now)}" for o in remaining]
        if not self._obligations:
            lines.append("No reporting obligation has been incurred.")
        return "\n".join(lines)


__all__ = [
    "DEFAULT_DEADLINE",
    "MAY_DISCHARGE",
    "EscalationError",
    "Obligation",
    "ObligationState",
    "Register",
]
