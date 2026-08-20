"""The write path: how something outside gets into the Global Adversary Graph.

Every other surface in this platform reads. This one lets an authenticated principal put
material *in*, which makes it the single highest-risk route in the codebase — graph poisoning
is in the threat model, and an HTTP endpoint that appends to the adversary graph is the
mechanism that attack would use.

The design rests on one sentence, and everything else follows from it:

    **A submission is not an observation.**

It is an assertion by whoever submitted it. The distinction is not stylistic: an OBSERVATION
in this model is something a collector directly recorded with the artifact preserved, and
:class:`~nemesis.core.claims.Claim` *refuses to construct one without sealed evidence*. A
submission has no artifact in the vault — nobody collected anything, someone typed something —
so the domain model already makes the dangerous outcome unrepresentable. This module leans on
that rather than re-implementing it, and a test asserts the refusal holds.

What a submission becomes is a claim of kind ``HYPOTHESIS`` derived from ``EXTERNAL_REPORT``,
attributed to the principal that submitted it. That derivation existed in the model before
anything used it; the write path is what it was for.

Three more properties, each because the alternative is a specific attack:

**Identity is established, never asserted.** The same ``PrincipalVerifier`` the gateway uses.
An endpoint that accepted a submitter's name would let an attacker attribute their own
poisoning to somebody else — which is worse than anonymous submission, because it is
poisoning *with a scapegoat baked into the provenance*.

**Not every role may write.** An auditor's whole value is that oversight does not require the
ability to act, and a reader of the graph has no business appending to it.

**Rate limited per principal.** Not for capacity — for *cost*. Graph poisoning at machine
speed is a different attack from graph poisoning by hand, and a bucket that refuses is the
difference. It is per-principal rather than per-connection because an attacker controls their
connections and not their identity.

Status: `IMPLEMENTED` for submission-as-claim, and for the isolation that was missing when
this module was first written. Submissions then landed in one graph, which is why this
endpoint was recorded as not-a-product; :mod:`nemesis.api.tenancy` closed that with one store
per tenant, stamped from the registered issuer rather than from anything the caller sends.
The gap named here is gone, and this paragraph says so rather than leaving a stale warning
that would teach a reader to distrust the status labels.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from nemesis.core.claims import Claim, ClaimKind, DerivationKind, Statement
from nemesis.core.entities import EntityType
from nemesis.core.identity import Principal, Role
from nemesis.core.temporal import TemporalExtent, utcnow

MAY_SUBMIT: Final[frozenset[Role]] = frozenset({Role.ANALYST, Role.INVESTIGATION_LEAD})
"""Roles permitted to write into the graph.

Deliberately not every authenticated principal. ``AUDITOR`` is excluded because oversight
must not require the ability to act — the same reasoning that keeps an auditor from requesting
an authorization. ``LEGAL_REVIEWER`` and ``OPERATOR`` are excluded because neither reviews
intelligence for a living, and a role that never needs a capability should never hold it.
"""

DEFAULT_SUBMISSIONS_PER_HOUR: Final = 60
"""A ceiling on how fast one principal may append to the adversary graph.

A choice, not a measurement, and small on purpose. The limit is not about capacity: poisoning
a graph at machine speed is a different attack from doing it by hand, and this is the
difference between the two.
"""

SUBMISSION_NOTICE: Final = (
    "Recorded as a HYPOTHESIS derived from an EXTERNAL_REPORT, attributed to the submitting "
    "principal. It is not an observation, it is not evidence, and nothing here corroborates "
    "it: a submission is an assertion by whoever submitted it."
)


class SubmissionRefusedError(Exception):
    """The submission was not accepted, and the reason is safe to return.

    An exception rather than a returned verdict because a refused write must not fall through
    into the graph by a caller forgetting to check — the failure mode a boolean return invites.
    """

    def __init__(self, reason: str, *, status: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


class IncidentSubmission(BaseModel):
    """What an outside party may say. Deliberately narrow.

    No confidence figure, no attribution, no claim about who is responsible — those are
    conclusions this platform reaches from evidence, and accepting them over HTTP would let a
    submitter write conclusions into a graph that is supposed to derive them.
    """

    model_config = ConfigDict(frozen=True)

    entity_type: EntityType
    entity_key: str = Field(min_length=1, max_length=1024)
    observed_at: datetime
    summary: str = Field(min_length=1, max_length=2000)
    reporter_reference: str | None = Field(
        default=None,
        max_length=200,
        description="The submitter's own ticket or case number, so they can correlate. Opaque "
        "to NEMESIS and never interpreted.",
    )


class SubmissionReceipt(BaseModel):
    """What was recorded, and — as prominently — what it is not."""

    model_config = ConfigDict(frozen=True)

    claim_id: str
    submitted_by: str
    recorded_at: datetime
    kind: ClaimKind = ClaimKind.HYPOTHESIS
    derivation: DerivationKind = DerivationKind.EXTERNAL_REPORT
    notice: str = SUBMISSION_NOTICE
    is_evidence: bool = False
    corroborated: bool = False


class RateLimiter:
    """A per-principal ceiling on writes, refusing rather than queueing.

    Per *principal* and not per connection, because an attacker chooses their connections and
    does not choose their verified identity — a limit on the thing they control limits nothing.

    Refuses rather than delays: a queued write still lands, so a queue converts a rate limit
    into a slower version of the same poisoning.
    """

    def __init__(
        self,
        *,
        per_hour: int = DEFAULT_SUBMISSIONS_PER_HOUR,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._per_hour = per_hour
        self._clock = clock
        self._seen: dict[str, deque[datetime]] = {}

    def check(self, principal_id: str) -> None:
        """Record an attempt, or raise. Attempts count whether or not the write then succeeds.

        Counting the attempt rather than the success is deliberate: a limiter that only counted
        accepted writes would let an attacker probe at any rate by sending submissions designed
        to fail validation.
        """
        now = self._clock()
        window = now - timedelta(hours=1)
        history = self._seen.setdefault(principal_id, deque())
        while history and history[0] < window:
            history.popleft()
        if len(history) >= self._per_hour:
            raise SubmissionRefusedError(
                f"this principal has submitted {len(history)} times in the last hour, at the "
                f"ceiling of {self._per_hour}. Appending to the adversary graph at machine "
                "speed is a different act from doing it by hand, and the limit is the "
                "difference",
                status=429,
            )
        history.append(now)

    def remaining(self, principal_id: str) -> int:
        return max(0, self._per_hour - len(self._seen.get(principal_id, ())))


def submission_claim(
    submission: IncidentSubmission, principal: Principal, *, now: datetime | None = None
) -> Claim:
    """Turn a submission into the only kind of claim it is entitled to be.

    ``HYPOTHESIS`` from ``EXTERNAL_REPORT``, with no supporting evidence — because there is
    none. The domain model would refuse an ``OBSERVATION`` here anyway: an observation must
    cite sealed evidence, and nobody collected anything. That refusal is the real control and
    this function is only the thing that does not try to work around it.
    """
    moment = now or utcnow()
    return Claim.create(
        kind=ClaimKind.HYPOTHESIS,
        statement=Statement(
            subject=f"{submission.entity_type.value}:{submission.entity_key}",
            predicate="was_reported_as_involved_in_an_incident",
            obj=submission.summary,
            qualifiers=(
                {"reporter_reference": submission.reporter_reference}
                if submission.reporter_reference
                else {}
            ),
            natural_language=(
                f"{principal.describe()} reported {submission.entity_key} as involved in an "
                f"incident observed at {submission.observed_at.isoformat()}."
            ),
        ),
        derivation=DerivationKind.EXTERNAL_REPORT,
        asserted_by=principal.actor_id,
        asserted_at=moment,
        valid_extent=TemporalExtent.at(submission.observed_at),
        notes=SUBMISSION_NOTICE,
    )


def check_may_submit(principal: Principal) -> None:
    """Refuse a principal whose roles do not include a writing one.

    Raises rather than returning a verdict, for the same reason the refusal type exists: a
    caller that forgets to check a boolean writes to the graph.
    """
    if not (principal.roles & MAY_SUBMIT):
        held = ", ".join(sorted(role.value for role in principal.roles)) or "no roles"
        raise SubmissionRefusedError(
            f"{principal.describe()} holds {held} and no role entitled to write into the "
            "adversary graph. Oversight must not require the ability to act, and a reader of "
            "the graph has no business appending to it",
            status=403,
        )


__all__ = [
    "DEFAULT_SUBMISSIONS_PER_HOUR",
    "MAY_SUBMIT",
    "SUBMISSION_NOTICE",
    "IncidentSubmission",
    "RateLimiter",
    "SubmissionReceipt",
    "SubmissionRefusedError",
    "check_may_submit",
    "submission_claim",
]
