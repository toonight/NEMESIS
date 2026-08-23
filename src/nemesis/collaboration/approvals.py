"""Asking a human, and refusing to treat the answer as permission.

This module carries the one asymmetry the whole integration exists to protect. NEMESIS
publishes an approval *request* into a channel where humans can read it, argue about it and
answer it. Nothing it reads back from that channel authorizes anything.

The reason is not caution, it is that the two operations are different in kind:

- A collaboration backend can tell you **who signed a message**. That is a real
  cryptographic fact, and the examined backends establish it properly.
- Authorization requires knowing **that a person holding a role, at an assurance level this
  deployment accepts, decided about a specific operation against a specific target in a
  specific state, within a window, with a rationale recorded**. No signature establishes
  any of that.

So a message saying "approved" produces a :class:`DecisionIntent`, which is a *reading of
untrusted text* and is named to be unmistakable for a decision. Turning one into an
:class:`~nemesis.core.authorization.Approval` requires
:class:`~nemesis.authz.gateway.AuthorizationGateway`, a verified
:class:`~nemesis.core.identity.IdentityAssertion` and a
:class:`~nemesis.authz.attestation.PrincipalVerifier` — none of which this module can
reach, because :mod:`nemesis.collaboration` sits below :mod:`nemesis.authz` in the layering
and an ``import-linter`` contract names the package. The wall is a fact about the import
graph, not a rule someone has to remember.

Two further properties follow from the same reasoning:

**A decision intent binds to a proposal digest, not to a conversation.** The brief's
requirement that "a generic *approved* chat reply must not authorize arbitrary later
actions" is met by making the reply meaningless without a digest that covers the operation,
every target fingerprint, the risk level and the expiry. A reply that does not carry it, or
carries one that no longer matches, resolves to :attr:`DecisionIntent.UNCLEAR`.

**An expired proposal cannot be answered.** :meth:`ApprovalNotice.intent_from` refuses
after :attr:`ApprovalNotice.responses_close_at`, so an approval request that scrolled off
the top of a channel three weeks ago cannot be revived by someone replying to it.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Final, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from nemesis.collaboration.base import InboundSignal
from nemesis.collaboration.events import (
    CollaborationEvent,
    EpistemicStanding,
    Reference,
    ReferenceScheme,
)
from nemesis.core.authorization import (
    ActionRisk,
    AuthorizationDecision,
    OperationClass,
    TargetFingerprint,
    risk_of,
)
from nemesis.core.identity import ActorKind
from nemesis.core.temporal import require_utc

PROPOSAL_DIGEST_LENGTH: Final = 16
"""How many hex characters of the proposal digest a human is asked to quote.

Sixty-four is unquotable and would simply be pasted wrong; eight is short enough that two
open proposals in a busy channel could plausibly collide. Sixteen is 64 bits — far beyond
what a person mistyping a code could hit, and short enough to read aloud.
"""

_DIGEST_PATTERN: Final = re.compile(rf"\b([0-9a-f]{{{PROPOSAL_DIGEST_LENGTH}}})\b")

_APPROVE_PATTERN: Final = re.compile(r"\b(approve[ds]?|authori[sz]e[ds]?|grant(?:ed)?)\b")
_REJECT_PATTERN: Final = re.compile(
    r"\b(reject(?:ed)?|den(?:y|ied)|refuse[ds]?|decline[ds]?|no-?go|veto(?:ed)?)\b"
)
"""Whole-word matching, and the word boundaries are the fix rather than a tidy-up.

The first version used plain substring containment, and two English words defeated it
immediately: ``unapproved`` and ``disapprove`` both contain ``approve``, so a message saying
the exact opposite of approval was read as approval. Both are now excluded by ``\\b``, and a
test constructs each.
"""

_APOSTROPHES: Final = str.maketrans({"\u2019": "'", "\u2018": "'", "\u02bc": "'"})
"""Curly apostrophes folded to the ASCII one before any matching.

Slack, iOS and macOS autocorrect all emit U+2019. Without this, ``don't`` was caught and
``don\u2019t`` — the form a person actually types on a phone — was not, so the difference
between reading a refusal and reading an approval was an apostrophe codepoint.
"""

_NEGATION_PATTERN: Final = re.compile(
    r"\w*n't\b|\b(?:not|no|nope|nah|none|nothing|nobody|never|neither|nor|cannot|"
    r"wont|dont|cant|unable|without|hold|wait|pause|unless|abstain|refrain|"
    r"blocked|blocking|objection)\b"
)
"""Words whose presence means an approval reading is no longer safe.

This is the second half of the same defect, and the more dangerous half, because no word
boundary catches it: ``do not approve <digest>`` contains an approval token, matched it, and
was read as ``APPEARS_TO_APPROVE``. So did ``never approve``, ``cannot approve`` and ``I
would not approve this``. Nothing acted on that reading — a `DecisionIntake` authorizes
nothing whatever it says — but the harm was never going to be a machine acting on it. It was
a human authorizer glancing at a table that said *appears to approve* beside a message that
said the opposite, and signing.

Contractions are matched generically as ``\\w*n't``, not by a hard-coded list, and this
took two attempts to get right — both failures the same shape as the original defect, one
layer up. The first listed ``don't``, ``won't``, ``doesn't`` and ``shouldn't``, and a review
produced ``couldn't``, ``mustn't`` and ``shan't`` immediately. The second wrote the generic
branch as ``\\bn't``, which cannot fire at all: in ``wouldn't`` the ``n`` is preceded by a
word character, so the boundary never holds. ``\\w*n't\\b`` is the form that works, and a test
asserts directly that it matches ``wouldn't`` — because a dead alternation in a regex is
invisible until someone writes the case it was supposed to catch.

A deliberate consequence, stated rather than discovered: bare ``no`` is a negation, so
"approved, no concerns" now reads as ``UNCLEAR``. That is the asymmetry below, applied.

The response is deliberately blunt and deliberately asymmetric. A negation anywhere in the
message makes ``APPEARS_TO_APPROVE`` unreachable; it does **not** promote the message to
``APPEARS_TO_REJECT``, because "do not approve" reads as refusal to a person and this is not
a person — inferring intent from adversary-reachable prose is the exact thing a crude parser
exists to avoid doing. The message becomes :attr:`DecisionIntent.UNCLEAR`, its text is kept
verbatim in the intake, and a human reads it.

The asymmetry is the point. Mis-reading a refusal as unclear costs a round trip. Mis-reading
a refusal as approval costs the control.
"""


class DecisionIntent(StrEnum):
    """What a message in a channel appeared to mean. Never what was decided.

    Every member is deliberately phrased as a reading rather than an outcome. There is no
    ``APPROVED`` member, and there will not be one: the type that carries an approval is
    :class:`~nemesis.core.authorization.Approval`, it is minted by the gateway, and it
    cannot be constructed here.
    """

    APPEARS_TO_APPROVE = "appears_to_approve"
    APPEARS_TO_REJECT = "appears_to_reject"
    UNCLEAR = "unclear"
    """The message did not parse as either, or carried no usable proposal digest, or carried
    one that does not match. The safe reading, and the default: a channel where ambiguity
    resolves toward approval is a channel that approves by accident."""

    REFUSED_EXPIRED = "refused_expired"
    """The proposal's response window had closed. A late reply is not a decision."""

    REFUSED_CONFLICTING = "refused_conflicting"
    """The message read as approval *and* rejection. Two people replying in one thread, a
    quoted message containing the opposite word, a model summarising both sides. Resolved
    to a refusal rather than to whichever token appeared first."""


class ApprovalNotice(BaseModel):
    """A request for a human decision, in the form that may be published.

    Carries every field the brief asks an approval object to carry — who asked, for what,
    against which target, on what evidence, at what risk, why, and what the policy engine
    already said — plus the two the brief does not name and this design requires: a digest
    binding the reply to this exact proposal, and a hard close time.

    What it deliberately does not carry: any field that could hold a decision. There is no
    ``status``, no ``approved_by``, no ``approved_at``. Those live on
    :class:`~nemesis.core.authorization.Approval`, inside the capability the gateway signs,
    where they are covered by a signature. A mutable status field on a published notice
    would be a second, unsigned record of the same fact, and the two would disagree the
    first time a publication was retried.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    capability_id: Annotated[str, Field(min_length=1, max_length=128)]
    """The identifier the gateway assigned when the request was raised. Present so the
    proposal, every decision and the eventual grant share one identifier — the notice does
    not mint its own, because a second identifier for one authorization is how a decision
    ends up attached to a different grant."""

    case_id: Annotated[str, Field(min_length=1, max_length=128)]
    requested_by: Annotated[str, Field(min_length=1, max_length=200)]
    requested_by_kind: ActorKind

    operation: OperationClass
    targets: Annotated[tuple[TargetFingerprint, ...], Field(min_length=1)]
    """Bound to the state in which they were observed. The fingerprint is what makes a
    stale approval fail closed when a domain changes hands between the reply and the act."""

    rationale: Annotated[str, Field(min_length=1, max_length=4000)]
    evidence_references: tuple[Reference, ...] = ()
    """Where the supporting material is, never the material. A human following one of these
    reads it inside NEMESIS, under access control and with the read recorded."""

    policy_decision: AuthorizationDecision | None = None
    """What the authorization gateway already concluded, published so the human sees it.

    A permitted decision is not a substitute for the human — it means the machine-checkable
    part passed. A denied one is published too: asking a person to approve something the
    policy already refuses is a question worth showing, because the answer is no and the
    request itself is a signal."""

    responses_close_at: Annotated[
        datetime, AfterValidator(lambda v: require_utc(v, "responses_close_at"))
    ]
    proposed_at: Annotated[datetime, AfterValidator(lambda v: require_utc(v, "proposed_at"))]
    """Both normalised to UTC on the way in, and the normalisation is load-bearing.

    :meth:`proposal_digest` hashes ``responses_close_at.isoformat()``. A first version called
    ``require_utc`` inside the model validator and discarded its return value, so a notice
    built with ``15:30+02:00`` kept that offset and digested differently from the identical
    instant written ``13:30+00:00`` — two codes for one proposal, and a reply quoting either
    one matching only half the time."""

    @model_validator(mode="after")
    def _enforce_notice_rules(self) -> Self:
        if self.responses_close_at <= self.proposed_at:
            raise ValueError(
                "responses_close_at must be after proposed_at; a proposal that is closed "
                "when it is published can never be answered, which is a silent refusal "
                "rather than a question"
            )
        if self.policy_decision is not None:
            if self.policy_decision.operation is not self.operation:
                raise ValueError(
                    f"policy_decision covers {self.policy_decision.operation.value!r} but the "
                    f"notice proposes {self.operation.value!r}; publishing a decision beside "
                    "an operation it did not evaluate misrepresents what was checked"
                )
            fingerprints = {target.fingerprint for target in self.targets}
            if self.policy_decision.target_fingerprint not in fingerprints:
                raise ValueError(
                    "policy_decision names a target fingerprint that is not among the "
                    "notice's targets; the published decision must be about the published "
                    "targets"
                )
        return self

    @property
    def risk(self) -> ActionRisk:
        """Derived from the operation, never supplied. See
        :data:`~nemesis.core.authorization.OPERATION_RISK`."""
        return risk_of(self.operation)

    def proposal_digest(self) -> str:
        """The token a reply must quote to count as a reply to *this* proposal.

        Covers the capability, the operation, every target fingerprint in order, the risk
        level and the close time. Changing any of them changes the digest, so a reply
        approving one proposal cannot be re-read as approving a different one that reused
        the conversation.

        Not a secret and not a signature. Anyone reading the channel can compute it, and
        that is fine: it is a binding, not an authenticator. Who said it is established by
        the backend's own signature check; whether they may decide is established by the
        gateway, later, against a verified identity.
        """
        body = {
            "capability_id": self.capability_id,
            "case_id": self.case_id,
            "operation": self.operation.value,
            "risk": int(self.risk),
            "targets": [target.fingerprint for target in self.targets],
            "responses_close_at": self.responses_close_at.isoformat(),
        }
        payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()[:PROPOSAL_DIGEST_LENGTH]

    def to_event(
        self,
        *,
        investigation_id: str,
        correlation_id: str,
        actor: str,
        actor_kind: ActorKind = ActorKind.AGENT,
    ) -> CollaborationEvent:
        """Project this notice into a publishable event.

        The summary tells a reader what to type back, because an approval request nobody
        can answer correctly is an approval request that gets answered incorrectly.
        """
        summary = (
            f"Approval requested for {self.operation.value} "
            f"(risk level {int(self.risk)} — {self.risk.name.lower().replace('_', ' ')}) "
            f"against {len(self.targets)} target(s). {self.rationale}\n\n"
            f"To answer, reply with APPROVE or REJECT and quote {self.proposal_digest()}. "
            f"Replies after {self.responses_close_at.isoformat()} are refused. "
            "A reply here is not an authorization: it is recorded as an intent and must be "
            "confirmed through the authorization gateway with a verified identity."
        )
        payload = {
            "capability_id": self.capability_id,
            "operation": self.operation.value,
            "risk_level": str(int(self.risk)),
            "target_count": str(len(self.targets)),
            "proposal_digest": self.proposal_digest(),
            "responses_close_at": self.responses_close_at.isoformat(),
            "requested_by": self.requested_by,
        }
        if self.policy_decision is not None:
            payload["policy_decision"] = "permitted" if self.policy_decision.permitted else "denied"
            if self.policy_decision.denial_reasons:
                payload["policy_denial_reasons"] = "; ".join(self.policy_decision.denial_reasons)[
                    :500
                ]

        references = (
            Reference(
                scheme=ReferenceScheme.CAPABILITY,
                case_id=self.case_id,
                locator=self.capability_id,
            ),
            *self.evidence_references,
        )
        return CollaborationEvent.for_publication(
            occurred_at=self.proposed_at,
            case_id=self.case_id,
            investigation_id=investigation_id,
            correlation_id=correlation_id,
            actor=actor,
            actor_kind=actor_kind,
            standing=EpistemicStanding.RECOMMENDATION,
            event_type="authorization.approval.requested",
            summary=summary,
            payload=payload,
            references=references,
        )

    def intent_from(self, signal: InboundSignal, *, now: datetime) -> DecisionIntent:
        """Read one inbound signal as an intent about this proposal.

        Refuses before it parses: an expired proposal returns
        :attr:`DecisionIntent.REFUSED_EXPIRED` whatever the message says, so a late reply
        cannot be resurrected by rewording it.

        The parse itself is deliberately crude — token matching over lowercased text — and
        the crudeness is safe *because the result authorizes nothing*. A cleverer parser
        would be a model reading adversary-reachable text and deciding what a human meant,
        which is the exact shape this architecture refuses. Anything it cannot read
        confidently becomes :attr:`DecisionIntent.UNCLEAR`.
        """
        require_utc(now, "now")
        if now >= self.responses_close_at:
            return DecisionIntent.REFUSED_EXPIRED

        body = signal.body.lower().translate(_APOSTROPHES)
        if not _matches_digest(body, self.proposal_digest()):
            return DecisionIntent.UNCLEAR

        approves = _APPROVE_PATTERN.search(body) is not None
        rejects = _REJECT_PATTERN.search(body) is not None
        negated = _NEGATION_PATTERN.search(body) is not None

        if approves and rejects:
            return DecisionIntent.REFUSED_CONFLICTING
        if rejects:
            return DecisionIntent.APPEARS_TO_REJECT
        if approves and not negated:
            return DecisionIntent.APPEARS_TO_APPROVE
        # An approval token under a negation, or no decision token at all. Both are the same
        # answer: this did not read as a decision, and a person should look at it.
        return DecisionIntent.UNCLEAR


class DecisionIntake(BaseModel):
    """One reading of one signal, kept as a record whatever it concluded.

    Retained even when the intent is ``UNCLEAR`` or refused, because "seven people replied
    and none of it parsed" is an operational fact about a channel, and a pipeline that
    discards what it could not understand cannot report it.

    The fields say plainly what this is worth: :attr:`author_verified` is the backend's
    signature check, and :attr:`authorizes` is a property that returns ``False``
    unconditionally. It exists so that a reader of the code, and any future author reaching
    for a shortcut, finds the answer written down at the point of temptation.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    capability_id: Annotated[str, Field(min_length=1)]
    signal_id: Annotated[str, Field(min_length=1)]
    provider: Annotated[str, Field(min_length=1)]
    author_reference: Annotated[str, Field(min_length=1)]
    author_verified: bool
    intent: DecisionIntent
    observed_at: datetime
    excerpt: Annotated[str, Field(max_length=500)] = ""

    @model_validator(mode="after")
    def _require_utc(self) -> Self:
        require_utc(self.observed_at, "observed_at")
        return self

    @property
    def authorizes(self) -> bool:
        """Always ``False``.

        A cryptographically verified message from a channel member expressing approval is
        evidence that a person said something. Authorization additionally requires an
        identity established at an assurance level this deployment accepts, a role that may
        approve this operation class, a rationale, and a signature over the capability —
        produced by :class:`~nemesis.authz.gateway.AuthorizationGateway`, which this plane
        cannot import. Nothing in this object is a substitute for that, and no combination
        of its fields becomes one.
        """
        return False


def read_intents(
    notice: ApprovalNotice, signals: Sequence[InboundSignal], *, now: datetime
) -> tuple[DecisionIntake, ...]:
    """Read every signal against one notice. Order preserved, nothing discarded."""
    return tuple(
        DecisionIntake(
            capability_id=notice.capability_id,
            signal_id=signal.signal_id,
            provider=signal.provider,
            author_reference=signal.author_reference,
            author_verified=signal.author_verified,
            intent=notice.intent_from(signal, now=now),
            observed_at=signal.received_at,
            excerpt=signal.body[:500],
        )
        for signal in signals
    )


def _matches_digest(body: str, digest: str) -> bool:
    return any(found == digest for found in _DIGEST_PATTERN.findall(body))


__all__ = [
    "PROPOSAL_DIGEST_LENGTH",
    "ApprovalNotice",
    "DecisionIntake",
    "DecisionIntent",
    "read_intents",
]
