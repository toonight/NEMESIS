"""What NEMESIS says out loud, and what it refuses to say.

A collaboration event is a **projection**, not a record. The record already exists — a
:class:`~nemesis.core.claims.Claim` in the claim store, an
:class:`~nemesis.ports.storage.AuditEvent` in the hash-chained trail, an
:class:`~nemesis.core.evidence.EvidenceObject` in the vault. This module builds the
read-only, redacted, reference-carrying view of one of those that a human in a chat
channel is allowed to see, and nothing else.

The distinction is the whole point and it is enforced structurally rather than described:

**A projection cannot become a source.** Nothing here is admissible upstream. A
collaboration event has no path into the graph, the claim store or the vault, because
:mod:`nemesis.collaboration` sits below those planes in the layering and cannot import
them. An event that arrives *from* a channel is an
:class:`~nemesis.collaboration.base.InboundSignal` — deliberately a different type with a
different name, so that no function accepts both.

**It carries references, not content.** Evidence travels as a
:class:`Reference` — ``evidence://case-x/evd_sha256-…`` — and never as bytes. A channel
message is stored in plaintext by every collaboration backend we have examined, its
retention is the operator's, and its deletion semantics are not ours. Publishing an
artifact into one converts a tamper-evident object into an untracked copy. So the envelope
has no field that can hold one: ``summary`` and ``payload`` are bounded strings scanned at
construction, and the only way to point at material is a reference to where it actually
lives.

**Its epistemic standing is a field with a closed vocabulary, checked against the thing it
projects.** The brief this design answers asks for observation, evidence, inference,
hypothesis, recommendation, decision and authorized action to be distinguishable rather
than flattened into "messages". NEMESIS already distinguishes six of those at construction
in :class:`~nemesis.core.claims.ClaimKind`, so :class:`EpistemicStanding` maps onto that
lattice instead of re-deriving it, and :func:`standing_of_claim` is the only sanctioned way
to obtain a standing for a claim — a caller cannot label a hypothesis an observation on the
way out any more than it can on the way in.

**Classification travels with it.** Every event carries a
:class:`~nemesis.core.disclosure.DisclosureClass`, and
:meth:`CollaborationEvent.for_publication` refuses to build anything above
``DELIVERABLE``. Founder decision D1 keeps persona linkage off every deliverable; a chat
channel is the most deliverable surface in the system, since it is the one with human
members, search, and an operator we do not control.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Final, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from nemesis.core.claims import Claim, ClaimKind, DerivationKind
from nemesis.core.disclosure import (
    DisclosureClass,
    DisclosureViolationError,
    most_restrictive,
    scan_for_internal_material,
)
from nemesis.core.identity import ActorKind
from nemesis.core.ids import CollaborationEventId, IdPrefix, content_id
from nemesis.core.temporal import require_utc

MAX_SUMMARY_LENGTH: Final = 2000
"""How long a published summary may be.

Not a display concern. A summary is free text that a human wrote or a model produced, and
it crosses a boundary where it stops being ours. Bounding it bounds what a single
publication can carry out, and it keeps the whole envelope under every message-size limit
the examined backends enforce (the smallest observed content cap is 64 KiB).
"""

MAX_PAYLOAD_ENTRIES: Final = 32
MAX_PAYLOAD_KEY_LENGTH: Final = 120
MAX_PAYLOAD_VALUE_LENGTH: Final = 500
MAX_REFERENCES: Final = 64


class EpistemicStanding(StrEnum):
    """What kind of assertion a published event is making.

    Ordered from strongest to weakest standing in the same sense as
    :data:`~nemesis.core.claims.EPISTEMIC_STRENGTH`, and deliberately *not* a superset of
    :class:`~nemesis.core.claims.ClaimKind`: the three members at the bottom name things
    that are not claims at all, and conflating them is what the brief calls storing
    everything as equivalent messages.
    """

    OBSERVATION = "observation"
    """A collector recorded it, with the artifact preserved. Projects
    :attr:`~nemesis.core.claims.ClaimKind.OBSERVATION` and
    :attr:`~nemesis.core.claims.ClaimKind.FACT`."""

    INFERENCE = "inference"
    """Derived from other claims by a named, replayable rule."""

    CORRELATION = "correlation"
    """Co-occurrence. Not identity, not common control, not causation."""

    HYPOTHESIS = "hypothesis"
    """Proposed and held open. Everything a model asserts lands here or below."""

    ATTRIBUTION = "attribution"
    """An assignment of responsibility. A judgment, whatever supports it."""

    RECOMMENDATION = "recommendation"
    """A proposed course of action, made by an agent or an analyst.

    Not a claim about the world, so it is not a :class:`~nemesis.core.claims.ClaimKind` and
    must never be stored as one. It is the thing a human is being asked to decide about,
    and it authorizes nothing by existing."""

    DECISION = "decision"
    """A named human decided. Projects a
    :class:`~nemesis.core.authorization.Approval` that has already been recorded by the
    gateway — never a message in a channel that reads like agreement."""

    AUTHORIZED_ACTION = "authorized_action"
    """An operation ran under a verified capability. Projects an
    :class:`~nemesis.ports.effects.EffectResult`, including a refusal: the record of what
    was refused is as much an authorized-action event as the record of what was done."""


_CLAIM_STANDING: Final[Mapping[ClaimKind, EpistemicStanding]] = {
    ClaimKind.OBSERVATION: EpistemicStanding.OBSERVATION,
    ClaimKind.FACT: EpistemicStanding.OBSERVATION,
    ClaimKind.INFERENCE: EpistemicStanding.INFERENCE,
    ClaimKind.CORRELATION: EpistemicStanding.CORRELATION,
    ClaimKind.HYPOTHESIS: EpistemicStanding.HYPOTHESIS,
    ClaimKind.ATTRIBUTION: EpistemicStanding.ATTRIBUTION,
}
"""Total over :class:`~nemesis.core.claims.ClaimKind`. A test asserts the totality, so a
new claim kind fails loudly here rather than defaulting to something publishable."""


_MODEL_DERIVATIONS: Final = frozenset(
    {DerivationKind.MODEL_ASSERTION, DerivationKind.STATISTICAL_MODEL}
)


def standing_of_claim(claim: Claim) -> EpistemicStanding:
    """The standing a claim may be published with. The only sanctioned mapping.

    Callers do not choose. The claim's kind was fixed at construction by
    :class:`~nemesis.core.claims.Claim`'s own validators, which already refused to let a
    model produce an observation; re-deriving the standing here rather than accepting one
    from the caller means a publication path cannot upgrade what the domain model
    downgraded.
    """
    return _CLAIM_STANDING[claim.kind]


class ReferenceScheme(StrEnum):
    """What kind of thing a reference points at.

    A closed set, because a reference is the one field in a published event that a reader —
    human or machine — is invited to follow. An open scheme would let a publisher point a
    reader at an arbitrary URL, which is how a collaboration channel becomes a phishing
    surface inside an investigation.
    """

    EVIDENCE = "evidence"
    CLAIM = "claim"
    ENTITY = "entity"
    INVESTIGATION = "investigation"
    CASE = "case"
    CAPABILITY = "capability"
    OPERATION = "operation"
    AUDIT = "audit"


class Reference(BaseModel):
    """A pointer to something that lives inside NEMESIS, published instead of its content.

    Rendered as ``scheme://case/locator``. The case segment is present so a reader can tell
    at a glance which investigation a locator belongs to without resolving it, and so a
    locator pasted into the wrong channel is visibly wrong.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    scheme: ReferenceScheme
    case_id: Annotated[str, Field(min_length=1, max_length=128)]
    locator: Annotated[str, Field(min_length=1, max_length=256)]

    @model_validator(mode="after")
    def _reject_embedded_separators(self) -> Self:
        for field, value in (("case_id", self.case_id), ("locator", self.locator)):
            if any(character in value for character in ("/", "\\", ":")):
                raise ValueError(
                    f"{field} must not contain a path or scheme separator; a reference is "
                    "rendered by joining its parts, and a separator inside one of them lets "
                    "a locator impersonate a different scheme or case"
                )
            if any(character.isspace() or ord(character) < 0x20 for character in value):
                raise ValueError(
                    f"{field} must not contain whitespace or control characters; a rendered "
                    "reference is a single token a reader is invited to follow, and a "
                    "newline inside one lets it display as two"
                )
        return self

    def render(self) -> str:
        return f"{self.scheme.value}://{self.case_id}/{self.locator}"


class CollaborationEvent(BaseModel):
    """One thing NEMESIS is willing to say in a channel humans can read.

    Frozen, deterministically identified, and buildable only through
    :meth:`for_publication`, which is where the classification wall and the internal-marker
    scan run. The plain constructor is not the door: a caller that assembles the fields
    itself gets the same validation, because the checks live in a model validator rather
    than in the factory.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: CollaborationEventId
    """Content-addressed over the canonical encoding of everything else. Two publications
    of the same event are the same event, which is what makes retry safe."""

    occurred_at: Annotated[datetime, AfterValidator(lambda v: require_utc(v, "occurred_at"))]
    """When the projected thing happened — not when it was published. A delayed publication
    must not appear to be a later event, or a channel read as a timeline lies about
    ordering.

    Normalised to UTC on the way in, because the identifier covers the ISO rendering and a
    ``+02:00`` offset would otherwise content-address to something different from the same
    instant expressed as ``Z`` — two identifiers for one event, and a retry that
    deduplicates against neither."""

    case_id: Annotated[str, Field(min_length=1, max_length=128)]
    investigation_id: Annotated[str, Field(min_length=1, max_length=128)]
    correlation_id: Annotated[str, Field(min_length=1, max_length=128)]
    """Groups events that belong to one line of work across channels. Present so that
    correlation does not require a channel per case — the failure mode the brief names as
    uncontrolled channel proliferation."""

    actor: Annotated[str, Field(min_length=1, max_length=200)]
    actor_kind: ActorKind

    standing: EpistemicStanding
    event_type: Annotated[str, Field(min_length=1, max_length=120)]
    """A dotted domain topic — ``threat.infrastructure.observed``, ``disrupt.recommended``.
    Free-form on purpose: it is a routing hint for subscribers, and it carries no authority.
    :attr:`standing` is the field that carries meaning, and it is closed."""

    summary: Annotated[str, Field(min_length=1, max_length=MAX_SUMMARY_LENGTH)]
    payload: Mapping[str, str] = Field(default_factory=dict)
    references: tuple[Reference, ...] = ()

    classification: DisclosureClass
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] | None = None
    """Optional and nullable, and the nullability is load-bearing. A projected opinion that
    is vacuous reports no number at all rather than 0.5, because "nobody looked" and "two
    sources disagree" are the same number and only one of them should stop an operation.
    See :mod:`nemesis.core.confidence`."""

    uncertainty_note: Annotated[str, Field(max_length=500)] = ""
    """Why the confidence is what it is, or why there is none. Published beside the number
    so a reader never sees a bare figure."""

    @model_validator(mode="after")
    def _enforce_publication_rules(self) -> Self:
        if self.classification is not DisclosureClass.DELIVERABLE:
            raise DisclosureViolationError(
                f"a collaboration event is classified {self.classification.value!r}; only "
                f"{DisclosureClass.DELIVERABLE.value!r} material may be published to a "
                "channel. Internal leads and restricted material direct the investigation "
                "and never leave it (founder decision D1)"
            )

        if len(self.payload) > MAX_PAYLOAD_ENTRIES:
            raise ValueError(
                f"payload has {len(self.payload)} entries, at most {MAX_PAYLOAD_ENTRIES} "
                "may be published"
            )
        for key, value in self.payload.items():
            # Keys are bounded too. An adversarial review found that only values were, so a
            # single event could carry 32 keys of unbounded length past a check whose whole
            # purpose is to bound what one publication can move — a guard on one of two
            # doors, which this repository elsewhere calls out as not a guard.
            if len(key) > MAX_PAYLOAD_KEY_LENGTH:
                raise ValueError(
                    f"payload key {key[:60]!r}… is {len(key)} characters, at most "
                    f"{MAX_PAYLOAD_KEY_LENGTH} may be published"
                )
            if len(value) > MAX_PAYLOAD_VALUE_LENGTH:
                raise ValueError(
                    f"payload[{key!r}] is {len(value)} characters, at most "
                    f"{MAX_PAYLOAD_VALUE_LENGTH} may be published. Publish a reference to "
                    "the material instead of the material"
                )
        if len(self.references) > MAX_REFERENCES:
            raise ValueError(
                f"{len(self.references)} references, at most {MAX_REFERENCES} may be published"
            )

        leaked = scan_for_internal_material(self.scannable_surfaces())
        if leaked:
            raise DisclosureViolationError(
                "internal material reached the collaboration boundary: " + "; ".join(leaked)
            )

        expected = derive_event_id(self.publication_payload())
        if self.event_id != expected:
            raise ValueError(
                f"event_id {self.event_id!r} does not match its content, which derives "
                f"{expected!r}. The identifier is content-addressed so that a retry is "
                "recognisable as a retry; one that does not match its content makes "
                "deduplication silently wrong"
            )
        return self

    def scannable_surfaces(self) -> dict[str, str]:
        """Every string this event puts in front of a reader, keyed for the scan report.

        The first version scanned four of nine, and an adversarial review demonstrated the
        gap by putting an internal marker in ``actor`` and publishing it. The lesson is the
        one this repository keeps relearning: a guard that covers the fields somebody
        remembered is a guard against the leaks somebody predicted. So this method
        enumerates from the model rather than from memory, and
        :func:`~nemesis.collaboration.events.test-side` coverage asserts that every
        ``str``-valued field on the model appears here — a new field fails the test rather
        than escaping the scan.

        Payload **keys** are included, not only values. A key is displayed to a reader
        exactly as a value is.
        """
        surfaces: dict[str, str] = {
            "case_id": self.case_id,
            "investigation_id": self.investigation_id,
            "correlation_id": self.correlation_id,
            "actor": self.actor,
            "event_type": self.event_type,
            "summary": self.summary,
            "uncertainty_note": self.uncertainty_note,
        }
        for key, value in self.payload.items():
            surfaces[f"payload.key[{key}]"] = key
            surfaces[f"payload[{key}]"] = value
        for index, reference in enumerate(self.references):
            surfaces[f"references[{index}]"] = reference.render()
        return surfaces

    def publication_payload(self) -> Mapping[str, object]:
        """Everything the identifier covers: the whole event except the identifier itself.

        Ordering is preserved for ``references``, so this is encoded by
        :func:`derive_event_id` rather than by
        :func:`~nemesis.core.canonical.canonical_bytes`, which sorts arrays.
        """
        return {
            "occurred_at": self.occurred_at.isoformat(),
            "case_id": self.case_id,
            "investigation_id": self.investigation_id,
            "correlation_id": self.correlation_id,
            "actor": self.actor,
            "actor_kind": self.actor_kind.value,
            "standing": self.standing.value,
            "event_type": self.event_type,
            "summary": self.summary,
            "payload": dict(sorted(self.payload.items())),
            "references": [reference.render() for reference in self.references],
            "classification": self.classification.value,
            "confidence": self.confidence,
            "uncertainty_note": self.uncertainty_note,
        }

    def integrity_hash(self) -> str:
        """SHA-256 over the published bytes, so a reader can check what they received.

        This is not tamper-evidence against the platform — NEMESIS computes it, and a
        NEMESIS that wanted to lie would compute a matching one. It detects a backend that
        rewrote a stored event, which the examined backends can do with no trigger stopping
        them and no read-path verification catching it.
        """
        return "sha256:" + hashlib.sha256(_encode(self.publication_payload())).hexdigest()

    @classmethod
    def for_publication(
        cls,
        *,
        occurred_at: datetime,
        case_id: str,
        investigation_id: str,
        correlation_id: str,
        actor: str,
        actor_kind: ActorKind,
        standing: EpistemicStanding,
        event_type: str,
        summary: str,
        classification: DisclosureClass = DisclosureClass.DELIVERABLE,
        payload: Mapping[str, str] | None = None,
        references: tuple[Reference, ...] = (),
        confidence: float | None = None,
        uncertainty_note: str = "",
    ) -> Self:
        """Build an event, deriving its identifier from its content.

        Raises :class:`~nemesis.core.disclosure.DisclosureViolationError` when the material
        may not leave, and :class:`ValueError` when it exceeds a published bound.
        """
        body = {
            "occurred_at": require_utc(occurred_at, "occurred_at").isoformat(),
            "case_id": case_id,
            "investigation_id": investigation_id,
            "correlation_id": correlation_id,
            "actor": actor,
            "actor_kind": actor_kind.value,
            "standing": standing.value,
            "event_type": event_type,
            "summary": summary,
            "payload": dict(sorted((payload or {}).items())),
            "references": [reference.render() for reference in references],
            "classification": classification.value,
            "confidence": confidence,
            "uncertainty_note": uncertainty_note,
        }
        return cls(
            event_id=derive_event_id(body),
            occurred_at=occurred_at,
            case_id=case_id,
            investigation_id=investigation_id,
            correlation_id=correlation_id,
            actor=actor,
            actor_kind=actor_kind,
            standing=standing,
            event_type=event_type,
            summary=summary,
            payload=dict(payload or {}),
            references=references,
            classification=classification,
            confidence=confidence,
            uncertainty_note=uncertainty_note,
        )


def classification_of(*classes: DisclosureClass) -> DisclosureClass:
    """The class a composite event takes. Re-exported so callers need not reach into core.

    A publication assembled from several findings takes the strictest of them — which for a
    channel means it usually cannot be published at all, and that is the intended outcome
    rather than a limitation to work around.
    """
    return most_restrictive(*classes)


def derive_event_id(body: Mapping[str, object]) -> str:
    """Content-address a publication body.

    Uses a local encoder rather than :func:`~nemesis.core.canonical.canonical_bytes`
    because that function sorts arrays, and ``references`` carries meaning in its order: an
    approval request naming an evidence bundle first and a target second is not the same
    published statement as one naming them the other way round. Sorting them would make two
    different events share an identifier, which is precisely the deduplication bug this
    identifier exists to prevent.
    """
    return content_id(IdPrefix.COLLABORATION, _encode(body))


def _encode(body: Mapping[str, object]) -> bytes:
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")


def is_model_derived(claim: Claim) -> bool:
    """Whether a claim came from a model, so a publication can say so beside it.

    Not a filter — a model's hypothesis is publishable and often the most useful thing in
    the channel. It is a labelling input: a reader deciding what to do about an assertion
    needs to know a model produced it, and the label must come from the claim's own
    derivation rather than from whoever wrote the message.
    """
    return claim.derivation in _MODEL_DERIVATIONS


__all__ = [
    "MAX_PAYLOAD_ENTRIES",
    "MAX_PAYLOAD_KEY_LENGTH",
    "MAX_PAYLOAD_VALUE_LENGTH",
    "MAX_REFERENCES",
    "MAX_SUMMARY_LENGTH",
    "CollaborationEvent",
    "EpistemicStanding",
    "Reference",
    "ReferenceScheme",
    "classification_of",
    "derive_event_id",
    "is_model_derived",
    "standing_of_claim",
]
