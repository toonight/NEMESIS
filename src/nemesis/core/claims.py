"""The claim taxonomy: what NEMESIS knows, and on what standing.

The Pursuit Engine must distinguish fact, observation, inference, hypothesis, correlation
and attribution. Most intelligence systems declare that distinction in documentation and
lose it in the database, where everything ends up as a row with a `confidence` float. Six
weeks later nobody can tell which rows were witnessed and which were guessed.

Here the distinction is structural and enforced at construction:

- An **observation** or **fact** must be backed by preserved evidence and must not have a
  model anywhere in its derivation chain. This is invariant 1 made mechanical: an LLM
  cannot produce a fact, no matter how the calling code is written.
- An **inference** must name the rule that produced it.
- A **correlation** asserts co-occurrence and nothing more. It cannot be silently read as
  identity or causation — the two most consequential upgrades in attribution work, and
  the two an adversary most wants us to make.
- A claim can never be epistemically stronger than the weakest thing it rests on. You
  cannot infer a fact from a hypothesis, and the type system will not let you try.

That last rule is the one that matters. Confidence dilution is easy to get right;
*standing* dilution is what fails in practice, because a chain of individually reasonable
steps quietly converts a guess into a certainty.
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.core.ids import ActorId, ClaimId, EvidenceId, IdPrefix, content_id
from nemesis.core.temporal import RecordVersion, TemporalExtent


class ClaimKind(StrEnum):
    """What sort of assertion this is. Ordering is defined by :data:`EPISTEMIC_STRENGTH`."""

    OBSERVATION = "observation"
    """Something a collector directly recorded, with the artifact preserved.
    "Passive DNS holds an A record for evil.example pointing at 203.0.113.7." """

    FACT = "fact"
    """An assertion about the world established by evidence and not by reasoning.
    Distinguished from an observation in that it is corroborated or authoritative:
    a registrar's own record of a domain's creation date, not one scanner's sighting."""

    INFERENCE = "inference"
    """Derived from other claims by a documented, replayable rule. Deterministic given
    its inputs — re-running the rule on the same inputs must yield the same claim."""

    CORRELATION = "correlation"
    """Two things co-occur or share an attribute. Asserts association only.
    Not identity. Not common control. Not causation. The distance between
    "these domains share a TLS certificate" and "the same person runs them" is the
    entire discipline of attribution."""

    HYPOTHESIS = "hypothesis"
    """A proposed explanation, held open for support or refutation. First-class: an
    investigation that cannot record what it suspects but has not shown is an
    investigation that will quietly present suspicion as finding."""

    ATTRIBUTION = "attribution"
    """An assignment of responsibility to an entity. Always a judgment, never an
    observation, however strong the supporting material. Carries multi-dimensional
    confidence rather than a single score."""


EPISTEMIC_STRENGTH: dict[ClaimKind, int] = {
    ClaimKind.FACT: 4,
    ClaimKind.OBSERVATION: 4,
    ClaimKind.INFERENCE: 3,
    ClaimKind.CORRELATION: 2,
    ClaimKind.HYPOTHESIS: 1,
    ClaimKind.ATTRIBUTION: 1,
}
"""How much standing each kind of claim has.

Attribution sits at the bottom alongside hypothesis on purpose. An attribution is a
conclusion, and a conclusion never has more standing than a hypothesis until an authority
outside this system accepts it. Nothing may be inferred *as fact* from an attribution.
"""


class DerivationKind(StrEnum):
    """What produced the claim. Determines what standing it is permitted to have."""

    DIRECT_COLLECTION = "direct_collection"
    """A collector recorded it. The only derivation that can yield an observation."""

    AUTHORITATIVE_RECORD = "authoritative_record"
    """A party with definitional authority stated it: a registry about its own registry,
    a ledger about its own transactions."""

    DETERMINISTIC_RULE = "deterministic_rule"
    """A named, versioned, replayable rule over other claims."""

    STATISTICAL_MODEL = "statistical_model"
    """A calibrated statistical or ML model. Its output is an inference at best."""

    MODEL_ASSERTION = "model_assertion"
    """An LLM said so. Invariant 1: this can never be an observation or a fact."""

    HUMAN_ANALYST = "human_analyst"
    """A named person's judgment. Carries standing, but is not evidence of itself."""

    EXTERNAL_REPORT = "external_report"
    """Asserted by a third party whose own derivation we cannot inspect."""


_MODEL_DERIVATIONS = {DerivationKind.MODEL_ASSERTION, DerivationKind.STATISTICAL_MODEL}
_EVIDENCE_BACKED_KINDS = {ClaimKind.OBSERVATION, ClaimKind.FACT}


class Statement(BaseModel):
    """The assertion itself, in a form both machines and analysts can read.

    Structured triple plus prose. The triple is what the graph queries; the prose is what
    an analyst reads and what an export shows a magistrate. Keeping both prevents the two
    common failures: a graph nobody can explain, and a narrative nothing can check.
    """

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    subject: Annotated[str, Field(min_length=1, max_length=512)]
    predicate: Annotated[str, Field(min_length=1, max_length=128)]
    obj: Annotated[str, Field(min_length=1, max_length=2048, alias="object")]
    qualifiers: dict[str, str] = Field(default_factory=dict)
    natural_language: Annotated[str, Field(min_length=1, max_length=2000)]

    def canonical(self) -> str:
        return json.dumps(
            {
                "subject": self.subject,
                "predicate": self.predicate,
                "object": self.obj,
                "qualifiers": dict(sorted(self.qualifiers.items())),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )


class DeceptionAssessment(BaseModel):
    """Whether an adversary could have arranged for us to believe this.

    Invariant 13. Attribution is the one analytic product an adversary has a direct
    incentive to shape: planting a false flag is cheaper than defending infrastructure.
    A system that only asks "how strong is this evidence?" and never "who benefits from my
    seeing it?" is trivially steerable, so the question is a required field rather than an
    optional enrichment.
    """

    model_config = ConfigDict(frozen=True)

    adversary_could_plant: bool
    """Whether the underlying material sits in a channel an adversary can influence."""

    planting_cost: str = Field(
        default="unknown",
        description="Rough effort for an adversary to have staged this: trivial, moderate, "
        "high, implausible. Cheap-to-stage signals must not carry heavy weight.",
    )

    benefits_from_belief: tuple[str, ...] = ()
    """Who gains if we accept this. An empty tuple means the question was not asked."""

    contra_indicators: tuple[str, ...] = ()
    """Observations that argue against this being staged."""

    @property
    def is_assessed(self) -> bool:
        return bool(self.benefits_from_belief) or bool(self.contra_indicators)


class Claim(BaseModel):
    """One assertion, with its standing, its derivation and its supports.

    Content-addressed: two identical claims derived identically from identical inputs are
    the same claim. Restating something does not make it more true, and in a fusion engine
    it must not be able to look like independent corroboration.
    """

    model_config = ConfigDict(frozen=True)

    claim_id: ClaimId
    kind: ClaimKind
    statement: Statement
    derivation: DerivationKind

    asserted_by: ActorId
    """The agent, rule or human that made this claim. Always attributable to someone."""

    asserted_at: datetime
    valid_extent: TemporalExtent
    """When the statement holds of the world — not when we recorded it."""

    version: RecordVersion = Field(default_factory=RecordVersion)

    supported_by_evidence: tuple[EvidenceId, ...] = ()
    derived_from_claims: tuple[ClaimId, ...] = ()
    contradicted_by_claims: tuple[ClaimId, ...] = ()
    """Recorded on the claim itself, so contradiction cannot be lost by omission when the
    claim is exported or read in isolation."""

    rule_name: str | None = Field(
        default=None,
        description="Required for deterministic-rule derivations. Names the replayable "
        "rule, so an inference can be recomputed and challenged.",
    )
    rule_version: str | None = None

    model_identifier: str | None = Field(
        default=None,
        description="Required when a model produced this. Which model said it is part of "
        "the claim, not metadata about it.",
    )

    deception: DeceptionAssessment | None = None

    notes: str | None = Field(default=None, max_length=4000)

    # -- structural rules -----------------------------------------------------

    @model_validator(mode="after")
    def _enforce_epistemic_rules(self) -> Self:
        # Invariant 1: a model assertion can never be an observation or a fact.
        if self.derivation in _MODEL_DERIVATIONS and self.kind in _EVIDENCE_BACKED_KINDS:
            raise ValueError(
                f"a {self.derivation.value} cannot produce a {self.kind.value}: "
                "model output is never evidence (invariant 1)"
            )

        # Observations and facts must rest on preserved material.
        if self.kind in _EVIDENCE_BACKED_KINDS and not self.supported_by_evidence:
            raise ValueError(
                f"a {self.kind.value} must cite at least one evidence object; "
                "an unbacked assertion is a hypothesis"
            )

        # Only direct collection or an authoritative record yields an observation.
        if self.kind is ClaimKind.OBSERVATION and self.derivation not in {
            DerivationKind.DIRECT_COLLECTION,
            DerivationKind.AUTHORITATIVE_RECORD,
        }:
            raise ValueError(
                f"an observation must be directly collected or authoritative, "
                f"not {self.derivation.value}"
            )

        # An inference must be replayable.
        if self.derivation is DerivationKind.DETERMINISTIC_RULE and not self.rule_name:
            raise ValueError("a deterministic-rule derivation must name its rule")

        # Model claims must name the model.
        if self.derivation in _MODEL_DERIVATIONS and not self.model_identifier:
            raise ValueError(f"a {self.derivation.value} must name the model that produced it")

        # A derived claim must say what it derives from.
        if self.derivation is DerivationKind.DETERMINISTIC_RULE and not self.derived_from_claims:
            raise ValueError("a deterministic-rule derivation must cite its input claims")

        # A claim cannot contradict itself.
        if self.claim_id in self.contradicted_by_claims:
            raise ValueError("a claim cannot be listed among its own contradictions")

        return self

    # -- construction ---------------------------------------------------------

    @staticmethod
    def compute_id(
        *,
        kind: ClaimKind,
        statement: Statement,
        derivation: DerivationKind,
        asserted_by: str,
        supported_by_evidence: tuple[str, ...],
        derived_from_claims: tuple[str, ...],
        rule_name: str | None,
        rule_version: str | None,
        model_identifier: str | None,
    ) -> str:
        """Derive the content address of a claim.

        Deliberately excludes timestamps and confidence. Re-deriving the same statement
        from the same inputs by the same rule yields the same claim, so a pursuit loop
        that revisits a pivot does not manufacture duplicate support for itself.
        """
        payload = json.dumps(
            {
                "kind": kind.value,
                "statement": statement.canonical(),
                "derivation": derivation.value,
                "asserted_by": asserted_by,
                "evidence": sorted(supported_by_evidence),
                "inputs": sorted(derived_from_claims),
                "rule": f"{rule_name or ''}@{rule_version or ''}",
                "model": model_identifier or "",
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
        return content_id(IdPrefix.CLAIM, payload)

    @classmethod
    def create(
        cls,
        *,
        kind: ClaimKind,
        statement: Statement,
        derivation: DerivationKind,
        asserted_by: str,
        asserted_at: datetime,
        valid_extent: TemporalExtent,
        supported_by_evidence: tuple[str, ...] = (),
        derived_from_claims: tuple[str, ...] = (),
        contradicted_by_claims: tuple[str, ...] = (),
        rule_name: str | None = None,
        rule_version: str | None = None,
        model_identifier: str | None = None,
        deception: DeceptionAssessment | None = None,
        notes: str | None = None,
    ) -> Claim:
        """Build a claim, deriving its content address."""
        claim_id = cls.compute_id(
            kind=kind,
            statement=statement,
            derivation=derivation,
            asserted_by=asserted_by,
            supported_by_evidence=supported_by_evidence,
            derived_from_claims=derived_from_claims,
            rule_name=rule_name,
            rule_version=rule_version,
            model_identifier=model_identifier,
        )
        return cls(
            claim_id=claim_id,
            kind=kind,
            statement=statement,
            derivation=derivation,
            asserted_by=asserted_by,
            asserted_at=asserted_at,
            valid_extent=valid_extent,
            supported_by_evidence=supported_by_evidence,
            derived_from_claims=derived_from_claims,
            contradicted_by_claims=contradicted_by_claims,
            rule_name=rule_name,
            rule_version=rule_version,
            model_identifier=model_identifier,
            deception=deception,
            notes=notes,
        )

    # -- properties -----------------------------------------------------------

    @property
    def epistemic_strength(self) -> int:
        return EPISTEMIC_STRENGTH[self.kind]

    @property
    def is_evidence_backed(self) -> bool:
        return bool(self.supported_by_evidence)

    @property
    def is_model_derived(self) -> bool:
        return self.derivation in _MODEL_DERIVATIONS

    @property
    def is_contradicted(self) -> bool:
        return bool(self.contradicted_by_claims)


def max_derivable_kind(inputs: tuple[Claim, ...]) -> ClaimKind:
    """The strongest kind a claim derived from these inputs may legitimately take.

    A conclusion inherits the standing of its weakest premise. This is the rule that stops
    a chain of individually defensible steps from laundering a hypothesis into a fact —
    the specific failure that produces confident, wrong attribution.

    With no inputs the answer is :attr:`ClaimKind.HYPOTHESIS`: a claim resting on nothing
    is a guess, whatever it asserts.
    """
    if not inputs:
        return ClaimKind.HYPOTHESIS

    weakest = min(claim.epistemic_strength for claim in inputs)

    # Derivation never yields an observation: nothing was witnessed, only reasoned.
    if weakest >= EPISTEMIC_STRENGTH[ClaimKind.INFERENCE]:
        return ClaimKind.INFERENCE
    if weakest >= EPISTEMIC_STRENGTH[ClaimKind.CORRELATION]:
        return ClaimKind.CORRELATION
    return ClaimKind.HYPOTHESIS


class EpistemicViolationError(ValueError):
    """Raised when a derivation would grant a claim more standing than its premises."""


def check_derivation(kind: ClaimKind, inputs: tuple[Claim, ...]) -> None:
    """Raise if deriving ``kind`` from ``inputs`` would inflate epistemic standing."""
    ceiling = max_derivable_kind(inputs)
    if EPISTEMIC_STRENGTH[kind] > EPISTEMIC_STRENGTH[ceiling]:
        weakest = min(inputs, key=lambda claim: claim.epistemic_strength) if inputs else None
        detail = (
            f"weakest premise is a {weakest.kind.value} ({weakest.claim_id})"
            if weakest
            else "there are no premises"
        )
        raise EpistemicViolationError(
            f"cannot derive a {kind.value} here: {detail}, so the strongest permissible "
            f"conclusion is a {ceiling.value}"
        )
