"""Ingest the local CyberTiel model's output as data — a lead, never evidence, never a naming.

The ``cti-toolkit`` runs a local model (CyberTiel-Coder, MLX) for three jobs and three only:
triage, search-pivot generation, and RAG answers grounded in the operator's knowledge cards. The
model's training is stale and it hallucinates specific facts, so its output is never taken as a
fact — it is a heuristic first pass, verified downstream against primary sources.

**The model is a separate process and is never imported here.** ``scripts/check_prohibited.py``
bans the model SDKs (``mlx``, ``transformers`` and the rest) everywhere, and this module imports
none of them. CyberTiel stays in ``~/cti-toolkit`` behind ``ct_rag.py`` / ``triage_cybertiel.py``;
what crosses into NEMESIS is its *text output*, handed to the functions here as ordinary data.

**What that output is allowed to become.** A :class:`~nemesis.core.claims.Claim` whose derivation
is :attr:`~nemesis.core.claims.DerivationKind.MODEL_ASSERTION` and whose kind is
:attr:`~nemesis.core.claims.ClaimKind.HYPOTHESIS` — or ``ClaimKind.INFERENCE`` when it cites the
card claims it was grounded in. It can never be an ``OBSERVATION`` or a ``FACT``: invariant 1,
enforced in ``Claim``'s own validator, so this module could not mint one even by mistake. The model
identifier travels on the claim, because *which* model said it is part of the claim and not
metadata about it. A :class:`~nemesis.core.claims.DeceptionAssessment` is attached to every claim:
the model may have read adversary-authored pages, and a planted page can steer its label as cheaply
as it steers a human analyst.

**Two refusals hold in code, not in a prompt.** The model may not be turned into a naming of a
person — a subject or object in :attr:`~nemesis.core.entities.EntityCategory.HUMAN_IDENTITY` is
refused (the platform emits observations about the human, never a model-authored accusation). And
the model's free-text *rationale is not carried into the graph at all*: only the structured
assessment (subject, predicate, object, and structured qualifiers such as a triage value) becomes a
claim, so an instruction — or a credential — planted in a page the model read cannot ride out of
this boundary as either instruction (invariant 5) or material. The reasoning stays in the toolkit's
own output; representing any credential it surfaced as a keyed
:class:`~nemesis.core.credentials.CredentialIndicator` is the engine's job, behind the
independent authorization path invariant AUTH-04 protects — not something the collect plane
reaches for.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Final

from nemesis.core.claims import (
    Claim,
    ClaimKind,
    DeceptionAssessment,
    DerivationKind,
    Statement,
)
from nemesis.core.entities import (
    CATEGORY_OF,
    EntityCategory,
    EntityType,
    NormalizationError,
    normalize_identifier,
)
from nemesis.core.relationships import RelationType
from nemesis.core.temporal import TemporalExtent, require_utc

_MAX_OBJECT_CHARS: Final = 2048
_PARSE_FAILURE_NOTE: Final = "MODEL_PARSE_FAILURE"

_LEAD_NOTE: Final = (
    "Model-derived lead: verify against primary sources before acting. Not evidence, not a "
    "finding, and never a naming of a person. The model's free-text reasoning is deliberately not "
    "carried into the graph."
)

_MODEL_DECEPTION: Final = DeceptionAssessment(
    adversary_could_plant=True,
    planting_cost="trivial",
    benefits_from_belief=(
        "the local model may have read adversary-authored content; a planted page can steer its "
        "label as cheaply as it steers a human analyst",
    ),
)


class ModelIngestError(ValueError):
    """The model output could not be ingested as a lead without violating a boundary.

    A construction error caught at construction: a missing model identifier, an attempt to assess a
    human identity, or a triage row that records a parse failure rather than an assessment.
    """


def _refuse_human_identity(entity_type: EntityType, role: str) -> None:
    if CATEGORY_OF[entity_type] is EntityCategory.HUMAN_IDENTITY:
        raise ModelIngestError(
            f"a model assessment may not name a human identity ({role} is "
            f"{entity_type.value}); the platform emits observations about the operator, never a "
            "model-authored naming of a person"
        )


def _object_term(obj: tuple[EntityType, str] | str) -> str:
    if isinstance(obj, tuple):
        entity_type, key = obj
        _refuse_human_identity(entity_type, "object")
        try:
            normalized = normalize_identifier(entity_type, key)
        except NormalizationError as exc:
            raise ModelIngestError(f"unusable object key: {exc}") from exc
        return f"{entity_type.value}:{normalized}"
    term = obj.strip()
    if not term:
        raise ModelIngestError("the object of a model assessment must not be empty")
    return term[:_MAX_OBJECT_CHARS]


def ingest_model_assessment(
    *,
    model_identifier: str,
    subject: tuple[EntityType, str],
    predicate: RelationType,
    obj: tuple[EntityType, str] | str,
    asserted_by: str,
    asserted_at: datetime,
    valid_extent: TemporalExtent | None = None,
    derived_from_claims: tuple[str, ...] = (),
    qualifiers: Mapping[str, str] | None = None,
) -> Claim:
    """Turn one local-model assessment into a ``MODEL_ASSERTION`` claim (a lead, not a fact).

    ``derived_from_claims`` are the ids of the knowledge-card claims the model was grounded in; when
    present the claim is an ``INFERENCE`` (grounded), otherwise a ``HYPOTHESIS`` (a bare proposal).
    Either way it is a ``MODEL_ASSERTION`` and can never be an observation or a fact.

    ``qualifiers`` carries the *structured* facets of the assessment (a triage value, risk flags);
    the model's free-text reasoning is deliberately not accepted, so nothing an adversary planted in
    a page the model read can ride into the graph through this function.
    """
    if not model_identifier.strip():
        raise ModelIngestError("a model assessment must name the model that produced it")
    require_utc(asserted_at, "asserted_at")
    _refuse_human_identity(subject[0], "subject")

    try:
        subject_key = normalize_identifier(subject[0], subject[1])
    except NormalizationError as exc:
        raise ModelIngestError(f"unusable subject key: {exc}") from exc

    object_term = _object_term(obj)
    kind = ClaimKind.INFERENCE if derived_from_claims else ClaimKind.HYPOTHESIS

    merged_qualifiers = {"model_derived": "true", **(dict(qualifiers) if qualifiers else {})}
    statement = Statement(
        subject=f"{subject[0].value}:{subject_key}",
        predicate=predicate.value,
        obj=object_term,
        qualifiers=merged_qualifiers,
        natural_language=(
            f"A local model assessed that {subject[0].value}:{subject_key} "
            f"{predicate.value} {object_term}. This is a model-derived {kind.value}: a lead to "
            "verify against primary sources, not evidence and not a finding, and never a naming of "
            "a person."
        ),
    )

    return Claim.create(
        kind=kind,
        statement=statement,
        derivation=DerivationKind.MODEL_ASSERTION,
        asserted_by=asserted_by,
        asserted_at=asserted_at,
        valid_extent=valid_extent or TemporalExtent.at(asserted_at),
        derived_from_claims=derived_from_claims,
        model_identifier=model_identifier,
        deception=_MODEL_DECEPTION,
        notes=_LEAD_NOTE,
    )


def triage_row_to_assessment(
    row: Mapping[str, object],
    *,
    subject: tuple[EntityType, str],
    asserted_by: str,
    asserted_at: datetime,
    model_identifier: str | None = None,
) -> Claim:
    """Turn one ``triage_cybertiel.py`` / ``triage_qwen.py`` output row into a ``HYPOTHESIS`` claim.

    A triage row is ``{"intel_type", "cti_value", "risk", "note", "model", ...}``. A row that
    recorded a parse failure, or names no ``intel_type``, is refused: a failure to classify is not a
    classification. Only the structured facets (``cti_value``, ``risk``) become qualifiers; the
    free-text ``note`` is not carried into the graph. The model identifier comes from
    ``model_identifier`` or, failing that, the row's own ``model`` field.
    """
    intel_type = row.get("intel_type")
    note = str(row.get("note") or "")
    if not isinstance(intel_type, str) or not intel_type or note == _PARSE_FAILURE_NOTE:
        raise ModelIngestError(
            "a triage row without an intel_type (or recording a parse failure) is not an "
            "assessment and is refused"
        )
    raw_model = row.get("model")
    resolved_model = model_identifier or (raw_model if isinstance(raw_model, str) else None)
    if not resolved_model:
        raise ModelIngestError("the triage row names no model; a model assessment must name one")

    qualifiers: dict[str, str] = {}
    cti_value = row.get("cti_value")
    if isinstance(cti_value, int):
        qualifiers["cti_value"] = str(cti_value)
    risk = row.get("risk")
    if isinstance(risk, list) and all(isinstance(flag, str) for flag in risk):
        qualifiers["risk"] = ",".join(risk)

    return ingest_model_assessment(
        model_identifier=resolved_model,
        subject=subject,
        predicate=RelationType.ASSOCIATED_WITH,
        obj=f"intel_type:{intel_type}",
        asserted_by=asserted_by,
        asserted_at=asserted_at,
        qualifiers=qualifiers,
    )


__all__ = [
    "ModelIngestError",
    "ingest_model_assessment",
    "triage_row_to_assessment",
]
