"""Cross-source corroboration of a threat actor — honest about what agreement means.

Two OSINT sources referencing the same ransomware operation is tempting to read as
corroboration. Usually it is not. ``ransomware.live`` republishes what leak sites post, and
``fastfire/deepdarkCTI`` indexes those same leak sites; both learn the actor's name and onion
from the actor advertising *itself*. An operator who controls its leak site controls what both
sources see, so their agreement is one origin heard twice — the "feed count is not source
count" problem this project keeps naming (ADR-0002, DEMO_SCENARIO.md §6).

This module does not decide that for you and does not inflate confidence. It hands each
source's opinion, with its provenance, to :func:`nemesis.core.fusion.establish_fact`, which
groups by origin, fuses dependent feeds with WBF (no uncertainty reduction) and only genuinely
independent origins with CBF. When both sources trace to the same ``upstream_of_record``, the
result reports **one** independent origin and says so. That is the point: the value here is
*enrichment* (linking an actor's victim claims to its infrastructure) and a *consistency
check* (the name resolves in both curated indexes), not a confidence boost.

**This is intelligence, not evidence** (invariant 1): the output is a
:class:`~nemesis.core.claims.ClaimKind` ``INFERENCE`` with a
:class:`~nemesis.core.claims.DeceptionAssessment` attached, never an ``EvidenceObject``.

The plane boundary is deliberate. ``resolve`` may not import ``nemesis.collect`` (the
import-linter contract "Resolution and attribution planes have no collection capability"), so
this module depends on ``core`` alone and takes neutral :class:`SourceView` inputs. Turning a
connector's ``PivotResult`` or a ``DeepDarkCtiReport`` into views is the caller's step, done
where collection types may be named.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict

from nemesis.core.claims import ClaimKind, DeceptionAssessment
from nemesis.core.confidence import Opinion
from nemesis.core.fusion import FusionResult, SourcedOpinion, establish_fact
from nemesis.core.provenance import SourceDescriptor

FACT_PREFIX = "actor-active"
"""All views attest one fact — 'this actor is a real, currently-active operation' — so they
fuse as accounts of a single fact rather than as separate findings."""


class SourceView(BaseModel):
    """What one OSINT source says about a threat actor, ready to fuse honestly.

    ``source`` carries the grading *and the provenance*: its ``upstream_of_record`` is what
    decides whether this view is independent of another. Two views whose sources share an
    upstream collapse into one origin — set them to the actor's own leak site when both
    sources merely relay the actor's self-presentation, which is the usual case.
    """

    model_config = ConfigDict(frozen=True)

    source: SourceDescriptor
    opinion: Opinion
    """This source's opinion on the proposition, before cross-source fusion."""
    detail: str = ""
    """A short human note on what the source contributes, e.g. 'claims 12 victims' or
    'leak site listed ONLINE'. Never the raw hostile content."""
    supporting: tuple[str, ...] = ()


class ActorCorroboration(BaseModel):
    """The cross-source picture of one actor, with agreement graded, not assumed."""

    model_config = ConfigDict(frozen=True)

    actor: str
    proposition: str
    contributing_sources: tuple[str, ...]
    details: tuple[str, ...]

    fusion: FusionResult
    independent_origins: int
    """Distinct origins after resolving aggregators and mirrors — from the fusion, not the
    number of sources consulted. This, not the source count, is what corroboration means."""
    independently_corroborated: bool
    """True only when at least two *independent* origins attest the actor. Two feeds of one
    leak site do not clear this bar however loudly they agree."""

    projected_probability: float
    deception: DeceptionAssessment
    discrepancies: tuple[str, ...]
    warnings: tuple[str, ...]
    claim_kind: ClaimKind = ClaimKind.INFERENCE

    def render(self) -> str:
        verdict = (
            "independently corroborated"
            if self.independently_corroborated
            else "referenced by multiple feeds of ONE origin — enrichment, not corroboration"
            if len(self.contributing_sources) > 1
            else "single-sourced"
        )
        return (
            f"{self.actor}: {verdict}; {self.independent_origins} independent origin(s); "
            f"projected {self.projected_probability:.0%}. " + " ".join(self.warnings)
        )


def corroborate_actor(
    actor_key: str,
    views: Sequence[SourceView],
) -> ActorCorroboration:
    """Fuse what several OSINT sources say about one actor, grading agreement honestly.

    ``views`` are the sources that reference ``actor_key`` (the caller filters). The result's
    ``independent_origins`` comes from :func:`establish_fact`, so views sharing an
    ``upstream_of_record`` count once no matter how many feeds carry them. A
    :class:`DeceptionAssessment` is always attached: an actor authors what these OSINT
    channels relay, so it can make them agree at trivial cost.
    """
    proposition = f"threat actor {actor_key} is a real, currently-active operation"

    sourced = [
        SourcedOpinion(
            source=view.source,
            opinion=view.opinion,
            supporting_claims=view.supporting,
            label=view.detail or view.source.identifier,
            fact_key=f"{FACT_PREFIX}:{actor_key}",
        )
        for view in views
    ]
    result = establish_fact(sourced)

    discrepancies = tuple(
        f"{left} vs {right} disagree (conflict {degree:.2f})"
        for left, right, degree in result.conflicting_pairs
    )
    # A liveness/direction split is a discrepancy in its own right, below the numeric conflict
    # threshold discounting compresses: one source asserting the actor is active while another
    # asserts it is not is exactly what an analyst wants flagged.
    positive = [v.source.identifier for v in views if v.opinion.belief >= v.opinion.disbelief]
    negative = [v.source.identifier for v in views if v.opinion.belief < v.opinion.disbelief]
    if positive and negative:
        discrepancies = (
            *discrepancies,
            f"sources disagree on activity: {', '.join(positive)} assert active, "
            f"{', '.join(negative)} do not",
        )
    if not views:
        discrepancies = ()
    elif len(views) == 1:
        discrepancies = (*discrepancies, "single-sourced: nothing to corroborate against")

    independent = result.independent_source_count
    corroborated = independent >= 2

    benefits = [
        "an operator controls both its leak site and its own posts, so it can make every "
        "OSINT relay of its self-presentation agree at trivial cost",
    ]
    contra: list[str] = []
    if corroborated:
        contra.append(
            f"{independent} genuinely independent origins attest this, which an actor cannot "
            "fabricate as cheaply as a single self-presentation"
        )

    deception = DeceptionAssessment(
        adversary_could_plant=True,
        planting_cost="trivial",
        benefits_from_belief=tuple(benefits),
        contra_indicators=tuple(contra),
    )

    return ActorCorroboration(
        actor=actor_key,
        proposition=proposition,
        contributing_sources=tuple(view.source.identifier for view in views),
        details=tuple(view.detail for view in views if view.detail),
        fusion=result,
        independent_origins=independent,
        independently_corroborated=corroborated,
        projected_probability=result.opinion.projected_probability,
        deception=deception,
        discrepancies=discrepancies,
        warnings=result.warnings,
    )


__all__ = [
    "FACT_PREFIX",
    "ActorCorroboration",
    "SourceView",
    "corroborate_actor",
]
