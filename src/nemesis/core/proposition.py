"""What kind of thing is being claimed, and how many planted facts it must survive.

Fusion did not previously know what proposition it was fusing, and that is why one planted
source could reach a band an analyst would act on. The bar for believing *"this domain
resolved to this address"* and the bar for believing *"this party is responsible"* are not
the same bar, and a calculus that cannot tell them apart must use one of them for both.

A finding that has to be withdrawn explicitly, because it was a stated design constraint:
**one origin can no longer reach an actionable band on an attribution.** Measured, the
planted single source and the legitimate single source are the same object —
``P=0.7812, u=0.4375, LIKELY`` for both, byte-identical in shape. No mechanism separates
them, so any fix that leaves one origin actionable has not fixed anything. The constraint
was unsatisfiable and is withdrawn here rather than quietly bent.

What replaces it is a **robustness margin**: the number of plantable facts whose removal a
conclusion must survive before it is reported. Not a threshold on strength — strength is
the axis an adversary can move, and a threshold on it is a threshold on the adversary's
budget. A margin is a count of the distinct facts an adversary must plant, which is a cost
they cannot buy down with more confident-looking evidence.
"""

from __future__ import annotations

from enum import StrEnum


class PropositionClass(StrEnum):
    """What is being claimed. Determines the robustness margin."""

    OBSERVATION = "observation"
    """A property of an artifact: this domain resolved here, this certificate was presented.

    Margin 0 — bit-identical to the behaviour before this mechanism existed. Planting does
    not change the truth of an observation: a domain an adversary registered really did
    resolve where it resolved. One reliable observer of that fact is genuinely sufficient,
    and refusing it would break the platform for no gain."""

    SHARED_ORIGIN = "shared_origin"
    """These artifacts share a controller: same certificate, same key, same cluster.

    Margin 1. Planting changes the truth here — an adversary who places their certificate
    on a third party's host manufactures exactly this proposition."""

    ACTOR_ATTRIBUTION = "actor_attribution"
    """This party is responsible.

    Margin 1. The claim that ends in a takedown request, a referral or a filing."""


ROBUSTNESS_MARGIN: dict[PropositionClass, int] = {
    PropositionClass.OBSERVATION: 0,
    PropositionClass.SHARED_ORIGIN: 1,
    PropositionClass.ACTOR_ATTRIBUTION: 1,
}
"""How many plantable facts a conclusion must survive losing.

The only stipulated number in this mechanism, and it is a count of adversary-owned facts
rather than a quantity of belief. The argument for 1: the measured attack is **one** planted
artifact, and the margin is precisely the number of distinct facts an adversary must own
before the answer moves at all.

Whether ACTOR_ATTRIBUTION deserves 2 was measured during design: the false-match rate was
already 0% at 1, so raising it bought nothing and cost a further large drop in actionable
findings on genuinely corroborated true cases. It is a separate enum member from
SHARED_ORIGIN so that it can be raised later without a schema change, which is the only
reason the two are distinct at margin 1.
"""


class MarginOutcome(StrEnum):
    """Why the reported opinion is what it is. Recorded so a refusal can be explained."""

    NO_MARGIN = "no_margin"
    """An OBSERVATION, or nothing to fuse. Reported as fused."""

    NOT_AN_ACCUSATION = "not_an_accusation"
    """The conclusion sits at or below its prior, so there is nothing to be robust about.

    Guard against margining exculpation. Removing support from a finding that already
    fails to accuse would push it further from accusing, which is not a safety property —
    and it would silently zero every deception alternative, which are single-source
    hypotheses by construction (invariant 13)."""

    NO_REMOVABLE_FACT = "no_removable_fact"
    """Every supporting fact is attested by a channel an adversary cannot author. Nothing
    to remove, so the conclusion stands unchanged."""

    EVERY_FACT_REMOVED = "every_fact_removed"
    """The only support was plantable. The honest report is that nothing was established."""

    SURVIVED = "survived"
    """The conclusion held after dropping the most load-bearing plantable fact."""
