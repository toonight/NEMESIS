"""What an attack is, what it may conclude, and why three verdicts rather than two.

The types here are small and the distinctions in them are the whole contribution. A harness that
reported pass/fail would be a harness that eventually reported a pass for an attack it could not
stage, and "we could not run it" reading as "the control held" is the failure this file is shaped
to prevent.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from nemesis.pilot.pilot import AutonomousPilot

if TYPE_CHECKING:  # pragma: no cover - import cycle broken for typing only
    from nemesis.breaker.arena import Arena


class AttackVerdict(StrEnum):
    """What happened when the attack ran."""

    HELD = "held"
    """The attack executed and the control refused it. The good outcome, and the *only* one that
    is evidence of anything: it means a specific construction was tried and specifically
    stopped."""

    VIOLATED = "violated"
    """The attack executed and got what it wanted. A confirmed vulnerability, mapped to the
    invariant it breaks."""

    INCONCLUSIVE = "inconclusive"
    """The attack could not be staged — a fixture would not build, a precondition was absent,
    the arena raised.

    Reported as its own verdict and never folded into ``HELD``. An attack that did not run tells
    you nothing about the control, and a report that counted it as a pass would be the vacuous
    assertion this repository has shipped before: a containment check that returned the literal
    ``False`` and was the headline of four tests."""


class AttackCategory(StrEnum):
    """Which surface an attack aims at. Used to group a report, not to score one."""

    AUTHORITY = "authority"
    CREDENTIAL = "credential"
    NETWORK = "network"
    EFFECT = "effect"
    EVIDENCE = "evidence"
    AUDIT = "audit"
    ISOLATION = "isolation"
    PERSISTENCE = "persistence"


class AttackPilotFactory(Protocol):
    """Builds the pilot that drives one attack.

    The seam a **model-backed attacker** plugs into, and the reason this is a Protocol rather
    than a concrete scripted class. Everything shipped is deterministic; a deployment that wants
    a frontier model in the attacker seat supplies a factory that returns a
    :class:`~nemesis.pilot.providers.seat.ProviderSeat` instead, and rotates which vendor sits
    there between runs.

    What a model-backed attacker changes and does not change: it changes what gets *tried*, and
    it changes nothing about what is *permitted*. The arena hands it the same four verbs and the
    same envelope, and every assertion in an attack is made on the platform's side. An attacker
    model that could widen its own authority would be demonstrating the finding rather than
    producing one.
    """

    def __call__(self, arena: Arena) -> AutonomousPilot: ...


@dataclass(frozen=True)
class AttackOutcome:
    """The result of one attack, with enough to reproduce it and nothing that flatters it."""

    attack_id: str
    invariant: str
    verdict: AttackVerdict
    summary: str
    transcript: tuple[str, ...] = ()
    """Move-by-move, in the platform's own words: what was proposed and what was ruled. The
    thing a reader checks the verdict against, because a verdict nobody can audit by eye is a
    verdict nobody should trust — the same rule
    :class:`~nemesis.pilotbench.metrics.Violation` follows for a lexical match."""

    evidence: tuple[str, ...] = ()
    """The specific observations the verdict rests on. Separate from the transcript because the
    transcript is what happened and this is which parts of it decided the answer."""

    @property
    def is_finding(self) -> bool:
        return self.verdict is AttackVerdict.VIOLATED

    def render(self) -> str:
        head = f"[{self.verdict.value.upper():12}] {self.attack_id}  ({self.invariant})"
        body = "\n".join(f"      {line}" for line in self.evidence)
        return f"{head}\n    {self.summary}" + (f"\n{body}" if body else "")


@dataclass(frozen=True)
class Attack:
    """One adversarial construction, bound to the invariant it is trying to break.

    ``invariant`` is required and is not decoration. An attack that cannot name what it would
    violate is an attack nobody can act on the result of: a reader seeing it fail does not know
    whether the platform is broken or the attack was wrong, and a reader seeing it pass does not
    know what was established. Binding each one to a stable identifier from
    `docs/security/INVARIANTS.md` is what makes the report a statement about the architecture
    rather than a list of anecdotes.
    """

    attack_id: str
    invariant: str
    category: AttackCategory
    description: str
    run: Callable[[Arena], Awaitable[AttackOutcome]]

    regression_test: str = ""
    """The test that pins this attack in the ordinary suite, when one does.

    Empty is allowed and is reported as such. An attack the Breaker checks and CI does not is an
    attack that stops being checked the moment nobody runs the Breaker, and the report says which
    those are rather than presenting the whole catalogue as continuously enforced.
    """

    tags: tuple[str, ...] = field(default_factory=tuple)


__all__ = [
    "Attack",
    "AttackCategory",
    "AttackOutcome",
    "AttackPilotFactory",
    "AttackVerdict",
]
