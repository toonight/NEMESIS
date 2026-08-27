"""Running the catalogue, and printing a result nobody can round up.

Two rules shape this file, and both are about not letting a number mean more than it does.

**An attack that did not run is never counted as one that held.** ``INCONCLUSIVE`` has its own
column and its own line in the verdict, and a run with any inconclusive attack does not report
itself as clean. The alternative — folding them into the pass count — is the vacuous assertion
this repository has already shipped once and written down twice.

**A held attack that nothing else pins is named.** The Breaker is an offline harness somebody has
to remember to run. An attack it checks and CI does not is an attack that stops being checked the
day nobody runs it, so the report prints which of them have a regression test behind them and
which are held only here.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from nemesis.breaker.arena import arena as build_arena
from nemesis.breaker.arena import discard
from nemesis.breaker.attack import Attack, AttackOutcome, AttackVerdict
from nemesis.breaker.attacks import ATTACKS


@dataclass(frozen=True)
class BreakerReport:
    """What one Breaker run established, and what it did not."""

    outcomes: tuple[AttackOutcome, ...]

    @property
    def held(self) -> tuple[AttackOutcome, ...]:
        return tuple(o for o in self.outcomes if o.verdict is AttackVerdict.HELD)

    @property
    def findings(self) -> tuple[AttackOutcome, ...]:
        """Confirmed vulnerabilities. The only thing here that is a claim about the platform."""
        return tuple(o for o in self.outcomes if o.verdict is AttackVerdict.VIOLATED)

    @property
    def inconclusive(self) -> tuple[AttackOutcome, ...]:
        return tuple(o for o in self.outcomes if o.verdict is AttackVerdict.INCONCLUSIVE)

    @property
    def clean(self) -> bool:
        """No finding **and** nothing unrun.

        Both halves, because a run that could not stage four of its attacks has not established
        that four controls hold — it has established that it could not check them, which is a
        different sentence and must not be able to print as this one.
        """
        return not self.findings and not self.inconclusive

    def unpinned(self, catalogue: Sequence[Attack] = ATTACKS) -> tuple[str, ...]:
        """Held attacks with no regression test naming them.

        An outcome whose id is not in the catalogue counts as unpinned rather than being skipped.
        A caller passing a filtered catalogue and a full outcome list would otherwise get a
        shorter list of unpinned attacks than is true, which is the wrong direction for a warning.
        """
        pinned = {a.attack_id for a in catalogue if a.regression_test}
        return tuple(o.attack_id for o in self.held if o.attack_id not in pinned)

    def render(self, catalogue: Sequence[Attack] = ATTACKS) -> str:
        by_id = {attack.attack_id: attack for attack in catalogue}
        lines = [
            "NEMESIS Breaker",
            "=" * 78,
            "",
            f"  attacks run     {len(self.outcomes)}",
            f"  held            {len(self.held)}",
            f"  FINDINGS        {len(self.findings)}",
            f"  inconclusive    {len(self.inconclusive)}",
            "",
        ]
        for outcome in self.outcomes:
            attack = by_id.get(outcome.attack_id)
            lines.append(outcome.render())
            if attack is not None:
                pin = attack.regression_test or "NO REGRESSION TEST — held only by this harness"
                lines.append(f"      pinned by: {pin}")
            lines.append("")

        if self.findings:
            lines += [
                "CONFIRMED VULNERABILITIES",
                "-" * 78,
                *(f"  {o.attack_id}: violates {o.invariant} — {o.summary}" for o in self.findings),
                "",
            ]
        if self.inconclusive:
            lines += [
                "NOT ESTABLISHED (the attack could not be staged; this is not a pass)",
                "-" * 78,
                *(f"  {o.attack_id}: {o.summary}" for o in self.inconclusive),
                "",
            ]
        unpinned = self.unpinned(catalogue)
        if unpinned:
            lines += [
                "HELD ONLY HERE (no regression test; stops being checked if nobody runs this)",
                "-" * 78,
                *(f"  {name}" for name in unpinned),
                "",
            ]
        lines += [
            "This is an offline harness driving scripted attackers against throwaway arenas.",
            "It holds no production credential, wires no production effect, and reaches no",
            "network. A HELD verdict means one specific construction was tried and stopped —",
            "not that the invariant holds against constructions nobody has written yet.",
        ]
        return "\n".join(lines)


async def run_breaker(catalogue: Sequence[Attack] = ATTACKS) -> BreakerReport:
    """Run every attack in its own arena, and never let one attack's failure end the run.

    An attack that raises becomes ``INCONCLUSIVE`` with the exception type, rather than taking
    the process with it. The reasoning is the mediator's about a pilot that raises: a harness one
    broken attack can silence is a harness that reports nothing on the day it matters — and here
    the stakes are lower but the shape is identical, because the alternative is a run that
    printed a traceback and no verdicts at all.
    """
    outcomes: list[AttackOutcome] = []
    for attack in catalogue:
        current = None
        try:
            current = await build_arena()
            outcomes.append(await attack.run(current))
        except Exception as exc:
            outcomes.append(
                AttackOutcome(
                    attack_id=attack.attack_id,
                    invariant=attack.invariant,
                    verdict=AttackVerdict.INCONCLUSIVE,
                    summary=(f"the attack could not be staged: {type(exc).__name__}: {exc}"[:300]),
                )
            )
        finally:
            if current is not None:
                discard(current)
    return BreakerReport(outcomes=tuple(outcomes))


__all__ = ["BreakerReport", "run_breaker"]
