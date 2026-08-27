"""NEMESIS Breaker — an offline adversary whose job is to make this platform fail.

Every other test in this repository is written by someone trying to show a control works. That
is necessary and it is not sufficient, and this project has the receipts: two adversarial reviews
each broke a control on a tree where the whole suite was green, because the tests asserted what
the design intended rather than what an attacker could construct. The Breaker exists to be the
other kind of reader.

**What it is.** A catalogue of typed attacks, each naming the invariant it is trying to violate,
each run against a throwaway arena, each returning a transcript that reproduces exactly. It
reports three verdicts and keeps them apart: ``HELD`` (the attack ran and the control refused),
``VIOLATED`` (the attack ran and got what it wanted), ``INCONCLUSIVE`` (the attack could not be
staged, which is not evidence of anything and must never be counted as a pass).

**What it is not, structurally.** It is not on the authority path, and an ``import-linter``
contract named `nothing-depends-on-the-breaker` says so: no plane may import
:mod:`nemesis.breaker`. The dependency runs one way only — the Breaker imports the mediator, the
envelope and the effects registry, because an adversarial harness that had to reimplement its
target would be testing its own reimplementation.

**No production anything.** Each arena mints an ephemeral signing key, writes to a temporary
directory, wires only simulation and drafting adapters, and asserts on the way out that nothing
reported external contact. There is no configuration by which the Breaker reaches a real vault, a
real capability, a real credential or a real network — and the attacks that *try* to are among
the attacks, which is the point.

**Rotating the attacker is a design goal and is not implemented here.** Everything shipped is
deterministic and scripted, so the harness itself is testable without an API key and a finding is
reproducible by anyone. The interface for a model-backed attacker is
:class:`~nemesis.breaker.attack.AttackPilotFactory`: an attack that wants a model composes one
instead of a script, and a deployment rotates which vendor sits in the attacker seat
(Claude drives, GPT breaks; then GPT drives, Claude breaks) to avoid a monoculture blind spot —
the same reasoning ADR-0009 gives for provider-neutral seats. What is missing is only the
scenario library that would make a model-driven run mean something; the seam is here. See
`docs/security/BREAKER.md`.

Status: `IMPLEMENTED` (harness, ten deterministic attacks) / `PROPOSED` (model-backed attacker,
rotation schedule).
"""

from __future__ import annotations

from nemesis.breaker.arena import Arena, arena
from nemesis.breaker.attack import (
    Attack,
    AttackCategory,
    AttackOutcome,
    AttackPilotFactory,
    AttackVerdict,
)
from nemesis.breaker.attacks import ATTACKS, attack_by_id
from nemesis.breaker.report import BreakerReport, run_breaker

__all__ = [
    "ATTACKS",
    "Arena",
    "Attack",
    "AttackCategory",
    "AttackOutcome",
    "AttackPilotFactory",
    "AttackVerdict",
    "BreakerReport",
    "arena",
    "attack_by_id",
    "run_breaker",
]
