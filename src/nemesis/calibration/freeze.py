"""The constants and the behaviour, frozen before anything is measured against them.

WHY A FREEZE COMES FIRST

This project's largest declared weakness is that no confidence figure it produces has ever
been scored against a known-correct answer. Fixing that needs a corpus of resolved cases, and
building one is worth nothing if the engine can be adjusted while the evaluation runs: a score
obtained by tuning against the same cases that measure you is a score of your tuning, not of
your method. Every calibration constant in this codebase is a documented *choice*, which makes
the temptation concrete — each one is a dial, and each dial moves a number somebody is about to
grade.

So the order is: freeze, then evaluate. This module makes the freeze **mechanical** rather than
a promise in a document, because a promise is exactly what gets quietly revised at the point it
becomes inconvenient.

WHAT IS FROZEN, AND HOW

Two things, by two different mechanisms, because they fail differently.

**The constants** are read from the modules that hold them and folded into a digest. A change
to any of them changes the digest, and the frozen value below no longer matches. That is not a
prohibition — constants *should* change when there is a reason — it is a requirement that the
change be **deliberate and visible**: updating the manifest is a line in a diff, with a commit
message, at a moment somebody chose.

**The behaviour** is pinned by golden vectors: fixed inputs, fixed outputs, in
`tests/invariants/test_calibration_freeze.py`. Hashing the source of the fusion operators would
have been easier and worse — a reworded comment would break it while a changed sign would not,
which is the wrong sensitivity in both directions. What matters is not that the code is
identical but that it *answers the same*.

WHAT THIS DOES NOT DO

It does not make the constants right. They remain choices, and freezing a choice does not
validate it — it only stops the choice from moving while it is being examined. It also cannot
tell an honest recalibration from a convenient one; it makes both visible, and visibility is
what an evaluation needs to be worth reading.
"""

from __future__ import annotations

import hashlib
import importlib
from typing import Final

CALIBRATION_CONSTANTS: Final[tuple[str, ...]] = (
    # Subjective-logic machinery: how belief, disbelief and uncertainty combine.
    "nemesis.core.confidence:VACUITY_THRESHOLD",
    "nemesis.core.confidence:BAND_RANGES",
    "nemesis.core.fusion:CONFLICT_ALERT_THRESHOLD",
    # Attribution: how much a planted artifact may move a conclusion, and what deception is
    # assumed to cost before any evidence is seen.
    "nemesis.attribute.engine:PLANTED_EVIDENCE_DISBELIEF_CEILING",
    "nemesis.attribute.engine:CONTRA_INDICATOR_DISCOUNT",
    "nemesis.attribute.engine:DECEPTION_BASE_RATE",
    "nemesis.attribute.engine:DEFAULT_BASE_RATE",
    "nemesis.attribute.engine:PLANTING_BELIEF_BY_COST",
    # Persona resolution: the base rate a linkage is measured against, and the floors and
    # ceilings that keep a fallible technique from becoming decisive.
    "nemesis.resolve.engine:ASSUMED_PERSONAS_PER_OPERATOR",
    "nemesis.resolve.engine:BASE_RATE_FLOOR",
    "nemesis.resolve.engine:BASE_RATE_CEILING",
    "nemesis.resolve.engine:NEGLIGIBLE_CONTRIBUTION",
    # Signal ceilings: what each technique is allowed to be worth at its very best.
    "nemesis.resolve.signals:STYLOMETRY_BELIEF_CEILING",
    "nemesis.resolve.signals:DEMONSTRATED_KEY_CONTROL_CEILING",
    "nemesis.resolve.signals:CONTRADICTION_BELIEF_CEILING",
    "nemesis.resolve.signals:IRREDUCIBLE_UNCERTAINTY",
    "nemesis.resolve.signals:MIN_POSTS_FOR_A_ROUTINE",
    "nemesis.resolve.signals:OPEN_WORLD_STYLOMETRY_PENALTY",
    "nemesis.resolve.signals:OBFUSCATION_STYLOMETRY_PENALTY",
    "nemesis.resolve.signals:BELIEF_CEILING",
    # Tables that decide as much as any scalar, and that the first scanner could not see
    # because it only matched `NAME = <digit>`.
    "nemesis.core.proposition:ROBUSTNESS_MARGIN",
    "nemesis.core.relationships:METHOD_RELIABILITY_CEILING",
    "nemesis.disrupt.options:OWNERSHIP_CONFIDENCE_FLOOR",
    "nemesis.disrupt.options:IMPACT_RANK",
    # Numerical-stability epsilons. Registered rather than excused: they decide behaviour at
    # boundaries, and "it is only an epsilon" is exactly the reasoning that lets a dial escape.
    # Registering one is free; missing one is not.
    "nemesis.core.confidence:_TOLERANCE",
    "nemesis.core.fusion:_EPS",
)
"""Every number that moves a confidence figure, named as ``module:NAME``.

Enumerated rather than discovered. A scan for module-level numbers would sweep in timeouts,
buffer sizes and scenario populations, and the difference between "a dial that changes what the
platform believes" and "a dial that changes how long it waits" is exactly the judgement a
regex cannot make. Adding a constant here is therefore a deliberate act — and leaving a new
calibration constant *out* is the way to defeat this whole mechanism, which is why
:func:`unregistered_calibration_constants` exists to make that omission visible too.
"""

FROZEN_DIGEST: Final = "747ba63d427d3f3f5afda82c8fc504e64421f3edae9da883baccb613c53dc1f1"
"""The digest of the values above, frozen 2026-08-20, before any evaluation exists.

Updated **only** as a documented event, in its own commit, with the reason. A mismatch is not
a failure of the code — it means a dial moved, and the question it forces is whether that
happened before an evaluation or during one.
"""


def observed_values() -> dict[str, object]:
    """Read every registered constant from the module that actually holds it.

    Imported rather than parsed, so a constant that was moved, renamed or shadowed fails loudly
    here instead of being silently read from a stale copy of the source.
    """
    values: dict[str, object] = {}
    for reference in CALIBRATION_CONSTANTS:
        module_name, _, attribute = reference.partition(":")
        module = importlib.import_module(module_name)
        if not hasattr(module, attribute):
            raise CalibrationFreezeError(
                f"{reference} is registered as a calibration constant and does not exist. "
                "Renaming or removing one is a change to what this platform believes, and it "
                "cannot be allowed to pass as an import error nobody reads."
            )
        values[reference] = getattr(module, attribute)
    return values


CALIBRATED_MODULES: Final[tuple[str, ...]] = (
    "nemesis/core/confidence.py",
    "nemesis/core/fusion.py",
    "nemesis/core/proposition.py",
    "nemesis/core/relationships.py",
    "nemesis/attribute/engine.py",
    "nemesis/resolve/engine.py",
    "nemesis/resolve/signals.py",
    "nemesis/disrupt/options.py",
)
"""Where confidence figures are decided. Scanned for constants the registry forgot.

Widened after a review: `ROBUSTNESS_MARGIN` and `METHOD_RELIABILITY_CEILING` are among the most
consequential dials in the platform and lived in modules this list did not name, so the scan
could not have found them however good it was. An incomplete module list defeats a scanner as
thoroughly as a bad pattern."""

_NOT_CALIBRATION: Final[tuple[str, ...]] = (
    "MAX_",
    "TIMEOUT",
    "SECONDS",
    "VERSION",
    "BYTES",
    "CHUNK",
)
"""Prefixes and words that mark a number as operational rather than epistemic. A timeout is a
dial; it is not a dial that changes what the platform believes."""


def unregistered_calibration_constants() -> tuple[str, ...]:
    """Module-level constants in the scoring modules that nobody registered.

    **Parsed with `ast`, not matched with a regex, and compared fully qualified.** The first
    version did neither, and a reviewer walked through both holes in one demonstration: it saw
    only ``NAME = <digit>``, so every dial that is a *table* — `BAND_RANGES`,
    `DEFAULT_BASE_RATE`, `BELIEF_CEILING`, `ROBUSTNESS_MARGIN`,
    `METHOD_RELIABILITY_CEILING` — was invisible; and it compared bare names, so a homonym in
    another module counted as registered. Changing `BAND_RANGES` alone moved a published
    confidence band from *likely* to *almost certain* while both checks stayed green.

    A table is not a lesser dial than a scalar. `BAND_RANGES` decides the word a reader
    actually sees, which is the only number most consumers of this platform will ever read.

    Still deliberately crude in one direction: it flags anything upper-case holding a number
    that is not registered or excluded. A false positive costs one line; a false negative costs
    the credibility of every figure the evaluation produces.
    """
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    registered = set(CALIBRATION_CONSTANTS)
    stray: list[str] = []

    def holds_a_number(node: ast.AST) -> bool:
        return any(
            isinstance(child, ast.Constant)
            and isinstance(child.value, int | float)
            and not isinstance(child.value, bool)
            for child in ast.walk(node)
        )

    for relative in CALIBRATED_MODULES:
        module = relative.removesuffix(".py").replace("/", ".")
        tree = ast.parse((root.parent / relative).read_text(encoding="utf-8"))
        for node in tree.body:
            name: str | None = None
            value: ast.expr | None = None
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                name, value = node.target.id, node.value
            elif (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                name, value = node.targets[0].id, node.value
            if name is None or value is None or not name.lstrip("_").isupper():
                continue
            if not holds_a_number(value):
                continue
            reference = f"{module}:{name}"
            if reference in registered or any(mark in name for mark in _NOT_CALIBRATION):
                continue
            stray.append(reference)
    return tuple(sorted(stray))


def freeze_digest(values: dict[str, object] | None = None) -> str:
    """Fold the registered constants into one value, order-independent.

    Sorted by name so re-ordering the registry cannot change the digest: what is frozen is the
    set of values, not the sequence somebody typed them in.
    """
    observed = values if values is not None else observed_values()
    folded = hashlib.sha256()
    for name in sorted(observed):
        folded.update(name.encode("utf-8"))
        folded.update(b"=")
        folded.update(repr(observed[name]).encode("utf-8"))
        folded.update(b"\x00")
    return folded.hexdigest()


def drifted() -> tuple[str, ...]:
    """Which constants no longer match the freeze — empty when the digest holds.

    Returns the names rather than a bare boolean, because "something moved" is not actionable
    and "``DECEPTION_BASE_RATE`` moved" is. The comparison is against the digest, so this can
    only report *that* the set changed; naming which one requires the frozen values, which are
    kept in the test that pins them.
    """
    return () if freeze_digest() == FROZEN_DIGEST else tuple(sorted(observed_values()))


class CalibrationFreezeError(RuntimeError):
    """A registered calibration constant is missing or unreadable.

    Its own type because it is a structural problem with the registry rather than a drift in a
    value: a caller checking "did a dial move" must not swallow "a dial disappeared".
    """


__all__ = [
    "CALIBRATED_MODULES",
    "CALIBRATION_CONSTANTS",
    "FROZEN_DIGEST",
    "CalibrationFreezeError",
    "drifted",
    "freeze_digest",
    "observed_values",
    "unregistered_calibration_constants",
]
