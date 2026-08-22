#!/usr/bin/env python3
"""Every number this repository states about itself, checked against the repository.

WHY THIS EXISTS

`CLAUDE.md` says documentation that contradicts the code is a defect. Counts are the part of
the documentation that rots fastest and silently: a badge reading `tests-845` was wrong within
an hour of being written, by the same person who wrote it, because eleven tests were added
next. Nobody re-reads a badge.

So the numbers stop being decoration and become a build step. A claim that disagrees with the
measurement fails CI, with the file, the line, and both values.

WHAT IS DELIBERATELY *NOT* AUTOMATIC

Only claims in the registry below are enforced, and adding one is a deliberate act. The
alternative — scanning for anything that looks like a count — would corrupt the record, because
this repository's documents also contain **historical** numbers:

    "...with a ten-line `str` subclass, on a tree where all 517 tests passed."

That sentence is *correct*. It describes a review that happened when the suite had 517 tests.
Auto-updating it to today's count would turn an accurate account of the past into a false one,
which is worse than the stale badge this script exists to prevent. A tool that cannot tell a
current claim from a historical one must not be allowed to rewrite either.

"~20 tests" and similar deliberate approximations are excluded for the same reason: they are
prose about magnitude, not assertions of a count.

COLLECTED, NOT PASSING — AND THE REASON IS A FINDING

The first version measured tests *passing*, because the badge said "passing". Its first run in
CI failed: 856 on the author's laptop, 844 on the Ubuntu runner. Twelve kernel-confinement
tests are gated on `sandbox_available()`, which is `sandbox-exec` and therefore macOS only,
and three more need a 29 GB local model.

So "856 passing" was a **macOS-specific claim about to be published as universal**, and the
check caught it on the one run that mattered. It also exposes something larger than a badge:
CI never exercises invariant 8's kernel-enforced form at all. That is recorded in
PROJECT_STATE rather than left as a number nobody reconciles.

`tests` therefore measures what is *collected* — 859 on every platform, because a skipped test
is still collected — and the badge says "tests" rather than "passing". How many actually run
depends on the machine, which is a property of this suite and not something a badge can carry.

USAGE
    uv run python scripts/check_documented_counts.py           # verify, exit 1 on mismatch
    uv run python scripts/check_documented_counts.py --fix     # rewrite claims to measured
"""

from __future__ import annotations

import argparse
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parent.parent


def _run(command: list[str]) -> str:
    """Run a measurement and return its combined output.

    Never raises on a non-zero exit: `mypy` and `pytest` both signal findings that way, and a
    measurement that refused to report because the tree has a failing test would make this
    script fail for a reason that is not its own.
    """
    finished = subprocess.run(  # noqa: S603 - fixed argv, no shell
        command, cwd=ROOT, capture_output=True, text=True, check=False
    )
    return finished.stdout + finished.stderr


def _extract(output: str, pattern: str, what: str) -> int:
    match = re.search(pattern, output)
    if match is None:
        raise SystemExit(
            f"could not measure {what}: no match for {pattern!r} in the tool's output.\n"
            "The tool changed its output format — fix the pattern rather than deleting the "
            "claim, or this script will certify numbers it can no longer read."
        )
    return int(match.group(1))


def measure_tests_collected() -> int:
    """Collected rather than passed: the only count that is the same on every platform.

    Collection also costs under a second, where a full run costs fifteen — and CI already runs
    the suite twice, so measuring it a third time would buy nothing.
    """
    return _extract(
        # The project-wide `-q` suppresses pytest 9's total during collection and leaves only
        # per-file counts. Override addopts for this measurement so the total remains a number
        # pytest itself computes rather than one this script has to re-sum.
        _run(["uv", "run", "pytest", "--collect-only", "-o", "addopts="]),
        r"(\d+) tests collected",
        "tests",
    )


def measure_contracts() -> int:
    return _extract(_run(["uv", "run", "lint-imports"]), r"Contracts: (\d+) kept", "contracts")


def measure_mypy_files() -> int:
    return _extract(_run(["uv", "run", "mypy"]), r"in (\d+) source files", "mypy source files")


def measure_invariants() -> int:
    """The invariants are numbered in CLAUDE.md; the count is derived, never typed twice."""
    text = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    return len(re.findall(r"^\d+\. \*\*", text, flags=re.MULTILINE))


def _freeze_module() -> object:
    """Import the freeze module, so these counts come from the mechanism and not from a regex.

    The alternative — parsing `freeze.py` — is what the freeze itself stopped doing after four
    reviews, and for the same reason: a parser agrees with a stale copy of the source.
    """
    import importlib
    import sys

    sys.path.insert(0, str(ROOT / "src"))
    return importlib.import_module("nemesis.calibration.freeze")


def measure_calibration_dials() -> int:
    """Every module-level dial in `src/nemesis`, as the freeze itself counts them."""
    return len(_freeze_module().discovered_constants())  # type: ignore[attr-defined]


def measure_categorical_dials() -> int:
    """Dials holding no numeric literal at all — the class four numeric scans could not see."""
    import ast

    freeze = _freeze_module()
    total = 0
    for relative in freeze.frozen_modules():  # type: ignore[attr-defined]
        for value in freeze._module_constants(relative).values():  # type: ignore[attr-defined]
            if not any(
                isinstance(node, ast.Constant)
                and isinstance(node.value, int | float)
                and not isinstance(node.value, bool)
                for node in ast.walk(value)
            ):
                total += 1
    return total


def measure_sandbox_gated_tests() -> int:
    """Tests that only run where the kernel can actually confine a process.

    On Linux every one of them skips and the suite still goes green, so this is the count of
    what CI verified about the confinement control before the macOS job existed: none of it.
    Derived by counting the decorator, because the first prose version of this number said
    "fifteen" — it had counted the three lines that *define* the marker as well.
    """
    import re

    total = 0
    for path in (ROOT / "tests").rglob("test_*.py"):
        total += len(re.findall(r"^@needs_sandbox\b", path.read_text(encoding="utf-8"), re.M))
    return total


def measure_frozen_modules() -> int:
    return len(_freeze_module().frozen_modules())  # type: ignore[attr-defined]


def measure_calibration_constants() -> int:
    """Read from the registry itself, so the protocol cannot claim a freeze wider than it is.

    This one matters more than the others: a document overstating how many dials are frozen is
    a document overstating how trustworthy every figure the evaluation produces will be. The
    count has already been wrong twice while the prose around it read as settled.
    """
    text = (ROOT / "src/nemesis/calibration/freeze.py").read_text(encoding="utf-8")
    block = text.split("CALIBRATION_CONSTANTS", 1)[1].split(")", 1)[0]
    return len(re.findall(r'^\s+"[\w.]+:\w+",', block, flags=re.MULTILINE))


MEASUREMENTS: Final[dict[str, Callable[[], int]]] = {
    "calibration_constants": measure_calibration_constants,
    "calibration_dials": measure_calibration_dials,
    "categorical_dials": measure_categorical_dials,
    "frozen_modules": measure_frozen_modules,
    "sandbox_gated_tests": measure_sandbox_gated_tests,
    "tests": measure_tests_collected,
    "contracts": measure_contracts,
    "mypy_files": measure_mypy_files,
    "invariants": measure_invariants,
}


@dataclass(frozen=True)
class Claim:
    """One place a document states a number, and which measurement settles it.

    ``pattern`` must contain exactly one capture group, around the digits alone, so ``--fix``
    can replace the number without touching the sentence around it.
    """

    path: str
    pattern: str
    measurement: str
    note: str = ""


CLAIMS: Final[tuple[Claim, ...]] = (
    Claim("README.md", r"tests-(\d+)-2ea043", "tests", "the badge that started this"),
    Claim(
        "docs/calibration/PROTOCOL.md",
        r"\*\*(\d+) constants additionally frozen by imported value\*\*",
        "calibration_constants",
    ),
    Claim(
        "docs/calibration/PROTOCOL.md",
        r"\*\*(\d+) constants frozen by imported value\*\*",
        "calibration_constants",
    ),
    Claim("docs/calibration/PROTOCOL.md", r"\*\*(\d+) dials\*\*", "calibration_dials"),
    Claim(
        "docs/architecture/PROJECT_STATE.md",
        r"on Linux (\d+) tests across three modules skipped",
        "sandbox_gated_tests",
    ),
    Claim("docs/architecture/PROJECT_STATE.md", r"\*\*(\d+) dials\*\*", "calibration_dials"),
    Claim(
        "docs/architecture/PROJECT_STATE.md",
        r"\*\*(\d+)\*\* additionally frozen by imported value so `drifted\(\)` names",
        "calibration_constants",
    ),
    Claim(
        "docs/calibration/PROTOCOL.md",
        r"\*\*(\d+) of\n  them holding no numeric literal at all\*\*",
        "categorical_dials",
    ),
    Claim(
        "docs/calibration/PROTOCOL.md",
        r"normalised syntax digest covering \*?\*?(\d+) modules",
        "frozen_modules",
    ),
    Claim(
        "docs/architecture/PROJECT_STATE.md",
        r"\*\*(\d+) module syntax digests\*\*",
        "frozen_modules",
    ),
    Claim(
        "src/nemesis/calibration/freeze.py",
        r"\b(\d+) (?:of them|dials)(?=[, ])",
        "calibration_dials",
    ),
    Claim(
        "src/nemesis/calibration/freeze.py",
        r", (\d+) hold no numeric literal",
        "categorical_dials",
    ),
    Claim("README.md", r"plane%20contracts-(\d+)%20enforced", "contracts"),
    Claim("README.md", r"(\d+) `import-linter` contracts", "contracts"),
    Claim("docs/architecture/PROJECT_STATE.md", r"\*\*(\d+) tests\.\*\*", "tests"),
    Claim(
        "docs/architecture/PROJECT_STATE.md",
        r"mypy strict \((\d+) source files\)",
        "mypy_files",
    ),
    Claim("docs/architecture/PROJECT_STATE.md", r"(\d+) plane contracts", "contracts"),
    Claim(
        "docs/architecture/PROJECT_STATE.md",
        r"the (\d+) invariants",
        "invariants",
        "counted from the numbered list in CLAUDE.md, never typed twice",
    ),
)
SPELLED_OUT: Final = [
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
    "eleven",
    "twelve",
    "thirteen",
    "fourteen",
    "fifteen",
    "sixteen",
    "seventeen",
    "eighteen",
    "nineteen",
    "twenty",
]
r"""Counts written as words, which this script cannot check and therefore refuses to allow.

The exclusion used to be a comment saying prose numbers were deliberately left alone. An
external reviewer then found `Eight \`import-linter\` contracts` in the README when there
were nine — the exact claim the badge two lines away had correct, and the exact hole the
comment described without closing. A checker that documents its own blind spot and leaves it
open has moved the defect into itself.

So a spelled-out count next to a tracked noun is now an error telling the author to write a
digit, which the registry above can then check. `nemesis` invariants stay exempt: "the fifteen
invariants" reads better than "the 15 invariants" and its count is derived from CLAUDE.md
rather than typed, so there is nothing to drift from."""

EXHAUSTIVE: Final[dict[str, str]] = {
    r"contracts?": "contracts",
    r"source files": "mypy_files",
}
r"""Nouns whose count is unambiguous, scanned EXHAUSTIVELY rather than by listed phrasing.

The registry above is opt-in: it checks the phrasings someone thought to add. That has now
failed three times on the same metric — a badge format, a count spelled as a word, and
`8 \`import-linter\` contracts` in a table while `9 plane contracts` two hundred lines away was
correct and matched. Each fix added one more phrasing and left the next one open, which is the
shape of a control that cannot work: enumeration cannot cover a space the author keeps
extending.

So for nouns that have exactly one true count, the default inverts. Every digit adjacent to one
is checked, and a phrasing nobody anticipated is caught rather than missed.

`tests` stays on the registry, and that is not laziness: test counts legitimately appear as
totals, as subsets ("the containment tests"), and as history ("a tree where all 517 tests
passed"). An exhaustive rule there would demand rewriting accurate statements about the past,
which is worse than the drift it prevents. The distinction is whether a noun has one true
count, not how much trouble it is to check."""


FORBIDDEN_PROSE: Final[tuple[tuple[str, str], ...]] = tuple(
    (path, noun)
    for path in ("README.md", "docs/architecture/PROJECT_STATE.md")
    for noun in ("contracts", "tests", "source files")
)


@dataclass(frozen=True)
class Mismatch:
    claim: Claim
    line: int
    claimed: int
    measured: int


def exhaustive_mismatches(measured: dict[str, int]) -> list[str]:
    """Every digit next to an unambiguous noun, in every tracked document."""
    found: list[str] = []
    for path in ("README.md", "docs/architecture/PROJECT_STATE.md", "SECURITY.md"):
        text = (ROOT / path).read_text(encoding="utf-8")
        for noun, measurement in EXHAUSTIVE.items():
            if measurement not in measured:
                measured[measurement] = MEASUREMENTS[measurement]()
            actual = measured[measurement]
            # At most two words between the digit and the noun, and never a digit that
            # belongs to something else. A looser window paired "152 source files" with a
            # "contracts" four words later, and read "invariant 8 rests on the import
            # contracts" as a count of contracts. A check that cries wolf gets switched off.
            pattern = rf"(?<!invariant )\b(\d+)\s+(?:[^\s.,;)]+\s+){{0,2}}{noun}\b"
            for match in re.finditer(pattern, text):
                if int(match.group(1)) == actual:
                    continue
                line = text.count("\n", 0, match.start()) + 1
                found.append(f"{path}:{line}  {match.group(0).strip()!r} — measured {actual}")
    return found


def spelled_out_counts() -> list[str]:
    """Counts written as words where a digit is required. Reported, never rewritten."""
    found: list[str] = []
    for path, noun in FORBIDDEN_PROSE:
        text = (ROOT / path).read_text(encoding="utf-8")
        for word in SPELLED_OUT:
            for match in re.finditer(rf"\b{word}\b[^.\n]{{0,24}}?\b{noun}\b", text, re.I):
                line = text.count("\n", 0, match.start()) + 1
                found.append(f"{path}:{line}  {match.group(0).strip()!r} — write the digit")
    return found


def check(*, fix: bool) -> list[Mismatch]:
    measured: dict[str, int] = {}
    mismatches: list[Mismatch] = []

    for claim in CLAIMS:
        path = ROOT / claim.path
        text = path.read_text(encoding="utf-8")
        found = list(re.finditer(claim.pattern, text))
        if not found:
            raise SystemExit(
                f"{claim.path}: no text matches {claim.pattern!r}.\n"
                "The sentence carrying this claim was edited or removed. Update the registry "
                "in this script deliberately — a claim that silently stops being checked is "
                "how the badge got stale in the first place."
            )

        if claim.measurement not in measured:
            measured[claim.measurement] = MEASUREMENTS[claim.measurement]()
        actual = measured[claim.measurement]

        for match in found:
            claimed = int(match.group(1))
            if claimed == actual:
                continue
            mismatches.append(
                Mismatch(claim, text.count("\n", 0, match.start()) + 1, claimed, actual)
            )

        if fix:

            def replace(match: re.Match[str], actual: int = actual) -> str:
                whole, digits = match.group(0), match.group(1)
                start = match.start(1) - match.start(0)
                return whole[:start] + str(actual) + whole[start + len(digits) :]

            path.write_text(re.sub(claim.pattern, replace, text), encoding="utf-8")

    return mismatches


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fix", action="store_true", help="rewrite the claims to the measured values"
    )
    arguments = parser.parse_args()

    mismatches = check(fix=arguments.fix)
    prose = spelled_out_counts()
    stray = exhaustive_mismatches({})

    if stray:
        print("COUNTS THE REGISTRY DID NOT LIST, AND THEY DISAGREE\n")
        for line in stray:
            print(f"  {line}")
        print(
            "\nThese nouns have exactly one true count, so every digit beside one is checked "
            "rather than only the phrasings someone remembered to register.\n"
        )
        return 1

    if prose:
        print("COUNTS WRITTEN AS WORDS, WHERE THIS SCRIPT CANNOT CHECK THEM\n")
        for line in prose:
            print(f"  {line}")
        print(
            "\nA spelled-out count is a claim nothing verifies. One of these read 'Eight "
            "contracts' beside a badge that correctly said nine.\n"
        )
        return 1

    if not mismatches:
        print(f"All {len(CLAIMS)} documented counts match the repository.")
        return 0

    if arguments.fix:
        print(f"Updated {len(mismatches)} claim(s):")
        for bad in mismatches:
            print(f"  {bad.claim.path}:{bad.line}  {bad.claimed} -> {bad.measured}")
        return 0

    print("DOCUMENTED COUNTS DISAGREE WITH THE REPOSITORY\n")
    for bad in mismatches:
        note = f"  ({bad.claim.note})" if bad.claim.note else ""
        print(f"  {bad.claim.path}:{bad.line}{note}")
        print(f"      states {bad.claimed}, measured {bad.measured}")
    print(
        "\nRun `uv run python scripts/check_documented_counts.py --fix` to update them.\n"
        "A number a document states about itself is a claim, and this repository's rule is "
        "that a claim contradicting the code is a defect — including when the claim is only "
        "a badge."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
