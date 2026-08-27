"""The register is a promise that something enforces each property. This checks the promise.

`docs/security/INVARIANTS.md` gives stable identifiers to the security properties this platform
claims, and for each one it names **what enforces it** and **what tests it**. That is the whole
value of the document: an identifier a reader can follow to a mechanism.

A register naming a test that does not exist is worse than no register. It reads as coverage,
survives every review that does not click through, and this repository's own rule is that
documentation contradicting the code is a defect rather than an untidiness. So the references are
resolved mechanically:

* every ``test_*.py`` the register names exists under `tests/`;
* every Breaker attack it names is in the catalogue;
* every invariant identifier it defines is used by at least one test module, so a property cannot
  be registered and then quietly enforced by nothing.

The third is the one that would catch the failure that matters. The first two catch a rename; the
third catches an entry added to the table because it sounded right.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.invariant

ROOT = Path(__file__).resolve().parents[2]
REGISTER = ROOT / "docs/security/INVARIANTS.md"
TESTS = ROOT / "tests"

_ID = re.compile(r"\*\*([A-Z]+-\d{2})\*\*")
_TEST_MODULE = re.compile(r"`(test_[a-z_]+\.py)`")
_ATTACK = re.compile(r"Breaker `([a-z-]+)`")


def _register() -> str:
    return REGISTER.read_text(encoding="utf-8")


def test_the_register_exists_and_defines_identifiers() -> None:
    """Guards every other test here from passing over an empty or moved file."""
    assert REGISTER.is_file(), f"{REGISTER} is gone; the invariant identifiers are now unowned"
    identifiers = set(_ID.findall(_register()))
    assert len(identifiers) >= 15, (
        f"the register defines {len(identifiers)} identifiers, which is fewer than the pass that "
        "created it added. Has a section been removed?"
    )


def test_every_test_module_the_register_names_exists() -> None:
    """A rename that leaves the register behind is caught here rather than by a reader."""
    named = sorted(set(_TEST_MODULE.findall(_register())))
    assert named, "the register names no test module; the enforcement column is prose"
    missing = [name for name in named if not list(TESTS.rglob(name))]
    assert missing == [], (
        f"the invariant register names test modules that do not exist: {missing}. Either the "
        "test was renamed and the register was not, or a property is enforced by nothing."
    )


def test_every_breaker_attack_the_register_names_is_in_the_catalogue() -> None:
    """The register cites Breaker attacks as evidence; an attack that is gone cites nothing."""
    from nemesis.breaker import ATTACKS

    catalogue = {attack.attack_id for attack in ATTACKS}
    named = sorted(set(_ATTACK.findall(_register())))
    assert named, "the register cites no Breaker attack"
    missing = [name for name in named if name not in catalogue]
    assert missing == [], f"the register cites Breaker attacks that no longer exist: {missing}"


def test_every_identifier_is_referenced_by_at_least_one_test_module() -> None:
    """The check that catches a property registered because it sounded right.

    An identifier is a claim that something enforces it. Naming it in at least one test module —
    in a docstring, a comment, an assertion message — is the cheapest possible evidence that
    somebody wired it to something. It is not proof the test is any good; it is proof the
    identifier is not orphaned, which is the failure this catches.
    """
    identifiers = sorted(set(_ID.findall(_register())))
    corpus = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(TESTS.rglob("test_*.py"))
    )
    orphaned = [name for name in identifiers if name not in corpus]
    assert orphaned == [], (
        f"these invariant identifiers appear in the register and in no test module: {orphaned}. "
        "An identifier is a promise that something enforces the property; an orphaned one reads "
        "as coverage and is not."
    )
