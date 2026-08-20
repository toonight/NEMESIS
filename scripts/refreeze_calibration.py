"""Regenerate the calibration freeze tables in `nemesis.calibration.freeze`.

Run this **deliberately**, in its own commit, with the reason in the message — never as a way
to make a red test green. That distinction is the whole mechanism: changing a dial is allowed,
changing it silently or during an evaluation is not.

    uv run python scripts/refreeze_calibration.py

The tables are generated rather than hand-edited because they hold hundreds of digests and a
hand edit is indistinguishable from a typo. Two hazards are handled here rather than hoped away:

- **Canonical values.** The digests fold values through
  :func:`nemesis.calibration.freeze.canonical`, so two runs on the same tree agree regardless of
  the interpreter's hash seed. An earlier version used `repr()` and produced a different digest
  on every run, which would have made the freeze fail at random and taught every reader that a
  red digest means nothing.
- **Stale bytecode.** CPython validates a `.pyc` against the source's size and mtime truncated
  to whole seconds, and every rewrite here swaps one 64-character digest for another, so the
  size never changes. A regeneration landing in the same second as the previous one was silently
  ignored: observed once, the source read `d8ee5a…` while the imported module read `cd7eb0…` and
  a test failed against a value present in no file. Dropping one `.pyc` was not enough either —
  the *values* are read from every other module in the tree, each with its own cache. So the
  whole measurement now runs in a subprocess under a fresh `PYTHONPYCACHEPREFIX`, which cannot
  see any cache this machine has ever written.

A refreeze that appears to work and does not is worse than one that fails.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FREEZE = ROOT / "src/nemesis/calibration/freeze.py"
WIDTH = 100

_MEASURE = textwrap.dedent("""
    import hashlib, json
    from nemesis.calibration.freeze import (
        discovered_constants, freeze_digest, module_digests, observed_values, value_digest,
    )

    def short(payload):
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    print(json.dumps({
        "FROZEN_VALUE_DIGESTS": {
            name: value_digest(name, value) for name, value in observed_values().items()
        },
        "CONSTANT_DIGESTS": {
            name: short(f"{name}={dump}") for name, dump in discovered_constants().items()
        },
        "MODULE_DIGESTS": module_digests(),
        "FROZEN_DIGEST": freeze_digest(),
    }))
""")


def _measure() -> dict[str, object]:
    """Read every digest from the tree on disk, in an interpreter with no cache of its own.

    A fresh `PYTHONPYCACHEPREFIX` is the point: it relocates *every* module's bytecode cache,
    not just this one file's, so no stale `.pyc` anywhere in `src/nemesis` can supply a value
    that the source no longer holds.
    """
    with tempfile.TemporaryDirectory(prefix="nemesis-refreeze-") as cache:
        completed = subprocess.run(  # noqa: S603
            [sys.executable, "-c", _MEASURE],
            capture_output=True,
            text=True,
            cwd=ROOT,
            check=True,
            env={
                "PYTHONPATH": str(ROOT / "src"),
                "PYTHONPYCACHEPREFIX": cache,
                "PATH": "/usr/bin:/bin",
            },
        )
    measured: dict[str, object] = json.loads(completed.stdout)
    return measured


def _rows(digests: dict[str, str]) -> str:
    """One `"name": "digest",` per line, wrapped where ruff would otherwise complain."""
    lines: list[str] = []
    for name, digest in sorted(digests.items()):
        flat = f'        "{name}": "{digest}",'
        if len(flat) <= WIDTH:
            lines.append(flat)
            continue
        lines.append(f'        "{name}": (\n            "{digest}"\n        ),')
    return "\n".join(lines) + "\n"


def _replace_table(source: str, table: str, rows: str) -> str:
    """Rewrite one table's body, whatever shape the formatter last left it in.

    Line-based rather than a regex over the whole file: an empty table formats as
    `MappingProxyType({})` on one line and a populated one spans hundreds, and a pattern that
    only matched the second shape failed silently the first time a table was emptied.
    """
    lines = source.splitlines(keepends=True)
    opening = next(
        (i for i, line in enumerate(lines) if line.startswith(f"{table}: Final[Mapping")), None
    )
    if opening is None:
        raise SystemExit(f"could not locate the {table} table")
    if lines[opening].rstrip().endswith("MappingProxyType({})"):
        closing: int | None = opening
    else:
        closing = next((i for i in range(opening, len(lines)) if lines[i].rstrip() == ")"), None)
    if closing is None:
        raise SystemExit(f"{table} has no closing parenthesis on its own line")
    header = f"{table}: Final[Mapping[str, str]] = MappingProxyType(\n    {{\n"
    return "".join(lines[:opening]) + header + rows + "    }\n)\n" + "".join(lines[closing + 1 :])


def main() -> int:
    measured = _measure()
    source = FREEZE.read_text(encoding="utf-8")

    for table in ("FROZEN_VALUE_DIGESTS", "CONSTANT_DIGESTS", "MODULE_DIGESTS"):
        digests = measured[table]
        assert isinstance(digests, dict)
        source = _replace_table(source, table, _rows(digests))
        print(f"{table:<22} {len(digests)} entries")

    values = measured["FROZEN_DIGEST"]
    source = re.sub(r'(FROZEN_DIGEST: Final = ")[0-9a-f]{64}(")', rf"\g<1>{values}\g<2>", source)
    FREEZE.write_text(source, encoding="utf-8")

    # Nothing measured above depends on this file's own tables — `frozen_modules()` excludes it,
    # and the values come from other modules — so one pass is enough and no re-read is needed.
    print(f"{'FROZEN_DIGEST':<22} {values}")
    print("Tables regenerated. Commit them on their own, with the reason.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
