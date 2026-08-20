"""A runtime import seal, parameterised by what the process in question must not reach.

Two workers use it and they forbid different things: the Effects worker legitimately verifies
capabilities and needs the public half of `nemesis.authz`, while a collector has no business
with authorization at all. One implementation, two lists.

**This is defence in depth and not a boundary**, and the distinction is load-bearing enough
to repeat wherever it appears. A finder is an object in a mutable list: hostile code already
running in the process removes it, or loads a module by path with ``spec_from_file_location``,
or ``exec``s the source. A review did all three. What the seal stops is the accidental import,
the careless refactor and the dependency that quietly grows an edge — worth having, and not
the same as stopping somebody who is already there. The boundary is the process and the
sandbox profile its parent applied.
"""

from __future__ import annotations

import sys
from importlib.abc import MetaPathFinder
from importlib.machinery import ModuleSpec
from typing import Any


class SealedImports(MetaPathFinder):
    """Refuses a named set of packages, loudly, before anything else runs."""

    def __init__(self, forbidden: tuple[str, ...], *, plane: str) -> None:
        self._forbidden = forbidden
        self._plane = plane

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> ModuleSpec | None:
        if any(fullname == name or fullname.startswith(name + ".") for name in self._forbidden):
            raise ImportError(
                f"the {self._plane} worker may not import {fullname!r}: this plane holds no "
                "reach into the intelligence platform (invariant 8), and a runtime that could "
                "import it would have that reach whatever the build-time contracts say"
            )
        return None


def seal_imports(forbidden: tuple[str, ...], *, plane: str) -> bool:
    """Install the seal, and say so, so a parent can record that it ran."""
    sys.meta_path.insert(0, SealedImports(forbidden, plane=plane))
    return True
