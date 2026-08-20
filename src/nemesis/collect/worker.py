"""A collector, running as somebody else's process.

Launched as ``python -m nemesis.collect.worker``, reads one pivot request from stdin, writes
one result to stdout, exits. It is the whole of what a compromised collector would have.

It seals the same modules the Effects worker does, and for the mirror-image reason: there,
the concern is a plane that could reach outward; here, it is a plane the outside world
reaches *into*. A parser exploit in a downloaded artifact lands in this process, and what it
finds is a connector, the domain model, and no route to the graph, the vault, the audit trail
or a signing key.

As with the Effects worker, the seal is **defence in depth and not a boundary** — a finder in
a mutable list is removable by code already running here. The boundary is the process and the
sandbox profile the parent applied.
"""

from __future__ import annotations

import json
import sys
from importlib import import_module
from typing import Any, Final

from nemesis.sandbox.seal import seal_imports

FORBIDDEN_PREFIXES: Final = (
    "nemesis.graph",
    "nemesis.evidence",
    "nemesis.pursuit",
    "nemesis.resolve",
    "nemesis.attribute",
    "nemesis.disrupt",
    "nemesis.effects",
    "nemesis.authz",
    "nemesis.slice",
)
"""What a collector must not be able to reach at runtime.

`nemesis.authz` entirely, not merely its key module: a collector has no business with
authorization at all, whereas the Effects worker legitimately verifies capabilities and
needs the public half.
"""


def _seal_imports() -> bool:
    return seal_imports(FORBIDDEN_PREFIXES, plane="collection")


def main() -> int:
    sealed = _seal_imports()
    try:
        envelope = json.loads(sys.stdin.read())
    except (ValueError, OSError) as exc:
        return _fail(f"the collector could not read its input: {type(exc).__name__}: {exc}")

    try:
        module_name, _, attribute = str(envelope["factory"]).partition(":")
        factory: Any = getattr(import_module(module_name), attribute)
        from nemesis.ports.collection import PivotRequest

        request = PivotRequest.model_validate(envelope["request"])
        connector = factory(envelope["as_of"])
    except (KeyError, ValueError, TypeError, AttributeError, ImportError) as exc:
        return _fail(f"the collector could not be built: {type(exc).__name__}: {exc}")

    import asyncio

    result = asyncio.run(connector.pivot(request))
    sys.stdout.write(json.dumps({"result": result.model_dump(mode="json"), "sealed": sealed}))
    sys.stdout.flush()
    return 0


def _fail(message: str) -> int:
    sys.stdout.write(json.dumps({"error": message}))
    sys.stdout.flush()
    return 1


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    raise SystemExit(main())
