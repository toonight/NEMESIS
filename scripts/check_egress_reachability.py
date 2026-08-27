#!/usr/bin/env python
"""Fail the build when a model-controlled context can reach the network the long way round.

The thin CI entry point over :mod:`nemesis.sandbox.reachability`, in the same relationship
`scripts/check_prohibited.py` has to the rule it enforces: the analysis is a typed, tested module
inside the package, and this file is the thing a workflow step runs.

Two checks, and the second one is why this is not four lines:

1. **No unbrokered egress.** Every path from a model-controlled root to a module that can reach
   the network or start a process must pass through a broker declared in
   :data:`~nemesis.sandbox.reachability.DECLARED_BROKERS`.

2. **The roots and brokers still name real modules.** A renamed root produces no findings and
   reads exactly like a pass, which is the shape of a check that has quietly stopped checking.
   An empty finding list is only believed once this has confirmed there was something to check.

Prints what it found either way. A scan that says only "OK" teaches a reader nothing about what
it covers, and this one's coverage is the interesting part.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from nemesis.sandbox.reachability import (  # noqa: E402 - after the sys.path bootstrap above
    DECLARED_BROKERS,
    MODEL_CONTROLLED_ROOTS,
    build_graph,
    process_spawning_modules,
    unbrokered_egress,
    unknown_roots_or_brokers,
)


def main() -> int:
    graph = build_graph(ROOT / "src")

    stale = unknown_roots_or_brokers(graph)
    if stale:
        print("EGRESS ANALYSIS IS NOT MEASURING WHAT IT CLAIMS\n")
        for name in stale:
            print(f"  {name} is declared as a root or a broker and is not a module in the tree")
        print(
            "\nA root that does not exist is a root nothing is checked from, and the analysis "
            "would have reported a clean pass. Fix the name in "
            "nemesis/sandbox/reachability.py."
        )
        return 1

    egress = sorted(graph.egress_capable)
    spawners = process_spawning_modules(graph)
    findings = unbrokered_egress(graph)

    print(f"Modules with egress capability: {len(egress)}")
    for name in egress:
        print(f"  {graph.capabilities[name].describe()}")
    print(f"\nModules that can start a process: {len(spawners)}")
    for name in spawners:
        print(f"  {graph.capabilities[name].describe()}")
    print(f"\nModel-controlled roots checked: {len(MODEL_CONTROLLED_ROOTS)}")
    for name in MODEL_CONTROLLED_ROOTS:
        print(f"  {name}")
    print(f"\nDeclared brokers: {len(DECLARED_BROKERS)}")
    for name in DECLARED_BROKERS:
        print(f"  {name}")

    if findings:
        print("\nNET-02 VIOLATED: unbrokered transitive egress\n")
        for finding in findings:
            print(f"  {finding.describe()}\n")
        print(
            f"{len(findings)} path(s). Either the new import is wrong, or the module it goes "
            "through is a broker — and declaring one means writing down what makes the far side "
            "policy-controlled rather than model-controlled."
        )
        return 1

    print(
        "\nNo unbrokered path from a model-controlled context to an egress capability.\n"
        "Note: this is a static import analysis. It does not see a callable handed in at "
        "construction, and it does not see out of the process."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
