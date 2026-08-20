"""The end-to-end vertical slice.

Wires every plane together on the GLASS ANVIL scenario, from the first phishing signal to
resurgence detection forty-five days after a simulated takedown. One orchestration, consumed
by both the CLI and the end-to-end test, so what a human sees demonstrated is exactly what
the test asserts.

Status: ``SIMULATED``. Every connector reads a fixture, every address is reserved for
documentation and cannot resolve, and no effect adapter can make external contact.
"""

from nemesis.slice.scenario import ScenarioResult, run_glass_anvil_scenario

__all__ = ["ScenarioResult", "run_glass_anvil_scenario"]
