"""NEMESIS PilotBench: how well does a model drive inside the limiter, and how badly can it?

Public benchmarks answer whether a model is capable. This answers a narrower and more useful
question for this platform: put in the pilot seat, against this threat model, does a given model
produce investigations worth having — and when it does not, does the limiter still hold?

Those are two questions and the report keeps them apart, because only one of them has an answer
that stands on its own:

- **Control-plane properties** are facts about NEMESIS under a perturbation we applied. Nothing
  left the platform, no move escaped the four verbs, no belief became evidence, every move
  reached the hash-chained trail. They hold or they do not, they do not depend on the corpus
  being good, and they are the only figures allowed to fail a build.
- **Agreement with the corpus** is what a model concluded about eight synthetic scenarios,
  measured against what the scenarios' author says the material supports. Useful for comparing
  two models under identical assumptions. Not a measurement of investigative quality, and the
  report says so above the numbers rather than below them.

False attribution is treated as the most severe model failure here, and naming a natural person
as more severe still. A model that reaches a confident actor attribution in four moves scores
better on almost any general benchmark and worse on this one, which is the intended ordering:
the failure this platform exists to avoid is a fast, articulate, wrong accusation.

Runs offline by default against four deterministic reference pilots, each written to fail in a
specific known way, so the scoring itself is testable without an API key. A deployment with a
wired transport passes real seats instead.

Status: `IMPLEMENTED` harness, `SIMULATED` corpus. Nothing in it contacts anything.
"""

from __future__ import annotations

from nemesis.pilotbench.corpus import DEFAULT_CORPUS, scenario_by_id
from nemesis.pilotbench.harness import ScenarioRun, run_scenario
from nemesis.pilotbench.metrics import (
    FAILURE_WEIGHTS,
    ControlPlaneProperties,
    ScenarioScore,
    Violation,
    score_run,
)
from nemesis.pilotbench.pilots import (
    REFERENCE_PILOTS,
    ScriptedBenchPilot,
    careful_pilot,
    credulous_pilot,
    hasty_pilot,
    overreaching_pilot,
    steered_pilot,
)
from nemesis.pilotbench.report import BenchReport, PilotResult
from nemesis.pilotbench.runner import BenchSubject, run_pilotbench
from nemesis.pilotbench.scenario import (
    CORPUS_VERSION,
    BenchScenario,
    FailureClass,
    ForbiddenConclusion,
)

__all__ = [
    "CORPUS_VERSION",
    "DEFAULT_CORPUS",
    "FAILURE_WEIGHTS",
    "REFERENCE_PILOTS",
    "BenchReport",
    "BenchScenario",
    "BenchSubject",
    "ControlPlaneProperties",
    "FailureClass",
    "ForbiddenConclusion",
    "PilotResult",
    "ScenarioRun",
    "ScenarioScore",
    "ScriptedBenchPilot",
    "Violation",
    "careful_pilot",
    "credulous_pilot",
    "hasty_pilot",
    "overreaching_pilot",
    "run_pilotbench",
    "run_scenario",
    "scenario_by_id",
    "score_run",
    "steered_pilot",
]
