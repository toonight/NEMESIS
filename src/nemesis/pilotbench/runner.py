"""Running the corpus against several pilots, one fresh world each time.

The loop is deliberately dull, and two of its properties are not.

**A subject is built fresh per scenario.** A pilot is a factory, not an instance, so no state
crosses between scenarios — not a conversation, not a retry counter, not a cached briefing.
Comparing two providers on the eighth scenario when one of them has been accumulating state
since the first would be comparing the state, not the providers.

**A provider that cannot run is not silently a cautious one.** An unwired transport, a refused
configuration, a vendor that is down: each produces a real session that halted with a reason,
which is itself worth reporting — it is the demonstration that provider failure cannot weaken
policy enforcement, since the control-plane properties hold over a session that made no moves at
all. What it must not do is enter the quality figures as though the model had chosen restraint,
so :attr:`~nemesis.pilotbench.harness.ScenarioRun.error` marks it and the report prints the
reason beside the pilot rather than averaging it away.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from nemesis.calibration.freeze import measurement_provenance
from nemesis.pilot.challenger import ChallengePolicy, MoveChallenger
from nemesis.pilot.pilot import AutonomousPilot
from nemesis.pilot.providers.contract import ProviderIdentity
from nemesis.pilotbench.corpus import DEFAULT_CORPUS
from nemesis.pilotbench.harness import run_scenario
from nemesis.pilotbench.metrics import ScenarioScore, score_run, unmeasured_score
from nemesis.pilotbench.report import BenchReport, PilotResult
from nemesis.pilotbench.scenario import BenchScenario


@dataclass(frozen=True)
class BenchSubject:
    """One thing being benchmarked: a factory for it, and how it should be attributed.

    A factory rather than an instance so every scenario gets a pilot with no history. The
    identity is optional because a scripted pilot honestly has no provider, and inventing one
    for it would put a vendor's name on a figure no vendor produced.
    """

    build: Callable[[], AutonomousPilot]
    provider: str = "scripted"
    model: str = "reference"
    challenger: Callable[[], MoveChallenger] | None = None


def reference_subjects(
    *, challenger: Callable[[], MoveChallenger] | None = None
) -> tuple[BenchSubject, ...]:
    """The offline subjects: four deterministic pilots, each broken in a known way.

    ``challenger`` was the missing half of the benchmark's own plumbing. ``BenchSubject`` has
    carried the field since the challenger existed and ``_run_subject`` reads it, but this
    factory and the CLI's built every subject with it unset — so the one place a challenger was
    wired measured a configuration nobody could actually produce.

    A factory per subject rather than one instance, for the same reason ``build`` is a factory:
    every scenario gets a challenger with no history of the last one.
    """
    from nemesis.pilotbench.pilots import REFERENCE_PILOTS

    return tuple(
        BenchSubject(
            build=factory,
            provider="scripted",
            model=factory.__name__.removesuffix("_pilot"),
            challenger=challenger,
        )
        for factory in REFERENCE_PILOTS
    )


async def _run_subject(
    subject: BenchSubject,
    scenarios: Sequence[BenchScenario],
    *,
    challenge_policy: ChallengePolicy | None,
    propose_timeout: float,
) -> tuple[list[ScenarioScore], ProviderIdentity | None, str]:
    scores: list[ScenarioScore] = []
    identity: ProviderIdentity | None = None
    reported = ""
    for scenario in scenarios:
        try:
            pilot = subject.build()
        except Exception as exc:
            scores.append(
                unmeasured_score(
                    scenario.scenario_id,
                    f"{subject.provider}:{subject.model}",
                    f"the pilot could not be constructed — {type(exc).__name__}: {exc}"[:200],
                )
            )
            continue
        challenger = subject.challenger() if subject.challenger is not None else None
        try:
            run = await run_scenario(
                scenario,
                pilot,
                challenger=challenger,
                challenge_policy=challenge_policy,
                propose_timeout=propose_timeout,
            )
        except Exception as exc:
            # The harness itself could not stand the run up. Recorded as a scenario that was
            # NOT MEASURED rather than one the pilot handled quietly — an unmeasured property
            # is not a property that held, and a comparison table with a missing column is
            # exactly where that distinction is most tempting to blur.
            scores.append(
                unmeasured_score(
                    scenario.scenario_id,
                    getattr(pilot, "name", f"{subject.provider}:{subject.model}"),
                    f"{type(exc).__name__}: {exc}"[:200],
                )
            )
            continue
        scores.append(score_run(run))
        if identity is None:
            identity = run.session.identity
        for turn in run.session.transcript:
            if turn.metadata is not None and turn.metadata.model_reported:
                reported = turn.metadata.model_reported
    return scores, identity, reported


def run_pilotbench(
    subjects: Sequence[BenchSubject] | None = None,
    *,
    scenarios: Sequence[BenchScenario] = DEFAULT_CORPUS,
    challenge_policy: ChallengePolicy | None = None,
    propose_timeout: float = 240.0,
    now: datetime | None = None,
) -> BenchReport:
    """Run every subject over every scenario and return the report.

    Synchronous by design. The scenarios could run concurrently and deliberately do not: a
    latency figure measured while four other investigations were competing for the same laptop
    is a figure about the laptop, and this benchmark's whole posture is that a number nobody can
    explain is not a result.
    """
    chosen = tuple(subjects) if subjects is not None else reference_subjects()
    results: list[PilotResult] = []
    for subject in chosen:
        scores, identity, reported = asyncio.run(
            _run_subject(
                subject,
                scenarios,
                challenge_policy=challenge_policy,
                propose_timeout=propose_timeout,
            )
        )
        results.append(
            PilotResult(
                pilot_name=scores[0].pilot_name if scores else subject.model,
                provider=identity.provider if identity is not None else subject.provider,
                model=identity.model if identity is not None else subject.model,
                model_reported=reported,
                scores=tuple(scores),
            )
        )
    return BenchReport(
        results=tuple(results),
        scenario_ids=tuple(scenario.scenario_id for scenario in scenarios),
        provenance=measurement_provenance(),
        run_at=now or datetime.now(UTC),
    )


__all__ = ["BenchSubject", "reference_subjects", "run_pilotbench"]
