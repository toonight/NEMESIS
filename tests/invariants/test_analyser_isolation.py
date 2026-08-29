"""The artifact analyser runs somewhere it can do less harm.

Quarantine exists because collected bytes are hostile. For as long as there was no confined
analyser, the pipeline built on that premise parsed those bytes **in the calling process** —
the one holding the graph, the claim store and an open vault. `StructuralAnalyser` said so
honestly by reporting `confined=False`, and `analysis_payload` was written for a worker that
did not exist.

These tests are gated on the kernel actually being able to confine anything, and the
`confinement` CI job turns a skip here into a failure: a control reported as tested that no
runner executed is the defect this repository keeps finding in itself.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from nemesis.collect import isolation as isolation_module
from nemesis.collect.isolation import ConfinedAnalyser, ConfinedWhenReal
from nemesis.collect.quarantine import (
    AnalysisReport,
    ArtifactAnalyser,
    ArtifactHandle,
    Quarantine,
    QuarantineError,
)
from nemesis.core.evidence import ContentSafety
from nemesis.sandbox.process import SandboxRun, sandbox_available

needs_sandbox = pytest.mark.skipif(
    not sandbox_available(),
    reason="kernel-enforced confinement needs macOS sandbox-exec; a plain subprocess is a "
    "boundary against an accident and none against code that means it",
)

EXECUTABLE = b"MZ\x90\x00" + b"\x00" * 64


def _admit(artifact: bytes, declared: ContentSafety) -> tuple[Quarantine, ArtifactHandle]:
    quarantine = Quarantine()
    return quarantine, quarantine.admit(artifact, declared_safety=declared)


def test_the_confined_analyser_satisfies_the_port() -> None:
    """Structural, so a signature drift is a failure here rather than at a call site."""
    assert isinstance(ConfinedAnalyser(), ArtifactAnalyser)


@needs_sandbox
def test_an_artifact_is_examined_in_a_confined_child_and_the_report_says_so() -> None:
    """The happy path, and the claim the whole extension point exists to make.

    `confined=True` is not decoration: it means a child process was started *and* the mechanism
    was the kernel's, which is the only combination under which "the parser ran somewhere it
    could not reach the investigation" is a fact rather than an intention.
    """
    quarantine, handle = _admit(b"<html>ordinary</html>", ContentSafety.ROUTINE)

    report = asyncio.run(quarantine.analyse(handle, ConfinedAnalyser()))

    assert report.failure is None, report.failure
    assert report.confined is True
    assert report.classification is ContentSafety.ROUTINE
    assert report.artifact_id == handle.artifact_id


@needs_sandbox
def test_the_classification_decision_survives_the_process_boundary() -> None:
    """The examination has to still *work* over there.

    A confinement that quietly degraded the analysis would trade one silent failure for
    another: the same executable structure must still raise `routine` to `malicious_code`, and
    the observation explaining why must come back with it.
    """
    quarantine, handle = _admit(EXECUTABLE, ContentSafety.ROUTINE)

    report = asyncio.run(quarantine.analyse(handle, ConfinedAnalyser()))

    assert report.classification is ContentSafety.MALICIOUS_CODE
    assert any("raised to malicious_code" in o for o in report.observations)
    assert report.confined is True


@needs_sandbox
def test_confined_material_carrying_an_obligation_is_still_held() -> None:
    """The confinement does not become a way around the gate it feeds."""
    quarantine, handle = _admit(b"held", ContentSafety.MANDATORY_REPORT)

    asyncio.run(quarantine.analyse(handle, ConfinedAnalyser()))

    with pytest.raises(QuarantineError, match="no automated exit"):
        quarantine.release(handle)


def test_the_child_cannot_attest_to_its_own_confinement(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE PROPERTY A COMPROMISED WORKER WOULD ATTACK FIRST.

    `confined` is decided by the parent from the process it observed, never read from the
    child's answer. A worker that has been taken over would otherwise certify its own
    containment — the one claim it must not be able to make, and the cheapest lie available to
    it, since the field is a bare boolean in a report it authors.

    Driven by a run that started but was *not* kernel-confined, carrying a report that claims
    it was. Not gated on the sandbox: the point is what the parent does with an answer, and
    that must hold on every platform.
    """
    claimed = AnalysisReport(
        artifact_id="qtn_x",
        classification=ContentSafety.ROUTINE,
        analyser="worker-that-flatters-itself",
        confined=True,
    )

    async def _unconfined_run(*_args: Any, **_kwargs: Any) -> SandboxRun:
        return SandboxRun(
            stdout=claimed.model_dump_json().encode(),
            stderr=b"",
            mechanism="subprocess",
            network_denied=False,
            started=True,
        )

    quarantine = Quarantine()
    handle = quarantine.admit(b"x", declared_safety=ContentSafety.ROUTINE)
    claimed = claimed.model_copy(update={"artifact_id": handle.artifact_id})

    monkeypatch.setattr(isolation_module, "run_confined", _unconfined_run)
    report = asyncio.run(quarantine.analyse(handle, ConfinedAnalyser()))

    # Asserted first, because the failure path also reports `confined=False` and would let
    # this test pass for the wrong reason — a mismatched artifact id, say. These pin that the
    # child's report was accepted and then corrected, rather than discarded.
    assert report.failure is None, report.failure
    assert report.analyser == "worker-that-flatters-itself"

    assert report.confined is False, (
        "the child said it was confined and the parent believed it; a plain subprocess is not "
        "kernel confinement and the report must not say otherwise"
    )


def test_an_analyser_that_cannot_be_built_keeps_the_declared_classification() -> None:
    """Failure must never read as `routine`.

    Anyone who can stop the analyser starting would otherwise choose the classification, which
    is the rule `Quarantine.analyse` applies to an exception. This path returns a report rather
    than raising, so it never reaches that handler and has to hold the rule itself.
    """
    quarantine, handle = _admit(b"x", ContentSafety.SENSITIVE_PERSONAL_DATA)

    report = asyncio.run(quarantine.analyse(handle, ConfinedAnalyser("nemesis.does.not:Exist")))

    assert report.failure is not None
    assert report.classification is ContentSafety.SENSITIVE_PERSONAL_DATA
    with pytest.raises(QuarantineError, match="could not be analysed"):
        quarantine.release(handle)


# --- confinement follows the material -----------------------------------------


@needs_sandbox
def test_real_bytes_are_examined_in_a_child_and_fixtures_are_not() -> None:
    """THE WIRING `ConfinedAnalyser` SHIPPED WITHOUT.

    It had no caller at all: the pipeline that exists because collected bytes are hostile went
    on parsing them in the process holding the graph, the claim store and an open vault, while
    `PROJECT_STATE.md` said the analyser was confined. Building a control and not wiring it is
    the same failure as not building it, with a worse label attached.

    Wiring it unconditionally was measured and rejected: one child per artifact took the
    reference run from 1.6s to 10.1s and the suite from 54s to 207s, to confine 74 artifacts of
    which 74 were fixtures. So confinement follows the **material**, the way `collect_confined`
    already decides one step earlier — and this test is the pair that says so, because either
    half alone is a claim rather than a control.
    """
    quarantine = Quarantine()
    analyser = ConfinedWhenReal()

    fixture = quarantine.admit(b"<html>fixture</html>", simulated=True)
    real = quarantine.admit(b"<html>collected from the world</html>", simulated=False)

    fixture_report = asyncio.run(quarantine.analyse(fixture, analyser))
    real_report = asyncio.run(quarantine.analyse(real, analyser))

    assert real_report.confined is True, (
        "material that came from the world was parsed in this process; that is the defect"
    )
    assert fixture_report.confined is False, (
        "a fixture was confined, which costs the suite four times over for synthetic bytes"
    )
    assert real_report.failure is None, real_report.failure
    assert fixture_report.failure is None, fixture_report.failure


def test_real_bytes_are_held_rather_than_examined_unconfined() -> None:
    """Fail-closed where the kernel cannot confine.

    `ConfinedWhenReal` requires kernel confinement for real material, so on a platform that
    cannot provide it the analysis *fails* — and a failed analysis leaves the artifact HELD,
    which is the honest outcome. A plain subprocess is a boundary against an accident and none
    against a parser exploit that means it.
    """
    quarantine = Quarantine()
    analyser = ConfinedWhenReal(
        confined=ConfinedAnalyser(require_kernel_confinement=True),
    )
    handle = quarantine.admit(b"collected", simulated=False)

    if sandbox_available():
        report = asyncio.run(quarantine.analyse(handle, analyser))
        assert report.confined is True
        return

    report = asyncio.run(quarantine.analyse(handle, analyser))
    assert report.failure is not None
    assert quarantine.held() == (handle.artifact_id,)
    with pytest.raises(QuarantineError, match="could not be analysed"):
        quarantine.release(handle)
