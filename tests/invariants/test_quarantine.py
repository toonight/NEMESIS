"""Unexamined is not safe, and the pipeline has to act like it.

`ContentSafety` has always said the right things — MALICIOUS_CODE "never executed outside an
isolated analysis pipeline", MANDATORY_REPORT "quarantined, never indexed". Both described a
control that did not exist: the word *quarantine* appeared only in fixture prose.

These tests are about the pipeline that makes those sentences true, and they are written the
way this project writes security tests: each one constructs the shortcut somebody would take
under deadline pressure, and asserts it is refused.

Covers **EVID-04** from `docs/security/INVARIANTS.md` — with the half that is *not* covered
named in the register and in the threat model: the monotonicity rule that stops a downgrade
lives inside `StructuralAnalyser`, a documented deployment extension point, so a replaceable
analyser can relabel material before the vault ever sees it.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from nemesis.collect.quarantine import (
    HELD_CLASSIFICATIONS,
    AnalysisReport,
    ArtifactHandle,
    Quarantine,
    QuarantineError,
    QuarantineState,
    StructuralAnalyser,
    seal_when_released,
)
from nemesis.core.evidence import ArtifactKind, ContentSafety, EvidenceObject
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.provenance import (
    CollectionMethod,
    ProvenanceChain,
    SourceClass,
    SourceDescriptor,
)
from nemesis.core.temporal import TemporalExtent, utcnow
from nemesis.evidence.escalation import UNCONFIGURED_AUTHORITY, Register
from nemesis.evidence.vault import FileSystemEvidenceVault
from nemesis.slice.scenario import run_glass_anvil_scenario

pytestmark = pytest.mark.invariant


class _Exploding:
    """An analyser that dies, as a parser meeting hostile bytes would."""

    name = "exploding-analyser"

    async def analyse(self, artifact: bytes, handle: ArtifactHandle) -> AnalysisReport:
        raise MemoryError("the parser died on this input")


class _Lying:
    """An analyser that declares everything routine — a compromised or naive one."""

    name = "lying-analyser"

    async def analyse(self, artifact: bytes, handle: ArtifactHandle) -> AnalysisReport:
        return AnalysisReport(
            artifact_id=handle.artifact_id,
            classification=ContentSafety.ROUTINE,
            analyser=self.name,
            confined=True,
        )


class _Escalating:
    """An honest analyser that finds the material worse than it was declared."""

    name = "escalating-analyser"

    async def analyse(self, artifact: bytes, handle: ArtifactHandle) -> AnalysisReport:
        return AnalysisReport(
            artifact_id=handle.artifact_id,
            classification=ContentSafety.MANDATORY_REPORT,
            analyser=self.name,
            confined=True,
        )


class _Sideways:
    """An analyser answering a class that neither dominates nor is dominated by the declared
    one — a disagreement rather than a revision."""

    name = "sideways-analyser"

    async def analyse(self, artifact: bytes, handle: ArtifactHandle) -> AnalysisReport:
        return AnalysisReport(
            artifact_id=handle.artifact_id,
            classification=ContentSafety.SENSITIVE_PERSONAL_DATA,
            analyser=self.name,
            confined=True,
        )


# --- Nothing reaches the vault unexamined ------------------------------------


def test_an_unexamined_artifact_cannot_be_released() -> None:
    """THE TEST THIS FILE EXISTS FOR.

    The shortcut under deadline pressure is "it's probably fine, seal it". Quarantine's only
    exit is analysis, and skipping it is refused rather than merely discouraged.
    """
    quarantine = Quarantine()
    handle = quarantine.admit(b"unexamined bytes")

    assert quarantine.state(handle) is QuarantineState.ADMITTED
    with pytest.raises(QuarantineError, match="has not been analysed"):
        quarantine.release(handle)


def test_a_handle_does_not_let_its_holder_read_the_artifact() -> None:
    """A path would let a caller open hostile bytes in *this* process, which is the act the
    confinement exists to prevent — and "just peek at it" is how that happens."""
    handle = Quarantine().admit(b"MZ hostile")

    fields = set(handle.__dataclass_fields__)
    assert "path" not in fields and "artifact" not in fields and "bytes" not in fields
    assert fields == {
        "artifact_id",
        "content_hash",
        "byte_length",
        "admitted_at",
        "declared_safety",
        # Added 2026-08-29 with `ConfinedWhenReal`, and pinned here on purpose: this set is
        # exhaustive so that widening the handle is a deliberate, visible event rather than a
        # convenience somebody adds. `simulated` is a bool the collection path sets from
        # `provenance.is_simulated`; it names *where the bytes came from*, never where they
        # are, which is the property this test is actually about.
        "simulated",
    }
    # And no filesystem path leaks through the repr — checked as a path rather than as the
    # word, since the repr deliberately says "no path".
    assert "/" not in repr(handle), repr(handle)


# --- Failure holds rather than releases --------------------------------------


def test_an_analysis_that_crashes_leaves_the_artifact_quarantined() -> None:
    """Treating unanalysable as routine converts every crash into an escape, and an adversary
    who can crash the analyser then chooses the classification."""
    quarantine = Quarantine()
    handle = quarantine.admit(b"input that kills the parser")

    report = asyncio.run(quarantine.analyse(handle, _Exploding()))

    assert report.succeeded is False
    assert quarantine.state(handle) is QuarantineState.HELD
    with pytest.raises(QuarantineError, match="could not be analysed"):
        quarantine.release(handle)


def test_a_failed_analysis_reports_that_it_was_not_confined() -> None:
    """An analysis that ran unconfined examined hostile bytes in an ordinary process, and a
    report hiding that would be worse than no report."""
    quarantine = Quarantine()
    handle = quarantine.admit(b"x")

    assert asyncio.run(quarantine.analyse(handle, _Exploding())).confined is False


def test_held_artifacts_are_listed_so_a_human_can_see_the_backlog() -> None:
    quarantine = Quarantine()
    first = quarantine.admit(b"one")
    second = quarantine.admit(b"two")
    asyncio.run(quarantine.analyse(first, _Exploding()))
    asyncio.run(quarantine.analyse(second, StructuralAnalyser()))

    assert first.artifact_id in quarantine.held()
    assert second.artifact_id not in quarantine.held()


# --- A classification may be raised, never lowered ---------------------------


def test_an_executable_declared_routine_is_raised_not_believed() -> None:
    """A collector's optimism must not become the platform's. Raising a classification is
    allowed; lowering one never is."""
    quarantine = Quarantine()
    handle = quarantine.admit(
        b"MZ\x90\x00 this is a PE header", declared_safety=ContentSafety.ROUTINE
    )

    report = asyncio.run(quarantine.analyse(handle, StructuralAnalyser()))

    assert report.classification is ContentSafety.MALICIOUS_CODE
    assert any("raised to malicious_code" in note for note in report.observations)


def test_a_declared_classification_is_never_lowered_by_the_shipped_analyser() -> None:
    quarantine = Quarantine()
    handle = quarantine.admit(b"ordinary text", declared_safety=ContentSafety.MALICIOUS_CODE)

    assert asyncio.run(quarantine.analyse(handle, StructuralAnalyser())).classification is (
        ContentSafety.MALICIOUS_CODE
    )


def test_malicious_code_may_still_be_sealed_because_sealing_is_not_running() -> None:
    """The distinction that keeps the pipeline useful: preserving malware as evidence is the
    job. *Executing* it is what the classification forbids, and sealing executes nothing."""
    quarantine = Quarantine()
    handle = quarantine.admit(b"MZ malware sample")
    asyncio.run(quarantine.analyse(handle, StructuralAnalyser()))

    assert quarantine.release(handle) == b"MZ malware sample"
    assert quarantine.state(handle) is QuarantineState.RELEASED


# --- Some classifications have no automated exit -----------------------------


def test_mandatory_report_material_has_no_automated_exit() -> None:
    """Its escalation is a human decision, and releasing it here would be making that
    decision by omission."""
    quarantine = Quarantine()
    handle = quarantine.admit(b"content", declared_safety=ContentSafety.MANDATORY_REPORT)
    asyncio.run(quarantine.analyse(handle, StructuralAnalyser()))

    with pytest.raises(QuarantineError, match="no automated exit"):
        quarantine.release(handle)
    assert quarantine.state(handle) is QuarantineState.HELD


def test_the_held_set_is_exactly_what_it_claims() -> None:
    """A tripwire: adding or removing a classification from the no-exit set is a decision
    about a legal obligation, not a refactor."""
    assert {ContentSafety.MANDATORY_REPORT} == HELD_CLASSIFICATIONS


def test_a_lying_analyser_cannot_release_mandatory_report_material() -> None:
    """THE TEST THIS NAME ALWAYS CLAIMED, and did not make.

    It used to assert its own opposite: the body released the material and the docstring
    explained why that was an acceptable limit. The threat model recorded it as one of two
    tests found asserting the negation of their own names, and noted that a name is what a
    coverage claim reads.

    What made it possible is the part worth fixing: the rule "raising a classification is
    allowed, lowering one never is" was written inside `StructuralAnalyser` — the component a
    deployment is explicitly invited to replace, and the one that by design parses hostile
    bytes. A rule enforced by the thing it constrains is not enforced. It is the gate's now.
    """
    quarantine = Quarantine()
    handle = quarantine.admit(b"x", declared_safety=ContentSafety.MANDATORY_REPORT)
    asyncio.run(quarantine.analyse(handle, _Lying()))

    with pytest.raises(QuarantineError, match="less restrictive"):
        quarantine.release(handle)
    assert quarantine.held() == (handle.artifact_id,), (
        "a refused release must leave the artifact visible in the backlog, not merely unsealed"
    )


def test_an_analyser_may_still_raise_a_classification() -> None:
    """The rule is monotonic, not frozen. An analyser that finds something worse than what was
    declared must be able to say so — that is the direction the control exists to allow, and a
    check that refused every disagreement would be a check somebody turns off."""
    quarantine = Quarantine()
    handle = quarantine.admit(b"x", declared_safety=ContentSafety.ROUTINE)
    asyncio.run(quarantine.analyse(handle, _Escalating()))

    with pytest.raises(QuarantineError, match="no automated exit"):
        quarantine.release(handle)
    assert quarantine.held() == (handle.artifact_id,)


def test_a_sideways_reclassification_is_refused_rather_than_guessed() -> None:
    """`ContentSafety` is not a ladder, and the partial order says so.

    `MALICIOUS_CODE` and `SENSITIVE_PERSONAL_DATA` are both above `ROUTINE` and neither is
    above the other, so an analyser answering one when the collector declared the other has
    not raised or lowered anything — it has disagreed. Releasing on that would pick a winner
    by accident. The shipped analyser never produces this: it records the second obligation as
    an observation and leaves the class alone. A replacement can, so the gate answers for it.
    """
    quarantine = Quarantine()
    handle = quarantine.admit(b"x", declared_safety=ContentSafety.MALICIOUS_CODE)
    asyncio.run(quarantine.analyse(handle, _Sideways()))

    with pytest.raises(QuarantineError, match="less restrictive"):
        quarantine.release(handle)


# --- Ceilings ----------------------------------------------------------------


def test_an_artifact_too_large_to_analyse_is_refused_at_the_door() -> None:
    """An artifact large enough to exhaust the analyser is a way to stop this platform
    examining anything at all."""
    quarantine = Quarantine(max_bytes=16)

    with pytest.raises(QuarantineError, match="past the"):
        quarantine.admit(b"x" * 17)


def test_the_shipped_analyser_does_not_claim_confinement_it_does_not_have() -> None:
    """`confined` is documented as reported rather than assumed; it was a hardcoded `True`.

    The heuristic analyser runs in the calling process. Sixteen tests passed while the field
    lied, because none of them read it — which is how an attestation nobody checks becomes an
    attestation nobody can trust. A deployment that takes up the `ArtifactAnalyser` extension
    point and runs it under a real sandbox reports `True` and earns it.
    """
    quarantine = Quarantine()
    handle = quarantine.admit(b"<html>ordinary</html>")
    report = asyncio.run(StructuralAnalyser().analyse(b"<html>ordinary</html>", handle))

    assert report.confined is False, (
        "the shipped analyser attested to kernel-enforced confinement it never had"
    )


def test_malware_under_a_non_routine_class_is_named_rather_than_lost() -> None:
    """`ContentSafety` is not a severity ladder — its members are different obligations, and
    the field holds one.

    An artifact declared `sensitive_personal_data` that also carries a PE header stays
    `sensitive_personal_data`: nothing is lowered, but the malware fact cannot be expressed in
    the classification, and a consumer keying on `MALICIOUS_CODE` to decide "never opened
    outside an isolated pipeline" would never see it. The disagreement is therefore written
    into the observations in words.

    Raised by a local-model review pass. Its stated finding — that the analyser *lowers* a
    classification — was refused: measured across all five members, it never does, and the
    argument rested on a `SAFE` member that does not exist. What survived is this narrower and
    real gap, which is why the pass was worth running and why its output is checked rather
    than believed.
    """
    quarantine = Quarantine()
    malware = b"MZ\x90\x00" + b"\x00" * 64

    for declared in ContentSafety:
        handle = quarantine.admit(malware, declared_safety=declared)
        report = asyncio.run(StructuralAnalyser().analyse(malware, handle))

        # The load-bearing half: never lowered, on any member.
        assert report.classification is declared or declared is ContentSafety.ROUTINE

        if declared is ContentSafety.ROUTINE:
            assert report.classification is ContentSafety.MALICIOUS_CODE
        elif declared is not ContentSafety.MALICIOUS_CODE:
            assert report.classification is declared
            assert any("classification stays" in o for o in report.observations), (
                f"{declared.value} carries executable structure and nothing in the report "
                "says so; the fact is known and unreachable"
            )


def test_nothing_reaches_the_vault_without_passing_quarantine(tmp_path: Path) -> None:
    """THE PIN FOR THE WIRING, measured across a full reference run.

    `Quarantine` was a module nothing instantiated: `PursuitEngine` sealed collected bytes
    straight into an append-only, hash-chained vault, and so did the reference scenario — in
    two more places. Wiring the engine alone left twenty-three artifacts examined and the rest
    going directly to the vault, which is why the decision now lives in one function,
    `seal_when_released`, that all three call.

    This counts rather than reads, for the same reason the collector-isolation pin does:
    reading the code is what said the control was in place while the measurement disagreed.
    """
    quarantined: list[int] = []
    sealed: list[int] = []

    original_admit = Quarantine.admit
    original_seal = FileSystemEvidenceVault.seal

    def counting_admit(self: Any, artifact: bytes, **kwargs: Any) -> Any:
        quarantined.append(1)
        return original_admit(self, artifact, **kwargs)

    async def counting_seal(self: Any, evidence: Any, artifact: bytes) -> Any:
        sealed.append(1)
        return await original_seal(self, evidence, artifact)

    Quarantine.admit = counting_admit  # type: ignore[method-assign]
    FileSystemEvidenceVault.seal = counting_seal  # type: ignore[method-assign]
    try:
        result = run_glass_anvil_scenario(workspace=tmp_path)
    finally:
        Quarantine.admit = original_admit  # type: ignore[method-assign]
        FileSystemEvidenceVault.seal = original_seal  # type: ignore[method-assign]

    assert sealed, "nothing was sealed at all; this test proved nothing"
    assert len(sealed) <= len(quarantined), (
        f"{len(sealed) - len(quarantined)} artifacts reached the vault without being "
        "examined; the vault is append-only, so admitting the wrong thing is unrecoverable"
    )
    assert result.attribute.result is not None
    assert result.resurgence is not None


def test_material_carrying_a_reporting_obligation_never_reaches_the_vault() -> None:
    """The reason the wiring had to happen before any real dark-web source.

    `HELD_CLASSIFICATIONS` is `MANDATORY_REPORT`, and the vault is append-only and
    hash-chained. Material that cannot legally be retained and cannot be deleted without
    breaking the chain is an engineering dead end, so the decision belongs *before* the seal.
    Here it is, as a property of `seal_when_released` rather than of a comment.
    """
    quarantine = Quarantine()
    artifact = b"declared as carrying a reporting obligation"
    handle = quarantine.admit(artifact, declared_safety=ContentSafety.MANDATORY_REPORT)
    asyncio.run(quarantine.analyse(handle, StructuralAnalyser()))

    with pytest.raises(QuarantineError):
        quarantine.release(handle)


# --- The other half of MANDATORY_REPORT --------------------------------------


def _reporting_evidence(artifact: bytes) -> EvidenceObject:
    now = utcnow()
    return EvidenceObject.seal(
        artifact=artifact,
        artifact_kind=ArtifactKind.DNS_RECORD,
        provenance=ProvenanceChain(
            collection_id=new_id(IdPrefix.COLLECTION),
            source=SourceDescriptor(source_class=SourceClass.INTERNET_SCAN, identifier="fixture"),
            method=CollectionMethod(
                collector_name="fixture",
                collector_version="1.0",
                parameters={},
                is_simulated=True,
            ),
            collected_at=now,
        ),
        observed_extent=TemporalExtent.at(now),
        content_safety=ContentSafety.MANDATORY_REPORT,
    )


def test_holding_reporting_material_opens_an_obligation(tmp_path: Path) -> None:
    """THE HALF THAT WAS BUILT AND WIRED TO NOTHING.

    `Register.incur` had zero callers in `src/`. Quarantine refused the material correctly,
    and then nothing opened, no deadline started and `held()` was read by nobody. The
    escalation module's own thesis is that "the dangerous obligation is the one that lands in
    a queue nobody reads", and a register with no producer is that queue with nothing in it —
    which reads, to anyone auditing, exactly like a platform that has never encountered such
    material.
    """
    register = Register()
    quarantine = Quarantine()
    artifact = b"material carrying a reporting obligation"

    sealed_id, report = asyncio.run(
        seal_when_released(
            FileSystemEvidenceVault(tmp_path / "vault"),
            _reporting_evidence(artifact),
            artifact,
            quarantine=quarantine,
            analyser=StructuralAnalyser(),
            obligations=register,
        )
    )

    assert sealed_id is None, "material with a legal clock must not reach the vault"
    assert report.classification is ContentSafety.MANDATORY_REPORT
    (obligation,) = register.open_obligations()
    assert obligation.artifact_id in quarantine.held()
    assert obligation.authority == UNCONFIGURED_AUTHORITY, (
        "an unconfigured deployment must say so on the record rather than name a plausible "
        "authority it was never told"
    )


def test_an_obligation_survives_the_restart_that_used_to_discharge_it(tmp_path: Path) -> None:
    """A duty with a clock on it, held only in memory, is discharged by a restart — silently,
    leaving no trace the platform ever owed anything. That is the failure this module names,
    reached by process exit rather than by anybody deciding it."""
    path = tmp_path / "obligations.jsonl"
    artifact = b"material carrying a reporting obligation"

    first = Register(path)
    asyncio.run(
        seal_when_released(
            FileSystemEvidenceVault(tmp_path / "vault"),
            _reporting_evidence(artifact),
            artifact,
            quarantine=Quarantine(),
            analyser=StructuralAnalyser(),
            obligations=first,
        )
    )
    (before,) = first.open_obligations()

    # A different process, reading the same file.
    (after,) = Register(path).open_obligations()
    assert after == before, "the obligation did not survive the restart"


def test_re_examining_held_material_does_not_restart_its_clock(tmp_path: Path) -> None:
    """An obligation whose deadline moves every time the material is re-examined never becomes
    overdue, and the collection path re-examines by construction — the same artifact arrives
    again on the next run."""
    path = tmp_path / "obligations.jsonl"
    register = Register(path)
    artifact = b"material carrying a reporting obligation"
    evidence = _reporting_evidence(artifact)

    for _ in range(3):
        asyncio.run(
            seal_when_released(
                FileSystemEvidenceVault(tmp_path / "vault"),
                evidence,
                artifact,
                quarantine=Quarantine(),
                analyser=StructuralAnalyser(),
                obligations=register,
            )
        )

    (obligation,) = register.open_obligations()
    assert len(path.read_text().splitlines()) == 1, (
        "the record grew on re-examination; the deadline it carries is the first one, and a "
        "file that appends per sighting invites a reader to believe the latest"
    )
    assert Register(path).open_obligations() == (obligation,)


def test_a_lying_analyser_cannot_suppress_the_obligation_either(tmp_path: Path) -> None:
    """One compromised component must not be able to close both doors.

    `release` refuses the downgrade, so the material is held whatever the analyser says. If
    the obligation were keyed on the *report* alone, the same lie that failed to release the
    material would still have stopped anybody being told about it — a quieter version of the
    same attack, and the one that survives a fix aimed only at the release path.
    """
    register = Register()
    artifact = b"material carrying a reporting obligation"

    sealed_id, report = asyncio.run(
        seal_when_released(
            FileSystemEvidenceVault(tmp_path / "vault"),
            _reporting_evidence(artifact),
            artifact,
            quarantine=Quarantine(),
            analyser=_Lying(),
            obligations=register,
        )
    )

    assert sealed_id is None
    assert report.classification is ContentSafety.ROUTINE, (
        "the analyser's answer is still recorded as what it said; the gate refuses to act on "
        "it rather than pretending it was never given"
    )
    assert len(register.open_obligations()) == 1, (
        "the obligation was keyed on the analyser's answer, so lying suppressed it"
    )


class _ExplodingTwice:
    """Fails the analysis, and then fails to say who it is."""

    @property
    def name(self) -> str:
        raise RuntimeError("name unavailable")

    async def analyse(self, artifact: bytes, handle: ArtifactHandle) -> AnalysisReport:
        raise RuntimeError("analysis blew up")


def test_an_analyser_that_fails_twice_still_leaves_the_artifact_held() -> None:
    """The handler that holds the artifact must not need the analyser's cooperation.

    `getattr(analyser, "name", "unknown")` was read *inside* the except block, and `getattr`
    answers `AttributeError` alone — so a `name` property raising anything else propagated out
    of the handler, and the state assignment below it never ran. The artifact stayed
    `ADMITTED`: not held, not in `held()`, and no obligation opened for it.

    Same shape as the effects registry two days earlier, where the crash handler consulted the
    object whose failure it was handling. The state is now set before anything optional is
    built, because holding the material is the part that must not depend on a second answer.
    """
    quarantine = Quarantine()
    handle = quarantine.admit(b"x", declared_safety=ContentSafety.MANDATORY_REPORT)

    report = asyncio.run(quarantine.analyse(handle, _ExplodingTwice()))

    assert quarantine.state(handle) is QuarantineState.HELD
    assert quarantine.held() == (handle.artifact_id,)
    assert report.failure is not None
    assert report.classification is ContentSafety.MANDATORY_REPORT
