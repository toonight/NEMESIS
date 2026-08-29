"""Where a downloaded artifact waits, and the one way out.

:class:`~nemesis.core.evidence.ContentSafety` has always said the right things.
``MALICIOUS_CODE`` is documented as "never executed outside an isolated analysis pipeline";
``MANDATORY_REPORT`` as "quarantined, never indexed, never exported through ordinary
channels". Both were true statements about an intent. The word *quarantine* appeared nowhere
in the code — only in fixture prose — and there was no pipeline for anything to be isolated
in. This is the same defect this project keeps finding in itself: a docstring describing a
control nobody built.

**The rule the module exists to enforce: unexamined is not safe.**

An artifact arriving from a collector is bytes an adversary may have chosen. It lands here,
not in the vault — the vault is for *sealed evidence*, and sealing something means asserting it
is what it claims to be. Quarantine is the state before that assertion can be made, and the
only exit is an analysis that ran somewhere the artifact could not reach anything.

Four properties, each because the alternative is a specific way this goes wrong:

**One entrance, one exit.** :meth:`Quarantine.admit` takes bytes and returns a handle, never a
path. A caller that could name the file could open it in this process, which is the whole
thing being avoided.

**Only *facts* come back.** What crosses back from an analyser is a :class:`AnalysisReport` —
a classification and observations — never the artifact. Returning the bytes would make any
confinement pointless: a parser exploit that reaches the parent through its own output is a
parser exploit that reached the parent.

**Confinement is an extension point, not something this module performs.** ``ArtifactAnalyser``
is an interface; the shipped :class:`HeuristicAnalyser` runs *in the calling process* and its
report says ``confined=False``. An earlier version of this docstring described the analyser as
"a child process under ``SandboxPolicy`` with reads confined and no socket", and the shipped
analyser hardcoded ``confined=True`` — a claim no code here made true, on a field whose own
documentation says it is reported rather than assumed. :mod:`nemesis.sandbox.process` provides
what a real deployment needs to honour that contract; wiring it is a deployment's step, and
until it does, an analyser is parsing hostile bytes in the parent and the report says so.

**Failure holds rather than releases.** An analysis that times out, crashes, or returns
nonsense leaves the artifact quarantined. The tempting alternative — treat unanalysable as
routine so the pipeline keeps moving — converts every crash into an escape, and an adversary
who can crash the analyser then chooses the classification.

**Some classifications have no ordinary exit at all.** ``MANDATORY_REPORT`` material is held:
the escalation is a human decision and no automated path releases it. That is a refusal the
platform makes about its own convenience.

Status: `IMPLEMENTED` for the pipeline. Honest scope: the demo and tests read fixtures; the
opt-in Tor connector can return real bytes but deliberately does not parse their content. What
is *not* here is a real confined analyser: the one shipped classifies by declared safety and
structure in the caller and reports that fact. A deployment that opens or parses documents
wires its own behind :class:`ArtifactAnalyser`.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Final, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from nemesis.core.evidence import ContentSafety, EvidenceObject, at_least_as_restrictive
from nemesis.core.temporal import utcnow
from nemesis.ports.storage import EvidenceVault, ObligationSink

MAX_ARTIFACT_BYTES: Final = 64 * 1_024 * 1_024
"""Ceiling on what may be admitted at all.

Not capacity: an artifact large enough to exhaust the analyser is a denial-of-service on the
pipeline that decides what is safe, and a pipeline that cannot run fails closed — so an
unbounded artifact is a way to stop the platform examining anything.
"""

HELD_CLASSIFICATIONS: Final[frozenset[ContentSafety]] = frozenset({ContentSafety.MANDATORY_REPORT})
"""Classifications with no automated exit.

``MANDATORY_REPORT`` triggers a legal obligation and its escalation is a human decision. A
pipeline that released it automatically would be making that decision by omission.
"""


class QuarantineState(StrEnum):
    """Where an artifact is in the one-way journey out."""

    ADMITTED = "admitted"
    """In quarantine, unexamined. Not safe, and not assumed to be."""

    ANALYSED = "analysed"
    """Examined in confinement. A classification exists."""

    RELEASED = "released"
    """Cleared to be sealed as evidence. The only state from which the vault may see it."""

    HELD = "held"
    """Examined and deliberately not released — either the analysis failed, or the
    classification has no automated exit."""


class QuarantineError(RuntimeError):
    """The pipeline refused. Never a default, never swallowed."""


@dataclass(frozen=True)
class ArtifactHandle:
    """A reference to quarantined bytes that does not let the holder read them.

    A handle rather than a path, deliberately. A caller holding a path can open the file in
    *this* process, which is precisely the act the confinement exists to prevent — and the
    convenience of "just peek at it" is how that happens.
    """

    artifact_id: str
    content_hash: str
    byte_length: int
    admitted_at: datetime
    declared_safety: ContentSafety
    simulated: bool = False
    """Whether these bytes came from a fixture rather than from the world.

    Carried on the handle because it decides *where* the examination runs, and the analyser
    is handed the handle and not the evidence. It is set by the collection path from
    `provenance.is_simulated`, which no external content can influence: a connector declares
    it, and connectors are in-tree.
    """

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"ArtifactHandle({self.artifact_id}, {self.byte_length}B, no path)"


class AnalysisReport(BaseModel):
    """What crossed back from the confined analyser. Facts, never the artifact."""

    model_config = ConfigDict(frozen=True)

    artifact_id: str
    classification: ContentSafety
    observations: tuple[str, ...] = ()
    analyser: str = Field(min_length=1)
    confined: bool
    """Whether the analysis actually ran under kernel-enforced confinement.

    Reported rather than assumed. An analysis that ran unconfined examined hostile bytes in an
    ordinary process, and a report that hid that would be worse than no report."""

    failure: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.failure is None


@runtime_checkable
class ArtifactAnalyser(Protocol):
    """Examines quarantined bytes and returns facts about them.

    Implementations run in the confined child, not here. The protocol exists so a deployment
    that genuinely opens documents can supply its own without touching the pipeline that keeps
    it contained.
    """

    @property
    def name(self) -> str: ...

    async def analyse(self, artifact: bytes, handle: ArtifactHandle) -> AnalysisReport:
        """Examine the bytes and report.

        Asynchronous because the implementation this extension point exists for runs the
        examination in a confined child process, and a synchronous signature would force every
        such implementation to smuggle an event loop into a thread. The shipped analyser does
        no I/O and is asynchronous only to satisfy this.
        """
        ...


class StructuralAnalyser:
    """The analyser that ships: classifies by declared safety and shape, and opens nothing.

    Honest about what it is. It does not detonate, unpack, or parse — it looks at the bytes'
    structure and at what the collector declared, and it never *lowers* a declared
    classification. Raising one is allowed; lowering one would let a collector's optimism
    become the platform's.

    **The raise only fires from ROUTINE, and that is a real limitation rather than an
    oversight.** :class:`~nemesis.core.evidence.ContentSafety` is not a severity ladder — its
    members are different *handling obligations*, and the field holds exactly one. An artifact
    declared ``SENSITIVE_PERSONAL_DATA`` that also carries a PE header stays
    ``SENSITIVE_PERSONAL_DATA``: nothing was lowered, but the malware fact cannot be expressed
    in the classification, and a consumer keying on ``MALICIOUS_CODE`` to decide "never opened
    outside an isolated pipeline" will not see it.

    So the disagreement is written into ``observations`` in words rather than left silent, and
    this paragraph exists because the previous version said only "raising one is allowed" —
    true, and readable as a promise that detected malware always yields ``MALICIOUS_CODE``. It
    does not. Carrying both obligations needs a set-valued classification, which is a schema
    change and is `PROPOSED`, not done.
    """

    name = "structural-analyser"

    _SIGNATURES: Final[tuple[tuple[bytes, str], ...]] = (
        (b"MZ", "DOS/PE executable header"),
        (b"\x7fELF", "ELF executable header"),
        (b"\xca\xfe\xba\xbe", "Mach-O fat binary header"),
        (b"PK\x03\x04", "ZIP container — may hold anything"),
        (b"%PDF", "PDF document — an active-content format"),
    )

    async def analyse(self, artifact: bytes, handle: ArtifactHandle) -> AnalysisReport:
        observations: list[str] = []
        classification = handle.declared_safety

        for signature, description in self._SIGNATURES:
            if artifact.startswith(signature):
                observations.append(f"begins with a {description}")
                if classification is ContentSafety.ROUTINE:
                    # Raising a classification is allowed; lowering one never is.
                    classification = ContentSafety.MALICIOUS_CODE
                    observations.append(
                        "raised to malicious_code: executable or active-content structure "
                        "declared as routine is a disagreement resolved conservatively"
                    )
                elif classification is not ContentSafety.MALICIOUS_CODE:
                    # Not a raise and not a lowering — a disagreement the single-valued field
                    # cannot hold. Said out loud, because the alternative is that an artifact
                    # is known to be executable and nothing downstream can tell.
                    observations.append(
                        f"executable structure present but the classification stays "
                        f"{classification.value}: this artifact carries two handling "
                        "obligations and the field holds one. Treat it as malicious_code as "
                        "well — no consumer keyed on that class will see it here"
                    )
                break

        if not artifact:
            observations.append("empty artifact")

        return AnalysisReport(
            artifact_id=handle.artifact_id,
            classification=classification,
            observations=tuple(observations),
            analyser=self.name,
            # False, because this analyser runs in the calling process. The field is
            # documented as reported rather than assumed, and a literal `True` here made it
            # assumed — a report attesting to confinement that never happened is worse than
            # no report, which is exactly what the field's own docstring says.
            confined=False,
        )


def _analyser_name(analyser: ArtifactAnalyser) -> str:
    """The analyser's name, or a placeholder, without letting the question fail the handler.

    `getattr(..., default)` is not enough and the reason is worth keeping: the default arm
    answers `AttributeError` alone, so a `name` **property** that raises anything else — very
    often the same failure that just took the analysis down — escapes. This is read while a
    failure is already being converted into a report, so there is nowhere left to raise to.
    """
    try:
        return str(analyser.name)[:120]
    # Deliberately unnarrowed: the point is to survive any answer, including none.
    except Exception:
        return "unknown"


class Quarantine:
    """A holding area for unexamined bytes, with analysis as the only exit.

    Holds the artifacts itself rather than handing out paths, so "just read it here" is not
    an available shortcut.
    """

    def __init__(
        self,
        root: Path | str | None = None,
        *,
        clock: Callable[[], datetime] = utcnow,
        max_bytes: int = MAX_ARTIFACT_BYTES,
    ) -> None:
        self._root = Path(root or tempfile.mkdtemp(prefix="nemesis-quarantine-"))
        self._root.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._max_bytes = max_bytes
        self._state: dict[str, QuarantineState] = {}
        self._reports: dict[str, AnalysisReport] = {}

    def admit(
        self,
        artifact: bytes,
        *,
        declared_safety: ContentSafety = ContentSafety.ROUTINE,
        simulated: bool = False,
    ) -> ArtifactHandle:
        """Take custody of bytes. They go here, never to the vault.

        The vault is for sealed evidence, and sealing asserts the material is what it claims
        to be. Quarantine is the state before anybody may make that assertion.
        """
        if len(artifact) > self._max_bytes:
            raise QuarantineError(
                f"artifact is {len(artifact)} bytes, past the {self._max_bytes}-byte ceiling; "
                "an artifact large enough to exhaust the analyser is a way to stop this "
                "platform examining anything"
            )
        digest = hashlib.sha256(artifact).hexdigest()
        handle = ArtifactHandle(
            artifact_id=f"qtn_{digest[:32]}",
            content_hash=f"sha256:{digest}",
            byte_length=len(artifact),
            admitted_at=self._clock(),
            declared_safety=declared_safety,
            simulated=simulated,
        )
        (self._root / handle.artifact_id).write_bytes(artifact)
        self._state[handle.artifact_id] = QuarantineState.ADMITTED
        return handle

    def state(self, handle: ArtifactHandle) -> QuarantineState:
        return self._state.get(handle.artifact_id, QuarantineState.ADMITTED)

    def report(self, handle: ArtifactHandle) -> AnalysisReport | None:
        return self._reports.get(handle.artifact_id)

    async def analyse(self, handle: ArtifactHandle, analyser: ArtifactAnalyser) -> AnalysisReport:
        """Examine the artifact and record what came back. Failure holds.

        The analyser is handed the bytes; the caller is not. What is returned is a report, and
        an analysis that fails leaves the artifact quarantined — treating unanalysable as
        routine would let anyone who can crash the analyser choose the classification.
        """
        path = self._root / handle.artifact_id
        try:
            artifact = path.read_bytes()
            report = await analyser.analyse(artifact, handle)
        except Exception as exc:
            # **Held first.** The state assignment used to sit below this block, and the block
            # read `getattr(analyser, "name", "unknown")` — which answers `AttributeError`
            # alone, so a `name` property raising anything else propagated out of the handler
            # and the artifact stayed `ADMITTED`: not held, not in `held()`, and no obligation
            # opened for it. Holding the material is the part that must not depend on a second
            # answer from the component that just failed to give a first one. Same shape as the
            # effects registry's crash handler, which consulted the object whose failure it was
            # handling.
            self._state[handle.artifact_id] = QuarantineState.HELD
            report = AnalysisReport(
                artifact_id=handle.artifact_id,
                classification=handle.declared_safety,
                analyser=_analyser_name(analyser),
                confined=False,
                failure=(
                    f"analysis failed ({type(exc).__name__}); the artifact stays quarantined, "
                    "because unexamined is not safe"
                ),
            )
        self._reports[handle.artifact_id] = report
        self._state[handle.artifact_id] = (
            QuarantineState.ANALYSED if report.succeeded else QuarantineState.HELD
        )
        return report

    def release(self, handle: ArtifactHandle) -> bytes:
        """Hand over the artifact for sealing, or refuse.

        The only path from quarantine to the vault, and it refuses four ways: unexamined,
        analysis failed, a classification less restrictive than the one declared, or a
        classification with no automated exit.
        """
        state = self.state(handle)
        report = self._reports.get(handle.artifact_id)

        if state is QuarantineState.ADMITTED or report is None:
            raise QuarantineError(
                f"{handle.artifact_id} has not been analysed. Unexamined is not safe, and "
                "releasing on the assumption that it is would make the pipeline decorative"
            )
        if not report.succeeded:
            raise QuarantineError(
                f"{handle.artifact_id} could not be analysed: {report.failure}. An adversary "
                "who can crash the analyser must not thereby choose the classification"
            )
        if not at_least_as_restrictive(report.classification, handle.declared_safety):
            # Outside the analyser deliberately. `StructuralAnalyser` already refuses to lower
            # a classification, but it is the documented extension point — the component a
            # deployment replaces, and the one that by design parses hostile bytes. A rule
            # enforced by the thing it constrains is not enforced, and the test asserting this
            # used to assert its own opposite because of it.
            self._state[handle.artifact_id] = QuarantineState.HELD
            raise QuarantineError(
                f"{handle.artifact_id} was declared {handle.declared_safety.value} and "
                f"{report.analyser!r} answered {report.classification.value}, which is less "
                "restrictive or incomparable. A classification may be raised and never "
                "lowered; with no order between two classes there is no honest merge, so the "
                "disagreement is held for a human rather than resolved by whoever wrote last"
            )
        if report.classification in HELD_CLASSIFICATIONS:
            self._state[handle.artifact_id] = QuarantineState.HELD
            raise QuarantineError(
                f"{handle.artifact_id} is classified {report.classification.value}, which has "
                "no automated exit: the escalation is a human decision and releasing it here "
                "would be making that decision by omission"
            )

        self._state[handle.artifact_id] = QuarantineState.RELEASED
        return (self._root / handle.artifact_id).read_bytes()

    def held(self) -> tuple[str, ...]:
        """Everything the pipeline refused to release, so a human can see the backlog."""
        return tuple(
            artifact_id
            for artifact_id, state in sorted(self._state.items())
            if state is QuarantineState.HELD
        )


def analysis_payload(handle: ArtifactHandle) -> bytes:
    """What a confined analyser child is told about its job. Never a path outside its own."""
    return json.dumps(
        {
            "artifact_id": handle.artifact_id,
            "content_hash": handle.content_hash,
            "byte_length": handle.byte_length,
            "declared_safety": handle.declared_safety.value,
            "simulated": handle.simulated,
            # The handle's remaining field. Included because the child reconstructs the whole
            # handle and an analyser is entitled to know how long the material has been held —
            # and because inventing a value on the far side would put a fabricated timestamp
            # in front of the one component that reads hostile bytes for a living.
            "admitted_at": handle.admitted_at.isoformat(),
        }
    ).encode()


__all__ = [
    "HELD_CLASSIFICATIONS",
    "MAX_ARTIFACT_BYTES",
    "AnalysisReport",
    "ArtifactAnalyser",
    "ArtifactHandle",
    "Quarantine",
    "QuarantineError",
    "QuarantineState",
    "StructuralAnalyser",
    "analysis_payload",
    "seal_when_released",
]


async def seal_when_released(
    vault: EvidenceVault,
    evidence: EvidenceObject,
    artifact: bytes,
    *,
    quarantine: Quarantine,
    analyser: ArtifactAnalyser,
    obligations: ObligationSink,
) -> tuple[str | None, AnalysisReport]:
    """Quarantine collected bytes, and seal them only if quarantine lets them go.

    **The single place that decides**, for the same reason `collect_confined` is one: there
    turned out to be three sealing sites — the pursuit engine's and two in the reference
    scenario — and wiring the first left twenty-three artifacts quarantined while the others
    still went straight to the vault. A rule implemented once per call site holds until
    somebody adds a call site.

    The vault is append-only and hash-chained. Anything that reaches it cannot be removed
    without breaking the chain, which is exactly the property that makes it evidence and
    exactly the property that makes admitting the wrong thing unrecoverable. Material carrying
    a reporting obligation cannot legally be retained and cannot be deleted — so the decision
    belongs before the seal, not after.

    ``obligations`` has no default, deliberately. This function's own argument for existing is
    that a rule implemented once per call site holds only until somebody adds a call site, and
    an optional sink would have reintroduced exactly that: a new caller would silently hold
    material carrying a legal clock and open nothing.

    Returns ``(sealed_id, report)``, with ``sealed_id`` None when the artifact is held. The
    caller drops anything citing a held artifact: a claim pointing at evidence that was never
    sealed has unresolvable provenance, which invariant 3 forbids.

    The classification the analyser returns is written onto the evidence, so what the vault
    records is what was *examined* rather than what the collector *declared*. That is safe
    only because :meth:`Quarantine.release` now refuses any classification less restrictive
    than the declared one: without that check this line meant a replaceable analyser chose
    what the append-only store recorded, and material carrying a legal clock could be sealed
    as routine and then not be removable.
    """
    handle = quarantine.admit(
        artifact,
        declared_safety=evidence.content_safety,
        simulated=evidence.provenance.is_simulated,
    )
    report = await quarantine.analyse(handle, analyser)
    try:
        released = quarantine.release(handle)
    except QuarantineError as refusal:
        # Refusing was only ever half of it. `Register.incur` had no caller in `src/`, so the
        # material was held correctly and then nothing opened, no deadline started, and the
        # backlog was read by nobody — which is indistinguishable, to anyone auditing, from a
        # platform that has never encountered such material.
        #
        # Keyed on the **declared** class as well as the analysed one, and that is the point:
        # an analyser that lowers a `mandatory_report` is already refused by `release`, and
        # reading only the report here would have let the same lie suppress the obligation
        # too. One compromised component should not be able to close both doors.
        if ContentSafety.MANDATORY_REPORT in {handle.declared_safety, report.classification}:
            obligations.incur(artifact_id=handle.artifact_id, reason=str(refusal))
        return None, report
    await vault.seal(
        evidence.model_copy(update={"content_safety": report.classification}), released
    )
    return evidence.evidence_id, report
