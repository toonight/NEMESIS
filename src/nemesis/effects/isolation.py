"""Running an effect in a process that can do less than this one.

Invariant 8 has been enforced by `import-linter` since ADR-0001, which is a build-time
boundary: it binds the code in this repository and binds nothing at runtime. ADR-0001 said
so plainly and listed "process-level isolation for Effects" as an unverified assumption.
Four adversarial reviews then closed their residual-risk sections with the same sentence —
an attacker with code execution in this process defeats every control, and isolation remains
`PROPOSED`. This module is where that changes.

**What the child does not have.** It is launched as ``python -m nemesis.effects.worker``
with a pipe for input, a pipe for output, and:

- *no private key* — it receives a public verifying key, so a fully owned worker still
  cannot mint a capability;
- *no importable intelligence platform* — the worker seals the graph, the vault, the
  collection and pursuit planes, and the signing module, before reading a byte of input;
- *no socket*, where the platform can enforce that (macOS ``sandbox-exec``). This is the
  only control that turns "nothing left the system" from the adapter's own report into
  something the kernel established;
- *no inherited environment* — the environment is built from nothing, so credentials this
  process happens to hold do not travel;
- *no time* — a deadline, after which it is killed and the operation is recorded as failed;
- *no memory, CPU or output to spare* — ceilings the worker applies to itself at bootstrap.

**What is not claimed.** Filesystem confinement and network denial come from
``sandbox-exec``, which exists on macOS and nowhere else. On any other platform this
executor still gives a separate process with no key, no imports and a deadline — and says
so in the :class:`~nemesis.ports.isolation.IsolationReport` rather than reporting a
confinement it did not get. Read the report, not this docstring, for what a given run
actually had.

**The decision is made here, not there.** The parent runs :func:`preflight` itself and
dispatches only if the operation is authorized. The worker re-runs it — a second, independent
check against the same signed bytes — but a worker that skipped the check entirely could
still only perform an operation this process already decided to allow. The result that comes
back is re-validated and its authorization verdict is replaced with the parent's, because a
compromised worker's account of its own authority is worth nothing.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import signal
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

from pydantic import ValidationError

import nemesis
from nemesis.core.authorization import (
    NO_CAPABILITY,
    AuthorizationCapability,
    OperationClass,
)
from nemesis.core.temporal import utcnow
from nemesis.effects.registry import (
    REGISTRY_NAME,
    Preflight,
    preflight,
    refusal_record,
    sanitize,
)
from nemesis.effects.worker import ENV_ADDRESS_SPACE, ENV_CPU_SECONDS, ENV_OUTPUT_BYTES
from nemesis.ports.authorization import TrustAnchor
from nemesis.ports.effects import EffectOutcome, EffectRequest, EffectResult
from nemesis.ports.isolation import IsolationReport
from nemesis.sandbox.process import SandboxPolicy

WORKER_MODULE: Final = "nemesis.effects.worker"

DEFAULT_DEADLINE_SECONDS: Final = 30.0
DEFAULT_ADDRESS_SPACE_BYTES: Final = 1_024 * 1_024 * 1_024
DEFAULT_CPU_SECONDS: Final = 20
DEFAULT_OUTPUT_BYTES: Final = 16 * 1_024 * 1_024

CREDENTIAL_PATHS: Final = (
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
    ".netrc",
    ".config/gcloud",
    "Library/Keychains",
)
"""Directories under the operator's home the Effects plane is denied reading.

An enumeration, and therefore incomplete — see :data:`SANDBOX_PROFILE`. Denying the whole
home directory would be structural and is not possible: in a source checkout the package and
its interpreter live there too, and the child could not start.
"""

MAX_STDERR_BYTES: Final = 256 * 1_024
MAX_DETAIL_CHARACTERS: Final = 4_000
MAX_ARTIFACTS: Final = 64
_REAP_SECONDS: Final = 5.0


class _OutputCeilingError(RuntimeError):
    """The worker tried to return more than the parent will hold."""


MAX_WORKER_OUTPUT_BYTES: Final = 8 * 1_024 * 1_024
"""Ceiling on what the parent will read back.

A worker that streams unbounded output is a worker that exhausts the parent's memory from
inside its own sandbox, which would make the isolation a denial-of-service primitive rather
than a control.
"""

SANDBOX_PROFILE: Final = """(version 1)
(allow default)
(deny network*)
(deny file-write*)
(allow file-write* (subpath "{workdir}"))
(allow file-write-data (literal "/dev/null") (literal "/dev/stdout") (literal "/dev/stderr"))
(deny mach-lookup (global-name "com.apple.coreservices.launchservicesd"))
(deny mach-lookup (global-name "com.apple.lsd.mapdb"))
(deny mach-lookup (global-name "com.apple.lsd.modifydb"))
(deny mach-lookup (global-name "com.apple.mDNSResponder"))
(deny mach-lookup (global-name "com.apple.mDNSResponder.dnsproxy"))
{read_denials}"""
"""macOS sandbox profile. Allow-default, with the denials that matter enumerated.

Allow-default is a deliberate, stated choice: a deny-default profile for CPython has to
enumerate every dylib, stdlib path and temporary file the interpreter touches, and a profile
maintained by enumeration fails *open* the first time an upgrade adds a path.

**The cost of that choice, found by an adversarial review, and why these rules exist.**
`(allow default)` permits `mach-lookup`, so a confined child could ask LaunchServices to
start a process — and that process is a child of ``launchd``, inheriting neither the network
denial nor the write denial. The kernel had denied *this* process a socket; it had not
denied it the ability to have another process open one. The LaunchServices and DNS services
are now denied by name.

The same review noted that `(allow default)` also permits reading anything, which matters
because the evidence vault, the audit trail and any persisted signing key live on disk and
need no import to read. `import-linter` blocks the import; nothing blocked the open().

The denials below are the answer, and the answer is **partial, by construction**. A read
*allowlist* would be the structural fix and would fail closed, which is the safe direction —
but it aborts CPython outright on this platform (``rc=134`` for an allowlist covering the
interpreter prefix, the package, ``/usr/lib``, ``/System`` and the dyld cache), so it is not
something to ship on a guess. What is here instead is an enumeration: the deployment's own
workspace, and the credential directories an attacker would reach for first.

Enumeration is exactly what this docstring argues against for writes, and the asymmetry is
deliberate rather than lazy: a missed write rule would let the plane *change* something
outside itself, while a missed read rule lets it *learn* something it should not. Both
matter and one is worse. Treat the read surface as narrowed, not closed, and see
`THREAT_MODEL.md` where it is recorded as an open gap.
"""


def sandbox_available() -> bool:
    """Whether this platform can enforce the profile above."""
    return sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").exists()


class IsolatedEffectsExecutor:
    """Performs one authorized operation in a confined child process.

    Holds the public verifying key and the revocation oracle — the means to refuse — and no
    signing key, so this class cannot widen what it dispatches either.
    """

    def __init__(
        self,
        anchor: TrustAnchor,
        *,
        deadline_seconds: float = DEFAULT_DEADLINE_SECONDS,
        address_space_bytes: int = DEFAULT_ADDRESS_SPACE_BYTES,
        cpu_seconds: int = DEFAULT_CPU_SECONDS,
        output_bytes: int = DEFAULT_OUTPUT_BYTES,
        allow_unsandboxed: bool = True,
        read_denied: Sequence[str | Path] = (),
    ) -> None:
        """``allow_unsandboxed`` is the deployment's call, and it is a real one.

        Left True so the demonstration and the test suite run on any platform. A deployment
        that means it sets it False, and then this executor refuses to run at all where the
        kernel cannot deny the child a socket — which is the honest behaviour for a plane
        whose whole claim is that nothing leaves the system.
        """
        self._anchor = anchor
        self._deadline = deadline_seconds
        self._address_space = address_space_bytes
        self._cpu_seconds = cpu_seconds
        self._output_bytes = output_bytes
        self._allow_unsandboxed = allow_unsandboxed
        # Paths this deployment will not let the Effects plane read: the workspace holding
        # the evidence vault and the audit trail, and any directory holding key material.
        # `(allow default)` permits reading anything, and reading the vault off disk needs
        # no import — which is how a review turned a confined worker into a way to read the
        # investigation it must not reach.
        self._read_denied = tuple(read_denied)

    async def perform(
        self,
        request: EffectRequest,
        capability: AuthorizationCapability,
        *,
        operation: OperationClass,
    ) -> tuple[EffectResult, IsolationReport]:
        """Decide here, act there, and believe only what can be re-derived."""
        sandboxed = sandbox_available()
        if not sandboxed and not self._allow_unsandboxed:
            report = self._report(sandboxed=False, workdir=None, started=False)
            return (
                self._refuse(
                    request,
                    operation,
                    "refused: this deployment requires kernel-enforced confinement for the "
                    f"Effects plane and {sys.platform!r} cannot provide it. Nothing ran.",
                ),
                report,
            )

        # The authorization decision is made in this process, on the signed bytes, before
        # anything is dispatched. A worker that ignored its own copy of this check could
        # still only perform what was already allowed here.
        check = preflight(request, capability, operation=operation, anchor=self._anchor)
        if not check.may_act:
            return (
                self._refuse(request, operation, check.detail, refusal=check.refusal),
                self._report(sandboxed=sandboxed, workdir=None, started=False),
            )

        workdir = Path(tempfile.mkdtemp(prefix="nemesis-effect-"))
        try:
            return await self._dispatch(
                request,
                capability,
                operation,
                workdir=workdir,
                sandboxed=sandboxed,
                check=check,
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    # -- the child -------------------------------------------------------------

    async def _dispatch(
        self,
        request: EffectRequest,
        capability: AuthorizationCapability,
        operation: OperationClass,
        *,
        workdir: Path,
        sandboxed: bool,
        check: Preflight,
    ) -> tuple[EffectResult, IsolationReport]:
        envelope = json.dumps(
            {
                "request": request.model_dump(mode="json"),
                "capability": capability.model_dump(mode="json"),
                "operation": operation.value,
                "verifying_key_pem": self._anchor.verifying_key.public_pem().decode(),
                "revoked": self._revoked(capability),
            }
        ).encode()

        # `-s` drops the user site directory; `-I` is deliberately NOT used because it also
        # discards PYTHONPATH, and the path to this package is the one environment variable
        # the child genuinely needs. The environment it gets is built from nothing anyway,
        # so there is nothing else in it for `-I` to protect against.
        command = [sys.executable, "-s", "-m", WORKER_MODULE]
        if sandboxed:
            command = [
                "/usr/bin/sandbox-exec",
                "-p",
                self._profile(workdir),
                *command,
            ]

        # Nothing is claimed before the process exists. A review reached this line with
        # `create_subprocess_exec` raising, and the report still asserted a separate
        # process, a denied network, a confined filesystem and a sealed interpreter — four
        # controls, for a run in which nothing was ever created.
        unstarted = self._report(sandboxed=False, workdir=None, started=False)
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=workdir,
                env=self._environment(),
                # Its own process group, so the deadline can kill descendants too. Without
                # this, `kill()` reached the direct child and `wait()` then blocked until the
                # inherited pipes closed — a grandchild holding them made a 2s deadline take
                # 90s, and a grandchild that never exits made it never return at all.
                start_new_session=True,
            )
        except OSError as exc:
            return (
                self._refuse(
                    request,
                    operation,
                    f"the effects worker could not be started ({type(exc).__name__}); nothing ran",
                    outcome=EffectOutcome.FAILED,
                ),
                unstarted,
            )

        report = self._report(sandboxed=sandboxed, workdir=workdir, started=True)

        try:
            stdout, stderr = await asyncio.wait_for(
                self._collect(process, envelope), timeout=self._deadline
            )
        except (TimeoutError, _OutputCeilingError) as exc:
            await self._terminate(process)
            reason = (
                f"exceeded its {self._deadline:g}s deadline"
                if isinstance(exc, TimeoutError)
                else f"tried to return more than {MAX_WORKER_OUTPUT_BYTES} bytes"
            )
            return (
                self._refuse(
                    request,
                    operation,
                    f"the effects worker {reason} and its process group was killed; the "
                    "operation is recorded as failed because nothing can say how far it got",
                    outcome=EffectOutcome.FAILED,
                ),
                report,
            )

        return self._interpret(request, operation, stdout, stderr, report, check=check)

    async def _collect(
        self, process: asyncio.subprocess.Process, envelope: bytes
    ) -> tuple[bytes, bytes]:
        """Read the child's output incrementally, refusing to buffer more than the ceiling.

        ``communicate()`` reads to EOF and only then can anything measure the result, which
        made the ceiling a post-mortem: a review put 600 MiB into the parent in 0.3 seconds
        and read the refusal "the output was discarded unread" — written after reading it.
        """
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None

        async def drain(stream: asyncio.StreamReader, ceiling: int) -> bytes:
            chunks: list[bytes] = []
            total = 0
            while chunk := await stream.read(64 * 1024):
                total += len(chunk)
                if total > ceiling:
                    raise _OutputCeilingError
                chunks.append(chunk)
            return b"".join(chunks)

        writer = process.stdin

        async def feed() -> None:
            try:
                writer.write(envelope)
                await writer.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass  # a worker that closed stdin is a worker that returns nothing usable
            finally:
                writer.close()

        # Tasks rather than a bare `gather`, so that when one raises — the output ceiling —
        # the siblings are cancelled instead of left reading a pipe nobody will close. The
        # first version leaked an open read transport on every deadline and every ceiling
        # breach, which a test in this repository caught before a review did.
        out_task = asyncio.create_task(drain(process.stdout, MAX_WORKER_OUTPUT_BYTES))
        err_task = asyncio.create_task(drain(process.stderr, MAX_STDERR_BYTES))
        feed_task = asyncio.create_task(feed())
        tasks: list[asyncio.Task[Any]] = [out_task, err_task, feed_task]
        try:
            await asyncio.gather(*tasks)
        except BaseException:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        return out_task.result(), err_task.result()

    async def _terminate(self, process: asyncio.subprocess.Process) -> None:
        """Kill the whole process group, and never our own.

        ``process.wait()`` alone returns when the pipes close, not when the child dies, so a
        descendant holding stdout kept a killed worker's ``perform()`` blocked for as long as
        the descendant lived — 90 seconds for a 2-second deadline, and forever for a
        descendant that never exits.

        The group is read once and compared against this process's own before anything is
        signalled. Writing this without that check killed the test suite that was exercising
        it: if ``start_new_session`` has not taken effect, or the child has been reaped and
        its pid reused, ``getpgid`` answers with *our* group, and ``SIGKILL`` to our own
        group takes down the platform. A kill switch that can fire at its owner is worse than
        no kill switch.
        """
        group: int | None = None
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            group = os.getpgid(process.pid)
        if group is not None and group != os.getpgrp():
            with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                os.killpg(group, signal.SIGKILL)
        with contextlib.suppress(ProcessLookupError, OSError):
            process.kill()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(process.wait(), timeout=_REAP_SECONDS)
        # Closing the transport is what releases the pipes. `wait()` returns on process exit
        # but leaves a read transport open when nothing ever reached EOF on it, and an
        # executor that leaks a file descriptor per killed worker is an executor that runs
        # out of them.
        transport = getattr(process, "_transport", None)
        if transport is not None:
            with contextlib.suppress(Exception):
                transport.close()

    def _interpret(
        self,
        request: EffectRequest,
        operation: OperationClass,
        stdout: bytes,
        stderr: bytes,
        report: IsolationReport,
        *,
        check: Preflight | None = None,
    ) -> tuple[EffectResult, IsolationReport]:
        """Parse what came back, and author the record here rather than accepting theirs.

        The first version of this method updated exactly one field and passed the rest of
        the worker's result through — including ``authorization``, which then went into the
        hash-chained audit trail. A review had a confined child return
        ``operation=registrar_suspension, permitted=true, denial_reasons=[]`` for a request
        that asked for a simulation, and the chain verified over it. That is the same
        "tamper-evident record of the wrong thing" two earlier reviews found in
        :mod:`nemesis.effects.registry`, reintroduced through the new process boundary — the
        one place the earlier fix could not reach.

        A worker is entitled to author exactly three things: whether it acted, what it did,
        and whether it believes it made contact. Everything identifying *what was
        authorized* comes from this process.
        """
        try:
            payload = json.loads(stdout or b"{}")
            if "error" in payload:
                raise ValueError(str(payload["error"]))
            result = EffectResult.model_validate(payload["result"])
            claimed = {str(k): int(v) for k, v in dict(payload.get("limits", {})).items()}
            sealed = bool(payload.get("sealed", False))
        except (ValidationError, ValueError, KeyError, TypeError) as exc:
            tail = stderr.decode(errors="replace").strip().splitlines()[-1:] or ["no stderr"]
            return (
                self._refuse(
                    request,
                    operation,
                    f"the effects worker returned nothing usable ({type(exc).__name__}: "
                    f"{exc}); last stderr line: {sanitize(tail[0], limit=200)}",
                    outcome=EffectOutcome.FAILED,
                ),
                report,
            )

        contact_claimed = bool(result.external_contact_made)
        authored = result.model_copy(
            update={
                # Identity of the operation: this process's, always. A worker that renamed
                # the class it performed would otherwise file its record under another one.
                "operation_id": request.operation_id,
                "operation": request.operation,
                # The verdict: this process reached it before dispatching, on the signed
                # bytes. A worker's account of its own authority is worth nothing.
                "authorization": check.decision
                if check is not None
                else refusal_record(
                    request,
                    operation=operation,
                    capability_id=NO_CAPABILITY,
                    now=utcnow(),
                    reasons=("no parent verdict was available for this run",),
                ),
                # Free text crossing a boundary that otherwise has no egress. A review used
                # `detail` to carry a listing of the operator's ~/.ssh out of an airtight
                # sandbox: stdout is the one channel left, so it is flattened and capped.
                "detail": sanitize(result.detail, limit=MAX_DETAIL_CHARACTERS),
                "produced_artifacts": tuple(
                    sanitize(artifact, limit=400) for artifact in result.produced_artifacts
                )[:MAX_ARTIFACTS],
                # Never rewritten to False. The worker's confession is the one thing it says
                # that is worth keeping, and the kernel's denial is recorded separately.
                "external_contact_made": contact_claimed,
            }
        )

        # Validated, not `model_copy`d: `model_copy` skips validation, so a worker could
        # report a CPU ceiling of 999999 or an address space of 1 and have it recorded.
        # Anything above what was requested is a claim this process will not repeat.
        return authored, IsolationReport.model_validate(
            report.model_dump()
            | {
                "address_space_bytes": self._within(
                    claimed, ENV_ADDRESS_SPACE, self._address_space
                ),
                "cpu_seconds": self._within(claimed, ENV_CPU_SECONDS, self._cpu_seconds),
                "file_size_bytes": self._within(claimed, ENV_OUTPUT_BYTES, self._output_bytes),
                "imports_sealed_by_worker": sealed,
                "contact_claimed_by_worker": contact_claimed,
            }
        )

    @staticmethod
    def _within(claimed: dict[str, int], name: str, requested: int) -> int | None:
        """A reported ceiling, accepted only if it is no weaker than the one asked for."""
        value = claimed.get(name)
        if value is None or value > requested:
            return None
        return value

    # -- helpers ---------------------------------------------------------------

    def _revoked(self, capability: AuthorizationCapability) -> bool:
        try:
            return bool(self._anchor.revocations.is_revoked(capability.capability_id))
        except Exception:
            # Fails closed, exactly as `preflight` does: an oracle that cannot answer is not
            # an oracle reporting no revocation. `preflight` has already refused by the time
            # this is reached, so this is the second lock on the same door.
            return True

    def _profile(self, workdir: Path) -> str:
        """The profile, with every path resolved.

        ``mkdtemp`` returns ``/var/folders/...`` and the kernel resolves it to
        ``/private/var/folders/...``, so the workdir allow rule never matched a single
        write. It failed closed, so nothing was exposed — but the child could write nowhere,
        the demonstration printed a directory it could not use, and the *positive* half of
        the profile had never once been exercised. The suite missed it because the test only
        asserted the negative.

        Built by :class:`~nemesis.sandbox.process.SandboxPolicy` rather than from this
        module's own template. The two had already drifted — the local copy denied
        ``mDNSResponder.dnsproxy`` and the shared one did not — which is precisely what the
        shared module's docstring says a duplicate does, one commit at a time. Keeping the
        template below as documentation of what this plane requires, and generating the actual
        profile from the one implementation, is the only arrangement where a correction lands
        in both places.

        ``confine_reads=True`` is the substantive change: reads are now denied by default and
        allowed only for the interpreter and this job. The blocklist below stays as a second
        lock — it names the workspace and the usual credential directories — but it is no
        longer the only thing standing between a compromised effect and the vault, the audit
        trail, or this platform's own source.
        """
        denied = tuple(
            Path(path).resolve()
            for path in (*self._read_denied, *(Path.home() / name for name in CREDENTIAL_PATHS))
            if Path(path).exists()
        )
        profile: str = SandboxPolicy(
            workdir=workdir,
            allow_network=False,
            read_denied=denied,
            confine_reads=True,
            # The worker is this package and must import it. Everything else is denied.
            read_allowed=(Path(nemesis.__file__).resolve().parent.parent,),
        ).profile()
        return profile

    def _environment(self) -> dict[str, str]:
        """Built from nothing, so nothing this process holds travels to the child.

        ``PATH`` is present because the interpreter needs one; ``PYTHONPATH`` because the
        package may be running from a source checkout. No token, no key path, no cloud
        configuration, no ``HOME``.
        """
        environment = {
            "PATH": "/usr/bin:/bin",
            ENV_ADDRESS_SPACE: str(self._address_space),
            ENV_CPU_SECONDS: str(self._cpu_seconds),
            ENV_OUTPUT_BYTES: str(self._output_bytes),
        }
        # Derived from where this package actually is, rather than inherited: a child that
        # resolved `nemesis` through the parent's PYTHONPATH would import whatever that
        # happened to point at, and this is the one import path that must not be ambient.
        roots = [str(Path(nemesis.__file__).resolve().parent.parent)]
        if site := os.environ.get("VIRTUAL_ENV"):
            roots.append(str(Path(site) / "lib"))
        environment["PYTHONPATH"] = os.pathsep.join(roots)
        return environment

    def _report(self, *, sandboxed: bool, workdir: Path | None, started: bool) -> IsolationReport:
        """Only what this process established. ``started`` gates every process-level claim."""
        confined = sandboxed and started and workdir is not None
        return IsolationReport(
            mechanism=("sandbox-exec" if sandboxed else "subprocess") if started else "none",
            separate_process=started,
            network_denied=confined,
            filesystem_confined_to=str(workdir.resolve()) if confined and workdir else None,
            private_key_withheld=True,
            # Left unset until the child says what it applied and what it sealed. A report
            # that named a ceiling before anything enforced it would be a wish.
            imports_sealed_by_worker=False,
            address_space_bytes=None,
            cpu_seconds=None,
            file_size_bytes=None,
            deadline_seconds=self._deadline if started else None,
        )

    def _refuse(
        self,
        request: EffectRequest,
        operation: OperationClass,
        detail: str,
        *,
        outcome: EffectOutcome = EffectOutcome.REFUSED_UNAUTHORIZED,
        refusal: EffectOutcome | None = None,
    ) -> EffectResult:
        return EffectResult(
            operation_id=request.operation_id,
            operation=request.operation,
            outcome=refusal or outcome,
            executed_at=utcnow(),
            adapter_name=REGISTRY_NAME,
            authorization=refusal_record(
                request,
                operation=operation,
                capability_id=NO_CAPABILITY,
                now=utcnow(),
                reasons=(detail,),
            ),
            detail=detail,
            external_contact_made=False,
        )
