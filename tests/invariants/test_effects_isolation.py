"""Invariant 8, enforced by the kernel rather than by the import graph.

`import-linter` has bound the Effects plane since ADR-0001, and it binds *this repository at
build time*. Every adversarial review so far closed with the same residual risk: an attacker
with code execution inside the process defeats every control here, and process isolation is
`PROPOSED`. These tests are what moves it.

They are deliberately mechanism tests. Each one runs a probe in the same confinement a real
effect gets and asserts what the kernel did, because the alternative — asserting that the
code *intends* to confine — is the kind of test that passed while four reviews found four
breaks. Where a control cannot be enforced on this platform, the test asserts that the
:class:`~nemesis.ports.isolation.IsolationReport` says so rather than that the control works.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from nemesis.authz.attestation import PrincipalVerifier
from nemesis.authz.gateway import AuthorizationGateway
from nemesis.authz.keys import CapabilitySigningKey
from nemesis.authz.providers import LocalDevelopmentIdentityProvider
from nemesis.core.authorization import (
    AuthorizationCapability,
    LegalBasis,
    OperationClass,
    TargetFingerprint,
)
from nemesis.core.identity import Role
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.temporal import utcnow
from nemesis.effects.isolation import (
    IsolatedEffectsExecutor,
    sandbox_available,
)
from nemesis.effects.registry import preflight
from nemesis.effects.worker import FORBIDDEN_PREFIXES
from nemesis.ports.authorization import TrustAnchor
from nemesis.ports.effects import EffectOutcome, EffectRequest

pytestmark = pytest.mark.invariant

DEV = LocalDevelopmentIdentityProvider()
ACTORS = PrincipalVerifier(DEV.registered_issuer())


def _executor(anchor: TrustAnchor, **kwargs: Any) -> IsolatedEffectsExecutor:
    """An executor for this suite, which has to run on Linux too.

    ``allow_unsandboxed=True`` **by name**, because the default is now the deployment-safe
    refusal — and that is the whole point of the default: a test default and a deployment
    default must not be the same value, and this suite is the test default. Eight tests here
    were silently relying on the old permissive one, which CI on Ubuntu found and a macOS run
    could not.

    The two tests about the refusal itself construct the executor directly, since the argument
    is what they are about.
    """
    kwargs.setdefault("allow_unsandboxed", True)
    return IsolatedEffectsExecutor(anchor, **kwargs)


needs_sandbox = pytest.mark.skipif(
    not sandbox_available(),
    reason="kernel-enforced confinement needs macOS sandbox-exec; the executor reports its "
    "absence rather than pretending, which test_the_report_never_claims_more is what covers",
)


# --- fixtures -----------------------------------------------------------------


def _target() -> TargetFingerprint:
    return TargetFingerprint.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type="domain",
        natural_key="glass-anvil.example",
        bound_attributes={"resolves_to": "198.51.100.23"},
    )


def _grant(
    operation: OperationClass = OperationClass.SIMULATION,
) -> tuple[AuthorizationGateway, AuthorizationCapability, TargetFingerprint]:
    gateway = AuthorizationGateway(CapabilitySigningKey.generate(), identity=ACTORS)
    target = _target()
    request = gateway.request(
        case_id=new_id(IdPrefix.CASE),
        audit_id=new_id(IdPrefix.AUDIT),
        requested_by=DEV.enrol("Grace", Role.ANALYST),
        justification="Rehearse the takedown.",
        targets=(target,),
        operations=frozenset({operation}),
        jurisdictions=("FR",),
        legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
        max_effect_description="A rehearsal that performs nothing.",
        lifetime=timedelta(hours=1),
    )
    gateway.approve(
        request.capability_id,
        approver=DEV.enrol("Ada", Role.INVESTIGATION_LEAD),
        rationale="Performs nothing.",
    )
    return gateway, gateway.issue(request.capability_id), target


def _request(target: TargetFingerprint, operation: OperationClass) -> EffectRequest:
    return EffectRequest(
        operation_id=new_id(IdPrefix.OPERATION),
        operation=operation,
        target_fingerprint=target.fingerprint,
        target_natural_key=target.natural_key,
        current_target_attributes=dict(target.bound_attributes),
        parameters={"rehearsed_operation": "registrar_suspension"},
        requested_by=new_id(IdPrefix.ACTOR),
        requested_at=utcnow(),
    )


def _anchor(gateway: AuthorizationGateway) -> TrustAnchor:
    return TrustAnchor(verifying_key=gateway.verifying_key, revocations=gateway.revocations)


class _NoRevocations:
    """A revocation oracle for probe profiles, which never reach a capability."""

    def is_revoked(self, capability_id: str) -> bool:
        return False


def _probe(script: str, *, sandboxed: bool) -> subprocess.CompletedProcess[str]:
    """Run a probe under exactly the confinement a real effect gets."""
    import tempfile
    from pathlib import Path

    import nemesis

    workdir = Path(tempfile.mkdtemp(prefix="nemesis-probe-"))
    command = [sys.executable, "-s", "-c", script]
    if sandboxed:
        # Built by the executor itself, so a probe cannot pass under a profile the real
        # thing does not use. Hand-rolling the profile here is how the `/var` vs
        # `/private/var` bug survived: the test and the product disagreed about the rules.
        profile = _executor(
            TrustAnchor(
                verifying_key=CapabilitySigningKey.generate().verifying_key,
                revocations=_NoRevocations(),
            )
        )._profile(workdir)
        command = ["/usr/bin/sandbox-exec", "-p", profile, *command]
    return subprocess.run(  # noqa: S603 - fixed command, no shell, test-only probe
        command,
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workdir,
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": str(Path(nemesis.__file__).resolve().parent.parent),
        },
    )


# --- The effect still works ---------------------------------------------------


def test_an_authorized_effect_runs_in_the_child_and_comes_back() -> None:
    """A boundary that refuses everything is not a boundary, it is an outage."""
    gateway, capability, target = _grant()
    executor = _executor(_anchor(gateway))

    result, report = asyncio.run(
        executor.perform(
            _request(target, OperationClass.SIMULATION),
            capability,
            operation=OperationClass.SIMULATION,
        )
    )

    assert result.outcome is EffectOutcome.SIMULATED
    assert result.adapter_name == "simulation-effects-adapter"
    assert not result.external_contact_made
    assert report.separate_process
    assert report.private_key_withheld
    assert report.imports_sealed_by_worker


def test_an_unauthorized_operation_never_reaches_a_child() -> None:
    """The decision is made in the trusted process, before anything is spawned.

    A worker that ignored its own copy of the check could still only perform what this
    process had already decided to allow — but the cheaper property is that a refused
    operation costs no process at all.
    """
    gateway, capability, target = _grant()
    forged = capability.model_copy(update={"signature": None})
    executor = _executor(_anchor(gateway))

    result, report = asyncio.run(
        executor.perform(
            _request(target, OperationClass.SIMULATION),
            forged,
            operation=OperationClass.SIMULATION,
        )
    )

    assert result.outcome is EffectOutcome.REFUSED_UNVERIFIED_CAPABILITY
    assert not report.separate_process, "nothing should have been spawned"


# --- What the kernel enforces -------------------------------------------------


@needs_sandbox
def test_the_child_cannot_open_a_socket() -> None:
    """The control that turns "nothing left the system" into something we established.

    Everywhere else, the absence of external contact rests on the declaration of the
    component that would have made it — which is the component under suspicion.
    """
    # TEST-NET-1 (RFC 5737), reserved for documentation and guaranteed not to route. The
    # earlier version dialled a public DNS resolver, so a sandbox that failed to engage
    # would have made genuine outbound contact with infrastructure this project does not own,
    # which invariant 15 forbids and which reads badly in a public repository whatever the
    # intent. A negative test must not depend on a third party to be negative.
    probe = _probe(
        "import errno, socket\n"
        "s = socket.socket(); s.settimeout(3)\n"
        "try:\n"
        "    s.connect(('192.0.2.1', 80)); print('CONNECTED')\n"
        "except OSError as exc:\n"
        "    print('DENIED', type(exc).__name__, exc.errno)\n",
        sandboxed=True,
    )
    assert "CONNECTED" not in probe.stdout, probe.stdout + probe.stderr
    # And the denial must be the KERNEL's, not the network's. An unroutable address fails on
    # its own with TimeoutError, so asserting only "DENIED" would pass just as happily with
    # the sandbox switched off — the exact vacuous green this file exists to prevent.
    assert "PermissionError" in probe.stdout, (
        "the connection was refused, but not by the sandbox: " + probe.stdout + probe.stderr
    )


@needs_sandbox
def test_the_child_cannot_write_outside_its_job_directory() -> None:
    """A drafting adapter takes an output directory from the request parameters.

    Confining writes means a caller cannot turn one authorized draft into a write anywhere
    the platform's own user can write.
    """
    probe = _probe(
        "import pathlib\n"
        "try:\n"
        "    pathlib.Path.home().joinpath('nemesis-escape.txt').write_text('x')\n"
        "    print('WROTE')\n"
        "except OSError as exc:\n"
        "    print('DENIED', type(exc).__name__)\n",
        sandboxed=True,
    )
    assert "DENIED" in probe.stdout, probe.stdout + probe.stderr
    assert "WROTE" not in probe.stdout


@pytest.mark.parametrize("module", sorted(FORBIDDEN_PREFIXES))
def test_the_child_cannot_import_the_intelligence_platform(module: str) -> None:
    """The runtime half of the `import-linter` contracts.

    Static contracts bind the code in this repository. This binds whatever is running, which
    is the version that matters once the plane is processing something hostile. The seal is
    installed before a byte of input is read, and it raises rather than warning.
    """
    probe = _probe(
        "from nemesis.effects.worker import _seal_imports\n"
        "_seal_imports()\n"
        "try:\n"
        f"    import {module}\n"
        "    print('IMPORTED')\n"
        "except ImportError as exc:\n"
        "    print('SEALED', 'invariant 8' in str(exc))\n",
        sandboxed=False,
    )
    assert "SEALED True" in probe.stdout, probe.stdout + probe.stderr


def test_the_seal_does_not_block_what_the_plane_legitimately_needs() -> None:
    """A seal that broke the worker would be discovered as an outage, not as a control."""
    probe = _probe(
        "from nemesis.effects.worker import _seal_imports\n"
        "_seal_imports()\n"
        "import nemesis.effects.registry, nemesis.effects.drafting, nemesis.effects.simulation\n"
        "import nemesis.authz.verification, nemesis.core.authorization, nemesis.ports.effects\n"
        "print('OK')\n",
        sandboxed=False,
    )
    assert probe.stdout.strip() == "OK", probe.stdout + probe.stderr


def test_verification_is_reachable_without_the_module_that_makes_keys() -> None:
    """Why `nemesis.authz.verification` exists at all.

    The worker must be able to check a signature. If checking required importing the module
    where a signing key is constructed, the seal would have to let that module through, and
    a compromised worker would have had the means to mint a capability.
    """
    probe = _probe(
        "from nemesis.effects.worker import _seal_imports\n"
        "_seal_imports()\n"
        "from nemesis.authz.verification import verify_capability, CapabilityVerifyingKey\n"
        "try:\n"
        "    import nemesis.authz.keys\n"
        "    print('KEYS REACHABLE')\n"
        "except ImportError:\n"
        "    print('VERIFY YES, KEYS NO')\n",
        sandboxed=False,
    )
    assert "VERIFY YES, KEYS NO" in probe.stdout, probe.stdout + probe.stderr


# --- What crosses the pipe ----------------------------------------------------


def test_no_private_key_crosses_the_boundary() -> None:
    """A fully owned worker still cannot mint a capability, because minting needs a key.

    Asserted against the bytes actually sent, not against the intent of the code that
    builds them.
    """
    gateway, capability, target = _grant()
    signer = CapabilitySigningKey.generate()
    sent: list[bytes] = []

    executor = _executor(
        TrustAnchor(verifying_key=gateway.verifying_key, revocations=gateway.revocations)
    )

    async def capture() -> None:
        original = asyncio.create_subprocess_exec

        # `Any` here is the stdlib's own signature, not laziness: these stand in for
        # `asyncio.create_subprocess_exec`, whose keyword arguments are heterogeneous by
        # design. Narrowing them would mean re-declaring a signature we do not own, and a
        # spy that took a *different* signature from the function it replaces would pass
        # the type checker while failing to be a substitute.
        async def spy(*args: Any, **kwargs: Any) -> Any:
            process = await original(*args, **kwargs)
            writer = process.stdin
            assert writer is not None
            write = writer.write

            def record(payload: bytes | bytearray | memoryview[int]) -> None:
                # The signature is the real writer's, not the narrower one this test needs:
                # a spy that accepted less than what it replaces is not a substitute.
                sent.append(bytes(payload))
                write(payload)

            writer.write = record  # type: ignore[assignment]
            return process

        asyncio.create_subprocess_exec = spy
        try:
            await executor.perform(
                _request(target, OperationClass.SIMULATION),
                capability,
                operation=OperationClass.SIMULATION,
            )
        finally:
            asyncio.create_subprocess_exec = original

    asyncio.run(capture())

    assert sent, "the executor never dispatched"
    envelope = json.loads(sent[0])
    payload = sent[0].decode()

    assert "PRIVATE KEY" not in payload
    assert signer.sign(b"probe").split(":")[1] not in payload
    assert envelope["verifying_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")
    assert set(envelope) == {
        "request",
        "capability",
        "operation",
        "verifying_key_pem",
        "revoked",
    }


# --- Failure is recorded, never raised ----------------------------------------


def test_a_worker_that_hangs_is_killed_and_recorded() -> None:
    """An operation whose outcome nobody recorded is the failure the trail exists to stop."""
    gateway, capability, target = _grant()
    executor = _executor(_anchor(gateway), deadline_seconds=0.25)

    async def stall() -> None:
        """Substitute a child that never finishes, so the deadline is what is under test."""
        original = asyncio.create_subprocess_exec

        async def sleeper(*_args: Any, **kwargs: Any) -> Any:
            return await original(
                "/bin/sleep",
                "30",
                stdin=kwargs["stdin"],
                stdout=kwargs["stdout"],
                stderr=kwargs["stderr"],
            )

        asyncio.create_subprocess_exec = sleeper
        try:
            result, _ = await executor.perform(
                _request(target, OperationClass.SIMULATION),
                capability,
                operation=OperationClass.SIMULATION,
            )
        finally:
            asyncio.create_subprocess_exec = original

        assert result.outcome is EffectOutcome.FAILED
        assert "deadline" in result.detail
        assert not result.authorization.permitted
        # `is None`, not falsy. This assertion used to read `not result.external_contact_made`,
        # which accepts the lie: the record said `False` — *nothing left the system* — in the
        # same breath as a detail saying nothing can say how far the worker got. A field that
        # cannot express "unknown" reads as a positive finding, and a test that accepts either
        # value cannot tell the two apart.
        assert result.external_contact_made is None, (
            "a killed worker cannot report that nothing left the system; nobody knows"
        )
        assert "nothing can say how far it got" in result.detail

    asyncio.run(stall())


def test_a_worker_that_returns_nonsense_is_recorded_as_failed() -> None:
    """The parent re-validates. A worker is untrusted in both directions."""
    gateway, _, target = _grant()
    executor = _executor(_anchor(gateway))

    report = executor._report(sandboxed=False, workdir=None, started=False)
    result, _ = executor._interpret(
        _request(target, OperationClass.SIMULATION),
        OperationClass.SIMULATION,
        b'{"result": {"operation_id": "not-an-id"}}',
        b"",
        report,
    )
    assert result.outcome is EffectOutcome.FAILED
    assert "nothing usable" in result.detail


# --- The report is the honest part --------------------------------------------


def test_the_report_never_claims_more_than_the_platform_gave() -> None:
    """The whole point of the report.

    ``external_contact_is_established`` is true only where the kernel denied the child a
    socket. On a platform that cannot, the same run still happens — in a child, with no key
    and no imports — and the report says the network was not denied, so a reader is not
    invited to treat the adapter's own declaration as proof.
    """
    gateway, capability, target = _grant()
    executor = _executor(_anchor(gateway))
    _, report = asyncio.run(
        executor.perform(
            _request(target, OperationClass.SIMULATION),
            capability,
            operation=OperationClass.SIMULATION,
        )
    )

    assert report.egress_denied_from_this_process == sandbox_available()
    assert (report.mechanism == "sandbox-exec") == sandbox_available()
    assert (report.filesystem_confined_to is not None) == sandbox_available()

    # macOS refuses RLIMIT_AS outright. Whatever the platform did, the report carries what
    # the child confirmed it applied — never what this process asked for.
    if sys.platform == "darwin":
        assert report.address_space_bytes is None, "macOS cannot set RLIMIT_AS"
    assert report.cpu_seconds is not None
    assert report.file_size_bytes is not None


def test_an_executor_built_with_no_argument_refuses_to_run_unconfined(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default is the deployment-safe value, and it was the other one.

    `allow_unsandboxed` defaulted to `True`, so on Linux an `IsolatedEffectsExecutor()` built
    with no argument ran the operation in a plain subprocess with full network and filesystem
    reach — recorded honestly as `network=NOT DENIED`, and overlookably. A deployment default
    and a test default must not be the same value: the caller who most needs the refusal is the
    one who never heard of the flag.

    This mattered more from the moment the pilot was routed through the executor, because until
    then the only caller was a demonstration that knew what it was doing.

    The demonstrations and benchmarks now pass `allow_unsandboxed=True` by name, which is what
    keeps this suite and CI running on Linux — and what makes the choice visible at the four
    places that make it.
    """
    gateway, capability, target = _grant()
    monkeypatch.setattr("nemesis.effects.isolation.sandbox_available", lambda: False)

    result, report = asyncio.run(
        IsolatedEffectsExecutor(_anchor(gateway)).perform(
            _request(target, OperationClass.SIMULATION),
            capability,
            operation=OperationClass.SIMULATION,
        )
    )

    assert result.outcome is EffectOutcome.REFUSED_UNAUTHORIZED
    assert "kernel-enforced confinement" in result.detail
    assert not report.separate_process, "nothing may have run"


def test_a_deployment_can_choose_to_run_unconfined_by_saying_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other half: the flag still exists, and naming it still works.

    A default that could not be overridden would be a default nobody could run the suite
    under, and this repository's own history says what happens to a control that stops the
    work — it gets removed rather than argued with.
    """
    gateway, capability, target = _grant()
    monkeypatch.setattr("nemesis.effects.isolation.sandbox_available", lambda: False)

    result, report = asyncio.run(
        IsolatedEffectsExecutor(_anchor(gateway), allow_unsandboxed=True).perform(
            _request(target, OperationClass.SIMULATION),
            capability,
            operation=OperationClass.SIMULATION,
        )
    )

    assert result.outcome is not EffectOutcome.REFUSED_UNAUTHORIZED, result.detail
    assert report.separate_process
    assert not report.egress_denied_from_this_process, (
        "a plain subprocess is not kernel confinement and the report must not say it is"
    )


def test_a_deployment_can_refuse_to_run_unconfined() -> None:
    """The honest behaviour for a plane whose whole claim is that nothing leaves."""
    gateway, capability, target = _grant()
    executor = IsolatedEffectsExecutor(_anchor(gateway), allow_unsandboxed=False)
    executor._allow_unsandboxed = False

    import nemesis.effects.isolation as isolation

    original = isolation.sandbox_available
    isolation.sandbox_available = lambda: False
    try:
        result, report = asyncio.run(
            executor.perform(
                _request(target, OperationClass.SIMULATION),
                capability,
                operation=OperationClass.SIMULATION,
            )
        )
    finally:
        isolation.sandbox_available = original

    assert result.outcome is EffectOutcome.REFUSED_UNAUTHORIZED
    assert "kernel-enforced confinement" in result.detail
    assert not report.separate_process
    assert not report.egress_denied_from_this_process


# ======================================================================================
# Round three. Every one of these reproduces something a review broke on a green tree.
# ======================================================================================


def test_the_parent_authors_the_audit_record_not_the_child() -> None:
    """The worst of the round, because the ADR claimed this already worked.

    A confined child returned ``operation=registrar_suspension, permitted=true,
    denial_reasons=[]`` for a request that asked for a simulation, and it went into the
    hash-chained trail, and the chain verified over it. ``_interpret`` was updating exactly
    one field and passing the rest of the worker's result through — including the
    authorization verdict, which is the field the whole boundary exists to protect.
    """
    gateway, capability, target = _grant()
    executor = _executor(_anchor(gateway))
    request = _request(target, OperationClass.SIMULATION)
    check = preflight(
        request, capability, operation=OperationClass.SIMULATION, anchor=_anchor(gateway)
    )
    assert check.may_act

    lying = json.dumps(
        {
            "result": {
                "operation_id": new_id(IdPrefix.OPERATION),
                "operation": "registrar_suspension",
                "outcome": "simulated",
                "executed_at": utcnow().isoformat(),
                "adapter_name": "not-a-real-adapter",
                "authorization": {
                    "permitted": True,
                    "capability_id": "cap_" + "f" * 32,
                    "operation": "registrar_suspension",
                    "target_fingerprint": target.fingerprint,
                    "evaluated_at": utcnow().isoformat(),
                    "denial_reasons": [],
                },
                "detail": "EXFIL[id_ed25519, known_hosts]\nand a forged second line",
                "produced_artifacts": ["vault://forged-bundle"],
                "external_contact_made": True,
            },
            "limits": {"NEMESIS_WORKER_CPU_SECONDS": 999_999},
            "sealed": True,
        }
    ).encode()

    result, report = executor._interpret(
        request,
        OperationClass.SIMULATION,
        lying,
        b"",
        executor._report(sandboxed=True, workdir=Path(tempfile.mkdtemp()), started=True),
        check=check,
    )

    # Identity and verdict: the parent's, always.
    assert result.operation is OperationClass.SIMULATION
    assert result.operation_id == request.operation_id
    assert result.authorization == check.decision
    assert result.authorization.capability_id == capability.capability_id
    assert "f" * 32 not in result.authorization.capability_id

    # Free text is the one channel out of an otherwise airtight sandbox, so it is flattened
    # and capped rather than copied into the trail verbatim.
    assert "\n" not in result.detail

    # And the child's confession is kept, not overwritten.
    assert result.external_contact_made
    assert report.contact_claimed_by_worker
    assert "WORKER CLAIMS IT MADE CONTACT" in report.render()

    # A ceiling weaker than the one requested is not repeated as though it were applied.
    assert report.cpu_seconds is None


def test_a_report_claims_nothing_when_no_child_was_started() -> None:
    """Four asserted controls for a run in which nothing was ever created."""
    gateway, capability, target = _grant()
    executor = _executor(_anchor(gateway))

    async def fail_to_spawn() -> None:
        original = asyncio.create_subprocess_exec

        async def refuse(*_args: Any, **_kwargs: Any) -> Any:
            raise OSError("no processes available")

        asyncio.create_subprocess_exec = refuse
        try:
            result, report = await executor.perform(
                _request(target, OperationClass.SIMULATION),
                capability,
                operation=OperationClass.SIMULATION,
            )
        finally:
            asyncio.create_subprocess_exec = original

        assert result.outcome is EffectOutcome.FAILED
        assert not report.separate_process
        assert not report.network_denied
        assert not report.egress_denied_from_this_process
        assert not report.imports_sealed_by_worker
        assert report.filesystem_confined_to is None
        assert report.mechanism == "none"

    asyncio.run(fail_to_spawn())


def test_the_deadline_kills_descendants_and_returns_promptly() -> None:
    """The deadline was not a kill switch.

    ``kill()`` reached the direct child and ``wait()`` then blocked until the inherited
    pipes closed, so a grandchild holding stdout kept a 2-second deadline running for 90
    seconds — and a grandchild that never exits kept it running forever. This is the
    platform's only kill switch for the Effects plane.
    """
    import time

    gateway, capability, target = _grant()
    executor = _executor(_anchor(gateway), deadline_seconds=0.5)

    async def spawn_a_survivor() -> None:
        original = asyncio.create_subprocess_exec

        async def with_grandchild(*_args: Any, **kwargs: Any) -> Any:
            return await original(
                "/bin/sh",
                "-c",
                "/bin/sleep 60 & exec /bin/sleep 60",
                stdin=kwargs["stdin"],
                stdout=kwargs["stdout"],
                stderr=kwargs["stderr"],
                start_new_session=True,
            )

        asyncio.create_subprocess_exec = with_grandchild
        started = time.monotonic()
        try:
            result, _ = await executor.perform(
                _request(target, OperationClass.SIMULATION),
                capability,
                operation=OperationClass.SIMULATION,
            )
        finally:
            asyncio.create_subprocess_exec = original
        elapsed = time.monotonic() - started

        assert result.outcome is EffectOutcome.FAILED
        assert "process group was killed" in result.detail
        assert elapsed < 20, f"the deadline did not bound the call: {elapsed:.1f}s"

    asyncio.run(spawn_a_survivor())


def test_the_kill_switch_never_fires_at_this_process() -> None:
    """Writing the process-group kill without this check killed the test suite running it.

    If ``start_new_session`` has not taken effect, or the pid has been reaped and reused,
    ``getpgid`` answers with *our* group. A kill switch that can fire at its owner is worse
    than no kill switch.
    """
    import inspect

    from nemesis.effects import isolation

    source = inspect.getsource(isolation.IsolatedEffectsExecutor._terminate)
    assert "os.getpgrp()" in source
    assert "group != os.getpgrp()" in source


def test_the_output_ceiling_is_enforced_while_reading_not_afterwards() -> None:
    """600 MiB reached the parent in 0.3s, and then it printed "discarded unread"."""
    gateway, capability, target = _grant()
    executor = _executor(_anchor(gateway), deadline_seconds=30)

    async def flood() -> None:
        original = asyncio.create_subprocess_exec

        async def firehose(*_args: Any, **kwargs: Any) -> Any:
            return await original(
                "/bin/sh",
                "-c",
                f"exec /usr/bin/yes {'x' * 4096}",
                stdin=kwargs["stdin"],
                stdout=kwargs["stdout"],
                stderr=kwargs["stderr"],
                start_new_session=True,
            )

        asyncio.create_subprocess_exec = firehose
        try:
            result, _ = await executor.perform(
                _request(target, OperationClass.SIMULATION),
                capability,
                operation=OperationClass.SIMULATION,
            )
        finally:
            asyncio.create_subprocess_exec = original

        assert result.outcome is EffectOutcome.FAILED
        assert "more than" in result.detail

    asyncio.run(flood())


@needs_sandbox
def test_the_child_can_write_inside_its_job_directory() -> None:
    """The positive half of the write rule, which had never once been exercised.

    ``mkdtemp`` returns ``/var/folders/...`` and the kernel resolves ``/private/var/...``,
    so the allow rule matched nothing at all. It failed closed, so nothing was exposed — the
    child could simply write nowhere, and the demonstration printed a directory it could not
    use. The suite missed it because only the negative was asserted.
    """
    probe = _probe(
        "import pathlib\n"
        "try:\n"
        "    pathlib.Path('inside.txt').write_text('x'); print('WROTE')\n"
        "except OSError as exc:\n"
        "    print('DENIED', type(exc).__name__)\n",
        sandboxed=True,
    )
    assert "WROTE" in probe.stdout, probe.stdout + probe.stderr


@needs_sandbox
def test_the_child_cannot_reach_launchservices_to_start_an_unconfined_process() -> None:
    """`(allow default)` permits mach-lookup, and a LaunchServices-started process is a
    child of launchd — inheriting neither the network denial nor the write denial.

    A review used ``/usr/bin/open`` to put an unconfined process on the machine from inside
    the sandbox. The kernel had denied *this* process a socket; it had not denied it the
    ability to have another process open one.
    """
    probe = _probe(
        "import subprocess\n"
        "done = subprocess.run(['/usr/bin/open', '-g', '-a', 'Calculator'],\n"
        "                      capture_output=True, timeout=20)\n"
        "print('RC', done.returncode)\n",
        sandboxed=True,
    )
    assert "RC 0" not in probe.stdout, (
        "LaunchServices started a process outside the sandbox: " + probe.stdout + probe.stderr
    )


@needs_sandbox
def test_the_child_cannot_read_the_evidence_vault_or_the_audit_trail() -> None:
    """`import-linter` blocks the import. Reading the vault off disk needs no import.

    The deployment names what the Effects plane may not read, and the scenario passes its
    workspace. This is an enumeration and it is incomplete by construction — see
    SANDBOX_PROFILE — but the workspace is the one that matters here.
    """
    import tempfile

    workspace = Path(tempfile.mkdtemp(prefix="nemesis-workspace-"))
    (workspace / "vault.jsonl").write_text("sealed evidence")

    gateway = AuthorizationGateway(CapabilitySigningKey.generate(), identity=ACTORS)
    executor = _executor(_anchor(gateway), read_denied=(workspace,))
    # The probe runs from the job directory, as `run_confined` runs the real worker. Under read
    # confinement the interpreter scans its cwd for imports, so a probe launched from the repo
    # root — which the allowlist does not include — dies before it can test anything.
    job = Path(tempfile.mkdtemp(prefix="nemesis-effect-"))
    profile = executor._profile(job)

    done = subprocess.run(  # noqa: S603 - fixed command, test-only probe
        [
            "/usr/bin/sandbox-exec",
            "-p",
            profile,
            sys.executable,
            "-s",
            "-c",
            f"import pathlib\n"
            f"try:\n"
            f"    print('READ', pathlib.Path({str(workspace / 'vault.jsonl')!r}).read_text())\n"
            f"except OSError as exc:\n"
            f"    print('DENIED', type(exc).__name__)\n",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=job,
        env={"PATH": "/usr/bin:/bin"},
    )
    assert "DENIED" in done.stdout, done.stdout + done.stderr
    assert "sealed evidence" not in done.stdout
