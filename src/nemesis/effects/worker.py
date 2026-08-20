"""The Effects plane, running as somebody else's process.

Launched as ``python -m nemesis.effects.worker``, reads one operation from stdin, writes one
result to stdout, exits. It is the whole of what a compromised Effects plane would have.

What it does **not** have, by construction rather than by policy:

- **No private key.** The parent hands it a public verifying key. A worker that is entirely
  owned still cannot mint a capability, because minting needs a key that never crossed the
  pipe.
- **No intelligence platform.** :func:`_seal_imports` installs an import hook that refuses
  the graph, the vault, the collection and pursuit planes, and the gateway's signing module.
  The refusal happens at bootstrap, before a single byte of input is read, and it aborts the
  worker rather than warning. `import-linter` already forbids these edges at build time;
  this is the same rule at runtime, where the attacker lives.
- **No socket, on a platform that can say so.** The parent runs this under a sandbox profile
  where it can. The worker does not attempt to verify that itself — a process asking whether
  it is confined can only ever report what its own libraries tell it.
- **No standing state.** One operation per process. The second call gets a new one, so it
  cannot ride on the first call's approval.

Everything crossing the pipe is JSON, parsed through the same models the parent uses, and
the parent re-validates what comes back. The worker is untrusted in both directions.
"""

from __future__ import annotations

import json
import os
import resource
import sys
from typing import Any, Final

from nemesis.sandbox.seal import seal_imports

FORBIDDEN_PREFIXES: Final = (
    "nemesis.graph",
    "nemesis.evidence",
    "nemesis.collect",
    "nemesis.pursuit",
    "nemesis.resolve",
    "nemesis.attribute",
    "nemesis.disrupt",
    "nemesis.authz.keys",
    "nemesis.authz.gateway",
    "nemesis.slice",
)
"""What the Effects plane must not be able to reach at runtime.

Mirrors the ``.importlinter`` contracts, which bind the code in this repository at build
time. This binds whatever is running, which is the version that matters once the plane is
processing something hostile. ``nemesis.authz.keys`` is on the list because it is where a
signing key would be constructed; the worker needs :mod:`nemesis.ports.authorization` to
*check* a signature, and that is a different module on purpose.
"""

ENV_ADDRESS_SPACE: Final = "NEMESIS_WORKER_ADDRESS_SPACE_BYTES"
ENV_CPU_SECONDS: Final = "NEMESIS_WORKER_CPU_SECONDS"
ENV_OUTPUT_BYTES: Final = "NEMESIS_WORKER_OUTPUT_BYTES"


def _seal_imports() -> bool:
    """Install the shared seal for this plane's forbidden list.

    The implementation lives in :mod:`nemesis.sandbox.seal` because the collection worker
    needs the same mechanism with a different list — and two copies of a security control
    drift apart one commit at a time.
    """
    return seal_imports(FORBIDDEN_PREFIXES, plane="effects")


def _apply_limits() -> dict[str, int]:
    """Self-imposed ceilings, set before any input is read. Returns what actually took.

    Applied here rather than through ``preexec_fn`` because ``preexec_fn`` is unsafe in a
    process with threads and the parent may well have them. The ordering is what makes this
    sound: the limits are in force before the worker looks at anything an attacker supplied,
    so hostile *content* meets them. They would not stop hostile *worker source*, which is a
    different threat and one the parent cannot solve by any means available to it either.

    A limit the platform refuses is skipped and left out of the return value rather than
    aborting the worker or being reported as applied. macOS rejects ``RLIMIT_AS`` outright,
    for instance — so on macOS the address-space ceiling does not exist, and the isolation
    report must say that instead of repeating what was requested. A control that quietly
    degrades into a number in a document is the failure this whole module exists to avoid.
    """
    applied: dict[str, int] = {}
    for name, limit in (
        (ENV_ADDRESS_SPACE, resource.RLIMIT_AS),
        (ENV_CPU_SECONDS, resource.RLIMIT_CPU),
        (ENV_OUTPUT_BYTES, resource.RLIMIT_FSIZE),
    ):
        raw = os.environ.get(name)
        if raw is None:
            continue
        value = int(raw)
        _, hard = resource.getrlimit(limit)
        ceiling = value if hard == resource.RLIM_INFINITY else min(value, hard)
        try:
            resource.setrlimit(limit, (ceiling, ceiling))
        except (OSError, ValueError):
            continue
        applied[name] = ceiling
    return applied


def main() -> int:
    sealed = _seal_imports()
    applied = _apply_limits()

    # Imported after the seal, so that a mistake in this module's own dependencies is
    # caught by the same rule rather than slipping in ahead of it.
    from nemesis.authz.verification import CapabilityVerifyingKey
    from nemesis.core.authorization import AuthorizationCapability, OperationClass
    from nemesis.effects.registry import EffectsRegistry, TrustAnchor
    from nemesis.ports.effects import EffectRequest

    try:
        envelope = json.loads(sys.stdin.read())
    except (ValueError, OSError) as exc:
        return _fail(f"the worker could not read its input: {type(exc).__name__}: {exc}")

    try:
        request = EffectRequest.model_validate(envelope["request"])
        capability = AuthorizationCapability.model_validate(envelope["capability"])
        operation = OperationClass(envelope["operation"])
        anchor = TrustAnchor(
            verifying_key=CapabilityVerifyingKey.from_pem(envelope["verifying_key_pem"].encode()),
            # The parent asked the issuing authority before dispatching. Its answer crosses
            # as a fact rather than as an endpoint, because a worker that could reach the
            # revocation store could reach the network, which is the thing being denied.
            revocations=_FixedAnswer(bool(envelope["revoked"])),
        )
    except (KeyError, ValueError, TypeError) as exc:
        return _fail(f"the worker was handed an unusable envelope: {type(exc).__name__}: {exc}")

    registry = EffectsRegistry(verifying_key=anchor.verifying_key, revocations=anchor.revocations)
    for adapter in _adapters(anchor, operation):
        registry.register(adapter)

    import asyncio

    result = asyncio.run(registry.execute(request, capability))
    sys.stdout.write(
        json.dumps(
            {
                "result": result.model_dump(mode="json"),
                "limits": applied,
                # Reported rather than assumed by the parent. The parent used to set this
                # before the process existed, and a run in which `create_subprocess_exec`
                # raised still reported a sealed interpreter.
                "sealed": sealed,
            }
        )
    )
    sys.stdout.flush()
    return 0


def _adapters(anchor: Any, operation: Any) -> list[Any]:
    """Only the adapter for the class being performed.

    A worker carrying every adapter would be a worker that could perform any implemented
    class if something rewrote the operation on its way in. One operation, one adapter.
    """
    from nemesis.core.authorization import OperationClass
    from nemesis.effects.drafting import (
        EvidenceExportAdapter,
        ProviderNotificationAdapter,
        TakedownRequestDraftAdapter,
    )
    from nemesis.effects.simulation import SimulationEffectsAdapter

    by_class = {
        OperationClass.SIMULATION: SimulationEffectsAdapter,
        OperationClass.PROVIDER_NOTIFICATION: ProviderNotificationAdapter,
        OperationClass.TAKEDOWN_REQUEST_DRAFT: TakedownRequestDraftAdapter,
        OperationClass.EVIDENCE_EXPORT: EvidenceExportAdapter,
    }
    adapter = by_class.get(operation)
    return [adapter(anchor)] if adapter is not None else []


class _FixedAnswer:
    """The parent's revocation answer, carried across as a value."""

    def __init__(self, revoked: bool) -> None:
        self._revoked = revoked

    def is_revoked(self, capability_id: str) -> bool:
        return self._revoked


def _fail(message: str) -> int:
    sys.stdout.write(json.dumps({"error": message}))
    sys.stdout.flush()
    return 1


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    raise SystemExit(main())
