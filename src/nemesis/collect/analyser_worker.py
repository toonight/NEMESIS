"""An artifact analyser, running as somebody else's process.

Launched as ``python -m nemesis.collect.analyser_worker``, reads one job from stdin, writes one
:class:`~nemesis.collect.quarantine.AnalysisReport` to stdout, exits.

This is the process a parser exploit lands in, and it is the reason the analyser extension
point was declared before anything took it up: quarantine exists because collected bytes are
hostile, and the shipped analyser examines them **in the calling process** — the one holding
the graph, the claim store and the open vault. `analysis_payload` was written for this worker
and had no caller for as long as there was no worker to call it.

What crosses back is facts, never the artifact. The bytes arrive here and stay here; the
report carries a classification and observations, and the job directory is destroyed by the
parent afterwards.

The import seal is the same one the collector worker installs, and **defence in depth rather
than a boundary**: a finder in a mutable list is removable by code already running here. The
boundary is the process and the sandbox profile the parent applied — and whether that profile
was actually in force is decided by the parent from the process it observed, never reported by
this side.
"""

from __future__ import annotations

import asyncio
import base64
import json
import sys
from datetime import datetime
from importlib import import_module
from typing import Any

from nemesis.collect.worker import FORBIDDEN_PREFIXES
from nemesis.sandbox.seal import seal_imports


def _seal_imports() -> bool:
    return seal_imports(FORBIDDEN_PREFIXES, plane="collection")


def main() -> int:
    _seal_imports()
    try:
        envelope = json.loads(sys.stdin.read())
    except (ValueError, OSError) as exc:
        return _fail(f"the analyser could not read its input: {type(exc).__name__}: {exc}")

    try:
        from nemesis.collect.quarantine import ArtifactHandle
        from nemesis.core.evidence import ContentSafety

        job = envelope["job"]
        handle = ArtifactHandle(
            artifact_id=str(job["artifact_id"]),
            content_hash=str(job["content_hash"]),
            byte_length=int(job["byte_length"]),
            admitted_at=datetime.fromisoformat(str(job["admitted_at"])),
            declared_safety=ContentSafety(job["declared_safety"]),
        )
        artifact = base64.b64decode(envelope["artifact"])
        module_name, _, attribute = str(envelope["factory"]).partition(":")
        factory: Any = getattr(import_module(module_name), attribute)
        analyser = factory()
    except (KeyError, ValueError, TypeError, AttributeError, ImportError) as exc:
        return _fail(f"the analyser could not be built: {type(exc).__name__}: {exc}")

    # The hash is checked here as well as by the parent. The parent wrote these bytes and this
    # is its own worker, so this is not a trust boundary — it is the cheap half of one, and it
    # catches the case the parent cannot see: a job directory that was tampered with between
    # the write and the exec.
    import hashlib

    if f"sha256:{hashlib.sha256(artifact).hexdigest()}" != handle.content_hash:
        return _fail(
            "the bytes handed to the analyser do not hash to the handle's content address; "
            "analysing them would attribute a report to material nobody sealed"
        )

    try:
        report = asyncio.run(analyser.analyse(artifact, handle))
    except Exception as exc:  # the analyser is the thing being contained
        return _fail(f"the analyser raised {type(exc).__name__}: {exc}")

    sys.stdout.write(report.model_dump_json())
    sys.stdout.flush()
    return 0


def _fail(message: str) -> int:
    sys.stdout.write(json.dumps({"error": message}))
    sys.stdout.flush()
    return 1


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    raise SystemExit(main())
