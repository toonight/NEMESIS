"""Can a model-controlled context reach the outside world by going the long way round?

`scripts/check_prohibited.py` answers a narrower question and answers it well: *does this module
import a network client, and is it allowed to?* That is a check on one hop. The August 2026
OpenAI Hugging Face incident was about the hops after the first one — agents denied direct
Internet access found it anyway, through an internal service that had it, through a package
resolver, through an artifact fetch, through a proxy nobody thought of as a proxy. Every
individual component was behaving exactly as designed. The reachability was a property of the
composition, and no per-component check can see a property of the composition.

So this module builds the import graph of `src/nemesis` and asks the composed question:

    **NET-02.** No execution context a frontier model controls may reach an egress-capable
    module except through a declared, policy-controlled broker.

**The two halves of "egress-capable", and why the second one exists.** A module is egress-capable
if it can put bytes on a network (:data:`NETWORK_MODULES`, the same list the prohibited-content
scan uses, so the two cannot disagree about what a network client is) — or if it can **start a
process** (:data:`PROCESS_CALLS`). The second half is not decoration. Process-spawning is how the
incident's most interesting paths worked, and it is invisible to an import scan here for a
concrete reason: this repository spawns with ``asyncio.create_subprocess_exec``, and ``asyncio``
is imported by half the tree. Detecting the capability therefore means detecting the *call*, not
the import, which is what :func:`process_spawning_modules` does.

**Model-controlled ≠ untrusted-input-handling.** The roots are the modules whose behaviour a
model steers turn by turn — the seam that receives its moves and the loop that drives that seam.
Not the effects plane, which is bounded by a signed capability and by kernel confinement rather
than by this analysis; not the collection plane, which is the *broker*, not the client.

**Brokers, and what declaring one costs.** A broker is a module a model-controlled context is
allowed to reach *through*, because what happens on the far side is chosen by policy rather than
by the model. :data:`DECLARED_BROKERS` names each one with the reason and the thing that makes
the far side policy-controlled — an allowlist, a registry, an injected transport. The list is
short on purpose: every entry is a place where the argument "the model does not choose the
destination" has to be true, and a list nobody has to justify entries in is a list that grows.

**What this cannot do.** It is static, so it sees imports and call names, not runtime
composition: a module handed a callable at construction reaches whatever that callable reaches,
and nothing here can see it. It also cannot see out of the process — a subprocess, a shared
filesystem, a database another service reads. The honest claim is that it closes the *import*
composition, which is the one an ordinary commit widens by accident, and it says so rather than
implying it closes the others.

Status: `IMPLEMENTED`. Run by `scripts/check_egress_reachability.py` in CI and asserted by
`tests/invariants/test_transitive_egress.py`.
"""

from __future__ import annotations

import ast
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

PACKAGE_ROOT: Final = "nemesis"

NETWORK_MODULES: Final[frozenset[str]] = frozenset(
    {
        # Transports.
        "socket",
        "http",
        "httpx",
        "requests",
        "urllib",
        "urllib3",
        "aiohttp",
        "websockets",
        "ftplib",
        "telnetlib",
        "smtplib",
        "paramiko",
        "scapy",
        # Model-vendor SDKs. Each carries a full HTTP stack behind a name that does not look
        # like one.
        "openai",
        "anthropic",
        "google",
        "google_genai",
        "googleapiclient",
        "vertexai",
        "ollama",
        "cohere",
        "mistralai",
        "groq",
        "together",
        "replicate",
        "litellm",
        "boto3",
        "botocore",
        "azure",
        "transformers",
        "vllm",
    }
)
"""Top-level module names that carry network capability.

Deliberately the same content as ``scripts/check_prohibited.py``'s list, and a test asserts the
two are identical rather than merely similar. Two lists of what counts as a network client, kept
by hand, would eventually disagree — and the day they disagree is the day one of the two checks
stops covering a transport the other still knows about.
"""

PROCESS_CALLS: Final[Mapping[str, frozenset[str]]] = {
    "asyncio": frozenset({"create_subprocess_exec", "create_subprocess_shell"}),
    "subprocess": frozenset({"Popen", "run", "call", "check_call", "check_output", "getoutput"}),
    "os": frozenset(
        {
            "system",
            "popen",
            "execv",
            "execve",
            "execvp",
            "execvpe",
            "execl",
            "execlp",
            "spawnv",
            "spawnve",
            "spawnl",
            "posix_spawn",
            "fork",
            "forkpty",
        }
    ),
    "multiprocessing": frozenset({"Process", "Pool", "spawn"}),
}
"""Call names that can put a new process on the machine, qualified by the module they live on.

**A flat name set does not work, and the first version proved it in one run.** ``run`` and
``call`` are among the commonest method names anywhere, and a set holding them bare matched
``asyncio.run`` — so the report named eight modules as process-spawning when two are, including the
CLI entry point and two demonstration scripts. A capability report that is mostly false
positives is a report nobody reads, and then it is a report nobody notices going quiet.

So the mapping is per-module: ``subprocess.run`` spawns and ``asyncio.run`` does not, and the
analysis has to know which module the attribute hangs off before it can say. That is also why
:func:`_call_base` refuses anything but a two-part attribute call — ``self.run()`` on a domain
object never reaches this table at all.
"""

PROCESS_MODULES: Final[frozenset[str]] = frozenset(PROCESS_CALLS)


MODEL_CONTROLLED_ROOTS: Final[tuple[str, ...]] = (
    # The seam a model's moves arrive at, and everything the mediator can name.
    "nemesis.pilot.mediator",
    # A second model sits here. Its vocabulary only subtracts, which bounds what it can *cause*
    # and says nothing about what it can *reach* — a different question, asked here.
    "nemesis.pilot.challenger",
    # The long-horizon loop above the seam. A supervisor may be model-backed (ADR-0011), so the
    # controller that consults one is a model-controlled context even though it is not a seat.
    "nemesis.evolution.controller",
    "nemesis.evolution.supervisor",
)
"""Modules whose behaviour a frontier model steers, turn by turn.

Not "modules that handle untrusted input", which would be most of the tree and would make the
analysis vacuous. The distinction that matters for NET-02 is *who chooses the next call*: a
connector parsing a hostile page is handling adversary bytes under a policy the adversary did not
write, while the mediator is executing a request a model composed.
"""

DECLARED_BROKERS: Final[Mapping[str, str]] = {
    "nemesis.collect.isolation": (
        "The single confinement gate. `collect_confined` decides whether a connector that "
        "declares hostile content runs at all and puts it in a kernel-confined child when it "
        "does. A model reaching egress through here reaches it as a policy-selected connector "
        "answering a typed PivotRequest, never as a destination the model named."
    ),
    "nemesis.collect.wire": (
        "The worker pipe. Configuration crosses it as non-secret data so a child can rebuild "
        "the same allowlist; nothing that crosses it is a destination a caller chose."
    ),
    "nemesis.pilot.providers.transport": (
        "The vendor seam. A deployment injects a transport holding the endpoint and the "
        "credential; the default refuses and no seat in the package contains network code. The "
        "model reaches its own vendor through here and cannot choose the endpoint, because the "
        "endpoint is configuration and the payload is a rendered request the model never sees "
        "the envelope of."
    ),
}
"""Modules a model-controlled context may reach an egress capability *through*.

Each entry states what makes the far side policy-controlled rather than model-controlled, and
that sentence is the thing a reviewer checks. Adding an entry is how this analysis is weakened,
so it is deliberately the most conspicuous edit anyone can make to this file.
"""


@dataclass(frozen=True)
class ModuleCapability:
    """What one module can reach for, and how the analysis knows."""

    module: str
    network: tuple[str, ...] = ()
    process: tuple[str, ...] = ()

    @property
    def is_egress_capable(self) -> bool:
        return bool(self.network or self.process)

    def describe(self) -> str:
        parts = []
        if self.network:
            parts.append("network via " + ", ".join(self.network))
        if self.process:
            parts.append("process via " + ", ".join(self.process))
        return f"{self.module}: {'; '.join(parts)}"


@dataclass(frozen=True)
class ReachabilityFinding:
    """One path from a model-controlled root to an egress capability, brokers excluded."""

    root: str
    target: str
    path: tuple[str, ...]
    capability: ModuleCapability

    def describe(self) -> str:
        return (
            f"{self.root} reaches {self.capability.describe()} with no declared broker on the "
            "way:\n    " + "\n      -> ".join(self.path)
        )


@dataclass(frozen=True)
class ImportGraph:
    """The internal import graph of one source tree, with each module's egress capability."""

    edges: Mapping[str, frozenset[str]]
    capabilities: Mapping[str, ModuleCapability]

    @property
    def egress_capable(self) -> frozenset[str]:
        return frozenset(name for name, cap in self.capabilities.items() if cap.is_egress_capable)


def _module_name(path: Path, src: Path) -> str:
    name = ".".join(path.relative_to(src).with_suffix("").parts)
    return name.removesuffix(".__init__")


def _call_base(node: ast.Call) -> tuple[str, str] | None:
    """``asyncio.create_subprocess_exec(...)`` -> ``("asyncio", "create_subprocess_exec")``.

    Returns ``None`` for anything that is not a two-part attribute call, which is what keeps a
    domain object's ``self.run()`` out of the process-capability set.
    """
    func = node.func
    if not isinstance(func, ast.Attribute):
        return None
    base = func.value
    if not isinstance(base, ast.Name):
        return None
    return base.id, func.attr


def build_graph(src: Path) -> ImportGraph:
    """Parse a source tree into its internal import graph and per-module egress capability.

    Import resolution is deliberately generous in one direction: ``from a.b import c`` adds an
    edge to ``a.b.c`` when that is a module and to ``a.b`` otherwise, so importing a *name* from
    a module still counts as reaching that module. Being generous is the safe direction for a
    reachability check — a missed edge is a path this analysis cannot see, and a spurious edge
    is at worst a broker somebody has to justify.
    """
    modules = {_module_name(path, src): path for path in sorted(src.rglob("*.py"))}
    edges: dict[str, set[str]] = defaultdict(set)
    capabilities: dict[str, ModuleCapability] = {}

    for name, path in modules.items():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        network: set[str] = set()
        process: set[str] = set()

        for node in ast.walk(tree):
            imported: list[str] = []
            if isinstance(node, ast.Import):
                imported = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                imported = [node.module, *(f"{node.module}.{a.name}" for a in node.names)]
            elif isinstance(node, ast.Call):
                base = _call_base(node)
                if base is not None and base[1] in PROCESS_CALLS.get(base[0], frozenset()):
                    process.add(f"{base[0]}.{base[1]}")
                continue
            else:
                continue

            for target in imported:
                root = target.split(".")[0]
                if root in NETWORK_MODULES:
                    network.add(root)
                if root != PACKAGE_ROOT:
                    continue
                resolved = target if target in modules else ".".join(target.split(".")[:-1])
                if resolved in modules and resolved != name:
                    edges[name].add(resolved)

        capabilities[name] = ModuleCapability(
            module=name, network=tuple(sorted(network)), process=tuple(sorted(process))
        )

    return ImportGraph(
        edges={name: frozenset(targets) for name, targets in edges.items()},
        capabilities=capabilities,
    )


def process_spawning_modules(graph: ImportGraph) -> tuple[str, ...]:
    """Modules that can start a process, for a reader who wants the list on its own."""
    return tuple(sorted(name for name, cap in graph.capabilities.items() if cap.process))


def _shortest_path(
    graph: ImportGraph, root: str, targets: Iterable[str], blocked: frozenset[str]
) -> dict[str, tuple[str, ...]]:
    """Breadth-first search from ``root``, refusing to enter any blocked module.

    Blocking the brokers rather than enumerating paths through them is what keeps this linear:
    the question NET-02 asks is not "how many ways are there round" but "is there any way round
    at all", and a graph with the brokers removed answers it in one traversal.
    """
    wanted = set(targets)
    if root in blocked or root not in graph.capabilities:
        return {}
    previous: dict[str, str | None] = {root: None}
    queue: deque[str] = deque([root])
    found: dict[str, tuple[str, ...]] = {}

    while queue:
        current = queue.popleft()
        for nxt in sorted(graph.edges.get(current, frozenset())):
            if nxt in previous or nxt in blocked:
                continue
            previous[nxt] = current
            queue.append(nxt)
            if nxt in wanted:
                trail = [nxt]
                while previous[trail[-1]] is not None:
                    parent = previous[trail[-1]]
                    if parent is None:  # pragma: no cover - loop guard, unreachable
                        break
                    trail.append(parent)
                found[nxt] = tuple(reversed(trail))
    return found


def unbrokered_egress(
    graph: ImportGraph,
    *,
    roots: Sequence[str] = MODEL_CONTROLLED_ROOTS,
    brokers: Iterable[str] = tuple(DECLARED_BROKERS),
) -> tuple[ReachabilityFinding, ...]:
    """Every way a model-controlled root reaches egress without passing a declared broker.

    Empty is the passing answer, and it is the answer today: the mediator has no import path to
    either egress-capable connector at all, brokered or otherwise. That is worth stating because
    it means the brokers are currently *slack in the contract* rather than load-bearing — the
    property holds more strongly than it needs to, and this function is here to notice the day
    it stops.
    """
    blocked = frozenset(brokers)
    targets = graph.egress_capable - blocked
    findings: list[ReachabilityFinding] = []
    for root in roots:
        for target, path in sorted(_shortest_path(graph, root, targets, blocked).items()):
            findings.append(
                ReachabilityFinding(
                    root=root,
                    target=target,
                    path=path,
                    capability=graph.capabilities[target],
                )
            )
    return tuple(findings)


def unknown_roots_or_brokers(graph: ImportGraph) -> tuple[str, ...]:
    """Declared roots and brokers that do not name a module in the tree.

    A root that no longer exists is a root nothing is checked from, and it fails silently: the
    analysis reports no findings and reads exactly like a pass. This is the same defect class as
    a test that asserts a constant, and it is cheap to close — so the CI entry point calls this
    before it believes an empty finding list.
    """
    known = set(graph.capabilities)
    missing = [name for name in MODEL_CONTROLLED_ROOTS if name not in known]
    missing += [name for name in DECLARED_BROKERS if name not in known]
    return tuple(sorted(missing))


__all__ = [
    "DECLARED_BROKERS",
    "MODEL_CONTROLLED_ROOTS",
    "NETWORK_MODULES",
    "PACKAGE_ROOT",
    "PROCESS_CALLS",
    "PROCESS_MODULES",
    "ImportGraph",
    "ModuleCapability",
    "ReachabilityFinding",
    "build_graph",
    "process_spawning_modules",
    "unbrokered_egress",
    "unknown_roots_or_brokers",
]
