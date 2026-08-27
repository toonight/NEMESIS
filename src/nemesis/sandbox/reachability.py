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

**What this cannot do, and the part of it that is checkable.** It is static, so it sees imports
and call names, not runtime composition: a module handed a callable at construction reaches
whatever that callable reaches, and nothing here can see it. It also cannot see out of the
process — a subprocess, a shared filesystem, a database another service reads. The honest claim
is that it closes the *import* composition, which is the one an ordinary commit widens by
accident, and it says so rather than implying it closes the others.

One of those blind spots is narrow enough to bound, so it is: a **dynamic import** —
``import_module``, ``__import__``, ``exec`` — is an edge this graph does not contain, and a
module that resolves an import name at runtime can reach anything. :func:`dynamic_import_sites`
enumerates them, and a test asserts the set is exactly the two that exist and no more. Both are
benign for a specific reason rather than by luck:

* ``nemesis.calibration.freeze`` imports modules to read their constants. It sits above the
  pilot in the layering, so no model-controlled root can reach it at all.
* ``nemesis.collect.worker`` resolves a connector factory from a ``module:function`` string,
  which is how a confined child rebuilds the connector it replaces — a handle cannot be pickled
  across the pipe without giving the child a deserialization surface. The string comes from a
  connector's own registered ``ConnectorCapabilities``, which is deployment configuration; no
  caller and no pilot supplies it.

A third site appearing is not necessarily wrong. It is a place where this analysis stops seeing,
and the test makes somebody say which.

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
            "startfile",
            "execv",
            "execve",
            "execvp",
            "execvpe",
            "execl",
            "execlp",
            "spawnv",
            "spawnve",
            "spawnvp",
            "spawnvpe",
            "spawnl",
            "spawnlp",
            "posix_spawn",
            "posix_spawnp",
            "fork",
            "forkpty",
        }
    ),
    "multiprocessing": frozenset({"Process", "Pool", "spawn"}),
    "ctypes": frozenset({"CDLL", "WinDLL", "PyDLL", "cdll", "windll"}),
}

NETWORK_CALLS: Final[Mapping[str, frozenset[str]]] = {
    "asyncio": frozenset(
        {
            "open_connection",
            "start_server",
            "open_unix_connection",
            "start_unix_server",
            "create_connection",
            "create_server",
            "create_datagram_endpoint",
        }
    ),
}
"""Network capability that arrives as a *call* rather than as an import.

``asyncio`` cannot go in :data:`NETWORK_MODULES`: it is imported by half this tree for its event
loop, and marking every one of those modules egress-capable would make the analysis report
everything and therefore nothing. But ``asyncio.open_connection`` is a full TCP client, and an
adversarial review pointed out that neither list saw it — a module opening a socket that way was
classified ``network=() process=()``.

So the same per-module qualification :data:`PROCESS_CALLS` uses applies here: the module is only
egress-capable if it calls one of these, not if it merely imports ``asyncio``.
"""
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


def _call_base(node: ast.Call, aliases: Mapping[str, str]) -> tuple[str, str] | None:
    """Resolve a call to ``(capability module, attribute)``, or ``None``.

    Three forms, and the last two were missing until an adversarial review used them:

    * ``asyncio.create_subprocess_exec(...)`` — a two-part attribute call, resolved directly.
    * ``sp.run(...)`` after ``import subprocess as sp`` — resolved through ``aliases``, because
      keying on the *written* name meant any alias evaded the table.
    * ``run(...)`` after ``from subprocess import run`` — an ``ast.Name`` call with no module
      prefix at all, resolved through ``aliases`` to the module it was imported from.

    Still ``None`` for a bare call whose name was never imported from a capability module, which
    is what keeps a domain object's ``self.run()`` and a local ``run()`` out of the set.
    """
    func = node.func
    if isinstance(func, ast.Attribute):
        base = func.value
        if not isinstance(base, ast.Name):
            return None
        return aliases.get(base.id, base.id), func.attr
    if isinstance(func, ast.Name):
        origin = aliases.get(f"{_BARE}{func.id}")
        return (origin, func.id) if origin else None
    return None


_BARE: Final = "\x00bare:"
"""Prefix distinguishing ``from x import y`` bindings from ``import x as y`` ones in one map.

A control character so it can never collide with a real identifier. Two lookups sharing one dict
rather than two dicts threaded through one function — the alternative is a second parameter that
every caller has to keep in step with the first.
"""


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map the names a module bound to the capability modules they came from.

    Only capability modules are tracked, so this stays small and cannot shadow an unrelated
    local name: an ``import json as run`` binds nothing here.
    """
    interesting = set(PROCESS_CALLS) | set(NETWORK_CALLS)
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in interesting and alias.asname:
                    aliases[alias.asname] = root
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            root = node.module.split(".")[0]
            if root in interesting:
                for alias in node.names:
                    aliases[f"{_BARE}{alias.asname or alias.name}"] = root
    return aliases


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

        aliases = _import_aliases(tree)
        package = name.rsplit(".", 1)[0] if "." in name else name

        for node in ast.walk(tree):
            imported: list[str] = []
            if isinstance(node, ast.Import):
                imported = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    imported = [node.module, *(f"{node.module}.{a.name}" for a in node.names)]
                elif node.level > 0:
                    # A relative import. The first version required `level == 0` and therefore
                    # produced **no edge at all** for `from ..net import client` — an adversarial
                    # review planted one and the graph came back empty. This tree has no relative
                    # imports today, so it was latent; nothing enforced that, and the planted-path
                    # test used an absolute import and would not have caught it.
                    base = package.rsplit(".", node.level - 1)[0] if node.level > 1 else package
                    prefix = f"{base}.{node.module}" if node.module else base
                    imported = [prefix, *(f"{prefix}.{a.name}" for a in node.names)]
            elif isinstance(node, ast.Call):
                base_call = _call_base(node, aliases)
                if base_call is None:
                    continue
                module_name_, attribute = base_call
                if attribute in PROCESS_CALLS.get(module_name_, frozenset()):
                    process.add(f"{module_name_}.{attribute}")
                if attribute in NETWORK_CALLS.get(module_name_, frozenset()):
                    network.add(f"{module_name_}.{attribute}")
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


DYNAMIC_IMPORT_CALLS: Final[frozenset[str]] = frozenset(
    {"import_module", "__import__", "load_module", "exec_module", "exec", "eval"}
)
"""Calls that resolve code to run at runtime, which is an edge the import graph cannot contain.

Matched on the call name alone rather than qualified by a module, unlike :data:`PROCESS_CALLS`.
The asymmetry is deliberate: ``run`` is a common method name and ``import_module`` is not, so
the qualification that stops the first from producing noise would only add a way for the second
to be missed — ``from importlib import import_module`` is the ordinary spelling and has no
module prefix at the call site at all.
"""


def dynamic_import_sites(src: Path) -> tuple[str, ...]:
    """Every place the tree resolves an import at runtime, as ``module:line: call``.

    Not a finding on its own, and not reported as one. A dynamic import is a **hole in this
    analysis**: an edge the graph does not contain, so a module that has one can reach anything
    its argument names. Enumerating them turns an unbounded caveat into a list somebody has to
    justify, which is the only honest thing to do with a blind spot you cannot close.
    """
    sites: list[str] = []
    for path in sorted(src.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if name in DYNAMIC_IMPORT_CALLS:
                sites.append(f"{_module_name(path, src)}:{node.lineno}: {name}")
    return tuple(sites)


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

    Empty is the passing answer and it is the answer today, but **not because there is nothing
    to broker** — a first reading of this said so and was wrong, and the correction is the useful
    part. Measured by removing each broker in turn:

    * ``nemesis.collect.isolation`` is **load-bearing**. Both model-controlled roots reach
      ``nemesis.sandbox.process`` — the confinement launcher, which starts processes — along
      ``mediator -> pursuit.engine -> collect.isolation -> sandbox.process``, and this broker is
      the only thing on it. That is the right module to be load-bearing: ``collect_confined`` is
      the single gate that decides whether a connector handling hostile content runs at all and
      puts it in a kernel-confined child. The path *should* exist and it *should* go through
      there.
    * ``nemesis.collect.wire`` and ``nemesis.pilot.providers.transport`` are slack: removing
      either changes nothing today. They are declared because the property they assert is one a
      reader should be able to check, not because a path currently runs through them.

    No model-controlled root reaches either **network**-capable connector at all, brokered or
    otherwise. The distinction between the two halves is worth keeping: the network property
    holds more strongly than the contract requires, and the process property holds exactly
    because of one broker.
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
    "DYNAMIC_IMPORT_CALLS",
    "MODEL_CONTROLLED_ROOTS",
    "NETWORK_CALLS",
    "NETWORK_MODULES",
    "PACKAGE_ROOT",
    "PROCESS_CALLS",
    "PROCESS_MODULES",
    "ImportGraph",
    "ModuleCapability",
    "ReachabilityFinding",
    "build_graph",
    "dynamic_import_sites",
    "process_spawning_modules",
    "unbrokered_egress",
    "unknown_roots_or_brokers",
]
