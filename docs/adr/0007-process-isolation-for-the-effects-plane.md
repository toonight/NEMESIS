# ADR-0007: The Effects plane runs in a process that can do less

- **Status:** accepted
- **Date:** 2026-08-16
- **Deciders:** founding architect
- **Plane:** effects, ports
- **Reversibility:** moderate. The executor is additive and the in-process registry still
  works, so a deployment can go back by wiring the registry directly. What is not cheap to
  reverse is the module split it forced — `nemesis.authz.verification` exists so that the
  Effects plane can check a signature without importing the module where keys are made.

## Context

[ADR-0001](0001-single-package-with-enforced-plane-separation.md) chose one package with
`import-linter` contracts, and said plainly what that buys and what it does not:

> **Where a real boundary is needed, it is a process boundary, not a packaging one.**
> […] **Unverified assumption:** that process-level isolation for Effects and dark-web
> collectors will be added before it is needed.

Four adversarial reviews then closed with the same residual risk, in four different
wordings: an attacker with code execution inside this process reaches `gateway._signer`, and
every control described in ADR-0005 and ADR-0006 is a control that attacker does not need to
defeat. Static contracts bind the code in this repository at build time. They bind nothing
at the moment the plane is processing something hostile.

The claim most exposed by this is the platform's loudest one. `external_contact_made = False`
was computed from what each adapter *declares about itself* — a claim by the component under
suspicion, in a plane whose entire purpose is to be the one that might reach outside.

## Decision

Effects run in a child process, launched per operation, holding as little as possible.

**What the child does not have.**

| | How |
|---|---|
| No private key | It receives a public verifying key over the pipe. A fully owned worker cannot mint a capability, because minting needs a key that never crossed. |
| No *accidental* import of the intelligence platform | `nemesis.effects.worker` installs an import hook refusing the graph, the vault, collection, pursuit, resolution, attribution, disruption, the gateway and the signing module. **Defence in depth, not a boundary** — see the correction below. |
| No socket **from this process** | macOS `sandbox-exec` with `(deny network*)`, inherited by fork/exec descendants. See the correction below for what this does *not* establish. |
| No filesystem beyond one directory | `(deny file-write*)` with an allow for the job directory (path resolved), removed afterwards. Reads are *narrowed*, not closed — see the correction below. |
| No inherited environment | The environment is built from nothing: `PATH`, the package path derived from where this package actually is, and three limit variables. No token, no key path, no `HOME`. |
| No time | A deadline, after which the child's whole **process group** is killed and the operation is recorded as failed. |
| No memory, CPU or output to spare | `RLIMIT_CPU` and `RLIMIT_FSIZE`, applied by the worker at bootstrap. |

**The decision is made in the parent.** `IsolatedEffectsExecutor.perform` runs `preflight`
itself — signature, reconstruction, revocation, scope, target binding, stop conditions — and
dispatches only if the operation is authorized. The worker runs the same checks again
against the same signed bytes, but a worker that skipped its copy entirely could still only
perform something this process had already decided to allow. A refused operation costs no
child process at all.

**The result is re-validated, and its verdict replaced.** The worker's account of its own
authority is worth nothing, so the parent substitutes the verdict it reached before
dispatching, along with the operation id and the operation class, and flattens the free text
before it reaches the audit trail. The worker's account of whether it made external contact
is kept as its own field beside the kernel's denial, never reconciled into one boolean.

**The report is the deliverable.** Every run returns an `IsolationReport` saying what was
*actually enforced*, and `egress_denied_from_this_process` is true only where the kernel
refused a socket to the process that ran the effect. The demonstration prints it at exactly
that strength, with the caveat attached:

```
egress from the effect process  DENIED by the kernel
  ~ This says nothing about a process the effect could have asked another service to start.
```

A control that silently degraded into a sentence is the failure this whole ADR is against —
and the first version of this document did it anyway, by printing "ESTABLISHED by the
kernel" for a per-process socket denial. See below.

**Limits are reported as applied, never as requested.** macOS rejects `RLIMIT_AS` outright.
The worker returns the ceilings that actually took; the parent accepts one only if it is no
weaker than what was asked and validates the whole report rather than `model_copy`-ing it,
because `model_copy` skips validation and a worker reported a CPU ceiling of 999999.
`output_bytes` was renamed `file_size_bytes`: it is `RLIMIT_FSIZE` and governs files, and it
never bounded the pipe it appeared to describe.

## What the first version of this ADR got wrong

Everything above the line describes the design. An adversarial review ran against the
implementation the day it was written and found that five of seven claims were false on a
fully green tree. Recording that here rather than quietly amending, because the pattern is
now four reviews old and is itself the most useful thing in this document.

- **"The verdict is replaced" was not implemented.** `_interpret` updated one field and
  passed the worker's `authorization` straight through. A confined child returned
  `operation=registrar_suspension, permitted=true, denial_reasons=[]` for a request that
  asked for a simulation, and it went into the hash-chained trail, and the chain verified.
  Two earlier reviews had found exactly this shape in `nemesis.effects.registry`; the
  process boundary is the one place that fix could not reach.
- **The deadline was not a kill switch.** `kill()` reached the direct child and `wait()`
  then blocked until the inherited pipes closed, so a grandchild holding stdout kept a
  2-second deadline running for 90 seconds — and one that never exits kept it running
  forever. Fixed with `start_new_session` and a process-group kill; the fix's *first*
  version killed the test suite exercising it, because `getpgid` answers with our own group
  when the session change has not taken effect. A kill switch that can fire at its owner is
  worse than no kill switch, and there is now a test asserting the guard exists.
- **The output ceiling was a post-mortem.** `communicate()` read to EOF and only then could
  anything measure it: 600 MiB reached the parent in 0.3 seconds and was met with "the
  output was discarded unread", written after reading it. Now read incrementally and killed
  on breach.
- **The workdir allow rule never matched.** `mkdtemp` returns `/var/folders/...`; the kernel
  resolves `/private/var/folders/...`. It failed closed, so nothing was exposed — the child
  could write nowhere, and the demonstration printed a directory it could not use. The suite
  missed it because only the negative was asserted; there is now a test for the positive.
- **The report claimed controls for runs that never happened.** Built before
  `create_subprocess_exec`, so a run in which spawning raised still asserted a separate
  process, a denied network, a confined filesystem and a sealed interpreter. Now built from
  the process existing, and the seal is reported by the child rather than assumed.
- **`external_contact_is_established` claimed more than a socket denial proves.**
  `(allow default)` permits `mach-lookup`, so a confined child could ask LaunchServices to
  start a process — a child of `launchd`, inheriting none of the confinement. The property
  is now `egress_denied_from_this_process`, the named services are denied, and the demo
  prints the caveat rather than "ESTABLISHED by the kernel".
- **The import seal is bypassable from inside.** `sys.meta_path` is a mutable list;
  `spec_from_file_location` loads by path; `exec` needs no import system at all. A review
  did all three. The seal stops the accidental import and the careless refactor. It is
  documented as defence in depth everywhere it is mentioned, and no longer as a control.
- **`(allow default)` permits reading anything**, and the evidence vault, the audit trail
  and a persisted signing key are all files. `import-linter` blocks the import; nothing
  blocked the `open()`. The deployment now names paths to deny and the scenario passes its
  workspace — an enumeration, and **incomplete by construction**. A read allowlist would be
  structural and fails closed, and it aborts CPython outright on this platform (`rc=134`),
  so it is not something to ship on a guess. Recorded as an open gap in `THREAT_MODEL.md`.
  **[Corrected 2026-08-17 — see the amendment below. This paragraph is wrong.]**

What survived, and is worth stating because it is the part that was actually built: no
private key crosses the pipe, verified against the bytes sent; network denial is real and is
inherited by fork/exec descendants; filesystem confinement resists symlinks, `..` and
`/dev/fd`; the environment leaks nothing; operation-class confusion is blocked at both ends;
every parent/child divergence fails closed; and there is no path from a module the worker can
import to a signing key — the `verification`/`keys` split holds.

## Consequences

**What this buys.** Invariant 8 moves from `PROPOSED` to `IMPLEMENTED`, with mechanism tests
that run probes under the real confinement and assert what the kernel did: a socket is
refused, a write to `$HOME` is refused, each forbidden module raises on import, a hanging
child is killed and recorded, a child returning nonsense is recorded as failed.

**What it does not buy.** A compromised *parent* is untouched by any of this — it holds the
signer. The boundary defends the direction that matters: hostile content reaching the
Effects plane cannot become reach into the intelligence platform, the vault, or the network.
That is the direction invariant 8 describes.

**Platform honesty.** `sandbox-exec` is macOS-only and is deprecated by Apple. On Linux the
equivalent is a network namespace or seccomp, and neither is implemented here; on Linux this
executor still gives a separate process, no key, sealed imports and a deadline, and the
report says the network was not denied. A deployment that will not accept that sets
`allow_unsandboxed=False` and the executor refuses to run at all — the honest behaviour for
a plane whose whole claim is that nothing leaves the system.

**Cost.** One process per operation, roughly 200ms of spawn. The demonstration runs six and
is perceptibly slower. That is the correct trade for a plane that exists to be distrusted,
and it is also a natural throttle: an agent cannot loop effects cheaply.

**A refusal moved.** `registrar_suspension` in the demonstration used to be refused for want
of an adapter. It is now refused at authorization, in the parent, before any child exists —
both facts remain true of it, and the authorization refusal fires first on purpose. Asking
whether we *could* perform an operation nobody authorized is the wrong question in the wrong
order.

**A module split, which was the point.** `nemesis.authz.verification` now holds the public
verifying key, `CapabilityVerification` and `verify_capability`; `nemesis.authz.keys` holds
the signing key and re-exports the rest. Without that split, a worker that needed to check a
signature would have had to import the module where a signing key is constructed — and the
seal would have had to let it through.

## Alternatives considered

**Keep `import-linter` and document the gap.** What the last four ADRs did. It is the right
answer right up until somebody reads the threat model as a description of runtime, which is
what a "no external contact" claim invites.

**A long-lived worker pool.** Faster, and it rebuilds the standing authority invariant 8
removes: the second operation would ride on the first one's process, and a worker
compromised by operation one would still be there for operation two. One process, one
operation.

**Containers or a VM.** Stronger, and correct eventually. It makes the platform undeployable
without an orchestrator, for a repository whose adapters currently draft text files. The
`EffectsExecutor` port is where that implementation goes when the first adapter that really
reaches outside arrives — which ADR-0001 already named as the trigger.

**A deny-default sandbox profile.** Attempted and rejected. A deny-default profile for
CPython has to enumerate every dylib, stdlib path and temporary file the interpreter
touches, and a profile maintained by enumeration fails *open* the first time an interpreter
upgrade adds a path. Two deny rules that hold are worth more than a hundred allow rules that
rot.

---

## Amendment, 2026-08-17: the read allowlist was not impossible

The paragraph above says a read allowlist "aborts CPython outright on this platform
(`rc=134`), so it is not something to ship on a guess". Measured rather than reasoned about,
that is wrong in three ways, and the ways matter more than the conclusion — a future reader
who trusts it will not attempt the fix.

**The abort is dyld, not CPython.** `/bin/echo` dies with the identical `rc=134` under the
same profile. Naming CPython sent anyone who read this looking at the interpreter, which is
the wrong component and the wrong search.

**It aborts because the allowlist was incomplete, not because one cannot work.**
`(deny file-read-data)` followed by `(allow file-read-data (subpath "/"))` runs fine. That
single check would have shown the mechanism was sound and reduced the problem to enumerating
paths — the check was never run, and the impossibility was inferred from a failure whose cause
was never diagnosed.

**Two paths were missing, and both are the kind an enumeration loses.** `(literal "/")` is
load-bearing: the union of every top-level directory is *not* equivalent to allowing the root,
because the root is read during path resolution — without it the child SIGABRTs with no output
at all, which is exactly the silent failure that produced the original claim. And the
interpreter prefix must be **realpath-resolved**: `sys.base_prefix` reported `cpython-3.13-…`
while the binary lives in `cpython-3.13.2-…`, so allowing the symlink allowed nothing. That is
the same `/var` versus `/private/var` failure this very ADR records two bullets above, one
layer up — the lesson was written down and then not applied.

**What shipped instead.** `SandboxPolicy(confine_reads=True)` denies reads by default. The
Effects plane now generates its profile from `SandboxPolicy` rather than its own template —
the two had already drifted, the local copy denying `mDNSResponder.dnsproxy` and the shared
one not. Verified against the real kernel: the job directory readable; the evidence vault, the
audit trail, the caller's SSH key and shell history denied.

**And one honest narrowing.** An early write-up of this claimed the allowlist also denies this
platform's own source. True for a bare probe; **false for the Effects worker**, which *is*
this package and must import it — under that profile the plane could not start at all. The
package root is named in `read_allowed`, and the correct statement is that everything *else*
is denied. A claim that survives a probe and dies against the real caller is the same defect
class as the paragraph this amendment corrects.

The collection plane has **not** been measured under read confinement and remains on the
blocklist. That is a gap, not a decision.
