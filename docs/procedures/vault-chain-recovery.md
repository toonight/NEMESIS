# Recovering a vault whose chain does not verify

`IMPLEMENTED` as a procedure. It describes what a human does; nothing here is automated, and
the last section says why.

## What this is for

`FileSystemEvidenceVault` refuses to extend a chain it cannot verify. That refusal is the
control — it is what makes the store tamper-evident — and it is also a dead end: once
`_chain_tip()` raises, no seal, no recorded read and no anchor can be appended, for the life of
the store. There is no automatic repair and there must not be one, because a store that could
rewrite its own history to make itself writable again is not evidence.

So the procedure is diagnostic, then human.

## Step 1 — Read the report before touching anything

```bash
nemesis verify --workspace <path>
```

`verify_integrity()` never raises: it returns `is_intact` and `log_defects`, oldest first. Copy
them somewhere outside the vault directory. Do not delete, truncate or reorder `log.jsonl`,
and do not remove `head.json` — everything below depends on the damaged state being intact.

## Step 2 — Decide which shape you are looking at

Three shapes, and they call for different people.

**Two writers, one root.** Two entries claim the same sequence *and* build on the same
predecessor hash. The report names this explicitly and says it is the signature concurrent
writers leave. Until 2026-08-27 this was reachable by accident: the vault's mutex was
per-instance and `_append` read the tip and wrote with nothing held across the two, so two
processes — or two `FileSystemEvidenceVault` objects in one process — raced. Measured then:
3 runs of 3 forked, 78 of 80 seals lost. `_exclusive()` now holds an `flock` across the whole
critical section, so a *new* fork of this shape means the lock file is not shared — separate
mounts, a copied directory, a container without the volume — which is a deployment fault and
not a code one.

**An edit.** `log entry N was altered after it was written` names an entry whose contents no
longer hash to the hash it carries. Nothing accidental produces this.

**A gap.** Entries reordered, inserted or removed, with no matching-tip pair. A truncated write
from a crash looks like this, and so does a deletion.

> **The concurrency signature lowers suspicion; it does not clear it.** Anyone who can write
> the log can write that shape on purpose. Treat it as a hypothesis to confirm against the
> deployment's own record of what was running at those timestamps — process supervisors, the
> audit trail, container logs — never as a verdict the vault issued.

## Step 3 — Anchor first, if you have one

If `anchors.jsonl` holds an anchor covering a head at or before the damage, that anchor is the
only part of this that an operator cannot have produced. Check it before anything else: it
tells you which prefix of the chain was already attested elsewhere, and that prefix is the part
you can still make claims about.

This build verifies no anchor types — `VERIFIED_ANCHOR_TYPES` is empty — so an anchor here
narrows the question and does not settle it.

## Step 4 — Preserve, then start a new vault

There is no supported edit that makes a forked chain verify again. The supported move is:

1. Copy the whole vault directory, read-only, under a name that records the incident.
2. Record in the audit trail who found it, when, and which shape the report named.
3. Start a new vault root for new material.
4. Re-seal from the **original artifacts** if you still hold them — never from the damaged
   vault's objects, whose custody is exactly what is in question.

Evidence sealed before the damage is not retroactively worthless. It is evidence whose chain
stops being self-verifying at a named point, and the honest description of that is the sentence
to put in front of anyone who relies on it.

## What is deliberately not here

**No repair tool.** Rewriting sequences and relinking hashes would produce a chain that
verifies, and the verification would then mean nothing — it would attest that somebody
successfully rewrote the log. The chain's value is that this is hard, and a shipped tool that
did it on request would hand an operator in the threat model exactly the instrument the store
exists to deny them.

**No automatic quarantine of the damaged store.** A vault that moved itself aside on a failed
verification would be a vault that could be made to hide material by making it fail. The
refusal is loud and stationary on purpose.

Related: `docs/architecture/THREAT_MODEL.md`, the vault rows in `docs/security/INVARIANTS.md`
(`EVID-01`–`EVID-10`), and ADR-0006 on signing the object and verifying by reconstruction.
