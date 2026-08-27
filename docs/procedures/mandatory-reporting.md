# Mandatory reporting: the procedure NEMESIS cannot execute

**Status:** `IMPLEMENTED` as a register and a set of refusals. The *content* of the procedure —
which authority, which window, which jurisdiction — is `REQUIRES_LEGAL_AUTHORITY` and is
deliberately left blank here. This repository cannot answer it and must not guess.

---

## Why this document exists rather than more code

`ContentSafety.MANDATORY_REPORT` marks material that triggers a legal reporting obligation.
Two halves follow, and only one of them is software:

- The platform must not let such material out through ordinary channels. **Built** —
  `nemesis.collect.quarantine` gives it no automated exit.
- Somebody must actually report it. **Not buildable.** A platform that could mark its own
  legal duty complete would be keeping a compliance record of its own convenience.

So `nemesis.evidence.escalation` does the only two things software honestly can: it **opens**
an obligation, and it **refuses to close one**. Everything below is the part a person does.

## What the register does and does not mean

| The register says | It does **not** say |
|---|---|
| An obligation was incurred, when, and about which artifact | That the material is in fact reportable — that is a legal judgement |
| A named legal reviewer recorded a discharge, when, with what reference | That a report was filed, accepted, or acted on |
| An obligation is overdue against a configured window | That the window is the correct one for this regime |

`discharged` means *a human said they did it*. NEMESIS cannot see a regulator's inbox, and a
status implying otherwise would be worse than no status at all.

## The procedure

1. **Quarantine holds it.** Material classified `MANDATORY_REPORT` has no automated exit. Do
   not work around this; the refusal is the control.
2. **The register opens an obligation**, with the artifact id, the moment it was incurred, and
   the deadline from the deployment's configured window. This happens automatically, at the
   hold, since 2026-08-27 — until then this step described something no code performed, and the
   refusal in step 1 left no record that a duty had been incurred at all. Re-examining the same
   artifact does not reopen or re-date it.
3. **A legal reviewer assesses it.** Not the analyst who found it — the role separation exists
   because the person who found the material is the wrong person to judge the duty it creates.
4. **They report through the channel their jurisdiction requires**, outside NEMESIS. The
   platform holds no credentials for any authority and makes no external contact
   (invariant 15).
5. **They record the discharge** with the channel reference — a case number, a submission id,
   something an auditor can follow.

## What a deployment must configure before this is real

- **`Obligation.authority`** — who is owed a report. Jurisdiction- and material-dependent.
- **`DEFAULT_DEADLINE`** — currently 72 hours. **A placeholder, not advice.** It is short
  enough to be uncomfortable, which is the right direction for a default nobody has reviewed.
- **Who holds `LEGAL_REVIEWER`**, and whether that person is reachable inside the window. An
  obligation whose only discharger is on leave is an obligation that will lapse.

## The failure mode this is built against

Not refusal — **silence**. An obligation nobody actively declines is not the dangerous case; an
obligation that lands in a queue nobody reads is. The register therefore gets louder with age:
overdue items lead its output, oldest first, and the deadline does not restart when the
material is re-examined. If nothing reads that output on a schedule, none of this works, and
that schedule is an operational commitment rather than a feature.
