# External review brief — the pilot seam and the autonomy envelope

**For:** an external reviewer on a different model family (Codex / GPT-5.x), 2026-08-20 or later.
**Why this document exists:** the reviewer's budget is limited, so it should be spent attacking
the highest-value targets rather than on orientation. Everything below is written to be attacked.

---

## Read this first: what has and has not been checked

The code in scope was reviewed by **Claude subagents** — the same model family that wrote it.
That review found four real defects (below), so it was not worthless. It is also, by this
project's own reasoning discipline, **one correlated opinion and not independent confirmation**.
An external model is the first genuinely independent pass over this code.

Treat every claim in `docs/architecture/PROJECT_STATE.md` about the pilot seam and the envelope
as **"survived a correlated review"**, which is weaker than "holds".

**Method that has worked here:** give the reviewer the actual file, not a summary, and task it to
**refute** rather than confirm. Historically ~2/3 of first-pass findings in this project do not
survive a refutation pass. Keep `UNVERIFIABLE` available as a verdict.

**A local pass runs between external ones.** `scripts/local-review.sh <file>` puts a file in front
of a local Qwen (a different model family, so less correlated than a Claude subagent; and the code
never leaves the machine). It is useful for docstring-versus-code contradictions and useless for
concurrency reasoning — do not spend the external budget on what it already covers, and do not
trust it on what it cannot. Its first run demonstrated both halves: it caught a real undocumented
limitation, and it was fed a *paraphrase* of a claim rather than the file's own words, so it
faithfully reported a contradiction that existed only in the paraphrase. The script now sends the
file itself for exactly that reason.

---

## Scope, most valuable first

### 1. The autonomy budget — an authority counter under concurrency (HIGHEST VALUE)

`src/nemesis/authz/envelope.py`, `src/nemesis/authz/store.py` (`register`, `debit`, `spends`).

This is the newest security-relevant code and the place where the author's own tests are least
trustworthy, because they were written alongside the code they check.

The claim to break: **a fleet sharing one envelope cannot spend more effects than its budget.**

Attack surface worth probing:
- `debit()` does `BEGIN IMMEDIATE`, reads `envelope_budgets`, reads the tip of `envelope_spends`,
  compares `next_sequence >= budget`, inserts, `COMMIT`. Is that actually serialized against a
  second process under WAL? Is `ROLLBACK` on the exhausted path correct, or does it leave a
  transaction open on some error path?
- The `sqlite3` connection uses `isolation_level=None` (autocommit) with explicit `BEGIN
  IMMEDIATE`. Is any statement in `debit`/`register` executing *outside* the transaction?
- `register()` returns `min(recorded, budget)` and refuses a larger one. Can two concurrent
  `register` calls interleave such that the larger wins?
- The test `test_two_processes_cannot_spend_past_the_ceiling_by_racing` uses 4 processes × 25
  attempts against a budget of 10. **Is that test actually capable of failing?** If the
  processes serialize by accident (start-up cost >> critical section), it proves nothing. Try to
  show the test is vacuous.
- `SpendRecord.chain_hash()` covers `model_dump(mode="json")`. Does the durable round-trip
  (`_parse`) reproduce byte-identical JSON, or can a stored row hash differently from the
  in-memory one it came from? If they differ, `verify_chain` is checking the wrong thing.
- Is the ledger's `spent`/`remaining` ever read outside a lock in a way a caller could act on?

### 2. Briefing egress to the model vendor (a real leak was found here)

`src/nemesis/pilot/mediator.py::_brief`, `src/nemesis/pilot/openai_pilot.py::build_request`,
`src/nemesis/pilot/anthropic_pilot.py::build_request`, `src/nemesis/core/disclosure.py`.

A hosted pilot transmits **every briefing to OpenAI/Anthropic**. A previous review found the
briefing carrying a RESTRICTED human-identity lead (`john doe`, `human_identity_lead`) to
the vendor. The fix filters entities to `DisclosureClass.DELIVERABLE`, redacts the seed and
hypotheses when the seed is internal-class, redacts markers from `last_ruling.reason`, and runs a
fail-closed `scan_for_internal_material` backstop.

The claim to break: **no internal-class or RESTRICTED material can reach a vendor request.**

Probe: entity `attributes` (are they serialized anywhere?), `Ruling.reason` free text from
`result.detail` (which quotes adapter output), `EntityView.natural_key` for a DELIVERABLE-typed
entity whose key nonetheless contains a person's name, hypothesis statements, `investigation_id`
correlation, and anything reachable through `Briefing.model_dump_json()` that the filter does not
walk. The backstop only catches NEMESIS's own marker vocabulary — it catches a marker, not an
idea.

**Known and accepted limitation (do not re-report):** the filter keys on entity *type*. A
DELIVERABLE-typed node whose *content* is a person's name — `domain:john-doe.example`, an
ORGANIZATION named after a person — passes verbatim. This bounds classified material, not
personal material. Worth attacking is whether the *stated* scope now matches the code, and
whether any path reintroduces a non-deliverable **type**.

### 3. The mediator loop and the closed vocabulary

`src/nemesis/pilot/mediator.py::drive`, `_validate`, `_apply_effect`; `src/nemesis/pilot/moves.py`.

Claims to break:
- A pilot cannot execute a verb outside `run_pivot | record_belief | request_effect | conclude`.
- A pilot cannot forge target state (`RequestEffect` has no field for it; the mediator reads the
  graph).
- A pilot's belief can only be `HYPOTHESIS`/`MODEL_ASSERTION`.
- `except Exception` around `propose` does not swallow `CancelledError` (deliberate) and does not
  swallow real bugs from `_apply`, `_brief` or `_record_move`.
- `asyncio.wait_for(propose_timeout)` actually cancels a stalled call and cannot be influenced by
  the pilot.
- `RequestEffect.parameters` is a free `dict[str,str]` reaching `EffectRequest.parameters`. What
  can a hostile pilot put there that survives `sanitize()` and the disclosure scan?

### 4. Cross-vendor symmetry

`model_seat.py` vs `openai_pilot.py` vs `anthropic_pilot.py`. The two seats must enforce
identically, or an adversary picks the weaker vendor. One asymmetry was already found (one parser
raised where the mirror returned a sentinel). Look for another.

---

## Defects already found and fixed (do not re-report; do try to show the fix is wrong)

| Sev | Defect | Fix |
|---|---|---|
| HIGH | Briefing transmitted a RESTRICTED human-identity lead to the model vendor; the docstring claimed it was "structurally absent". The import-contract defence was a red herring — the material arrived via the graph a pivot populated. | Disclosure-class filter in `_brief`, pivots on internal-class entities refused, fail-closed backstop |
| MEDIUM | A hanging `pilot.propose()` parked the session forever; the move ceiling counts iterations, not seconds | `asyncio.wait_for(propose_timeout)` |
| LOW | `parse_tool_call` raised `AttributeError` on a non-dict `message` where the Anthropic mirror returned a sentinel | `isinstance(message, Mapping)` guard |
| LOW | A containment test claimed "never propagates the exception"; `drive` catches `Exception`, not `BaseException` | Narrowed the claim, added a propagation test |
| MEDIUM | `PilotSession.refused_effects` filtered on `effect_outcome`, so refusals raised before the Effects plane were not counted — the summary said 2 where the transcript showed 5 | Keyed on the move, pinned by a test |
| LOW | A tool-call `kind` inside the arguments could override the tool *name*, so the audit trail would record the wrong verb | Tool name is authoritative; `kind` stripped from arguments in both seats |

---

## Ground rules for the review

- Cite `file:line`. A finding whose citation does not contain what it claims is `UNVERIFIABLE` at
  best.
- A docstring is a **claim to be checked**, never evidence. This repository has repeatedly shipped
  confidently-worded docstrings describing controls the code did not enforce — that is the single
  most productive place to look.
- Run things: `uv run pytest <file> -q` works, and the fastest way to prove a finding is a failing
  test that constructs the attack.
- Report the ratio (confirmed / refuted / unverifiable). It tells the reader how much to trust the
  rest.
