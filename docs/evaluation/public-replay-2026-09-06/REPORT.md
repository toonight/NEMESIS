# First public-case retrieval evaluation

**SIMULATED collection; IMPLEMENTED NEMESIS execution.** Run on 6 September 2026, using the
installed local `qwen3.8:27b-q8_0` model and a deterministic breadth-first reference.

**The local pilot did not improve retrieval in this experiment.** It recovered six of nine
selected published assertions, versus all nine for the reference. Two completed summaries
incorrectly said no evidence had been collected. This supports keeping NEMESIS in laboratory
status and prioritizing what the pilot can see and remember before expanding its features.

## Measured results

| Case | Baseline recall | Local recall | Baseline queries | Local queries | Local repeated queries | Baseline seconds | Local seconds |
|---|---:|---:|---:|---:|---:|---:|---:|
| R17 — 3CX excerpt | 3/3 | 2/3 | 7 | 7 | 2 | 0.024 | 338.81 |
| R42 — BEATDROP excerpt | 3/3 | 2/3 | 8 | 5 | 0 | 0.023 | 211.33 |
| R83 — Solorigate excerpt | 3/3 | 2/3 | 8 | 7 | 4 | 0.020 | 329.46 |
| Total | **9/9** | **6/9** | **23** | **19** | **6** | **0.067** | **879.59** |

The local run took approximately 14 minutes 40 seconds and reported **48,598 tokens**, with
complete per-turn token metadata. The original score field named `connector_calls` counts query attempts, including one
unsupported local query with no connector to invoke: **18 actual local connector invocations**.
The current runner separates `query_attempts` and `connector_calls`; the original scores and
[evaluated replay implementation](replay-snapshot.py.txt) are preserved. The baseline made no model requests; its provider token field is null
because it has no provider meter. The local model's four fewer query attempts came with three
missed assertions. This is not an efficiency gain at equivalent recall.

The local arm used 22 moves and the baseline 24, with the same maximum of eight per case.
The local run had one unsupported query and one refused malformed move. R83 ended without a
valid conclusion. No effect was requested in either arm. Monetary cost, power consumption,
hardware amortization and analyst time were **not measured**. Fixture query units are not
real API prices. Wall-clock timing includes local inference and possibly model loading; it
must not be extrapolated to hosted models or real source response times.

[Machine-readable scores](scores.json) · [Frozen manifest](manifest.json) ·
[Hashes of the complete run matrix](runs-sealed.json)

## Manual review of the captured trajectories

These are observations about the captured run, not an independently adjudicated error rate.
Attribution accuracy and false-positive rate remain unmeasured.

- **R17:** the pilot collected historical DNS assertions in turns 1 and 2, then its final
  `conclude` said no evidence was sealed and no entities were discovered. That contradicts the
  recorded rulings. It never requested `threat_intel_lookup` on the seed, missing the report's
  POOLRAT communication assertion. See the [full R17 trajectory](runs/R17-local.json).
- **R42:** the pilot discovered the downloader and the subsequent payload, but stopped with
  budget remaining before extracting C2 from the downloader. Its final summary again described
  its previous queries as producing no evidence or new entities. The omitted assertion was
  the second service endpoint. See the [full R42 trajectory](runs/R42-local.json).
- **R83:** the pilot retrieved the C2 hostname and its parent relationship, then requested
  unsupported registration records and repeated the seed's empty resolution query four times.
  Its final output was not a valid move and was refused. It never looked up the malware to
  retrieve the separate vendor API activation check. See the [full R83 trajectory](runs/R83-local.json).

The summaries contain no explicit positive actor attribution, and neither arm requests an
effect. That does **not** establish a low false-positive rate: the corpus has nine selected
positive assertions and no representative negative population. With no performed effects,
this is also not a new effects-containment experiment.

## What the experiment identifies

The collection path preserves published assertions as labelled synthetic evidence, and the
same pipeline can retrieve all selected facts with a small deterministic traversal. The local
pilot's behavior reduces that coverage and misreports its own progress.

The pilot's `Briefing` has no observation text, relationship triples or source artifacts, and
only the most recent ruling. The replay wrapper supplies an attempted-query list to both arms,
without earlier result counts. Those are visible interface limits. **It is an inference** that
richer structured evidence context and durable result memory would help; this run does not
isolate their causal effect from the model's capabilities. In particular, the model repeated
queries despite receiving an attempt history.

The next improvements are **PROPOSED**, not silently mixed into this measurement:

1. Expose a bounded, disclosure-filtered view of collected relationships, source references,
   dates and cumulative positive/empty/failed results through the pilot seam.
2. Retain query-result memory and test explicit loop handling on a fresh corpus, including
   retrieval failures and shared legitimate services.
3. Compare the revised configuration with the same simple reference, then evaluate independently
   prepared new cases and analyst-graded conclusions. Operational validation remains
   **REQUIRES_EXTERNAL_DATA**.

## Provenance and limits

The [protocol](../PUBLIC_REPLAY.md) specifies three anonymized public-report excerpts from
Mandiant and Microsoft. The selected facts, retrieval index and expected answers were curated
here. This is a small, constructed retrieval exercise, not independent operational ground truth.
No confidence interval or general claim of model inferiority follows from three cases, one model
and one seed. The result does not evaluate an external frontier model or the Evolution driver.

The inputs and answers were hashed before execution. All six trajectories were persisted and
sealed before a separate scoring invocation opened the answers. The first pass is retained,
including unsuccessful queries, repeated queries, malformed output and wrong summaries. No
prompt, query budget, corpus annotation or pilot behavior was tuned after observing it.

A post-run code review found a metadata defect: this original manifest's `engine_digest` field
contains the **confidence-value digest**, not the full source-code digest. The original manifest
and [exact runner snapshot](runner-snapshot.py.txt) are preserved rather than repaired in place.
The current runner fixes that check and has a regression test; this first run cannot claim a
pre-execution source-integrity gate. A [source snapshot digest](evaluated-engine.json) was captured
afterward and is labelled with that timing. Input, answer and trajectory integrity checks did run.

All 43 confidence-value digests remain unchanged. These results change the assessment of the
current pilot path, not NEMESIS's confidence weights. Local storage audit/vault checks and the
repository test suite are reported in the change's validation record, separately from the
analytical result.
