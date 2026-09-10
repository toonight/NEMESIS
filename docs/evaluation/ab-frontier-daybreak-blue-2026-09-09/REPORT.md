# A/B frontier — Daybreak Blue

**SUPPORTED IN THIS RIG / NOT YET GENERALIZED.** A complete 6+6 session run with
`gpt-daybreak-blue-latest` shows that the ranked frontier materially improves the value obtained
per unit of simulated collection cost. The effect survives the protocol's five-metric Bonferroni
threshold. It does not yet show better attribution or hypothesis settlement.

## Verdict

The frontier has operational value for this pilot and fixture:

- mean value per cost increased from **0.4753** to **0.6872**: **+0.2118 / +44.6%**;
- the exact unpaired permutation p-value is **0.002164** over all 924 allocations and survives
  the declared **0.01** threshold;
- Daybreak Blue chose an offered frontier pivot on **45/45** proposals and the top-ranked pivot
  on **33/45 (73.3%)**;
- repeated pivot types fell from **11/41 (26.8%)** in Arm A to **0/45** in Arm B;
- mean distinct pivot types per session increased from **5.0** to **7.5**.

This is the protocol's “interesting case”: the model uses the frontier consistently while still
overriding its first-ranked entry 26.7% of the time. The frontier guides the pilot without merely
turning it into a deterministic sort executor.

## Execution identity

| Property | Recorded value |
|---|---:|
| Model configured in Codex CLI | `gpt-daybreak-blue-latest` |
| Reasoning effort | `high` |
| Sessions | 6 Arm A + 6 Arm B |
| Move ceiling | 8 |
| Local LLM calls | 0 |
| Prompt version | `2026-08-22` |
| Prompt digest | `280cc00ac80f8c4d` |
| Tool schema digest | `1acf5fe818d36547` |
| Input tokens reported | 1,679,162 |
| Output tokens reported | 13,728 |
| Provider failures after retry | 0 |
| Malformed moves / refusals | 0 / 0 |

The arms alternated A, B for six blocks. Both used the same synthetic seed, simulated connectors,
fixed `as_of`, budget, envelope, prompt, schemas, model, reasoning effort and move ceiling. Arm A
received `"frontier": []`; Arm B received the ranked frontier produced by
`RuleBasedPursuitPolicy`.

## Five declared comparisons

| Session-level metric | Arm A mean | Arm B mean | B − A | Exact p | At 0.01 |
|---|---:|---:|---:|---:|---:|
| value per cost | 0.4753 | 0.6872 | +0.2118 | 0.002164 | **PASS** |
| expected information gain | 0.4899 | 0.6576 | +0.1677 | 0.062771 | no |
| claims per pivot | 1.1032 | 1.6071 | +0.5040 | 0.181818 | no |
| pivots executed | 6.8333 | 7.5000 | +0.6667 | 0.121212 | no |
| shared-infrastructure fraction | 0.0000 | 0.0000 | 0.0000 | 1.000000 | no |

The test enumerated every `C(12, 6) = 924` unpaired allocation, as written in the protocol. Arm B
also produced 72 claims versus 46 in Arm A, but raw totals are descriptive because move counts
differed. The normalized claims result did not reach the adjusted threshold.

## What the run demonstrates

The frontier removed unproductive repetition and exposed a broader sequence of admissible pivots.
Every Arm B session used seven or eight distinct pivot types. Arm A averaged five and repeated
resolution, registration, certificate reuse, hosting-neighbour or service-fingerprint collection.
The complete separation in value per cost—every Arm B session scored above every Arm A
session—produced the smallest possible two-sided p-value for a 6+6 exact unpaired test.

NEMESIS retained control throughout. Daybreak Blue proposed moves; the mediator validated every
move against the disclosed entities, closed tool vocabulary, budget and simulation-only envelope.
No effect execution, external contact, local model or dark-web collection was part of this A/B.

## Limits on the claim

This is a repeated synthetic fixture, not a representative set of real IOCs. The sessions are
model replications over the same evidence graph, so the permutation test can overstate
generalization across investigations. The next confirmatory run should use multiple frozen IOCs
and at least eight paired blocks, then use the paired sign-flip analysis described by the
preflight.

All three hypotheses remained open in every session. The current rig therefore cannot establish
that the frontier improves hypothesis settlement, attribution correctness or analyst decision
quality. Arm B outcomes split evenly between `attribution_uncertain` and `scope_exhausted`.

The model was invoked through `codex exec`. Its surrounding Codex system/developer context wrapped
the verbatim NEMESIS instructions, and a constant transport instruction converted the four tool
choices into structured output. This preserves the A/B contrast but is not a pure native
`ProviderSeat` request. The CLI recorded the configured model identifier but did not emit a
separate backend-reported model field.

## Integrity

The machine-readable figures are in [result-summary.json](result-summary.json). The full transient
run summary was sealed as SHA-256
`a04aa35759e4f85ca1db1dd77342d8cbd5ab06774d1007cac67ae7b221e980f4`; the runner as
`05c51697c26ef053a118a1cbd2dad90312513364e1541e51bd4bfa96fc539f18`; and the output schema as
`540e030c5eec095468393d9f59ce3b6bab470b013aa962005ae569d20d56ceec`.
