# A/B frontier protocol validation

**PROPOSED / REQUIRES_EXTERNAL_DATA.** The frontier mechanism and the experiment's control
boundary work, but the protocol is not yet capable of producing a defensible live-model A/B
result. No hosted frontier seat, credential, or model identifier was configured, so no model
response or comparative effect estimate was fabricated.

## What was tested

| Check | Result |
|---|---|
| System prompt version | PASS: `2026-08-22` |
| System prompt digest | PASS: `280cc00ac80f8c4d` |
| Move-tool schema digest | PASS: `1acf5fe818d36547` |
| Closed four-tool vocabulary and required arguments | PASS |
| Arm A empty frontier | PASS in memory; the wire carries `"frontier": []` |
| Arm B ranked frontier | PASS: four initial entries ranked 0.80, 0.65, 0.55, 0.40 |
| Frontier entries restricted to already disclosed entities | PASS |
| Pilot-selected pivots receive policy priors and hypothesis labels | PASS |
| Identical fixed pilot has equal effects in both arms | PASS |
| Targeted frontier and isolation tests | PASS: 20 tests |
| Ruff and strict mypy | PASS |
| Full repository test suite | PASS outside the outer Codex sandbox |
| Prohibited-content scan | PASS |
| Live frontier-model sessions | NOT RUN: provider, credential, and model are absent |

The fixed-pilot equivalence check used `max_moves=8` and the same four-pivot sequence in each
arm. Both arms executed the same pivots, produced three claims, received five accepted rulings,
and concluded with the same outcome. Arm A exposed frontier lengths `[0, 0, 0, 0, 0]`; Arm B
exposed `[4, 7, 7, 6, 5]`. This establishes that populating the frontier changes the pilot's
information without independently changing the mediator's control decisions.

## Blocking findings

1. **The protocol is not runnable as written.** It provides no runner, provider/model identifier,
   exact connector manifest, fixed `as_of`, decoding values, retry policy, or output schema. The
   repository's available test fixture uses simulated connectors at
   `2026-03-10T00:00:00Z`; that choice is not declared in the protocol.
2. **The arm description is wrong at the wire boundary.** `PilotContext.user_content()` serializes
   all briefing fields. Arm A therefore transmits `"frontier": []`; Arm B transmits the same key
   populated. The treatment is the value of one field, not the presence of a new key.
3. **The available rig defaults to 40 moves.** The protocol requires eight. A dedicated runner
   must pass `max_moves=8`; the existing `_brief_once` fixture does not demonstrate that setting.
4. **Hypothesis settlement is an inert outcome.** H1/H2/H3 are opened, but the current pursuit
   path never transitions them from `OPEN` to `SUPPORTED`, `REFUTED`, or `UNDECIDABLE`.
   “Hypotheses settled” would therefore be constant and cannot measure either arm.
5. **The drift control and significance plan conflict at the proposed sample size.** Six paired
   A/B blocks permit only 64 sign assignments, so the smallest two-sided paired exact p-value is
   `2/64 = 0.03125`. It cannot cross the stated Bonferroni threshold of 0.01. Treating the 12
   sessions as unpaired gives 924 allocations and a minimum p-value of approximately 0.00216,
   but discards the pairing introduced to control provider drift. Eight pairs are the minimum
   that can attain a two-sided paired p-value below 0.01 (`2/256 = 0.0078125`).
6. **`top_p` cannot be held constant by this implementation.** `DecodingParameters` supports
   maximum output tokens, temperature, reasoning effort, and an optional seed. It has no
   `top_p` field, and provider payloads do not send one.
7. **The five tested metrics are not predeclared.** The protocol lists more than five possible
   measures without naming the five inferential outcomes, their session-level aggregation,
   zero-denominator handling, direction of benefit, or primary outcome. Applying Bonferroni
   after observing the results would not repair this ambiguity.

## Required changes before a paid live run

- Add a runner that writes one immutable result per session and fixes `max_moves=8`, total
  budget, seed, connectors, `as_of`, retry policy, model, reasoning effort, temperature, output
  limit, and seed support.
- Use eight randomized A/B pairs if provider drift is handled by pairing, and apply an exact
  paired sign-flip permutation test to session-level differences.
- Remove hypothesis settlement until a tested state-transition mechanism exists.
- Declare one primary comparison and exactly four secondary comparisons before collecting data.
  Keep Arm-B on-frontier and top-ranked rates descriptive unless a null model for those rates is
  declared.
- Record configured and provider-reported model identifiers, substitution, retries, latency,
  token usage, prompt digest, schema digest, and the exact serialized user message for every
  turn.

The protocol's central idea survives validation: a non-empty ranked frontier is an isolated,
advisory treatment and does not widen authority. The current document can support a preflight,
but not yet the live causal claim it proposes to measure.
