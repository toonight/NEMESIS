# ADR-0015 — Human identity may be hypothesised, never asserted

**Status: ACCEPTED, 2026-09-12.** Founder decision. Supersedes the "human identity is refused
structurally before scoring, and emits nothing" design as it stood in
[IRON_TIDE §3.5](../architecture/IRON_TIDE.md) and in the refuse-only branch of the identity
gate. It does **not** touch founder decision D1's export wall
([ADR references in `attribute/disclosure.py`](../../src/nemesis/attribute/disclosure.py)),
which is unchanged and stays unchanged.

---

## Context

The `HUMAN_IDENTITY` dimension had exactly two outcomes: a strong-shape gate *passed* (scored,
and only then could a natural person be named) or the gate *refused*, before scoring, emitting
nothing but a reason. The refusal was the safe default and it is a good default: naming a natural
person is the single most damaging output this platform can produce, it is irreversible once it
leaves the building, and in a pursued operation the name on offer is as likely to have been
placed for us to find as to be true.

But a pursuit platform that can *never even hypothesise* about the human behind an operation is,
in the founder's words, pointless — "ça rime à rien". The whole point of PURSUE → ATTRIBUTE is to
reach, carefully and with owned uncertainty, toward the operator. Refusing to hold any hypothesis
at all is not caution; it is abdication. The Intelligence Graph is *built* to admit speculation
(invariant 2); the dimension that most needs it was the one forbidden from producing any.

The tension is real and it is not resolved by wishing it away: a hypothesis that names a person
on thin, plantable evidence *is* the accusation the wall exists to prevent, whatever label sits
on top of it.

## Decision

Emit hypotheses; never emit an accusation. Concretely, four rules, three of them enforced in code
the model cannot reach.

1. **The strong-shape gate is unchanged.** `run_identity_gate` still decides one thing — whether
   the evidence has the *shape* to name a person (≥2 independent origins, ≥1 outside a channel the
   adversary can write into, ≥1 corroborated statement, no model in the support). That, and only
   that, is `IdentityDisposition.SCORED`: the sole disposition that may assert a natural person's
   identity. Even then the finding is `RESTRICTED` and cannot reach an external product.

2. **The former refuse branch splits by `IdentityDisposition`.**
   - `WITHHELD` when there is nothing to hypothesise (`NO_EVIDENCE`) **or** when every supporting
     signal sits in a channel the adversary can write into (`ONLY_ADVERSARY_INFLUENCEABLE`).
     Hypothesising from a plant is doing the adversary's work; WITHHELD does not repeat the name.
     This is where GLASS ANVIL and IRON TIDE land — their identity lead is a single anonymous
     post in an adversary-writable channel — so their behaviour is unchanged.
   - `HYPOTHESIS` otherwise: a legitimate but insufficient lead (a single reputable OSINT origin,
     a model-authored inference). The dimension emits a deception-discounted hypothesis with
     **explicit, low confidence** — invariant 4 applied to the hardest dimension — run through the
     same `_orient` inversion and planting alternatives as every other dimension, so a cheaply
     plantable support collapses the estimate rather than raising it.

3. **A hypothesis names no natural person as a finding.** `AttributionResult.names_a_person` is
   True only for `SCORED`. `HYPOTHESIS` and `WITHHELD` are both False. And the export wall is
   untouched: `HUMAN_IDENTITY` stays `RESTRICTED`, `redact_for_disclosure` drops it, and
   `ExternalAttributionProduct` has no field that can carry it. So "émettre des hypothèses sans
   accuser qui que ce soit" is implemented literally: the hypothesis lives in the Intelligence
   Graph; nothing that names a person crosses into a deliverable without unplantable, corroborated
   evidence — which is exactly the `SCORED` gate.

4. **Invariant 1 is preserved.** A model's say-so may *contribute to a hypothesis* — the
   Intelligence Graph admits speculation — but can never produce a `SCORED` naming, because the
   gate still refuses model-derived support for `SCORED`. The reference wiring has the **local
   Ollama pilot** author the hypothesis text; the engine mints it as a `HYPOTHESIS` claim, never
   an `EvidenceObject`. A model proposing a candidate is a lead; a model naming a person is not
   evidence, and the code enforces the difference.

## Consequences

- The identity-wall export tests (`tests/invariants/test_identity_wall.py`) are unchanged: the
  wall did not move.
- GLASS ANVIL, IRON TIDE and the calibration scenario route to `WITHHELD`; their published bands
  and their `names_a_person is False` acceptance criteria are unchanged. The calibration freeze
  re-freezes because two module *syntax digests* changed (added code), not because any band moved.
- `CLAUDE.md`'s invariant list, `PROJECT_STATE.md` and `IRON_TIDE.md §3.5` are updated to state the
  new contract as a documented label change, not a silent promotion.

## What this does not do

- It does not let a natural person's name leave the platform. The `RESTRICTED` wall is the
  boundary and it did not move.
- It does not weaken the `SCORED` gate. Naming a person as a finding still requires the same
  unplantable, corroborated, model-free shape it always did.
- It does not enable naming a person on plantable or single-adversary-channel evidence — that
  routes to `WITHHELD`, not `HYPOTHESIS`.
