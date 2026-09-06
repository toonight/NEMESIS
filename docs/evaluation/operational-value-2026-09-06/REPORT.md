# Operational value evidence card

**Result: operational control value demonstrated in the laboratory.** NEMESIS retained complete
retrieval on the selected public-report corpus while adding evidence traceability, tamper
detection, auditable decisions and enforced authorization boundaries.

This is a narrower and more useful claim than saying the autonomous pilot is operationally
valuable. The first local-model evaluation did not show that: it retrieved 6/9 selected facts
against 9/9 for a deterministic traversal. The value demonstrated here belongs to the NEMESIS
framework around the pilot.

## Predefined gates

| Gate | Measured result |
|---|---:|
| Selected report assertions retrieved | **9/9** |
| Observation claims backed by sealed evidence | **9/9** |
| Original evidence vaults and audit chains intact | **3/3 cases** |
| Modified artifact detected on a disposable copy | **PASS** |
| Modified audit event detected on a disposable copy | **PASS** |
| Rescore from persisted run records identical | **PASS** |
| Control properties under adversarial scripted pilots | **40/40 runs** |
| Effect requests actually exercised | **64** |
| Authorized simulated effects accepted | **16** |
| Effects refused by controls | **48** |
| External contacts observed | **0** |
| Model belief promoted to evidence | **0** |

All ten gates in the machine-readable card passed. The control suite did not merely verify a
system that refuses everything: it accepted sixteen authorized rehearsals and rejected forty-eight
requests that crossed adapter, operation, target or budget boundaries.

[Machine-readable evidence card](evidence-card.json) · [R17 run](runs/R17.json) ·
[R42 run](runs/R42.json) · [R83 run](runs/R83.json)

## What is operationally useful now

NEMESIS can serve today as a laboratory workflow for a controlled investigation:

1. A deterministic investigator retrieved every selected assertion through the real mediator,
   graph, claim store, evidence vault and audit trail in 23 offline connector calls.
2. Every resulting observation remained linked to sealed source material. Altering a copied
   artifact broke vault verification, and altering a copied audit event broke chain verification.
3. Untrusted pilot behavior remained descriptive. Its beliefs did not become evidence, and its
   requested effects stayed inside the signed capability, target and budget constraints.
4. The persisted case records reproduced the same retrieval scores, so a reviewer can inspect
   the path that produced the result rather than trust a summary.

That is concrete operational value for evidentiary discipline and risk containment. It reduces
two failure classes the project was designed around: an unsupported model assertion entering the
evidence record, and an unauthorized effect leaving the investigation boundary.

## What this does not prove

The corpus is a **SIMULATED** reconstruction of three curated public reports. The 0.045-second
retrieval time measures in-memory fixtures, not real source latency. The adversarial pilots are
scripts written in this repository. No real takedown, notice, scan, probe or external contact was
attempted. No blind analyst comparison, representative negative population or independent
ground-truth adjudication exists here.

Therefore this result does not establish:

- autonomous-pilot uplift, attribution accuracy or novel infrastructure discovery;
- analyst minutes saved, monetary return, infrastructure cost or incident impact;
- superiority over another platform offering comparable provenance and authorization controls;
- production readiness or resistance to attacks absent from the scripted perturbations.

Economic value and autonomous-pilot value remain explicitly false in the evidence card, with
their measurements left null. Demonstrating those requires a prospective shadow deployment with
licensed or operator-owned sources, independent labels, analyst timing and repeated cases. That
work remains **REQUIRES_EXTERNAL_DATA**.

## Reproduction

With the repository dependencies installed:

```bash
uv run python scripts/demonstrate_operational_value.py \
  --out /tmp/nemesis-operational-value \
  --base-commit "$(git rev-parse HEAD)"
```

The command is offline. It uses only fixture-backed connectors and simulated effects. It exits
non-zero if any operational gate fails. The evidence card records the runner, corpus, answer,
engine and confidence-value digests. The retained result was measured from base commit
`13cd471ad48b703d27a7fccf9ad8d85b700ecdd4`; the demonstration script and this report are the
change being reviewed.

The underlying public-case methodology and source links are documented in
[the replay protocol](../PUBLIC_REPLAY.md).
