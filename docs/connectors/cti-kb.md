# CTI knowledge-base adapters (KB allowlist + local-model output)

**Status:** `IMPLEMENTED`. These are pure, in-process adapters — no I/O, no network, no model SDK.
They turn the local `cti-toolkit`'s artifacts into first-class NEMESIS objects without letting the
toolkit itself into the package.

## `parse_cti_kb` — KB cards to reviewable onion candidates

`nemesis.collect.cti_kb.parse_cti_kb` is the KB-card sibling of `parse_deepdarkcti`. It takes the
*text* of operator-supplied `kb/actor-*.md` cards and produces validated
`OnionService` **candidates** for `TorOnionConnector`'s allowlist, plus a reconciling `CtiKbReport`.

It keeps the deepdarkCTI parser's discipline exactly:

- **No fetch, ever.** Pure text-to-structure. Approving a candidate and collecting from it stay a
  separate, operator-gated, kernel-confined act (invariant 15). The output is a *proposal*.
- **No credentials.** A card is untrusted (invariant 5); if any onion embeds `user:password@`, the
  whole card is dropped and counted.
- **No trust in the card.** Every onion is re-validated through the connector's v3-checksum gate;
  the entity type (forum vs marketplace) is inferred from the card's category.
- **No illegal-content target.** A card whose text carries an illegal-content indicator is dropped
  and counted, never turned into a collection target — material that must be reported is not
  material to add to a monitoring allowlist.

Every accepted candidate is `MANDATORY_REPORT` by default (a leak site holds stolen victim data), so
`must_not_be_indexed` follows. One candidate is emitted per card (the first onion that validates),
which keeps the report's arithmetic a single reconciling sum:
`cards_seen == accepted + dropped_no_onion + dropped_invalid_onion + dropped_duplicate +
dropped_bad_name + credentials_dropped + illegal_content_dropped`. A card's additional mirror
addresses are for the operator to add explicitly, or to recover from the raw `deepdarkCTI` index via
`parse_deepdarkcti`, which counts at the row level.

```python
from pathlib import Path
from nemesis.collect.cti_kb import parse_cti_kb, candidate_summary

cards = [p.read_text() for p in Path("~/cti-toolkit/kb").expanduser().glob("actor-*.md")]
report = parse_cti_kb(cards)
print(report.render())
for line in candidate_summary(report):  # name -> onion host [safety]; never the URL path
    print(line)
```

## `ingest_model_assessment` — the local model's output as a lead, never a fact

`nemesis.collect.cybertiel` takes the output of `ct_rag.py` / `triage_cybertiel.py` (produced out of
process) and turns it into a `Claim`:

- kind `HYPOTHESIS`, or `INFERENCE` when it cites the card claims it was grounded in — never an
  `OBSERVATION` or `FACT` (invariant 1, enforced in `Claim`'s own validator);
- `derivation=MODEL_ASSERTION` with `model_identifier` set — *which* model said it is part of the
  claim;
- a `DeceptionAssessment` on every claim (a planted page can steer the model's label);
- a refusal to name a human identity as subject or object.

The model is a separate process and is **never imported** (`scripts/check_prohibited.py` bans the
model SDKs). Only the *structured* assessment is carried into the graph — the model's free-text
rationale is deliberately not, so nothing an adversary planted in a page the model read rides out of
this boundary as instruction or material. `triage_row_to_assessment` is the direct bridge from a
triage JSON row (`intel_type`, `cti_value`, `risk`), refusing a row that recorded a parse failure.

```python
from datetime import UTC, datetime
from nemesis.collect.cybertiel import triage_row_to_assessment
from nemesis.core.entities import EntityType

claim = triage_row_to_assessment(
    {
        "intel_type": "ransomware_dls",
        "cti_value": 5,
        "risk": ["exposes_victim_pii"],
        "model": "CyberTiel-...",
    },
    subject=(EntityType.MARKETPLACE, "some-leak-site"),
    asserted_by=pilot_actor_id,
    asserted_at=datetime.now(UTC),
)
# claim.kind is HYPOTHESIS; claim.derivation is MODEL_ASSERTION
```

## On credentials — a deliberate omission

Neither adapter imports `nemesis.core.credentials`. Invariant **AUTH-04** keeps the credential types
importable by exactly one module so that discovery cannot be wired to use; `CLAUDE.md` forbids
weakening that. The collect plane instead relies on the stronger structural guarantee that it never
stores adversary-authored free text (a victim name is a node key, a summary is a fixed template, a
model rationale is not carried into the graph), so there is nothing to redact. Representing a
discovered credential as a keyed `CredentialIndicator` is the engine's job, behind AUTH-04's
independent authorization path — see ADR-0016.
