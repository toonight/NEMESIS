# Public-report replay protocol

**IMPLEMENTED** evaluation harness; **SIMULATED** collection. This experiment asks whether a
local pilot retrieves a small set of published relationships more efficiently than a simple
breadth-first search, through the same NEMESIS mediator. It does not validate autonomous
attribution, discover new infrastructure, or establish production readiness.

The corpus contains three historical cases and nine selected assertions from two publishers:

| Case | Primary report | Excerpt represented |
|---|---|---|
| R17 | [Mandiant, 20 April 2023](https://cloud.google.com/blog/topics/threat-intelligence/3cx-software-supply-chain-compromise) | POOLRAT C2 and historical DNS overlap, including different resolution dates |
| R42 | [Mandiant, 28 April 2022](https://cloud.google.com/blog/topics/threat-intelligence/tracking-apt29-phishing-campaigns) | BEATDROP's use of Trello and delivery of BEACON |
| R83 | [Microsoft, 18 December 2020](https://www.microsoft.com/en-us/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/) | A generated Solorigate C2 hostname, its parent domain, and a separate vendor API activation check |

These reports are independent of NEMESIS's demonstrations, but the **benchmark annotations
are authored here**, not independently adjudicated. Published claims are not infallible ground
truth. Two cases share a publisher; their facts are not nine independent trials.

## Data and disclosure

`data/benchmarks/public-replay-v1/inputs.json` contains normalized report assertions and a
manually chosen query index. Domains become reserved `.example` identifiers, IPs become
RFC 5737 addresses, and malware identifiers are synthetic hashes. No malware is included.
Case names, original identifiers, source links, expected record IDs and interpretation cautions
are in `answers.json`. The model receives neither file: it gets only the mediator's briefing.

The connector observes **a reconstructed report assertion**, not the original network activity.
All evidence carries `is_simulated=True`, one upstream report identity per case, and preserved
artifact bytes. A date from a DNS table is retained; other records use the publication date as
a replay timestamp, not a claimed exact incident date. No population size, selectivity, ownership
or calibrated confidence is invented. Missing answers mean absent from the selected excerpt,
not absent in the world. Query routes are artificial retrieval affordances; these are not live
passive-DNS, malware-analysis or threat-intelligence services.

The current `Briefing` exposes entity identifiers and the last ruling, **not observation text,
relationship triples, or source artifacts**. Both arms receive an identical query menu and a
bounded list of attempted queries. The replay wrapper supplies that memory; it is not a claim
that the base provider seat is stateful. Reports retain the exact briefings so this visibility
limit can be inspected. No case-specific clues or expected labels are added to them.

## Frozen comparison

- Baseline: visit each visible entity in discovery order; try each available pivot once; stop.
- Local model: the existing Ollama `LocalPilot` and its ordinary tool schema. Defaults to the
  already installed `qwen3.8:27b-q8_0`; 512 output tokens, temperature 0.6, seed 20260906,
  no retries. Ollama's existing adapter disables hidden thinking.
- Eight moves and eight unitless query-cost units per case, including any conclusion move.
  Each real connector invocation costs one unit. Invalid/unsupported moves consume the move
  ceiling. No effects budget is available. Each arm gets fresh stores, signing key and envelope.
- One repetition, baseline before local within each case, sequential execution. No hyperparameter
  selection from the results. Cold model loading can contribute to the first model timing.
- Persist all runs before scoring. Failures and refusals remain in transcripts; they are not
  replaced by successful retries or silently omitted.

The freeze records input/answer SHA-256, engine digest, runner hash, model name, sampling settings
and host details. `run` does not open the answers. It seals the complete matrix of run JSON files;
`score` opens labels in a **separate invocation**, verifies file hashes and rejects missing runs.
This is procedural separation for a model with no filesystem tool, not a security boundary against
a local process or the benchmark author. Public cases may occur in model training; anonymization
reduces recognition but does not establish uncontaminated holdout data.

## Measurements and limits

Retrieval recall is the number of unique expected report assertions preserved through actual
collection divided by the selected expected assertions. Duplicate returns do not add credit.
This is corpus coverage, **not useful novel discoveries**, and says nothing about all the facts
omitted during curation. A simple traversal is expected to perform well on these small graphs.

Also record wall time, moves, connector calls, empty/failed queries, repeated queries, refusals,
termination, and provider-reported tokens. Missing token telemetry remains null. Query units are
not dollars. Model API invoices do not exist for this local experiment; electricity, hardware,
human effort and end-to-end production costs are unmeasured, so monetary cost remains null.

Attribution accuracy and false-positive rate remain null: nine positive assertions provide no
representative negative population. Unlabelled statements are not automatically false. Review
any free-text conclusions manually against the withheld cautions, distinguishing unsupported
claims from demonstrably incorrect ones. A model that abstains can avoid errors while achieving
nothing; always inspect recall and termination alongside that abstention.

No statistical superiority, generalization to new cases, analyst time savings, independent
calibration, production data quality or frontier-model capability can be inferred from one local
model on three curated excerpts. Operational validation remains **REQUIRES_EXTERNAL_DATA**:
new case records with independently prepared labels, realistic licensed-source latency/cost,
blind analyst review, negative controls and repeated trials.

## Reproduction

From the repository root with dependencies installed and the selected model already in Ollama:

```bash
uv run python scripts/evaluate_public_replay.py freeze --out /tmp/nemesis-replay-new
uv run python scripts/evaluate_public_replay.py run --out /tmp/nemesis-replay-new
uv run python scripts/evaluate_public_replay.py score --out /tmp/nemesis-replay-new
```

Only `run` connects anywhere, and its fixed transport addresses `127.0.0.1:11434` only. It accepts
no external endpoint or API credentials and does not follow redirects. A fresh output directory
is required; prior runs are preserved. Models need not produce identical moves despite the seed.
Normal CI uses a deterministic pilot and never contacts Ollama.

The first measured run and its interpretation are in
[public-replay-2026-09-06/REPORT.md](public-replay-2026-09-06/REPORT.md).
