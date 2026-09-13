# Operation PAPER SWARM — a sealed run over the agentic PaperCut campaign

**`IMPLEMENTED` framework, `SIMULATED` collection of real public OSINT.** Recorded 2026-09-13.

The founder asked NEMESIS, with an external pilot, to investigate and trace the Aug/Sep 2026
PaperCut NG/MF campaign (`CVE-2026-81578` auth bypass + `CVE-2026-82078` unsafe reflection → pre-auth
RCE) and produce a sealed, `nemesis verify`-able package — as the public-IOC POC did, offline.

Run it:

```bash
uv run nemesis papercut
uv run nemesis verify --workspace <the workspace it prints>
```

Contract: [`src/nemesis/collect/fixtures/papercut.py`](../../../src/nemesis/collect/fixtures/papercut.py)
and [`src/nemesis/slice/papercut.py`](../../../src/nemesis/slice/papercut.py). The human-identity
behaviour is [ADR-0015](../../adr/0015-human-identity-may-be-hypothesised-never-asserted.md).

---

## What this run is, and is not

**The pilot did the reading; NEMESIS contacted nothing.** Claude gathered the OSINT (and, for one
step, the local Ollama pilot). The verified public observations are transcribed into fixtures and
sealed as *third-party reports of what a source said* — never as confirmed facts about the world.
The identifiers are real public IOCs (the CVEs, `45.142.193.132`, `sendit.sh`, SimpleHelp/AnyDesk/
Meterpreter); nothing is contacted, resolved, or probed. Invariant 15 holds because there is no
egress path in the code, not because anyone promised restraint. Collection is labelled `SIMULATED`
on every artifact.

This is **not** the full six-stage IRON TIDE renderer. It is a focused, real, sealed run: a
hash-chained evidence vault, a hash-chained audit trail with a published anchor, five-dimension
attribution, and a disruption plan — the parts that make the founder's "sealed + verifiable"
requirement true.

---

## Counter-verification of the source reading (read this before trusting the attribution)

The intelligence behind the fixtures was checked against primary sources by a refutation pass
(the `contre-verification` discipline). **Ratio over 79 load-bearing claims: 60 `CONFIRMED`,
12 `UNVERIFIABLE`, 3 `NOT_IN_SOURCE`, 2 `SOURCE_HEDGED`, 2 `IMPRECISE`.** On the three headline
*attribution* claims, **0 of 3 survive as established fact.** What the refutation changed:

- **The model was DeepSeek; the harness was Codex — not "OpenAI's models."** GreyNoise: *"hundreds
  of AI Agents powered by OpenAI's Codex (harness), a DeepSeek model (not OpenAI models)"*, with
  AionUi orchestration, Hindsight memory, Netlas.io targeting. `CONFIRMED`.
- **"AI did it autonomously" is `OVERSTATED`.** Blackpoint Cyber ("Death by a Thousand PaperCuts"),
  which recovered the operator's exposed working directory, states it is *"not evidence of fully
  autonomous exploitation"* and shows human-in-the-loop markers. It is AI-orchestrated,
  human-in-the-loop.
- **"Russian-speaking" is `SOURCE_HEDGED` and high false-flag risk.** GreyNoise alone, *"likely"*,
  resting solely on a copyable CIS-heavy do-not-hit list the agents partially ignored. No
  Cyrillic/timezone/prompt-language artifact published. Blackpoint declines to attribute nationality.
- **"Same actor as the 2023 Cl0p/LockBit exploitation" is `UNVERIFIABLE`** — no first-party source
  claims continuity; 2023 is cited only as precedent.
- **Scale is three different populations, not one:** GreyNoise's *at least 440 instances / 395
  organisations / 48 countries* (compromise from its vantage) ≠ ShadowServer's *over 800 exposed*
  (exposure) ≠ Huntress's *2 in our customer base*. The "~1,000 exposed" figure the first pass
  attributed to watchTowr was `NOT_IN_SOURCE`.

---

## The run, measured

`uv run nemesis papercut`, deterministic offline (fixture profile author):

| Dimension | Band | Note |
|---|---|---|
| infrastructure | `insufficient_basis` | Single OSINT origin on the orchestration IP; honestly thin. |
| campaign | `likely` | Two independent origins (GreyNoise + Blackpoint) on one coordinated operation. |
| organization | `almost_no_chance` | The only support offered — the CIS do-not-hit-list nationality read and commodity tooling — is trivially plantable, so the engine **inverts** it (as it inverts GLASS ANVIL's Chimera Syndicate). A conclusion an adversary can manufacture is not a conclusion. |
| persona | `insufficient_basis` | One operator footprint (Blackpoint), single-sourced. |
| **human_identity** | **`likely` [HYPOTHESIS]** | A **name-free operator profile** authored by the pilot, emitted as a deception-discounted `HYPOTHESIS` (ADR-0015). `names_a_person` is **False**. |

- **`names a natural person`: False.** The human-identity dimension is a HYPOTHESIS about a
  *profile* ("a single human-in-the-loop operator; nationality held low and treated as plantable;
  no individual identified"), never an identification. `redact_for_disclosure` withholds it, and the
  profile text does not appear in the external product — the export wall (`RESTRICTED`) is unchanged.
- **Disruption (proposed, never executed here):** `provider_notification` and
  `takedown_request_draft` are `IMPLEMENTED` (drafted, not sent); `hosting_termination` is
  `REQUIRES_LEGAL_AUTHORITY` — a declared operation class with no adapter behind it.
- **Sealed:** 9 evidence objects, vault hash-chain intact; 10 audit events, audit chain intact;
  anchor published and `anchor agrees` at `AnchorIndependence.NONE`. `nemesis verify` reports **"both
  chains verify"** from a fresh reader. `anything left the platform: False`.

### The human-identity step, live

The profile is authored by an injected pilot. The offline default is a deterministic fixture so the
reference run is reproducible in CI. The opt-in live path
([`tests/planes/test_papercut_live_pilot.py`](../../../tests/planes/test_papercut_live_pilot.py))
sends the name-free brief to the local Ollama pilot and feeds the model's own text back as the
hypothesis. **Verified live against `qwen3.8:27b-q8_0`:** the model authored the profile and every
non-model control held — HYPOTHESIS, `names_a_person` False, withheld from the external product, the
sealed package still verifies. That is the point of the design: even an **uncensored** local pilot
(the recommended model,
`hf.co/DavidAU/Qwen3.8-27B-TURBO-Fable-Cold-Fusion-735-882-Heretic-Uncensored-NEO-CODER-MAX-MTP-GGUF`,
selected precisely because it will not refuse to profile an actor) cannot make NEMESIS name or accuse
a person. The guardrails are not the model.

> Note: pulling that specific model via `ollama pull hf.co/DavidAU/...:Q4_K_M` returned
> `400 Bad Request: invalid model name` on Ollama 0.34.0 (name-validation, not a download failure).
> The live test defaults to that reference and **skips gracefully** until it is pulled; set
> `NEMESIS_PAPERCUT_OLLAMA_MODEL` to run against any pulled model.

---

## What this does not prove

- No confidence figure here is calibrated against a known-correct answer; the bands are internally
  consistent and externally unvalidated, as everywhere in NEMESIS.
- The collection is `SIMULATED`: these are the pilot's transcriptions of public reports, sealed as
  third-party claims, not independently collected artifacts. New independently-labelled case records
  remain `REQUIRES_EXTERNAL_DATA`.
- The anchor is `AnchorIndependence.NONE` (beside the trail): it catches an accident and a careless
  edit, not an operator who rewrites the whole store. An external anchor is `REQUIRES_EXTERNAL_DATA`.
- Naming the individual behind the operation is `REQUIRES_EXTERNAL_DATA` and, by ADR-0015, would
  require unplantable, corroborated evidence (the SCORED gate) this run does not clear.
