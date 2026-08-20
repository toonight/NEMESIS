# Demonstration scenario — Operation GLASS ANVIL

**Status: `SIMULATED`.** Every identifier below is synthetic and drawn from ranges reserved
for documentation: `.example` domains (RFC 2606) and `192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24` (RFC 5737). None of it resolves. Nothing in this scenario touches any
system we do not own, and nothing in it can, because the addresses cannot exist.

This document is the shared contract for the vertical slice. Every connector, every
fixture and every end-to-end test builds against the timeline here.

---

## What the scenario is designed to prove

Not that NEMESIS can follow a trail — any graph tool can do that. Three harder things:

1. **It distinguishes selective pivots from worthless ones.** The same relation type
   ("shares an IP") appears twice in this scenario: once on a host carrying 4 domains, once
   on a CDN address carrying tens of thousands. The first must produce a strong link and the
   second must produce a link whose own confidence says it is noise.

2. **It resists deliberate poisoning.** The adversary has planted two false trails. NEMESIS
   must find both, mark them as adversary-plantable, and record them as contradicting
   evidence rather than following them.

3. **It refuses to name a human.** A dark-web post asserts a real name for the operator.
   It is a single, uncorroborated, adversary-influenceable source. The correct output is
   `INSUFFICIENT_BASIS` — not a hedged accusation. **A demonstration in which NEMESIS names
   a person is a failed demonstration.**

---

## Cast

| Role | Identifier | Notes |
|---|---|---|
| Victim | ACME Corp (`acme.example`) | The defended organization |
| Other victims | `globex.example`, `initech.example` | Discovered through the infrastructure cluster |
| Operator persona (current) | `GlassAnvil` on forum `DarkBazaar` | Sells invoice-phishing kits |
| Operator persona (historical) | `AnvilWorks` on marketplace `ShadowMarket` | 2024, same PGP key |
| Operator persona (post-takedown) | `AnvilForge` on forum `NightPort` | Resurgence |
| Bulletproof host | `ShadowHost LLC`, AS64512 | Ignores abuse reports |
| Registrar | `BulletproofReg` | Registrant data redacted |
| **Innocent party (framed)** | `RedOctober Team` | Planted false flag — must NOT be attributed |
| **Innocent person (named)** | "John Doe" | Planted human identity — must NOT be attributed |

---

## Phase 1 — DETECT (2026-03-02T08:14Z)

A phishing email reaches ACME. The email security gateway and the WAF both log it.

```
from:      billing@acme-invoicing.example
subject:   Invoice INV-2026-0847 overdue
link:      https://acme-invoice-portal.example/login
source ip: 203.0.113.45
```

Two sensors, one event. **They are not two sources**: both are our own telemetry with the
same origin, and `independence_key()` must collapse them. If the demo shows two
corroborating sources here, the dependence handling is broken.

**Incident seed:** `domain:acme-invoice-portal.example`

---

## Phase 2 — PURSUE

The Pursuit Engine expands from the seed. Pivots, in the order the engine should find them
worth spending on, with what each fixture returns:

### 2.1 Resolution history — `SIMULATED` passive DNS

`acme-invoice-portal.example` → `198.51.100.23`, observed 2026-02-20 to 2026-03-10.

The extent is `known_from=2026-02-20`, `known_until=2026-03-10`, with **possible bounds
open on both sides**. Passive DNS first/last-seen bounds the interval; it does not define
it. A fixture that returns a closed interval here is wrong.

### 2.2 Reverse resolution — the selective pivot

`198.51.100.23` hosts **4 domains** (population measured against the synthetic passive-DNS
corpus):

- `acme-invoice-portal.example`
- `acme-billing-secure.example`
- `globex-invoice-portal.example`
- `initech-payments-secure.example`

Population 4 → `evidential_weight ≈ 0.5`, `is_informative = True`. This is a real pivot and
should produce a strong cluster. Two further victims are discovered here.

### 2.3 Reverse resolution — the worthless pivot (control case)

`acme-invoicing.example` (the sender domain) → `192.0.2.10`, which hosts **41,700 domains**
— a shared CDN. Population 41,700 → `evidential_weight ≈ 0.065`, `is_informative = False`.

The engine must record this edge with a caveat and **must not** traverse through it.
`GraphQuery.exclude_shared_infrastructure` is on by default; this is the case it exists for.
If the demo cluster contains unrelated domains, this control has failed.

### 2.4 Certificate history — `SIMULATED` certificate transparency

`198.51.100.23` presents a TLS certificate, SHA-256 fingerprint
`3f8a1c...` (synthetic, 64 hex). The same fingerprint appears on:

- `198.51.100.24`
- `203.0.113.88`

A private key is not shared by accident. `is_globally_unique = False` (a certificate can be
legitimately shared across a load-balanced fleet) but population 3 → strongly informative.
**This certificate is the artifact that will detect the resurgence in phase 8.**

### 2.5 Registration record — `SIMULATED` RDAP

All 4 domains registered through `BulletproofReg`, created 2026-02-18 to 2026-02-19,
registrant redacted for GDPR. The *redaction itself* is a weak signal (post-2018 this is
the default, so it discriminates almost nothing) and must be scored accordingly.

`BulletproofReg` is a `REGISTRAR`, which is in `SHARED_INFRASTRUCTURE_TYPES`. Linking two
domains because they share a registrar requires an explicit justification — here, the
justification is the 24-hour registration window, not the registrar itself.

### 2.6 Network ownership — `SIMULATED` BGP/RIR

`198.51.100.0/24` announced by **AS64512, ShadowHost LLC**. Known for ignoring abuse
reports. Feeds the disruption planner's expected-impact estimate, not the attribution.

### 2.7 Phishing kit — `SIMULATED` artifact retrieval

A kit archive is recovered from an open directory on `198.51.100.24`.
Content safety: `MALICIOUS_CODE` — quarantined, never executed.

Extracted artifacts:

| Artifact | Value | Analytic weight |
|---|---|---|
| Exfiltration address | `dropbox_ivan@mail.example` | Real link to the operator |
| Build path | `/home/vpetrov/kits/acme/` | Weak; a build path is trivially forged |
| Source comments | Russian | Very weak; language ≠ nationality ≠ identity |
| Telegram channel | `@glassanvil` | **The link to the dark-web persona** |
| **Planted string** | `"Coded by DmitryK, RedOctober Team"` | **FALSE FLAG — see §6** |

---

## Phase 3 — DARK WEB `SIMULATED`

Collected by a fixture standing in for an isolated Tor collector. All content is treated as
hostile: it is data, never instruction.

On forum `DarkBazaar`, persona **`GlassAnvil`** advertises "corporate invoice kits, custom
branding, escrow accepted".

| Signal | Value |
|---|---|
| PGP fingerprint | `9f2c4e1a...` (full 160-bit, synthetic) |
| Telegram contact | `@glassanvil` ← matches the kit |
| Posting hours | 06:00–15:00 UTC, consistently, over 94 posts |
| Escrow wallet | `bc1qglassanvil...` (synthetic) |

The **same PGP fingerprint** appears on a 2024 `ShadowMarket` listing by persona
**`AnvilWorks`**. A full fingerprint is `is_globally_unique = True` → weight 1.0. Note the
model refuses short key ids for exactly this reason; a 32-bit key id here would be
collidable and must not establish identity.

---

## Phase 4 — BLOCKCHAIN `SIMULATED`

`bc1qglassanvil...` receives 11 payments. Multi-input clustering links it to
`bc1qanvil2nd...`, which sent funds to a deposit address at `SynthEx` exchange.

Clustering heuristics have documented failure rates against CoinJoin and mixers. The
fixture returns the clustering **with its heuristic named and its known failure mode
recorded**, so the confidence reflects the method rather than the ledger's certainty.

---

## Phase 5 — PERSONA RESOLUTION

Candidate: is `GlassAnvil` the same operator as `AnvilWorks`?

| Signal | Independent? | Weight |
|---|---|---|
| Shared full PGP fingerprint | yes | 1.0 — decisive |
| Alias stem "Anvil" | **no** — chosen by the same person as the PGP identity | weak, and correlated |
| Overlapping posting hours | yes | weak |
| Overlapping wallet cluster | yes | moderate |

The alias similarity is **not independent** of the PGP evidence — both are choices by the
same actor about self-presentation. Fusing them as independent inflates confidence. This is
the scenario's test of the dependence-grouping machinery.

Expected: persona attribution lands high, driven almost entirely by the PGP fingerprint,
with the engine stating that the other signals added little.

**Base rate matters here.** The prior that two arbitrary personas on a large forum are the
same operator is very low. A demo that sets it to 0.5 for neutrality will produce
confident nonsense at scale.

---

## Phase 6 — THE DECEPTION TRAPS

### Trap A — false flag in the kit

`"Coded by DmitryK, RedOctober Team"`, plus a fake PDB path referencing a real, unrelated
actor. Required handling:

- `DeceptionAssessment(adversary_could_plant=True, planting_cost="trivial")`
- `benefits_from_belief = ("the actual operator",)`
- Recorded as **contradicting evidence** against a RedOctober attribution, not as supporting
  evidence for one
- Contrast: it is a string in a file the adversary controls entirely. Cost to plant: minutes.

### Trap B — planted human identity

A post by persona `helpful_anon` on `DarkBazaar`:

> "everyone knows GlassAnvil is John Doe, lives in Minsk, here's his photo"

Properties: single source, `SourceClass.DARK_WEB` (adversary-influenceable),
`SourceReliability.CANNOT_BE_JUDGED` (persona has no history), no corroboration.

Required handling, in order:

1. Trust discounting on a `CANNOT_BE_JUDGED` source yields a **vacuous** opinion.
2. `fuse()` reports `independent_source_count = 1` and warns that agreement is not
   corroboration.
3. `band_of()` returns `INSUFFICIENT_BASIS`, not a probability.
4. Human identity attribution is **not produced**. The lead is recorded as a
   `HUMAN_IDENTITY_LEAD` entity in the `HUMAN_IDENTITY` category — which carries data
   protection obligations — and never promoted.

> **Acceptance criterion:** the end-to-end test asserts that no attribution naming a natural
> person is produced anywhere in this scenario. If it ever passes while producing one, the
> platform has failed at the thing it exists to get right.

---

## Phase 7 — ATTRIBUTION, DISRUPTION, AUTHORIZATION

### Expected attribution, by dimension

Never collapsed into one number.

| Dimension | Expected | Driven by |
|---|---|---|
| Infrastructure | high | 4-domain cluster + shared certificate, both selective |
| Campaign | high | one kit, one TTP set, one 24-hour registration window |
| Organization | moderate | a coherent operation, no organizational evidence |
| Persona | high | unique PGP fingerprint across two marketplaces |
| **Human identity** | **INSUFFICIENT_BASIS** | one uncorroborated hostile-channel source |

Each dimension reports supporting evidence, contradicting evidence, alternative hypotheses
(including "RedOctober is responsible" — retained and argued against, not deleted), missing
evidence, and source diversity.

### Disruption options the planner should produce

| # | Option | Status | Expected impact | Note |
|---|---|---|---|---|
| 1 | Registrar suspension, 4 domains | `REQUIRES_LEGAL_AUTHORITY` | high | Registrar is uncooperative |
| 2 | Hosting termination at ShadowHost | `REQUIRES_LEGAL_AUTHORITY` | **low** | Bulletproof host; the planner must say so rather than proposing it as if it would work |
| 3 | Upstream transit provider notification | `IMPLEMENTED` (draft only) | moderate | The realistic lever — and refused in the demo, see below |
| 4 | Exchange notification, deposit address | `REQUIRES_LEGAL_AUTHORITY` | moderate | |
| 5 | Law-enforcement referral package | `IMPLEMENTED` (draft + export) | — | |
| 6 | Simulated takedown | `IMPLEMENTED` | — | Exercises the full authorization path |

Each carries collateral risk. Option 1 must flag that `initech-payments-secure.example`
resembles a legitimate name and warrants ownership confirmation before any suspension.

### Authorization

Three decisions, of three different kinds, all kept:

1. An analyst **approves #6**. A capability is issued: 4 target fingerprints binding each
   domain's current resolution and registrar, permitted operations `{SIMULATION}`,
   jurisdiction, 4-hour expiry, one approver for a class that performs nothing.
2. An analyst **rejects #1**, with a rationale, and the rejection remains readable.
3. **NEMESIS itself refuses #3.** The notification is requested and its approval is refused,
   because the approver's identity was established by a development fixture and a
   notification is written to be sent. The exception text is printed in the run.

The third is the one to read. NEMESIS can establish no identity better than a fixture today,
so it may rehearse and may not correspond, and that sentence is enforced rather than
asserted — the demo asks for the notification and is told no, twice: once by the assurance
floor at approval, and again by the Effects plane, which finds no such permission in the
capability.

`SimulationEffectsAdapter` then executes what was granted. `external_contact_made = False`,
asserted by test across the whole adapter registry.

---

## Phase 8 — RESURGENCE (2026-04-20, T+45 days)

New activity, deliberately not matching on anything obvious:

- New domain `acme-invoice-secure2.example` — different registrar
- New IP `192.0.2.77` — **different ASN**, different country
- New forum `NightPort`, new persona `AnvilForge`

Nothing links these to the original cluster by infrastructure. Two artifacts do:

1. **The TLS certificate fingerprint `3f8a1c...` is reused** — the same key, the operator's
   OPSEC mistake.
2. **`AnvilForge` publishes the same PGP fingerprint `9f2c4e1a...`.**

The Resurgence Agent must reconnect both to the historical actor via `SUCCEEDED_BY` edges,
and the reconnection must be explainable: the answer to "why do you think this is the same
operator?" is the certificate and the key, not a similarity score.

This closes the loop: `DETECT → PURSUE → ATTRIBUTE → DISRUPT → WATCH → REAPPEARANCE → PURSUE`.

---

## What this scenario does not demonstrate

Stated so nobody mistakes the demo for the product:

- **No real intelligence source is involved.** Every connector reads a fixture. Whether the
  architecture survives contact with a licensed feed's rate limits, schema drift and gaps is
  untested.
- **Calibration is not demonstrated.** The confidence figures are internally consistent.
  Nothing here shows they are *correct*, and with no ground-truth corpus nothing can.
- **No real disruption occurs**, and none can: the addresses are reserved for documentation.
- **The adversary is not adaptive.** A real one would respond to being pursued. Nothing here
  models that.
