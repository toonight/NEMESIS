# Operation IRON TIDE — the IP-seeded scenario

**Status: `SIMULATED`.** Every connector reads a fixture. Every identifier is drawn from
ranges reserved for documentation: `.example` domains (RFC 2606), `192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24` (RFC 5737), private-use AS numbers (RFC 6996). Nothing
resolves, so invariant 15 holds structurally rather than by promise.

This document is the contract. `src/nemesis/collect/fixtures/iron_tide.py` and
`src/nemesis/slice/iron_tide.py` are its executable form. Where the two disagree, this wins.

Run it with:

```bash
uv run nemesis trace
```

---

## 1. Why a second scenario exists

GLASS ANVIL (`DEMO_SCENARIO.md`) starts from a domain somebody clicked. That is the easy
seed. A domain carries a registration, a certificate history and a resolution history, so the
rule policy has four questions to ask it before it has to think.

An IP address is the harder seed and the far more common one — it is a line in a firewall
log — and it is harder for a reason that is the whole point of this scenario:

> **An address is guilty of nothing by being an address.**

Three names on an address is a finding if the address carries one customer, and noise wearing
the same shape if it carries twelve thousand. Until something counts the tenants, the two
observations are identical. GLASS ANVIL never has to face this, because a domain seed reaches
its cluster through registration and certificates rather than through co-location.

So IRON TIDE is built to make the platform *earn* every hop, and to make it refuse the hops
it has not earned.

### What it exercises that GLASS ANVIL cannot

| Property | Covered by |
|---|---|
| A tenant count is collected before co-location is believed | `test_the_tenant_count_is_collected_before_co_location_is_believed` |
| The same relation is selective on one address and worthless on another | `test_the_reverse_pivot_on_the_seed_is_selective_and_the_one_on_the_platform_is_not` |
| A strong edge *onto* a crowded node licenses nothing *out of* it | `test_a_strong_edge_onto_a_crowded_node_licenses_nothing_out_of_it` |
| One statement attested by two origins, one unplantable | `test_one_statement_is_attested_by_two_origins_one_of_which_is_unplantable` |
| Independent corroboration is the only thing that reaches `very likely` | `test_the_only_multi_origin_dimension_is_the_only_one_to_reach_very_likely` |
| Policy, pilot and analyst moves are reported apart | `test_the_policy_the_pilot_and_the_analyst_are_reported_separately` |
| Uninvolved co-tenants pulled into the case are surfaced | `test_the_uninvolved_co_tenants_are_reported_rather_than_absorbed` |

---

## 2. The cast

| Role | Identifier | Why it is what it is |
|---|---|---|
| The IOC | `203.0.113.201` | The seed. One line in an egress log. |
| Second C2 | `198.51.100.77` | Reached only through the certificate. |
| The control | `192.0.2.144` | Shared hosting, **12,400** customers. |
| Names on the seed | 3 | `fleet-sync-api`, `manifest-relay`, `nwl-driver-portal` |
| Names on the second | 2 | `depot-telemetry`, `nwl-fuelcard` |
| Certificate | `a41d7be0…` | Self-signed, presented by all three addresses. |
| Implant | `6b1f9c0d…` | `TIDEHOOK` loader, quarantined by the victim's EDR. |
| Persona | `TideWalker` on `SaltPier` | An access broker, not "the actor". |
| Victim | NORTHWIND Logistics | Two sensors, one operator. |
| Framed party | `Chimera Syndicate` | Real, unrelated, named by a planted build tag. |

### The three numbers that are the test, not decoration

- **3 names on `203.0.113.201`, with 1 customer on the address.** Selective, and the tenant
  count is what makes it so.
- **2 names on `198.51.100.77`, with 1 customer.** More selective still.
- **12,400 names on `192.0.2.144`, with 12,400 customers.** Worth `0.07` and bands as
  *insufficient basis*.

Changing any of them without changing this document silently removes a test.

---

## 3. The run, stage by stage

### 3.1 DETECT — an address, a sample, and no claim about whose it is

Two of NORTHWIND's own sensors, one operator:

- `northwind-egress-netflow-02` — 47 TLS sessions from a finance workstation to
  `203.0.113.201:8443` over six days, 300 s ± 12 s.
- `northwind-edr-fleet` — the implant that held the socket, quarantined.

They collapse to **one** provenance cluster, so their agreement is *not* corroboration. What
they buy is **two distinct facts in a channel an adversary cannot author**
(`UNPLANTABLE_SOURCE_CLASSES = {OWN_SENSOR, LAW_ENFORCEMENT}`).

The stage carries an explicit `what_the_seed_does_not_say`, rendered to the console, because a
run that shows a beacon and no caveat invites exactly the inference the rest of the run spends
its budget refusing to make.

### 3.2 PURSUE — three tiers of agency, kept apart

GLASS ANVIL reports two tiers (autonomous, directed) and folds the pilot into the second.
IRON TIDE reports three, because a move an external model chose and the engine executed is
neither a move the engine chose nor a move a human made, and ADR-0008 turns on being able to
tell them apart.

**Tier 1 — the deterministic policy (42 pivots).** Ordered by value-per-cost, so the walk is
reproducible:

```
network_ownership     203.0.113.201    0.50/0.6 = 0.833   → ASN, operator. Worth ~nothing, correctly.
reverse_resolution    203.0.113.201    0.75/1.0 = 0.750   → 3 names
proxy_classification  203.0.113.201    0.60/1.5 = 0.400   → 1 customer. THE HINGE.
service_fingerprint   203.0.113.201    0.45/1.5 = 0.300   → the certificate
  ↳ branches on 3 domains → resolution, registration, certificate history
  ↳ branches on the certificate → certificate_reuse → 198.51.100.77, 192.0.2.144
      ↳ branches on both → their names, their tenant counts
```

`CERTIFICATE_HISTORY` is **not** in `PIVOTS_FOR_ENTITY[IP_ADDRESS]`, so an address-seeded run
can only meet a certificate through `service_fingerprint`. That is why the new connector is
load-bearing rather than convenient.

**Tier 2 — the pilot, through `PursuitEngine.execute_pivot` (5 pivots).** The policy has no
rule that says *ask our own sensors what they already hold* — `OWN_TELEMETRY` appears in no row
of `PIVOTS_FOR_ENTITY` — and no rule that reaches the implant, which entered the graph from the
detection rather than from a pivot, so no branch opened on it. The pilot names those moves; the
engine keeps the routing, the budget, the provenance ordering and the audit line. **The pilot
proposes; the engine disposes.**

**Tier 3 — one analyst leap (3 pivots).** The implant configuration yields an onion address and
a messaging handle. The dark-web connector answers only for `PERSONA`, `FORUM` and
`MARKETPLACE`, and nothing maps a handle or an onion address to a vendor. A human recognised
the panel on a `SaltPier` vendor profile. Recorded as `collection.directed` with the reason
attached, and reported apart from everything above it.

### 3.3 CLUSTER — 32 entities, 61 edges

| From | Relation | To | Population | Weight | Band |
|---|---|---|---|---|---|
| 3 × domain | `resolves_to` | `203.0.113.201` | 3 | 0.63 | likely |
| `203.0.113.201` | `hosted_on` | Kestrel Datacenter BV | 1 | 0.95 | very likely |
| 3 × address | `presents_certificate` | `a41d7be0…` | 3 | 0.63 | likely |
| 2 × domain | `resolves_to` | `198.51.100.77` | 2 | 0.95 | very likely |
| 5 × domain | `registered_through` | Tidewater Domains | 5 | 0.43 | likely |
| **3 × domain** | **`resolves_to`** | **`192.0.2.144`** | **12,400** | **0.07** | **insufficient basis** |

The last row is the control, and it is sharper than GLASS ANVIL's CDN case: `192.0.2.144` is
reached by the *strongest* pivot in the run — the same private key — and every edge out of it
is then worth nothing. **A strong link to a node licenses nothing from it.**

### 3.4 STANDING — including the nodes it refuses to call the adversary's

| Node | Role | Why |
|---|---|---|
| `203.0.113.201` | `unknown` | Observed use only. Nothing establishes who owns or controls it. |
| `198.51.100.77` | `unknown` | Same. |
| `192.0.2.144` | `unknown` | An owner is established; no adversary control is. |
| NORTHWIND Logistics | `victim_infrastructure` | The node is itself the harmed party. |
| Anchorline Hosting | `shared_infrastructure` | Adversary traffic through a host is not a reason to act against the host. |

**The seed stays `unknown` while the infrastructure dimension reaches `likely`.** That is not
a defect and it is the most important line in this document: the attribution and the role gate
do not talk to each other, by design. Attribution answers *who is responsible*; the gate
answers *whose is this node*, and only the second is what the effects boundary reads. A future
change that wired one into the other to "finish the picture" would fail
`test_the_seed_address_is_never_classified_as_the_adversarys`.

### 3.5 ATTRIBUTE — four assessed, one refused

| Dimension | Band | P | Origins | Plantable | Margin |
|---|---|---|---|---|---|
| infrastructure | likely | 0.584 | 1 | 4 / 4 | survived |
| **campaign** | **very likely** | **0.850** | **2** | **3 / 4** | survived |
| organization | insufficient basis | 0.050 | 1 | 2 / 2 | every fact removed |
| persona | roughly even | 0.489 | 1 | 4 / 4 | survived |
| human identity | insufficient basis | — | 1 | 1 / 1 | refused before scoring |

Three things in that table are the point of the scenario.

**Campaign is the only dimension with two origins and the only one to reach `very likely`.**
The statement *"the implant reaches `fleet-sync-api.example`"* is attested twice: by NORTHWIND's
own recursive resolver, and by a commercial configuration extraction. Both produce a
**byte-identical `Statement`**, so `fuse` sees one fact with two attesting origins rather than
two facts. One of those origins is `OWN_SENSOR`, so the fact is unremovable by the robustness
margin. Measured: re-homing that connector from the fixture-set operator to the victim's
operator moved campaign from `likely` P=0.662 to `very likely` P=0.850. Independent
corroboration is worth precisely that, and nothing else in the run buys it.

**Organization is refused, and the refusal is the mechanism working.** The build tag naming
`Chimera Syndicate` is offered *in support* on purpose, so that the engine has to be the thing
that refuses it. Its `DeceptionAssessment` says `planting_cost="trivial"`, so the engine
inverts it to contradicting evidence. One plantable supporting fact is left, the robustness
margin at `ACTOR_ATTRIBUTION` removes it, and the honest report is that nothing was
established. A conclusion an adversary can manufacture by planting one artifact is not a
conclusion.

**Human identity is refused structurally, before anything is scored.** One anonymous post, one
origin, an adversary-writable channel. The gate returns `SINGLE_SOURCED` and the assessment
carries no number to hedge.

### 3.6 EVIDENCE

62 objects sealed, vault chain intact, 64 audit events, chain intact. Every artifact carries
`AdmissibilityDefect.SIMULATED_COLLECTION` — usable as intelligence, never presentable as
proof. The run records what it cannot defend against: the hash chain is one we compute
ourselves, and no external anchor exists.

---

## 4. What the run does not reach

**It ends at a persona.** NEMESIS has an `EntityType.THREAT_ACTOR` member and **no code that
constructs one** — the only production references are the enum declaration
(`core/entities.py:69`) and the adversary-type table it appears in
(`core/infrastructure.py:555`). `AttributionRequest.subject` is free text, so the assessment is
*about a string* and nothing in the graph carries it.

This is reported on every run (`IronTideResult.actor_gap`) rather than left for a reader to
infer that a persona is an actor.

Minting an actor node is **not a missing line of code**. `disclosure_of_entity` returns
`INTERNAL_LEAD` for a persona and `DELIVERABLE` for a threat actor — pinned by
`tests/invariants/test_identity_wall.py:218` — so promoting a cluster to an actor node moves it
across the boundary the identity wall is built on. It needs its own decision, its own ADR and
its own tests. `PROPOSED`.

---

## 5. Findings from driving this end to end

Three things this scenario surfaced about the framework itself, each verified against the code
rather than inferred.

**The IP-side connectors were missing.** `PIVOTS_FOR_ENTITY[IP_ADDRESS]` has proposed
`proxy_classification` and `service_fingerprint` since it was written, and nothing answered
either: both came back `REQUIRES_EXTERNAL_DATA` on every address in every run. On a domain seed
that costs little. On an address seed it is the difference between an investigation and a
guess. `SimulatedHostProfileConnector` closes it, and needed **no new enum member and no edit
to `policy.py`** — only connector capability. Status of the pivots: `SIMULATED`.

**The planner branches onto co-tenants of a crowded host.** `PursuitEngine._spawn_branches`
does not consult edge confidence, so a name on a 12,400-customer platform gets a branch and a
budget exactly like a name on a dedicated lease. Measured on this run: **9 pivots spent on 3
uninvolved third parties**, every one returning nothing. The graph correctly declines to
believe anything about them — but the important cost is not the budget. It is that
`ridgeline-freight.example`, `bramblewood-dental.example` and `st-aidans-pcc.example` are now
**entities in an investigation's graph**. The run reports them under
`ClusterStage.bystanders` rather than hiding a collateral-collection fact behind a spend
figure. Not fixed here; surfaced and measured.

**The framer-cost rule does not reach the attribution engine.** ADR-0013's staging-cost
argument is implemented as `FRAMER_COSTLY_KINDS` / `has_framer_costly_signal` in
`pursuit/resurgence.py`, keyed on `ResurgenceSignalKind` — a vocabulary `nemesis.attribute`
never touches. Verified: `grep -rn "framer" src/nemesis/attribute/ src/nemesis/core/fusion.py`
returns nothing. What actually governs an attribution is the **robustness margin** plus
**deception inversion**, which is what this scenario demonstrates. Whether the framer-cost
argument should also apply to attribution is an open question, not a claim this document
makes.

---

## 6. Relationship to GLASS ANVIL

They share no fixtures, no operator string and no connector instances.

- `FIXTURE_OPERATOR` vs `IRON_TIDE_OPERATOR` — two distinct provenance clusters, so the two
  synthetic worlds can never fuse as two origins.
- `FIXTURE_SET` is now a per-connector value rather than a module constant, so an IRON TIDE
  artifact does not record its provenance as `glass-anvil`.
- `SimulatedHostProfileConnector` is wired into `iron_tide_connectors()` only. Adding it to
  `simulated_connectors()` would change the reference scenario's pivot count, audit trail and
  frozen calibration for a capability that scenario does not need.

The one shared change is `SimulatedOwnSensorConnector.supported_entity_types`, widened from
`{DOMAIN}` to `{DOMAIN, IP_ADDRESS, MALWARE}`. GLASS ANVIL never asks `OWN_TELEMETRY` for
either of the new types, so its run is unchanged.
