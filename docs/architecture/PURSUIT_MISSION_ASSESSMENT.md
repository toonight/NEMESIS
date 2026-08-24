# Pursuit-mission assessment

**Date: 2026-08-23.** An assessment of the existing codebase against the persistent
adversary-pursuit mission, before any implementation.

Everything below carries an epistemic label. This document describes what *is*, what is
*missing*, and what is *proposed*; the proposals are `PROPOSED` until code and tests exist.

## How this was produced, and how much to trust it

Six readers mapped the planes (195 capabilities catalogued), two analysts produced gap and
duplicate-capability lists from opposite priors, and four adversarial refuters attempted to
kill every claimed gap by hunting the counter-example in the tree.

**Refutation outcome: 26 candidate gaps, 0 killed outright, 20 downgraded to
`PARTIAL_EXISTS_BUT_INCOMPLETE`, 6 confirmed absent.** Zero outright kills is a weaker
result than this repository's own counter-verification history would predict, so treat the
six `CONFIRMED` findings as solid and the twenty `PARTIAL` findings as "the mechanism exists,
the wiring does not" rather than "this is missing".

Independently verified by direct reading before being stated here (not taken from an agent):
the preflight refusal chain, `TargetFingerprint` semantics, the mediator's effect path,
`OwnershipEvidence`, the import-linter layering, the `Relationship` construction rules, and
both defects in section B.3. Everything else is agent-reported with a file:line citation and
should be re-read before it is acted on.

Baseline at assessment time: 1669 passed / 13 skipped / 3 xfailed, ruff clean, mypy clean
(235 files), import-linter 13/13 contracts kept.

---

## A. Existing capability map

The short version: **most of the mission's epistemic and authorization machinery already
exists and is adversarially tested. What is missing is almost entirely the target-nature
layer and the wiring between components that were built and never connected.**

| Mission requirement | Status | Where |
|---|---|---|
| §14 FACT / INFERENCE / HYPOTHESIS separated and enforced | `IMPLEMENTED` | `core/claims.py:38` `ClaimKind`, `:378` `max_derivable_kind`, `:405` `check_derivation` |
| §16 Source independence, dependent sources collapsed | `IMPLEMENTED` | `core/provenance.py:178` `provenance_cluster`; `core/fusion.py:451` `establish_fact`; `core/proposition.py` robustness margin |
| §4 Precise edge semantics, no generic `RELATED_TO` | `IMPLEMENTED` | `core/relationships.py:37` — 32 members; zero occurrences of `RELATED_TO` in the tree |
| §4 Per-edge confidence / provenance / first-seen / evidence / contradiction | `IMPLEMENTED` | `core/relationships.py:246` `Relationship` |
| §4 Identity-asserting edges must cite claims | `IMPLEMENTED` | `core/relationships.py:88`, validator at `:290` |
| §4 Pivots through shared infrastructure need justification | `IMPLEMENTED` | `core/relationships.py:296` |
| §20 Capability envelopes: target binding, expiry, approvals, revocation, stop conditions | `IMPLEMENTED` | `core/authorization.py:459`; Ed25519 in `authz/keys.py` |
| §17 Attribution ≠ authorization | `IMPLEMENTED` (structurally) | `.importlinter` — `authz` sits strictly below `disrupt : attribute : resolve : effects` and imports none of them |
| §19 Four-verb seam, closed | `IMPLEMENTED` | `pilot/moves.py:308-360`, discriminated union at `:376` |
| §12/13 Attribution ladder | `IMPLEMENTED` under other names | `attribute/dimensions.py:45` five dimensions × `core/confidence.py:235` eight bands |
| §13 No LLM may promote attribution state | `IMPLEMENTED` | `attribute/engine.py:406` `run_identity_gate`, runs *before* fusion |
| §15 Hypothesis challenger | `IMPLEMENTED` but unwired | `pilot/challenger.py:126` `MoveChallenger` — see B/G15 |
| §5 Effects fail closed outside the envelope | `IMPLEMENTED` | `effects/registry.py:147` `preflight` — nine ordered refusals |
| §7/8 Effects hold no ambient authority | `IMPLEMENTED` | `ports/effects.py`; process isolation per ADR-0007 |
| §8 Takedown *proposal* path | `IMPLEMENTED` (as drafts) | `effects/drafting.py:289` `ProviderNotificationAdapter`, `:327` `TakedownRequestDraftAdapter` |
| §9 Resurgence *state* | `IMPLEMENTED` | `pursuit/investigation.py:233` `MONITORING_RESURGENCE`; `pursuit/engine.py:597` |
| §9/11 Resurgence *recognition* | `SIMULATED` | hand-scripted for one demo at `slice/scenario.py:2563` |
| §10 Cross-run graph accumulation | `IMPLEMENTED` | `graph/memory.py:145` `merge_entities`; `graph/journal.py` |
| §21 Runtime guardian | absent | see B/G14 |
| §2/3 Ownership / control / use / responsibility | absent | see B/G1 |
| §6/7 Remediation of authorized assets | absent | see B/G6 |

Two findings worth stating plainly because they change the shape of the work:

**The exculpatory hypothesis is already first-class.** `pursuit/engine.py:172` opens, at
investigation step 0 and before any evidence arrives, hypothesis H2: *"{seed} belongs to an
unrelated party whose infrastructure was compromised or abused"*, with refutation conditions
and an `Opinion`. The engine docstring at `:143` explains why: starting with only the
incriminating hypothesis is how an investigation confirms itself. The mission's
`COMPROMISED_LEGITIMATE` role does not need a new modelling track — it needs H2's resolution
to be written onto the asset.

**The target-nature enforcement seam exists, is fail-closed, adversarially tested, and
inert.** `OBSERVABLE_STOP_CONDITIONS` (`pilot/mediator.py:284`) holds exactly one member,
`target_ownership_contested`, cleared only when the mediator positively observes an entity
attribute — never on the pilot's word (`:336` strips pilot attestations; an earlier version
let a pilot clear its own constraint). The preflight refuses on any uncleared blocking
condition (`effects/registry.py:380`). It protects nothing today only because nothing writes
the attribute it reads.

---

## B. Gap analysis

### B.1 Confirmed absent (6)

| ID | Gap | Blocks | Severity |
|---|---|---|---|
| G6 | No `OperationClass` member, adapter, port or declared-and-unimplemented interface for remediating an asset the operator is authorized over. The case is *unmodelled*, not refused — an operator asking for it must first invent a class name that does not exist. | Phase 5 | blocking |
| G7 | No ordering primitive requiring evidence be sealed before a destructive effect. `preflight` has no evidence branch, `effects` cannot import `nemesis.evidence`, and `ApprovalRequest.supporting_evidence` is optional, unvalidated and untested. | Phase 5 | blocking |
| G15 | The hypothesis challenger ships wired to nothing. `challenger=` is passed at two sites, both in `pilotbench`; the two factories that build a bench subject (`pilotbench/runner.py:52`, `cli/main.py:1243`) both leave it `None`, and all three product mediators pass nothing. | Phase 4 | major |
| GAP-5 | No graph object carries a case or investigation identifier. `Entity`, `Relationship` and `Claim` have no `case_id`, and neither `GraphStore` nor `ClaimStore` can answer "which cases has this adversary appeared in". Accumulation is real; the indexing is absent. | Phase 2 | major |
| GAP-7 | Durability of the accumulated adversary memory is not asserted across investigations. | Phase 2 | minor |
| GAP-8 | `Relationship`'s four construction rules have no negative test. | — | minor |

### B.2 Mechanism exists, wiring does not (the 20 `PARTIAL` findings, condensed)

- **G1 / GAP-3 — the four-way distinction.** Nothing separates legal ownership from current
  control from observed use from attributed responsibility. `RelationType.CONTROLS` exists and
  is the strictest edge in the vocabulary; there is no ownership counterpart, and
  `OwnershipEvidence` conflates the two under the ownership name.
- **G2 — no per-entity role assessment.** Four operational roles exist as *entity types*
  (`C2_INFRASTRUCTURE`, `PROXY_INFRASTRUCTURE`, …, documented at `entities.py:102` as "a role,
  not a thing"), but `Entity` is frozen with only `attributes: dict[str,str]` and `labels` —
  no `Opinion`, no `supporting_claims`, no per-attribute extent. No `GraphStore` method
  annotates a node with a scored assessment.
- **G3 — malicious use is expressible but gates nothing.** It can be carried on
  `Relationship.confidence` and as `ContentSafety.MALICIOUS_CODE`, but no consumer reads such
  a score as an input to effect eligibility, and `PropositionClass` has no member for it.
- **G4 / G5 — the §5 gate.** No eligibility concept exists under any name (`grep` for
  `eligib|may_target|target_class|permitted_target` over `src/` returns zero). More
  importantly, plane separation *forbids* the enforcement point from computing one: `effects`
  and `authz` cannot import `attribute` or `disrupt`, and those four are sibling layers. This
  is not an accident to be worked around — it is what makes §17 true.
- **G17 — `OwnershipEvidence` is caller-supplied.** `DisruptionLever.ownership` is an input to
  the planner, not a derivation from the graph. In the one production construction it is
  derived from the INFRASTRUCTURE dimension — whose question is common *control* — and the only
  "this may be an innocent party's asset" signal is a string-prefix test,
  `domain.startswith("initech")` (`slice/scenario.py:1900`).
- **GAP-1 — nothing writes entity attributes in production.** Widened from the original claim:
  `Entity.create` is called without attributes at both production sites
  (`pursuit/engine.py:152`, `pursuit/materialize.py:158`), and no API or CLI route mutates
  them. Every attribute-based control therefore depends on whoever seeded the graph.
- **GAP-4 / G10 — `graph/recall.py` has zero production callers.** The module is complete and
  tested; its own docstring labels the pursuit wiring `PROPOSED` because history biasing pivot
  selection is a real risk. `resurgence_candidates` discards its `entity` argument
  (`recall.py:252`). No test asserts the `MONITORING_RESURGENCE` transition.
- **G11 — the resurgence arithmetic exists in the wrong plane.** `resolve/` already has the
  right maths (seven signal kinds with per-kind belief ceilings, correlation groups,
  independence collapse, leave-one-out margin). The blocker is not statistical:
  `PROPOSITION_TEMPLATE` hard-locks the plane to one sentence about two personas, and
  `.importlinter` quarantines `resolve` as `INTERNAL_LEAD` because of founder decision D1. A
  campaign-resurgence finding is `DELIVERABLE`, so routing it through `resolve` either breaks a
  contract or misclassifies the output.
- **G14 — no cross-turn control.** Per-move validation is thorough; nothing keys on a
  *sequence*. `ports/storage.py:234` already says "a pattern of denied attempts is a security
  signal" — a docstring describing a control nobody built.
- **GAP-9 — 11 of 32 `RelationType` members have zero producers**, including `REDIRECTS_TO` and
  `COMMANDS` — precisely the redirector/C2 vocabulary the mission asks for. The missing work is
  connectors and predicate selection, not schema.

### B.3 Two defects found in passing (both verified by direct reading)

1. **Asymmetric disclosure enforcement at the pilot seam.** `_apply_pivot` refuses a pivot on
   any non-`DELIVERABLE` entity (`pilot/mediator.py:865`). `_apply_effect`
   (`pilot/mediator.py:956-1040`) has no equivalent check. An entity the pilot may not *look
   at* is one it may still *request an effect against*. Partially mitigated: the preflight
   scans effect `parameters` for internal material (`effects/registry.py:281`), but that is a
   content scan, not a check on the target's disclosure class.

2. **`is_executable_now` ignores ownership.** `disrupt/options.py:397` returns only
   `implementation_status is IMPLEMENTED`, so a weakly-owned option with a blocking collateral
   risk still appears in `DisruptionPlan.executable_now`. Meanwhile `is_ownership_sound`'s own
   docstring calls itself "the gate the planner ranks on" — it is a sort key, not a gate, and
   no test asserts a refusal. **Latent, not live**: nothing executes from that list today, and
   real execution goes through the authorization gateway. It is exactly the sentence the
   mission's central invariant forbids, sitting in the presentation layer.

---

## C. Duplicate capability analysis

47 mission concepts were checked against existing machinery: **11 are the same thing under a
different name, 25 are reusable with extension, 11 are superficially similar and must not be
merged.** The ones that change the plan:

### Build nothing — these already exist

| Mission asks for | Already is | Note |
|---|---|---|
| Precise edge vocabulary instead of `RELATED_TO` | `RelationType`, 32 members | `RELATED_TO` has never existed here. Adding members costs a `CATEGORY_OF` entry and a **calibration refreeze**. |
| Source independence | `provenance_cluster` + WBF/CBF fusion + robustness margin | ADR-0003/0004 make routing through `fuse()` binding. |
| Capability envelopes | `AuthorizationCapability` + `AutonomyEnvelope` | "Envelope" is overloaded: the capability bounds *what*, the autonomy envelope bounds *how often*. |
| `OPERATES` edge | `OPERATED_BY` | Same edge, opposite orientation; there is no reverse-edge normalisation, so adding it doubles every traversal. |
| `PROXIES_THROUGH` edge | `PROXY_INFRASTRUCTURE` node role | Proxying already stops traversal (`graph/memory.py`) and collapses pivot value ×0.1 (`pursuit/policy.py:125`). An edge would need all of that reimplemented. |
| `SHARES_INFRASTRUCTURE_WITH` edge | `SHARED_INFRASTRUCTURE_TYPES` + `PivotSelectivity.population_size` | Co-location is deliberately modelled as a *counted population* so "shares an IP with 41,698 others" scores differently from "with three". An edge flattens that to a boolean. |
| `ATTRIBUTED_TO` edge | `ClaimKind.ATTRIBUTION` (epistemic strength 1) | Kept off the graph on purpose: as an edge it becomes traversable and citable as a premise. |

**Consequence: no new `RelationType` members are proposed.** The genuinely absent edges
(`OWNS`, `COMPROMISED`, `ABUSES`) are better expressed as claims and a role assessment — see E.

### Reuse the model, move the enforcement

- **`OwnershipEvidence`** — the judgement model is right (`Opinion` not float; independent
  origins counted separately from confidence; a 0.55 floor; a disjunctive `is_weak`). Its
  *placement* is wrong: per-`DisruptionOption`, unpersisted, in a plane cut off from `effects`
  in both directions. Move the model to `core`; do not rebuild it and do not try to import it.
- **`TargetFingerprint.bound_attributes`** — flagged independently by two analysts and by
  direct reading as **the single highest-leverage reuse available**. See F.
- **`StopCondition` + `OBSERVABLE_STOP_CONDITIONS`** — the repository's only per-target abort
  primitive, already fail-closed and pilot-unforgeable. Extend it rather than inventing a
  gate beside it.
- **`MoveChallenger`** — the `Protocol` is stateless by contract but nothing enforces
  statelessness, and `Briefing.last_ruling` is already handed to it. **A stateful challenger
  can accumulate cross-turn history and block on a sequence today, with no new runtime.** That
  is the cheapest route to §21.

### Do not merge

- **`EntityType.VICTIM` is not `VICTIM_INFRASTRUCTURE`.** It models "an incident touched this
  party" as a node with personal-data and retention consequences. A victim-owned asset is a
  property of the *asset*, which is a `DOMAIN` or `IP_ADDRESS`.
- **`evolution/memory.py` is not adversary memory.** Three unrelated things share the word:
  `graph/memory.py` (the store), `evolution/memory.py` (per-run trajectory memory, whose
  poisoning defences are designed for model-generated text), and the mission's "persistent
  adversary memory" (the graph journal).
- **The six-rung attribution ladder is the collapsed score founder decision D2 refused, in
  state clothing.** Rungs 1–3 are the CAMPAIGN / INFRASTRUCTURE / PERSONA dimensions; rungs 4–5
  are two positions on an axis the code deliberately makes one pass/refuse gate.
  **Load-bearing warning:** the collapse test's forbidden-name list contains `overall`,
  `score`, `combined`, `aggregate`, `total`, `confidence`, `collapse` — but **not** `state`,
  `stage`, `rung` or `level`. An `attribution_state` field would slip past the test while
  reversing the decision it protects.
- **`run_identity_gate` is not `refuse_human_identity`.** The first is structural and *can* be
  passed (passing means the evidence is the right shape to be scored); the second is branchless
  and always refuses. Conflating them would turn a refusal into a rung.

---

## D. Security invariants that must remain true

The 15 in `CLAUDE.md` are unchanged and non-negotiable. This work adds four that must hold
after it lands, each expressible as a test:

16. **Malicious use alone never authorizes disruption.** An effect against a target whose role
    is not established, or is established as victim / compromised-legitimate /
    abused-legitimate-service / shared, fails closed at the effects boundary — not in a ranking.
17. **A role classification is a signed fact at the point of enforcement, never a computed
    one.** The effects plane verifies a classification bound into the capability; it never
    computes one, because computing one would require the imports that make §17 false.
18. **A classification the platform did not positively observe is not a classification.** An
    absent role attribute fails closed, exactly as an unobserved bound attribute already does.
19. **Remediation authority is asset-scoped and never inferred from attribution.** Authority
    over an environment is an out-of-model, signed assertion; no confidence in *who* the
    adversary is may substitute for it.

---

## I. Dependency decision

Honest scope limit: this session had no network access, so the named projects were assessed as
*the concepts the brief describes*, not as codebases whose current contents were inspected. A
verdict below that rests on unverified assumptions about a project says so.

| Candidate | Verdict | Reasoning |
|---|---|---|
| ATHF concepts (typed hunt framework) | **NATIVE** | The typed pursuit loop, closed pivot vocabulary and cost-priced branch selection already exist in `pursuit/`. Nothing to import. |
| MAS-Hunt validation concepts (challenger / validator / gate) | **NATIVE** | Already built: `pilot/challenger.py` (challenger), `core/fusion.py` + `provenance_cluster` (evidence validator), `attribute/engine.py:406` (attribution gate). The work is wiring, not adoption. |
| ALTEDA runtime concepts (agent-behaviour anomaly detection) | **NATIVE** | The telemetry exists (`TurnRecord`, `PilotSession`); the blocking seam exists (`MoveChallenger`). An external runtime would add a trust boundary to watch a seam we already own. |
| Google ADK | **DEFER** | No concrete gap. NEMESIS's premise is that the pilot is external and untrusted and the harness is not a model; an agent-development kit sits on the wrong side of that line. Revisit only if multi-pilot orchestration becomes a requirement the four-verb seam cannot express. |
| CyberAgents Exchange | **DEFER** — discovery source only | Insufficient verified knowledge of the project to classify it further. Treating it as a source of ideas costs nothing; adopting it would add a runtime and a trust boundary. |

Dependency-budget answers for the only additions proposed below: **zero new external
packages.** Nothing in E–H requires a library NEMESIS does not already depend on.

---

## E. Data model proposal — `PROPOSED`

One new module: **`src/nemesis/core/infrastructure.py`**. It goes in `core` and nowhere else,
because `core` is the only layer every plane above may import — including `effects` and
`authz`, which are forbidden from importing `attribute` and `disrupt`. It has no I/O, exactly
like `core/fusion.py` and `core/retention.py`, which are the precedent for substantial pure
decision logic living in `core`.

```python
class InfrastructureRole(StrEnum):
    UNKNOWN = "unknown"  # the default, and a valid terminal answer
    ACTOR_OWNED = "actor_owned"
    ACTOR_CONTROLLED = "actor_controlled"
    COMPROMISED_LEGITIMATE = "compromised_legitimate"
    ABUSED_LEGITIMATE_SERVICE = "abused_legitimate_service"
    SHARED_INFRASTRUCTURE = "shared_infrastructure"
    VICTIM_INFRASTRUCTURE = "victim_infrastructure"


class ControlFacet(StrEnum):
    """The four independent questions. Answering one answers none of the others."""

    LEGAL_OWNERSHIP = "legal_ownership"
    CURRENT_CONTROL = "current_control"
    OBSERVED_USE = "observed_use"
    ATTRIBUTED_RESPONSIBILITY = "attributed_responsibility"


class FacetAssessment(BaseModel):  # frozen
    facet: ControlFacet
    holder: str  # natural key of who, or "" for unestablished
    opinion: Opinion  # never a float, never a bool (invariant 4)
    independent_source_count: int  # fusion sense: distinct origins, not feed count
    basis: str  # named so a reviewer can attack it
    supporting_claims: tuple[ClaimId, ...]
    extent: TemporalExtent  # control is temporary; ownership usually is not


class RoleAssessment(BaseModel):  # frozen
    entity_id: EntityId
    natural_key: str
    role: InfrastructureRole
    opinion: Opinion  # confidence in the ROLE, distinct from any facet
    facets: tuple[FacetAssessment, ...]
    assessed_at: datetime
    reasoning: tuple[str, ...]
```

`FacetAssessment` is `OwnershipEvidence` generalised: same proven shape (an `Opinion` rather
than a float, independent origins counted *separately* from confidence, a named attackable
basis, cited claims), same 0.55 floor and same disjunctive `is_weak`, moved to `core` where
the enforcement point can reach it. `disrupt.OwnershipEvidence` becomes a thin alias over the
`LEGAL_OWNERSHIP` facet rather than a second implementation.

**No new `RelationType` members.** Section C found 11 of 32 already have no producer, and a
new member forces a calibration refreeze. `OWNS` / `COMPROMISED` / `ABUSES` are expressed as
`FacetAssessment` rows plus `Statement.qualifiers` on the existing `CONTROLS` claim
(`core/claims.py:117`), which is where the ownership-vs-control qualifier belongs.

**`PropositionClass` gains one member, `LEGAL_OWNERSHIP`**, with its own `ROBUSTNESS_MARGIN`.
Three of the mission's four distinctions already map onto existing proposition classes; only
legal ownership has none. This is a stronger mechanism than a label: it sets how many planted
facts a conclusion must survive.

**The projection.** `Entity` stays frozen and unchanged. The assessment's *conclusion* is
written to `Entity.attributes` as a narrow, deterministic, lossy projection:

```python
ROLE_ATTRIBUTE: Final = "infrastructure_role"
ROLE_CONFIDENCE_ATTRIBUTE: Final = "infrastructure_role_band"

def role_attributes(assessment: RoleAssessment) -> dict[str, str]
```

This is the §10 rule applied: the `RoleAssessment` (with its claims and opinions) is canonical
state; the attribute is a rebuildable index that exists so the enforcement point can *see* it.

This also closes GAP-1 — the finding that **no production path writes any entity attribute at
all**. A writer is required, not optional: without one every attribute-based control,
including the one that already exists, remains inert.

## F. Effects model proposal — `PROPOSED`

**The four-verb seam stays closed.** Remediation, disruption and takedown are all already
expressible as `RequestEffect.operation: OperationClass` — a *parameter*, not a verb. No new
verb is proposed, and none is needed.

### The decision gate, split by what each site can know

The §5 gate cannot be one function, because the enforcement point is deliberately cut off from
the knowledge the gate needs. Splitting it is not a compromise — it is what preserves §17.

**At approval time**, where ownership, collateral and authority context are all available:

```python
def assess_disruption_eligibility(
    *, operation: OperationClass, assessment: RoleAssessment,
    collateral: Sequence[CollateralRisk], legal_basis: LegalBasis,
) -> EligibilityVerdict
```

Ordered exactly as §5 specifies — malicious-use confidence, ownership, control, shared-service,
victim/third-party, collateral, authority — returning a verdict with every refusal named. A
human approver sees this before signing.

**At execution time**, where only signed facts are available, the classification travels
*inside the signature*:

```python
bound_attributes = {..., "infrastructure_role": "actor_controlled"}
```

`TargetFingerprint.bound_attributes` is an arbitrary `dict[str,str]` hashed into the signed
digest (`core/authorization.py:255`). The preflight then already enforces, with no new code:

- the role must be **positively observed** at execution — an absent attribute is refused with
  `REFUSED_TARGET_CHANGED` ("an unobserved attribute is not an unchanged one",
  `effects/registry.py:341`);
- the role must be **unchanged since approval** — if we subsequently learn the host is a
  compromised victim, the fingerprint no longer matches and the capability is spent on nothing.

Plus one deterministic table in `core`, consulted by `preflight`, so an operation class can
never be executed against a role it may not touch:

```python
ELIGIBLE_ROLES: Final[Mapping[OperationClass, frozenset[InfrastructureRole]]]
```

**This is the whole gate.** No new plane, no new store, no new service, no new trust boundary,
and no import that would make "attribution ≠ authorization" false. The mechanism was already
built, signed and adversarially tested; what was missing was a vocabulary, an obligation that
the key be present, and a writer.

Two placement rules that are load-bearing:
- The role goes in `bound_attributes`, **not** `TargetFingerprint.entity_type` — that field is
  taken from the approved record at `registry.py:355` and never re-observed against the live
  graph, so a classification placed there would be bound but not freshness-checked.
- Enforcement goes in `preflight`, **not** the mediator. Two execution paths exist —
  `mediator._apply_effect` and `IsolatedEffectsExecutor` (`slice/scenario.py:2439`) — and both
  pass through `preflight`. A gate in the mediator alone is bypassable.

### Remediation of authorized assets (Phase 5, `PROPOSED`)

One new `OperationClass` member, `REMEDIATE_AUTHORIZED_ASSET`. The cost is known and
deliberate: an `OPERATION_RISK` row, an `APPROVAL_ROLES` row, a `MINIMUM_ASSURANCE` decision,
`IRREVERSIBLE_OPERATIONS` membership (forcing dual control), an adapter, a calibration
refreeze, and updating the two tests that assert the operation set **by equality**
(`tests/invariants/test_authorization_invariants.py:280`, `tests/planes/test_effects.py:200`).
Those equality assertions are the intended tripwire: the set must not grow quietly.

Authority over an environment must be an out-of-model signed assertion — a capability whose
`legal_basis` names it — never a pilot claim and never inferred from attribution confidence
(invariant 19). The remediation menu of §6 (`ISOLATE_HOST`, `REMOVE_C2_COMPONENT`,
`ROTATE_SECRETS`, …) belongs in `EffectRequest.parameters`, not in new operation classes.

**Evidence before destruction** (G7) reuses the existing seam rather than adding one: a
blocking `StopCondition` named `evidence_preserved_for_target`, added to
`OBSERVABLE_STOP_CONDITIONS`, cleared only when the mediator positively observes that the
target's evidence has been sealed. `nemesis.pilot` sits above `nemesis.evidence` in the
layering and may read the vault; `nemesis.effects` may not and does not need to.

## G. Resurgence architecture — `PROPOSED`

**The arithmetic already exists and is correct.** `resolve/signals.py` has seven signal kinds
with per-kind belief ceilings, five correlation groups, independence collapse by
`independence_key`, population-based selectivity, and a leave-one-out robustness margin.
`INFRASTRUCTURE_REUSE` is already a signal kind. Building a second correlation engine would be
the exact architecture inflation §24 forbids.

**The blocker is not statistical, it is disclosure.** `PROPOSITION_TEMPLATE`
(`resolve/engine.py:60`) hard-locks the plane to one sentence about two personas, and
`.importlinter` quarantines `resolve` as `INTERNAL_LEAD` under founder decision D1. A campaign
resurgence finding is `DELIVERABLE`. Routing it through `resolve` either breaks a contract or
misclassifies the output.

Recommendation: extract the proposition-agnostic core — fusion, independence collapse,
`fact_key`, robustness margin, leave-one-out, attainable ceiling — into `core` alongside
`core/fusion.py`, which is where most of it structurally belongs anyway, and let both
`resolve` (persona linkage, `INTERNAL_LEAD`) and a new thin resurgence caller
(`DELIVERABLE`) sit on top. This removes a duplicate rather than adding one.

**False resurgence is prevented by the primitives that already exist**, and this must be
explicit: shared hosting, a popular registrar and a common TLS stack are not signals. The
existing `PivotSelectivity.population_size` scores "shares an IP with 41,698 others"
differently from "with three", `SHARED_INFRASTRUCTURE_TYPES` collapses pivot value ×0.1, and
the `Relationship` validator already refuses an unjustified pivot through shared
infrastructure. Resurgence signals must route through those, not around them.

**The resurgence watch is a stored query, not a service.** `MONITORING_RESURGENCE` already
exists as an investigation state; `RelationType.SUCCEEDED_BY` already exists for "what
replaced this". No long-running process is proposed. The work is to turn the hand-written
demo at `slice/scenario.py:2563` into an engine and to give `graph/recall.py` its first
production caller.

## H. Attribution and adversary memory — `PROPOSED`

### The ladder — and an honest disagreement with the brief

The mission's six rungs map onto the existing five dimensions × eight bands:

| Mission rung | Existing representation |
|---|---|
| `UNKNOWN` | every dimension at `INSUFFICIENT_BASIS` |
| `CAMPAIGN_CLUSTER` | CAMPAIGN dimension band |
| `OPERATOR_CLUSTER` | INFRASTRUCTURE dimension band |
| `LIKELY_PERSONA` | PERSONA dimension band |
| `REAL_WORLD_IDENTITY_HYPOTHESIS` | `run_identity_gate` passed |
| `STRONGLY_CORROBORATED_IDENTITY` | **no counterpart, deliberately** |

**A single ordered rung is the collapsed score founder decision D2 refused.** It should be
built as a read-only reporting projection that states it is lossy, must never be an input to
any decision, and must never be stored on an entity. The collapse test's forbidden-name list
must gain `state`, `stage`, `rung` and `level`, because today an `attribution_state` field
would pass that test while reversing what it protects.

Recommending against a stored ladder is a deviation from §13 as written, and it is deliberate:
§13's own requirement that "no LLM promote attribution state without deterministic evidence
requirements" is better served by the existing pass/refuse gate than by a rung a model can
argue its way up.

### Persistent adversary memory

Cross-run accumulation is already real: `merge_entities` merges on `(entity_type,
natural_key)`, `widen_extent` widens temporal bounds, and the journal makes it durable and
rebuildable. What is missing (GAP-5) is **indexing, not storage** — nothing can answer "which
cases has this adversary appeared in".

Proposal: a rebuildable projection from the existing journal and audit trail, keyed by natural
key → investigation ids and prior conclusions. **Zero new authoritative stores**; §10's own
rule that derived indexes are acceptable if they remain rebuildable projections is the
governing constraint, and the journal is what they rebuild from.

Do not put a `case_id` on `Entity` — the same adversary appears in many cases, which is the
entire point of the graph.

## J. Complexity budget

For everything proposed above, across all phases:

| Budget line | Count |
|---|---|
| New authoritative databases | **0** |
| New trust boundaries | **0** |
| New runtime services | **0** |
| New long-running processes | **0** |
| New queues | **0** |
| New external packages | **0** |
| New Python modules | 3–4 (`core/infrastructure.py`; a classification engine; a resurgence caller; a guardian reader) |
| New `OperationClass` members | 1 (`REMEDIATE_AUTHORIZED_ASSET`, Phase 5 only) |
| New `RelationType` members | **0** |
| New pilot verbs | **0** |
| New import-linter contracts | 1–2 |
| Calibration refreezes required | 1 per module-constant change |

## Implementation priority, revised against what was found

**Strike from the plan — already built:**
- Phase 4 (hypothesis challenger) is *built and tested*; the work is wiring three product
  mediators, not building a challenger.
- §4 (graph semantics), §16 (source independence), §20 (capability envelopes) and §17
  (attribution ≠ authorization) need nothing.

**Revised order:**

1. **Ownership / control / use classification and the effects gate** — Phase 1, and the
   highest-value change in the assessment. It is the only one that makes the mission's central
   invariant true rather than advisory, and it completes a seam that already exists, is already
   fail-closed, and protects nothing today.
2. **A writer for entity attributes** (GAP-1) — a prerequisite for 1, not a separate phase.
3. **Wire the challenger** into the three product mediators (Phase 4, cheap).
4. **A stateful challenger as the runtime guardian** (Phase 8) — no new runtime; the seam
   already accepts one.
5. Adversary-memory indexing (Phase 2) → resurgence engine (Phase 3) → remediation (Phase 5)
   → takedown recipient derivation (Phase 6).

Phase 7 (human attribution state machine) is recommended **not** to be built as specified; see H.
