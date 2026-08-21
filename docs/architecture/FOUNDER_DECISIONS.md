# Open decisions for the founder

Decisions an engineer's default would get wrong in a way no code review would catch,
because they turn on product direction, legal exposure or cost structure rather than on
technical merit. Each names the **working default** currently implemented, so development
is never blocked — but a default is not an answer, and every one of these is reversible
only at increasing cost.

Source: the foundational research pass of 2026-08-15
(`docs/research/2026-08-15-foundational-research-synthesis.md`), 286 claims checked against
primary sources with 62% confirmed. Legal points below are **architectural constraint
discovery, not legal advice**, and several rest on sources the verification pass could not
access.

---

## D1 — Unit of resolution: the operator, or the organization? **[ANSWERED 2026-08-15]**

> **ANSWER: both, separated by a wall.** Organizational attribution is the deliverable
> product. Persona linkage remains, but as an *internal investigative lead* — never
> exported, never presented as a conclusion, never reaching a disruption package or an
> evidence export.
>
> **Consequences to implement.** This is not a labelling change; it is a data-flow
> constraint, and it must be enforced structurally or it will erode:
> - `PersonaLinkageAssessment` must not be reachable from any export or referral path.
> - The attribution product exposes ORGANIZATION and below; PERSONA is marked internal.
> - The evidence-export adapter must refuse to include persona-linkage material.
> - An import contract or an equivalent structural check should carry this, not a comment.
>
> **Status: IMPLEMENTED, 2026-08-15.** Enforced three ways, because a wall resting on one
> of them has a gap nobody has looked at:
> 1. `ExternalAttributionProduct` has **no field** capable of holding a persona or
>    human-identity assessment, and `ExternalDimension` refuses construction with one.
>    `redact_for_disclosure()` is the only route to the external type.
> 2. Withholding is **recorded, not silent**: the product states which dimensions were
>    held back and under what class, without restating what they contain. A recipient told
>    nothing would otherwise read the silence as "nothing was found".
> 3. A boundary guard on `EffectRequest.parameters`, the free-text channel no type can
>    constrain, refuses any operation carrying internal-classified markers — checked
>    *before* the capability verdict is acted on, so being authorized is not a defence.
>
> Plus an import contract: `nemesis.disrupt` may not import `nemesis.resolve`, so a
> disruption package cannot reach persona linkage by import. Effects was already denied
> `resolve` by the ambient-authority contract.
>
> **What it does not do**, stated so nobody over-trusts it: the free-text guard catches a
> marker, not an idea. An analyst who paraphrases a persona linkage into a takedown request
> will succeed, and no code here stops them. It prevents the *accidental* path — a caller
> passing an internal assessment's own rendered text into a document because that was the
> field at hand.

**Why it matters most.** This is the question of whether we are studying the right object at
all, and the research pass raised it *after* the fusion design was built.

If the unit is the **organization** rather than the individual operator:

- The dependence-block machinery in `core/fusion.py` becomes largely unnecessary — most of
  its subtlety exists to keep individual-linkage confidence honest.
- The harm profile drops sharply. Misattributing a criminal group is a serious error;
  misidentifying a *person* is a life-altering one.
- GDPR Article 10 exposure (data relating to criminal convictions and offences) drops
  substantially, because organizational attribution touches far less personal data.
- The attribution claim becomes considerably more defensible to a regulator or a court.

If the unit is the **operator**, NEMESIS is a more powerful product and a far more dangerous
one, and the human-identity firewall stops being a safety feature and becomes the entire
liability position.

**Working default:** operator-level persona linkage, with a hard structural gate that
refuses to produce human-identity attribution. Implemented and tested.

**What would change:** answering "organization" would let us simplify the fusion layer and
strengthen the legal position. Answering "operator" means the identity firewall must be
documented as a product constraint, not a configuration default (see D2).

---

## D2 — Do we sell "attribution", or "corroborated technical linkage"? **[ANSWERED 2026-08-15]**

> **ANSWER: multi-dimensional attribution.** The vocabulary stays "attribution", carried by
> five separate dimensions with no collapsed score, and a human-identity dimension that no
> configuration can raise above `INSUFFICIENT_BASIS`.
>
> **What this obliges.** Choosing the stronger word means the ceilings have to do more work,
> not less. The UI must make uncertainty visible by default rather than on request, because
> Rid & Buchanan's objection — formalism implying exaggerated precision — applies with full
> force to a product that calls its output attribution. Currently implemented as engineering
> defaults; whether they also become contractual constraints remains open.

A positioning and liability decision, not a naming one.

Rid & Buchanan's *Attributing Cyber Attacks* pre-names our failure mode: formalism that
implies "an exaggerated degree of precision". A wrong attribution rendered in a polished,
provenance-decorated interface is **more** dangerous than the same error in a text file,
because production value reads as confidence. That applies directly to the analyst UI.

If the answer is "corroborated technical linkage", the confidence ceilings and the identity
firewall must ship as **documented product constraints** that a customer cannot switch off
— which is a contractual and marketing commitment, not a default.

**Working default:** the vocabulary is "attribution" with five separate dimensions and no
collapsed score, and the human-identity dimension cannot be raised past
`INSUFFICIENT_BASIS` by configuration. Effectively the cautious position, undeclared.

---

## D3 — Shipped on-premises, or SaaS only?

The single highest-leverage answer for downstream constraints. It determines:

- Whether copyleft and source-available licences upstream (Neo4j CE's GPLv3, Memgraph's
  BSL, ArangoDB's community terms, IntelOwl's AGPL, Sigma's GPL) are live legal questions
  or irrelevant.
- Whether NEMESIS is an "electronic communication service" or "remote computing service"
  under 18 U.S.C. §2258E(6). A publicly offered SaaS plausibly is — which switches on both
  a CSAM reporting duty and a safe harbour that an on-premises product does not get.
- Whether evidence-vault witnesses are customer-run (which works) or vendor-run (which
  proves nothing against us — see D5).

**Working default:** local-first, single-tenant, no deployment model committed. Nothing in
the codebase assumes either.

---

## D4 — Does NEMESIS ever ingest media from criminal marketplaces?

A criminal-exposure decision, not a capability one.

18 U.S.C. §2252A(d)'s affirmative-defence ceiling is far below any realistic crawl volume,
and §2258A(f)(3) confirms there is no duty to scan — which means deploying a mandatory
classifier can *manufacture* the knowledge the offence requires. The research pass's
recommendation, which the architecture currently follows, is metadata, text and hashes
only. Never media. Ever.

**Working default:** implemented. `ContentSafety.MANDATORY_REPORT` exists at schema level;
such material is never indexed and never exported. The **escalation procedure is not
implemented**, and it is a human procedure before it is code.

---

## D5 — Who runs a witness for the evidence vault, and will they accept the side channel?

The vault's anti-insider property depends on several organizations in separate legal
control cosigning checkpoints. Every cosigner thereby learns origin, tree size and
timestamp on each checkpoint — that is, **our collection tempo**.

For a sensitive or classified deployment that is a counterintelligence objection, not a
technical one. Until a design partner's internal audit function actually signs something,
this property is designed-in and **not realised**, and buyers must be told so plainly.

**Working default:** locally signed anchors only, explicitly reported as *not* externally
held. `VaultIntegrityReport.is_defensible_against_insider` returns False. The vault reports
its own weakness rather than implying integrity it does not have.

---

## D6 — What does "legally defensible" mean here?

Three very different budgets:

| Standard | What it requires |
|---|---|
| Internally auditable | What exists today |
| Regulator-defensible | External anchoring, documented chain of custody, role separation |
| Courtroom-admissible | The above, plus a qualified timestamping authority contract, an external audit, and **a US-qualified human certifier who can be deposed** |

That last item is a hiring and entity-structure decision. FRE 902(12) is civil-only, so an
EU-signed certification is inert in US criminal proceedings. Separately: ISO/IEC
27037/27041/27042/27043 cost roughly €600–800 to purchase, and no conformance claim should
be made to a government buyer before someone has read them.

**Working default:** internally auditable, with the admissibility test returning *defects*
rather than a boolean so the gap to a higher standard is always visible.

---

## D7 — Spend on real data volume now, or keep proving adapters against free tiers?

Roughly $120–500/month. Free tiers cannot populate a graph, cannot stress the
Intelligence/Evidence split, cannot surface the correlation-quality problems that decide
whether attribution works at all, and cannot produce a real cost-per-pivot.

The counter-argument is that the MVP is deliberately synthetic and this can wait. The
research pass disagrees, and it has the better of it: the architecture is currently
unvalidated against any real data, and that will remain true until someone pays.

**Working default:** synthetic only. The seven connectors used by every shipped command are
fixtures, flagged `is_simulated` throughout, and that flag cannot be cleared downstream. An
opt-in Tor snapshot adapter now exists but has no target configured, is never placed in the
demo registry and makes no contact unless a deployment supplies an authorized onion allowlist.

---

## D8 — Sanctions posture on adversary interaction

Does NEMESIS ever transact with a sanctioned nexus — an undercover persona purchase, a
sample buy, marketplace access? OFAC FAQ 562 means our own wallet clustering can *create* a
blocking-and-reporting obligation for a US customer. EU Regulation 2019/796 Article 3(2)
reaches conduct "indirectly".

**Working default:** block by default. No purchasing, no transactions, no engagement with
criminal personas — a hard prohibition in `CLAUDE.md`, not a setting.

---

## D9 — NEMESIS's own licence model

Every incumbent monetises by edition-splitting: OpenCTI, Neo4j, Memgraph, TheHive 5, MinIO.
Our answer determines which upstream licences are tolerable, which interacts with D3.

**Working default:** proprietary, all rights reserved. Chosen dependencies are permissive
(Pydantic MIT, cryptography Apache-2.0/BSD), so nothing is foreclosed.

---

## What is *not* on this list

Reversible engineering choices are made and documented in `docs/adr/` without asking:
storage engine, agent topology, module layout, fusion operators. If one of those turns out
to be wrong, it costs a refactor. Everything above costs more than that.
