# ADR-0009: Provider-neutral pilot seats, and the benchmark that grades who sits in one

- **Status:** accepted
- **Date:** 2026-08-22
- **Deciders:** founding architect, founder
- **Plane:** pilot (restructured), pilotbench (new), audit, cli
- **Reversibility:** moderate, and lower than ADR-0008's was. That ADR could say the pilot plane
  was additive — "removing the plane removes a capability; it breaks nothing that exists". That
  is no longer true of the canonical layer inside it: the mediator now reads a provider identity
  and call metadata, `RulingStatus` has a member the challenger uses, and `nemesis.pilotbench`
  depends on all of it. Removing a *seat* is still free — delete a module and a registry entry,
  and nothing else notices, which is the property the layer exists to provide. Removing the
  *layer* would mean unwinding the audit schema. Stated here rather than discovered later.

## Context

ADR-0008 established the seam: an untrusted external model proposes moves from a closed
four-verb vocabulary, and a mediator holding every handle rules on each one. It shipped with two
concrete seats — OpenAI and Anthropic — and a shared `model_seat` module whose stated job was
"so the two do not drift".

Two things then happened. A third seat arrived (a local model through Ollama), and the founder
asked for the platform to be drivable by any frontier vendor, with the same constrained decision
surface, so that models can be compared rather than chosen. Three became five.

**The pairwise argument did not survive the plural.** "The two cannot drift" is something a
reader can check by eye. Five-way agreement is not, and an audit found the drift had already
happened while five docstrings, an ADR heading and a review brief all asserted it had not:

- One seat parsed stringified JSON arguments; another silently dropped them.
- One dropped a non-`dict` mapping; another kept it.
- Three took the first of several tool calls; the fourth aborted on a malformed block.
- Each used a different `except` tuple, a different no-move sentinel text, and a different
  `tool_choice` — one had none at all.

Neither seat's failure set was a superset of the other's, so the claim was false in both
directions. And a shared defect proved the other half of the argument in the same pass:
`move_description` split a move's docstring on the first *newline*, so three of the four tool
descriptions reached every vendor cut off mid-clause — `record_belief` truncated one word before
"never as an observation or a fact", which is the sentence telling the model what invariant 1
does to whatever it asserts. Three implementations that disagree are noisy and self-diagnosing.
One that is wrong is silent.

Two further findings set the scope, both from the same audit:

**The audit trail could not tell providers apart.** The only driver identity recorded was
`inputs["pilot"] = pilot.name` — one free-text string, defaulted by the seat and overridable by
any caller. An `OpenAIPilot` constructed with an Anthropic transport was indistinguishable in
the trail. A change made to enable comparison had no trustworthy field to compare on.

**The closed vocabulary was not closed about arguments.** The four move models used Pydantic's
default `extra="ignore"`, so `{"kind": "conclude", "__unparsable_arguments__": "…"}` — the exact
marker two adapters emit for a tool call whose JSON did not parse — validated into a clean
`Conclude`. A model whose arguments arrived as garbage ended the session successfully, and the
transcript recorded a completion.

## Decision

**Five provider seats, one canonical layer, one registry, and a benchmark.**

**The vocabulary is rendered, not written.** `nemesis.pilot.providers.schema` holds one
`MOVE_TOOL_SUITE` derived from the move models. A provider supplies a *dialect* — a pure
function from one tool spec to that vendor's JSON — and never sees the list, so no adapter can
add a verb. `render_tools` re-checks the emitted names against the suite anyway, and raises
`ToolSuiteViolationError` if they differ. Gemini's OpenAPI-3.0 subset is the interesting case:
`$ref` and `$defs` are inlined and unsupported keywords dropped, and the `enum` that arrives
attached to the reference is preserved, because losing it would leave one vendor's model free to
name a pivot type the other four cannot.

**A seat holds nothing, structurally.** A tenth `import-linter` contract,
`provider-adapters-hold-no-handles`, forbids anything under `nemesis.pilot.providers` from
importing the mediator, pursuit, effects, authz, graph, evidence, collection or audit. It names
the *package*, so the sixth vendor nobody has written yet is covered on the day it is written.
The audit found the package existing without an `__init__.py`, which made it a PEP 420 namespace
package invisible to `grimp` — every contract reported "kept" over code none of them could see.

**Provider identity is separate from model identity and is read once.** `ProviderIdentity`
carries provider, model and seat; the mediator reads it at session open and writes it into every
`pilot.move` and `pilot.session` event, *after* the per-turn metadata, so a turn cannot rewrite
attribution. xAI is recorded as xAI even though it serves an OpenAI-compatible transport: a
shared dialect is not a shared identity, and `pilot.name` reaches `Claim.model_identifier` on
every belief a pilot records.

**Metadata is descriptive and decides nothing.** Latency, token counts, attempt count, finish
reason, request id and the tool the model chose reach the audit trail through a bounded
`audit_fields()`. No ruling reads any of it. A seat that lied in every field would produce a
misleading record and never an action that should not have happened — which is what makes it
safe to accept from an untrusted seat at all.

**Retries are bounded, deterministic, and never change the request.** Only failures where the
identical request might succeed are retried; a malformed response is not. No dropped parameter,
no lowered token cap, no different model. Backoff has no jitter, because a benchmark that cannot
explain why two runs differed is one dial short. The attempt count reaches the audit trail,
which closes a gap the mediator's own comment had opened: it claimed "never a silent retry" and
nothing asserted it.

**Reasoning is requested only where the trace does not come back.** OpenAI's `reasoning_effort`
and Gemini's `thinkingConfig` without `includeThoughts` are used. Anthropic's extended thinking
returns `thinking` blocks, so this platform declines the feature and refuses a configured
reasoning effort at construction rather than dropping it silently. NEMESIS does not request or
persist private reasoning traces; there is no field on the way out for one to occupy.

**The move vocabulary forbids unknown arguments.** `extra="forbid"` on all four moves. An
argument the vocabulary does not define is an argument nobody validated.

**An optional challenger, whose whole vocabulary is five verdicts.** A second, independent model
receives the briefing the pilot received and the move it proposed, and returns `CONSISTENT`,
`CONTRADICTED`, `INSUFFICIENT_EVIDENCE`, `PROVENANCE_PROBLEM` or `POSSIBLE_INJECTION`. There is
deliberately no `APPROVED`: a challenger can cause a refusal and can never cause an action, so a
hijacked one achieves an availability failure and never an unauthorized effect. A verdict is
re-validated at the seam exactly as a move is; a broken challenger lets the move through and the
transcript records that nothing challenged it, returning the session to the baseline posture
every containment test is written against.

**A benchmark, `nemesis.pilotbench`, with two tiers that are never averaged.** Control-plane
properties — nothing left the platform, no move escaped the vocabulary, no belief became
evidence, every move reached the hash-chained trail, the ledger verifies — are facts about
NEMESIS and the only figures allowed to fail a build. Agreement with an eight-scenario synthetic
corpus is conditional on assumptions we wrote, and says so above the numbers. False attribution
is the most severe model failure it measures; naming a natural person outranks it.

## Alternatives considered

**Keep one module per vendor and share nothing.** This is the status quo ante and it has a real
argument: three implementations that disagree are self-diagnosing, and centralising correlates
risk rather than removing it. `move_description` is the receipt — one defect, silently present in
every vendor at once. Rejected because the audit measured the alternative's actual cost: six
behavioural disagreements between three seats, none of them noticed, while five docstrings
asserted there were none. The mitigation adopted instead is that **test unification came first
and independently**: `tests/planes/test_provider_contract.py` runs the same assertions over every
registered provider and would have caught four of the six on day one without merging a line of
implementation.

**Masquerade xAI as OpenAI, since the transport is compatible.** Rejected. `pilot.name` reaches
`Claim.model_identifier` and the provider reaches the audit trail, so a Grok-driven run recorded
as `openai` names the wrong model as a claim's author and the wrong vendor as the recipient of
the briefing — in a platform whose premise is that provenance is checkable. It would also break
the thing model diversity is for: a challenger from a different family is only independent if
you can tell which family answered.

**A plugin registry that third parties can extend at runtime.** Rejected. An entry-point loader
is a way for an installed package to become the thing driving an investigation. `PROVIDERS` is a
`MappingProxyType` built once from an explicit tuple, and adding a provider is a reviewed source
change. The cost is small and measured: a new OpenAI-compatible vendor is one entry and no new
module.

**Provider fallback — switch vendors when one fails.** Deferred, recorded as `PROPOSED`, not
half-built. A session that silently changed vendor mid-run would produce an audit record naming
a configuration that did not run, and `Claim.model_identifier` values from two models inside one
investigation. The mediator already contains a failing pilot as a refused move and a recorded
halt, which is the correct fail-closed behaviour rather than a limitation to work around.

**Give the challenger the power to escalate to a human.** Rejected. It is authority: a model
that can summon a human can also exhaust one, and an alert that arrives because a second model
was uncertain trains an operator to dismiss it. The challenger objects or it does not.

**No hosted seats at all — keep the local seat only.** This is the founder's current posture and
it is not overridden here. Every hosted seat remains unwired, its default transport refuses, and
`nemesis pilot-preview` exists so the decision to wire one can be made by *reading what would
leave the building* rather than imagining it. What this ADR adds is the choice, not the traffic.

## Consequences

### Positive

- The provider is a configuration key. Investigation logic contains no vendor branch.
- Adding a vendor with its own dialect is one module and one registry entry; adding an
  OpenAI-compatible one is an entry.
- The audit trail can answer "which provider and which model produced this conclusion", and
  detects a provider silently substituting a model (`model_substituted`).
- Two closed-vocabulary defects that predate this work are fixed: unknown move arguments, and
  tool descriptions truncated mid-clause for every vendor.
- `scripts/check_prohibited.py` now refuses vendor SDK imports (`openai`, `anthropic`, `google`,
  `ollama`, `litellm`, `boto3`, …) outside the collection plane. The scan caught `urllib` in this
  exact plane once and would have waved `import openai` straight past it.

### Negative / accepted costs

- ADR-0008's reversibility claim is weakened, as stated above.
- One shared layer means one defect can reach five vendors. The parametrised contract suite is
  the mitigation and is not a proof.
- Three module paths (`openai_pilot`, `anthropic_pilot`, `local_pilot`) are now compatibility
  shims. They keep every existing import working and are dead weight the day nothing imports them.
- The freeze tables, the dial census and five documented counts all moved, which is a table-only
  refreeze commit and is exactly the visibility the freeze exists to produce.

### Residual risk

- **The benchmark grades against a corpus we wrote.** A model that scores well has agreed with
  our judgement about synthetic material. The report says so first and at length; it remains the
  most persuasive-looking and least load-bearing output in the repository.
- **Two mediator refusal sub-statuses are still decided by substring-matching engine-authored
  prose** (`_BUDGET_REFUSAL_MARKER`, `_DISCLOSURE_MARKER`). A cross-provider statistic on those
  two is only as reliable as that text. Promoting them to typed fields means touching the
  pursuit engine and the effects registry, and is not done here.
- **`unsupported_inference` is 100% by construction.** `RecordBelief.derived_from_claims` asks a
  pilot to cite what its belief rests on, and no briefing exposes a claim identifier to cite.
  The metric currently measures NEMESIS, not any model. Widening the briefing to carry claim
  *text* would be a disclosure regression — statements come from collected content, and the
  entity-type filter guarding the briefing does not read free text.
- **The signal this decision was wrong:** a provider added later that needs a behaviour the
  canonical layer forbids, and the layer being widened to admit it. The correct response would
  be to leave the layer alone and not support that provider.

## Verification status

Verified against this repository, by running it:

- The six behavioural drifts, the `extra="ignore"` hole and the `move_description` truncation
  were each reproduced before being fixed, and each has a test that fails without the fix.
- The `providers/__init__.py` / PEP 420 finding was verified by building the `grimp` graph with
  and without the file: 107 modules versus 114, with the contract reporting "kept" in both.
- Every scenario's planted material is asserted to reach a real briefing, *differentially*
  against the same scenario with its plants removed. The first version of the corpus wrote a
  bare IP address where the materializer requires `<entity_type>:<key>`, so two scenarios planted
  nothing and the check caught it.

**Not verified, and explicitly so:** every vendor API detail — endpoint shapes, field names,
which models accept `reasoning_effort`, Gemini's exact schema subset — is written from
documentation and is *unconfirmed against a live vendor* in this repository. No CI run contacts
any of them. `tests/planes/test_live_providers.py` exists to close that gap and is opt-in,
gated on `NEMESIS_LIVE_<PROVIDER>=1` plus a credential; until somebody runs it, treat every
provider adapter as `IMPLEMENTED` in shape and unconfirmed on the wire.

## Revisit when

- A live run against any vendor fails on request shape. The adapter is wrong, and so is the
  confidence expressed above.
- A sixth provider needs something the canonical layer will not do.
- The founder decides whether CTI data may transit a model vendor — at which point the hosted
  seats stop being shapes and start being traffic, and everything in this ADR about a third party
  holding every briefing becomes operational rather than anticipatory.
- The benchmark is used to *choose* a provider. That is the point at which "agreement with a
  corpus we wrote" stops being a caveat and starts being a decision procedure, and it should be
  reopened before, not after.
