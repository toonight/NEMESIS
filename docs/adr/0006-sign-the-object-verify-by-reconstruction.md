# ADR-0006: Sign the object, and verify by reconstructing it

- **Status:** accepted
- **Date:** 2026-08-16
- **Deciders:** founding architect
- **Plane:** core domain model, control plane, effects plane
- **Supersedes:** the signing-payload construction described in
  [ADR-0005](0005-identity-is-established-not-asserted.md). The identity split in ADR-0005
  stands; the encoding underneath it did not.
- **Reversibility:** low, and deliberately so. Every signature in the system now covers
  different bytes, and the verification contract returns a different object than it did.
  Nothing persists signatures yet, so the migration cost today is zero and will not stay so.

## Context

An adversarial review was asked to refute the claim that ADR-0005's boundary held. It
refuted it, four ways, from one root cause — and every finding was reproduced by execution,
against a tree where all 517 tests passed.

Both signing payloads were **hand-written projections** of their models:

```python
"permitted": sorted(op.value for op in self.permitted_operations),
"expires_at": self.expires_at.isoformat(),
"roles":      sorted(role.value for role in self.roles),
```

Every decision downstream, meanwhile, compared the **objects**:

```python
operation in self.permitted_operations
moment >= self.expires_at
principal.roles & APPROVAL_ROLES[operation]
```

So the signature covered a *rendering* of the grant while the platform acted on the *grant*.
Anything that rendered as the approved value and compared as something else lived in the gap.
Python makes such a thing trivial — an `enum` member *is* its value, a `StrEnum` hashes as
its string, and a subclass may override `__eq__`, `__hash__` or `isoformat` while remaining,
to a serializer, exactly what it inherits from:

```python
class RendersAs(str):
    def __hash__(self):
        return hash("provider_notification")

    def __eq__(self, other):
        return other == "provider_notification" or str.__eq__(self, other)


forged = capability.model_copy(
    update={"permitted_operations": frozenset({RendersAs("simulation")})}
)
forged.signing_payload() == capability.signing_payload()  # True — the bytes are identical
verify_capability(forged, key).signature_valid  # True — the signature is genuine
OperationClass.PROVIDER_NOTIFICATION in forged.permitted_operations  # True
```

Reproduced end to end, a capability permitting `SIMULATION` and nothing else **drafted a
provider notification**. The same shape defeated capability expiry (`MAX_CAPABILITY_LIFETIME`
became advisory), defeated `forbidden_operations` (explicit denial could be removed while
still rendering), and made an identity assertion that serialized as `analyst` establish a
`legal_reviewer` — producing an audit record showing a legal review that no issuer ever
vouched for, indexed by a real actor id.

No private key, no `model_construct`, no monkeypatching. `model_copy(update=...)` skips
validation, which is its documented behaviour, and that was enough.

## Decision

Two rules, each sufficient on its own for most of the attack surface, adopted together
because neither is sufficient for all of it.

**1. The payload is the model's own serialization, not a summary of it.**

```python
def signing_payload(self) -> bytes:
    return canonical_bytes(self.model_dump(mode="json", exclude=UNSIGNED_FIELDS))
```

A field cannot be signed as one thing and read as another when nobody chose how to render
it. A field added later is covered by default rather than by somebody remembering. Only the
signature itself and the two revocation fields are excluded, for the reason ADR-0005 gives:
revoking must not make a withdrawn capability indistinguishable from a forged one.

**2. Verification reconstructs, and only the reconstruction is acted on.**

`verify_capability` now parses the signed bytes back through the model's validators and
returns the result as `CapabilityVerification.authenticated` — `None` unless the signature
verified *and* the reconstruction is structurally coherent. `preflight` reasons about that
object and never about the one it was handed. `PrincipalVerifier.verify` does the same: the
assertion passed in is treated as an envelope carrying a signature, and audience, expiry,
roles, assurance and subject are all read from the reconstruction.

A signature proves an issuer produced *these bytes*. What the bytes say is a question you
answer by parsing them — never by trusting the object that arrived beside them. A
reconstructed object cannot carry a masked enum or a lying `datetime`, because it was built
from text by code the attacker does not control.

Rule 2 is the load-bearing one. Rule 1 depends on a serializer rendering the *actual* value,
which it does — but a `str` subclass whose content is genuinely `"simulation"` while its
equality is `"provider_notification"` defeats rule 1 completely, with truly identical bytes
and a genuinely valid signature. `tests/invariants/test_value_confusion.py` builds exactly
that and asserts the platform still refuses. That test is the point of this ADR.

**Canonical encoding.** `nemesis.core.canonical` sorts object keys and sorts arrays by their
own encoding. Sorting is required for correctness, not tidiness: Pydantic serializes a
`frozenset` in set-iteration order and Python randomises string hashing per process, so an
unsorted payload would verify in the process that signed it and nowhere else. It is *safe*
only because nothing signed here carries meaning in its ordering. If a signed field ever
does, this is the wrong encoding and a deterministic non-sorting one is right.

**A second, independent reviewer** was run against the corrected tree with the same
refutation brief, and found two more — neither in the value-confusion class, both reproduced
here before being believed:

- **The gateway handed out references to its own records.** `request()` returned the very
  object it retained, so a requester could have a rehearsal approved and then edit the
  record the approver had signed off on. An approved `SIMULATION` became a working
  `PROVIDER_NOTIFICATION` capability that drafted a document, with no key involved. The same
  applied to `Approval`: adding `legal_reviewer` to the returned object defeated
  `check_legal_basis_reviewed` and produced an authentic court-order capability that no
  qualified reviewer had approved — with an audit trail saying one had. `model_config
  frozen=True` is not a defence, because `__dict__` is still there and the attacker is
  inside the process by assumption. The gateway now copies on write **and** on read.

- **Documents were composed from the unauthenticated capability.** Reconstruction had been
  wired into `preflight` but not into `_document`, so a `str` subclass whose *content*
  matched the signed authority reference — identical bytes, so the encoding layer is
  bypassed entirely — but whose `__str__` returned `"TGI Paris ord. 2026/9999 - seizure
  authorised"` put a fabricated court order into a notification addressed to a provider.
  The drafting adapter's docstring already said a document must not cite "the caller's idea
  of its own legal basis". `Preflight` now carries the reconstruction and adapters compose
  from it.

The second is the more instructive: the fix had been applied at the boundary that *decides*
and not at the one that *writes*, which is the harder half to remember and the half a human
actually reads.

Three findings from the same review, fixed alongside:

- **Effects adapters verified against a key the caller passed in.** `registry.adapters` is
  public; an attacker took a wired adapter, handed it a capability signed by their own key
  *together with that key*, and got a drafted document. Adapters now hold a `TrustAnchor`
  fixed at construction, and the registry refuses to register an adapter whose anchor names
  a different authorizer, or none.
- **`check_dual_control` had no caller.** Now called at issuance over the set of distinct
  approvers.
- **`not_before` was unbounded**, so the lifetime ceiling was a window rather than a limit.
  Now bounded by the same ceiling.

## Consequences

**What this buys.** The entire value-confusion class is closed for both signed models, at
two independent layers, with regression tests that construct the attacks rather than
describing them. A signed field that is added and forgotten fails a test that enumerates
`model_fields`.

**What it does not buy.** An attacker who executes arbitrary code in this process can reach
`gateway._signer` and mint whatever they like; none of this touches that. What it defends is
the case the platform is actually built around — a component that holds a legitimately
issued capability, or can call an adapter, and holds no signing key. That is the planner, a
connector, a collector, the Effects plane itself. Process isolation is what closes the rest,
and it is `PROPOSED`, not `IMPLEMENTED`.

**A behaviour change worth naming.** The reconstruction has no revocation fields, so a
capability's self-declared `revoked_at` is no longer part of the reconstructed grant.
`preflight` therefore reads it from the presented object explicitly, and **only in the
refusing direction**: a self-declared revocation refuses, and its absence proves nothing.
An attacker gains nothing by adding one, an honest caller that stamps a withdrawal it knows
about is not ignored, and the authoritative answer still comes from the oracle.

**Cost.** Every signature changes. Two tests asserted properties that the old encoding made
true and the new one makes obsolete — a target rename beneath a kept fingerprint now breaks
the signature rather than surviving it for the structural check to catch, and an edited
audience now breaks the signature before the audience check is reached. Both were rewritten
to assert the stronger property and to reach the original control by a route that still
exercises it.

**What would change this decision.** A signed field whose ordering carries meaning would
invalidate the array sorting. Persisted signatures would make the encoding a compatibility
surface, at which point it needs a version tag inside the payload.

## Alternatives considered

**Type gates at every decision point** (`type(x) is OperationClass`, `is datetime`, …).
Cheap, and it does defeat all four exploits. Rejected as the primary defence because it is a
list that must stay complete: every new comparison against a signed field is a new place to
remember, and the failure mode of forgetting is silent. It survives as an implicit
consequence of rule 2 — a reconstructed object is correctly typed everywhere, once.

**Keep the projections and add the missing fields.** This is what a narrow reading of the
findings suggests, and it would have fixed the four reported exploits and none of the class.
The review found four; the encoding permitted an unbounded number.

**Have `signing_payload` reject non-exact types before serializing.** Attractive, but it
puts the check on the attacker's side of the boundary: `signing_payload` is called on the
object the attacker controls, in a process they control, so it is a check that runs at their
convenience. Reconstruction happens on the verifier's side, which is the side that matters.
