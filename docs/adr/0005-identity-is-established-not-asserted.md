# ADR-0005: Identity is established by a verifier, not asserted by a caller

- **Status:** accepted
- **Date:** 2026-08-16
- **Deciders:** founding architect
- **Plane:** control plane (authorization gateway), core domain model
- **Reversibility:** moderate. The types are additive and the fixture provider is small.
  What is expensive to reverse is the API shape: the gateway no longer accepts a
  `Principal`, and every call site now passes an assertion. Going back means going back
  through all of them.

## Context

The gateway used to accept caller-supplied actor ids and role strings. That was fixed once:
`Principal` replaced the strings, and roles, assurance and the provider name became fields
the policy read rather than words the caller typed.

An external audit then pointed out that the fix had moved the problem rather than solved it.
`Principal` is an ordinary Pydantic model. Anything that could call the gateway could also
build one:

```python
forged = Principal(
    actor_id=new_id(IdPrefix.ACTOR),
    display_name="Ada",
    roles=frozenset({Role.INVESTIGATION_LEAD, Role.LEGAL_REVIEWER}),
    assurance=AssuranceLevel.HARDWARE_BACKED,
    authenticated_by="corporate-sso",
    authenticated_at=utcnow(),
)
gateway.approve(request_id, approver=forged, rationale="...")
```

The gateway checked the roles, checked the assurance floor, found both satisfactory, and
issued a genuine Ed25519 capability. The signature was authentic. The audit record named a
provider that does not exist. Every control downstream — dual control, the assurance floor,
the role table, the legal-basis check — was reading fields the attacker had written.

This is worth stating plainly because it is the general shape of the mistake: **a signature
proves that bytes were not edited after signing. It says nothing about whether they were
true when signed.** The capability chain was cryptographically sound end to end and rested
on an unverified assertion at the top.

## Decision

Split *stating* an identity from *deciding what it establishes*.

1. A provider issues an **`IdentityAssertion`**: issuer, subject, audience, display name,
   roles, assurance, authentication time, expiry, a unique assertion id, and a signature
   over the canonical encoding of all of it. Providers assert; they do not conclude.

2. A **`PrincipalVerifier`** is the only supported route from an assertion to a `Principal`.
   It is **mandatory at gateway construction** — there is no default and no optional path —
   and it checks, in order: the issuer is on an allowlist, the audience is this gateway, the
   signature verifies against that issuer's key, the assertion has not expired.

3. Each issuer is registered with an **assurance ceiling**. The issuer states what it did;
   the deployment states what that issuer's word is worth here. When the two disagree the
   ceiling wins, so an issuer cannot promote itself by asserting more. A ceiling caps and
   never raises.

4. The gateway's `request`, `approve` and `reject` take assertions. Roles, assurance and
   actor id used by the policy come **only** from the verifier's output.

The local development provider is registered at `DEVELOPMENT`. An assertion it signs
claiming `HARDWARE_BACKED` is downgraded to `DEVELOPMENT` at verification, which is then
refused by the assurance floor for anything whose product leaves the platform.

Two adjacent defects found while doing this were fixed in the same change:

- **`check_legal_basis_reviewed` was never called.** It is now applied at issuance to the
  assembled approval set — the question "did anybody qualified read the instrument?" is not
  one that any single approval can answer.
- **`Approval.approver_role` was a comma-joined display string.** It is now
  `approver_roles: frozenset[Role]`, because a policy check that has to parse a display
  string back into roles is a policy check waiting to be fooled by a comma. The display
  string remains as a derived property, for humans only.

## Consequences

**What this buys.** Inventing an issuer name yields an assertion nothing accepts. Claiming
stronger authentication than the issuer can perform is downgraded rather than believed.
Adding a field to either signed model without adding it to the payload now fails a test
that enumerates the model's fields rather than a test somebody remembered to write.

**What the first version of this ADR got wrong.** An adversarial review broke the design
described above and it is worth recording rather than quietly amending. Both signing
payloads were hand-written projections — ``op.value``, ``role.value``,
``dt.isoformat()`` — while every decision compared the objects those projections came from.
A ten-line ``str`` subclass that serialized as ``simulation`` and compared equal to
``provider_notification`` produced byte-identical signed bytes, a genuinely valid signature,
and a provider notification drafted from a rehearsal grant. The same trick made an assertion
serializing as ``analyst`` establish a ``legal_reviewer``, and a ``datetime`` subclass made
expiry unenforceable.

The correction is in [ADR-0006](0006-sign-the-object-verify-by-reconstruction.md) and it
supersedes the encoding described here: sign the model's own serialization, and verify by
parsing the signed bytes back into a fresh object that is then the only thing acted on. The
identity split above survives unchanged — it was the encoding beneath it that was wrong.

**What it does not buy, stated so nobody overreads it.** In-process, an attacker who already
executes arbitrary code inside the control plane can reach the signing key and does not need
any of this. The boundary is meaningful against a *component* that can call the gateway but
holds no issuer key — an agent, a connector, a compromised planner — and it becomes a real
authentication boundary the day assertions arrive from a separate process or host. That day
is also when assertion replay starts to matter: `assertion_id` is unique and signed, but
nothing yet keeps the set of spent ids.

**Cost.** Every gateway call site changed. Test fixtures that reached a higher assurance by
`model_copy(update={"assurance": HARDWARE_BACKED})` no longer work — which is the point,
since that was the exploit kept in the test suite. `tests/support/identity.py` supplies a
second fixture issuer registered at `HARDWARE_BACKED` instead, so a test elevates an
identity the way a deployment would: by registering an issuer and saying what it is worth.

**Cost we accepted.** The demonstration lost its abuse-notification draft. It now requests
the notification, is refused by the assurance floor, and prints the refusal — which is a
better demonstration and a thinner one. NEMESIS can currently establish no identity better
than a fixture, so it may rehearse and may not correspond. That is now enforced twice: once
at approval, and again at the Effects boundary, which finds no such permission in the grant.

**What would change this decision.** A real identity provider. Wiring one means implementing
one verifier and registering it with a ceiling; the gateway does not change. That was the
reason for the split.

## Alternatives considered

**Make `Principal` unforgeable in-process** (private constructor, module-private token). Not
possible in Python in any way an attacker with code execution respects, and it would have
produced a control that reads as strong and is not.

**Keep `Principal` at the API and verify inside the gateway.** Rejected: the type would then
be the thing a caller supplies *and* the thing the verifier produces, and the two are not
the same object. Making the input type structurally different from the output type is what
stops the confusion at compile time rather than at review time.

**Implement OIDC now.** Rejected as premature and dishonest: a convincing fake authenticator
is worse than none, because it produces audit records that look like logins. The assertion
is shaped like an OIDC id-token so that the real thing is a verifier implementation, not a
rewrite.
