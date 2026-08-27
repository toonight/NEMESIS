"""The adapter registry and the guards every adapter runs before it acts.

This plane is assumed compromised. Nothing here trusts its caller: the orchestrator that
built the request may itself be the attacker, so every check the orchestrator performed is
performed again, from the capability object, immediately before acting.

Three things live here because all four adapters need them and none of them may be skipped:

``preflight`` — the ordered verification (capability, then target state, then stop
conditions). Ordered deliberately: a target-state check on an unauthorized operation would
leak that the target is known to us before establishing any right to look at it.

``sanitize`` — flattening of caller-supplied strings before they reach a document. A draft
is a NEMESIS-branded artifact that leaves the system's epistemic controls behind; a
parameter value carrying newlines could forge its banner lines and make it read as though
it carried authority nobody granted.

``EffectsRegistry`` — the operation-class lookup. Its most important behaviour is what it
does for the classes with no adapter: it refuses, with a record, rather than raising or
improvising. Those are the ``REQUIRES_LEGAL_AUTHORITY`` classes, and their refusal is the
feature, not a gap waiting to be filled.
"""

from __future__ import annotations

import hmac
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, model_validator

from nemesis.authz.verification import verify_capability
from nemesis.core.authorization import (
    MVP_IMPLEMENTED_OPERATIONS,
    NO_CAPABILITY,
    AuthorizationCapability,
    AuthorizationDecision,
    OperationClass,
    TargetFingerprint,
)
from nemesis.core.disclosure import scan_for_internal_material
from nemesis.core.infrastructure import (
    OBSERVE_AND_PRESERVE_OPERATIONS,
    ROLE_ATTRIBUTE,
    InfrastructureRole,
    eligible_roles,
    is_role_eligible,
)
from nemesis.core.temporal import utcnow
from nemesis.ports.authorization import CapabilityVerifier, RevocationOracle, TrustAnchor
from nemesis.ports.effects import EffectOutcome, EffectRequest, EffectResult, EffectsAdapter

__all__ = [
    "REGISTRY_NAME",
    "STOP_CONDITION_CLEARED",
    "STOP_CONDITION_PARAMETER_PREFIX",
    "EffectsRegistry",
    "Preflight",
    "TrustAnchor",
    "default_registry",
    "preflight",
    "refusal_record",
    "sanitize",
]

REGISTRY_NAME: Final = "effects-registry"

STOP_CONDITION_PARAMETER_PREFIX: Final = "stop_condition."
"""Prefix under which a caller states that a blocking stop condition was checked."""

STOP_CONDITION_CLEARED: Final = "cleared"
"""The only value that clears a stop condition. Anything else, including absence, refuses.

A stop condition an adapter cannot evaluate and silently treats as satisfied is decoration.
The adapter has no way to observe "the registrant has contested ownership", so it demands
that whoever can observe it says so explicitly, per operation, in the request it signed up
to. Fail-closed is the only direction that leaves the condition meaning anything.
"""

_CONTROL_CHARACTERS: Final = re.compile(
    "["
    "\x00-\x1f\x7f-\x9f"  # C0 and C1
    "\u2028\u2029"  # LINE SEPARATOR, PARAGRAPH SEPARATOR
    "\u0085"  # NEXT LINE
    "\u000b\u000c"  # VT, FF — inside C0, named because `splitlines()` breaks on them
    "\u200b-\u200f"  # zero-width space/joiners, LTR/RTL marks
    "\u202a-\u202e"  # bidi embedding and override
    "\u2066-\u2069"  # bidi isolates
    "\ufeff"  # zero-width no-break space
    "]"
)
_RUNS_OF_SPACE: Final = re.compile(r"\s{2,}")


def sanitize(value: str, *, limit: int = 400) -> str:
    """Reduce a caller-supplied string to one harmless line.

    Control characters — newlines above all — are what turn a data field into document
    structure. The layout of a draft is not negotiable by whoever supplied its parameters.

    **ASCII was not enough, and an adversarial review proved it with one codepoint.** The class
    was ``[\\x00-\\x1f\\x7f-\\x9f]``, which misses U+2028 LINE SEPARATOR — and Python's own
    ``str.splitlines()`` breaks on U+2028, as do browsers and most editors. Substituting it for a
    newline in this repository's own document-forgery payload produced a draft that reads, to any
    ordinary reader, as carrying a fabricated ``Legal basis: court_order`` line. The control and
    the test that guarded it both assumed ASCII line structure.

    Three families are now covered and each is here for a different reason. The line breakers
    (U+2028/29/85, VT, FF) forge structure. The zero-width characters (U+200B to U+200F, and
    U+FEFF) hide text inside a field that looks short. The bidi controls (U+202A to U+202E and
    U+2066 to U+2069) reorder what a human reads without changing what a machine compares — a
    document whose rendered
    meaning differs from its bytes is the same defect as a ``str`` subclass whose ``__str__``
    lies, which this codebase has already been bitten by twice.
    """
    flattened = _RUNS_OF_SPACE.sub(" ", _CONTROL_CHARACTERS.sub(" ", value)).strip()
    if len(flattened) > limit:
        return f"{flattened[:limit]} [truncated at {limit} characters]"
    return flattened or "<empty>"


class Preflight(BaseModel):
    """The outcome of the pre-execution checks, refusal or not.

    Carries the decision either way: a refusal that does not record what was evaluated is
    indistinguishable, after the fact, from an adapter that was never called.
    """

    model_config = ConfigDict(frozen=True)

    decision: AuthorizationDecision
    approved_target: TargetFingerprint | None = None
    refusal: EffectOutcome | None = None
    detail: str = ""

    granted: AuthorizationCapability | None = None
    """The grant as reconstructed from the signed bytes. Present whenever the signature and
    the structure both checked out, and ``None`` otherwise.

    **An adapter must compose its document from this, never from the capability it was
    handed.** The two can differ while the bytes and the signature are both genuine: a
    ``str`` subclass whose content is the approved authority reference but whose ``__str__``
    returns something else produced a provider notification citing a fabricated court order.
    The drafting adapter's own docstring said a document must not cite "the caller's idea of
    its own legal basis", and that is precisely what it was doing."""

    @property
    def may_act(self) -> bool:
        return self.refusal is None

    @model_validator(mode="before")
    @classmethod
    def _a_refusal_is_never_recorded_as_permitted(cls, data: Any) -> Any:
        """A refused preflight cannot carry a decision that says the operation was permitted.

        **This is the third time the same defect has been found here, and the first time it is
        fixed structurally.** :func:`refusal_record` exists because two earlier reviews found a
        refused operation written into the hash-chained trail as ``permitted: true`` with no
        denial reasons. It was applied to four branches. An adversarial review of this plane
        then found the other ten — every target-binding refusal, every stop-condition refusal,
        the D1 disclosure refusal, the role-gate refusal — each passing the *genuine*
        ``authorizes()`` verdict straight through. That verdict is ``permitted=True``, because
        the grant really did permit the operation class; something else refused it.

        Measured before the fix: a D1 disclosure refusal reached the trail as
        ``permitted=True, denial_reasons=[]``, and ``verify()`` returned True over it. A
        tamper-evident record of the wrong thing.

        Patching branch eleven would have left branch twelve, so the invariant lives on the
        type: whatever a caller passes, a ``Preflight`` carrying a refusal *cannot* hold a
        permissive decision. The refusal's own detail becomes the denial reason, which is what
        an investigator actually reads.

        ``mode="before"`` and not ``"after"``, which is a real distinction rather than a style
        choice: an ``after`` validator that returns a new object is **ignored** on the
        ``__init__`` path — pydantic warns and keeps the original. The first version of this fix
        did exactly that and the defect survived it, which is a reminder that a control has to be
        observed working rather than reasoned to.

        Derived rather than raised, deliberately. Raising here would turn a refusal — the normal,
        correct outcome — into an exception on the path whose whole job is to record that a
        refusal happened.
        """
        if not isinstance(data, dict):
            return data
        decision = data.get("decision")
        if data.get("refusal") is None or not isinstance(decision, AuthorizationDecision):
            return data
        if not decision.permitted:
            return data
        refusal = data["refusal"]
        # The refusal's own vocabulary value, never the detail prose. The first version used
        # the detail and the briefing's fail-closed disclosure backstop caught it within one
        # run: a D1 refusal's detail *names the internal markers it caught*, so echoing it into
        # a structured field carried them into `Ruling.authorization`, onto the next briefing,
        # and — for a hosted seat — to a vendor. A structured field holds a structured value;
        # the prose stays in `detail`, which the mediator already redacts on that path.
        reason = str(getattr(refusal, "value", refusal))
        return {
            **data,
            "decision": decision.model_copy(
                update={"permitted": False, "denial_reasons": (reason,)}
            ),
        }


def refusal_record(
    request: EffectRequest,
    *,
    operation: OperationClass,
    capability_id: str,
    now: datetime,
    reasons: tuple[str, ...],
) -> AuthorizationDecision:
    """The decision written into the audit trail when the grant cannot be trusted.

    Built here from values this plane knows, never by calling ``authorizes()`` on the object
    under suspicion. Two reviews found the same shape: a refused operation was recorded with
    ``permitted: true`` and no denial reasons, and on the forged path the record was composed
    by the attacker — including a ``capability_id`` pointing an investigator at a grant with
    nothing to do with the event. Both records went into the hash-chained trail and the chain
    verified, which is the worst of both worlds: a tamper-evident record of the wrong thing.
    """
    return AuthorizationDecision(
        permitted=False,
        capability_id=capability_id,
        operation=operation,
        target_fingerprint=request.target_fingerprint,
        evaluated_at=now,
        denial_reasons=reasons,
    )


def preflight(
    request: EffectRequest,
    capability: AuthorizationCapability,
    *,
    operation: OperationClass,
    anchor: TrustAnchor,
) -> Preflight:
    """Verify authenticity, then revocation, then scope, target and stop conditions.

    ``anchor`` is required, with no default, and it is the adapter's own — never the
    caller's. An earlier version checked nothing at all, and a capability with
    ``signature=None`` whose only approval the attacker had granted themselves produced a
    drafted document. The version after that checked against a key the caller passed in,
    which is the same hole wearing a signature.

    ``operation`` is the class the *adapter* implements, never the one the request claims.
    A request labelled ``simulation`` handed to the takedown drafter would otherwise be
    authorized as a simulation and executed as a takedown.

    The clock is read here rather than accepted as an argument. A caller-supplied "now" is
    all an attacker needs to make an expired capability valid again, which is precisely the
    thing invariant 9 exists to prevent.

    **The capability argument is an envelope.** Once its signature verifies, every check
    below runs against ``verification.authenticated`` — the grant reconstructed from the
    signed bytes — and never against the object that arrived. An adversarial review handed
    this function a capability whose permitted operations serialized as ``simulation`` and
    compared as ``provider_notification``, and a provider notification was drafted from a
    rehearsal grant. The signature was genuine; the object was not what it said.
    """
    now = utcnow()

    # Authenticity first. Everything below reasons about the capability's contents, and
    # reasoning about the contents of a document nobody signed is how a forgery gets
    # treated as a policy question.
    verification = verify_capability(capability, anchor.verifying_key, now=now)
    if not verification.is_authentic or verification.authenticated is None:
        return Preflight(
            # The structured verdict carries no capability id, because nothing here
            # authenticated one. The id the caller *claimed* goes into the free-text detail,
            # labelled as a claim: it is evidence about what was presented, and it must not
            # sit in a field an investigator reads as "the grant this concerned". A review
            # found the recorded decision on this path — id included — was authored by the
            # attacker, and written into the hash-chained trail, which then verified.
            decision=refusal_record(
                request,
                operation=operation,
                capability_id=NO_CAPABILITY,
                now=now,
                reasons=(
                    "the capability's signature does not verify against the key this plane holds",
                    *verification.structural_failures,
                ),
            ),
            refusal=EffectOutcome.REFUSED_UNVERIFIED_CAPABILITY,
            detail=(
                "refused: the capability's signature does not verify against the key this "
                f"plane holds — {verification.signature_failure or 'no signature present'}"
                + (
                    f"; structural failures: {'; '.join(verification.structural_failures)}"
                    if verification.structural_failures
                    else ""
                )
                + "; the capability presented claimed the id "
                f"{sanitize(verification.capability_id, limit=64)!r}"
            ),
        )

    # Then revocation, which needs state and therefore cannot be answered offline. Fails
    # closed: an oracle we cannot reach is not an oracle reporting no revocation.
    #
    # The presented object's own `revoked_at` is honoured too, and only in the refusing
    # direction. It is outside the signature, so an attacker can strip it — which is why it
    # cannot be relied on to refuse — but adding one buys an attacker nothing except a
    # refusal, and an honest caller that stamps a withdrawal it already knows about should
    # not have it ignored. A signal that can only ever say no is safe to read from anywhere.
    granted = verification.authenticated
    decision = granted.authorizes(
        operation=operation,
        target_fingerprint=request.target_fingerprint,
        now=now,
    )

    if capability.is_revoked:
        reason = sanitize(capability.revocation_reason or "no reason recorded", limit=120)
        return Preflight(
            decision=refusal_record(
                request,
                operation=operation,
                capability_id=granted.capability_id,
                now=now,
                reasons=(f"the capability presented is marked revoked: {reason}",),
            ),
            refusal=EffectOutcome.REFUSED_REVOKED,
            detail=f"refused: the capability presented is marked revoked ({reason})",
        )
    try:
        revoked = anchor.revocations.is_revoked(granted.capability_id)
    except Exception as exc:
        return Preflight(
            decision=refusal_record(
                request,
                operation=operation,
                capability_id=granted.capability_id,
                now=now,
                reasons=(f"the revocation oracle could not be consulted ({type(exc).__name__})",),
            ),
            refusal=EffectOutcome.REFUSED_REVOKED,
            detail=(
                f"refused: the revocation oracle could not be consulted "
                f"({type(exc).__name__}). An unreachable oracle is not an absent revocation."
            ),
        )
    if revoked:
        # The reconstruction cannot carry revocation state — those fields are outside the
        # signature by design — so the record has to be built here. Recording `permitted`
        # for an operation the oracle just refused was a regression that survived a full
        # green suite, because nothing asserted what the *record* said.
        return Preflight(
            decision=refusal_record(
                request,
                operation=operation,
                capability_id=granted.capability_id,
                now=now,
                reasons=("the issuing authority has withdrawn this capability",),
            ),
            refusal=EffectOutcome.REFUSED_REVOKED,
            detail=(
                "refused: the issuing authority has withdrawn this capability. The copy "
                "presented here may predate the withdrawal; the oracle, not the object, "
                "is what says whether a grant still stands."
            ),
        )

    # Founder decision D1's wall, at the only boundary that can enforce it here. Effects
    # receives its content as a string dictionary, which no type can constrain, so this is
    # where internal-classified material would leak into a document. Checked before the
    # capability verdict is acted on: a leak is not something to weigh against having been
    # authorized, and an authorized operation carrying persona-linkage prose is exactly the
    # case worth refusing loudest.
    leaked = scan_for_internal_material(request.parameters)
    if leaked:
        return Preflight(
            decision=decision,
            refusal=EffectOutcome.REFUSED_UNAUTHORIZED,
            detail=(
                "refused: the request carries internal-classified material into a plane "
                "that produces documents for external recipients — "
                + "; ".join(leaked)
                + ". Persona linkage is an investigative lead, never a deliverable "
                "(founder decision D1). Supply an ExternalAttributionProduct instead; it "
                "has no field capable of holding one."
            ),
        )

    if request.operation is not operation:
        return Preflight(
            decision=decision,
            refusal=EffectOutcome.REFUSED_UNAUTHORIZED,
            detail=(
                f"request is labelled {request.operation.value} but was handed to the "
                f"{operation.value} adapter; the adapter performs its own class, so this "
                "request would have been authorized as one operation and executed as another"
            ),
        )

    if not decision.permitted:
        return Preflight(
            decision=decision,
            refusal=EffectOutcome.REFUSED_UNAUTHORIZED,
            detail=decision.render(),
        )

    approved = next(
        (
            target
            for target in granted.targets
            if hmac.compare_digest(target.fingerprint, request.target_fingerprint)
        ),
        None,
    )
    if approved is None:
        # Unreachable through `authorizes`, which already checks membership. Kept because
        # a future widening of that check must not silently drop the target binding.
        return Preflight(
            decision=decision,
            refusal=EffectOutcome.REFUSED_UNAUTHORIZED,
            detail="no approved target matches this fingerprint",
        )

    missing = sorted(
        key for key in approved.bound_attributes if key not in request.current_target_attributes
    )
    if missing:
        return Preflight(
            decision=decision,
            approved_target=approved,
            refusal=EffectOutcome.REFUSED_TARGET_CHANGED,
            detail=(
                f"the target's current state was not observed for bound attribute(s) "
                f"{', '.join(missing)}; an unobserved attribute is not an unchanged one, and "
                "accepting the omission would let a caller defeat target binding by simply "
                "not looking"
            ),
        )

    observed = {key: request.current_target_attributes[key] for key in approved.bound_attributes}
    recomputed = TargetFingerprint.compute(
        entity_id=approved.entity_id,
        entity_type=approved.entity_type,
        natural_key=request.target_natural_key,
        bound_attributes=observed,
    )
    if not hmac.compare_digest(recomputed, approved.fingerprint):
        # The natural key goes into the recomputation on purpose: an approval for
        # evil.example must not be spendable on a request that names innocent.example
        # while quoting the approved fingerprint.
        changed = sorted(
            key for key, value in approved.bound_attributes.items() if observed[key] != value
        )
        divergence = (
            f"bound attribute(s) {', '.join(changed)} differ from the approved state"
            if changed
            else f"the request names target {sanitize(request.target_natural_key, limit=120)!r}, "
            f"which is not the approved target's natural key"
        )
        return Preflight(
            decision=decision,
            approved_target=approved,
            refusal=EffectOutcome.REFUSED_TARGET_CHANGED,
            detail=(
                f"{divergence}; the approval was granted against a state this target no "
                "longer has — it may have been transferred, reassigned or rebuilt for a "
                "legitimate owner since"
            ),
        )

    # Whose target is this? Checked after target binding, so the role read here is both the
    # one an approver signed and — because it is a bound attribute — the one just re-observed
    # from the graph. Read off `approved`, which comes from the capability reconstructed from
    # the signed bytes, never off the object that arrived.
    #
    # This is the mission's central rule made deterministic: observing an adversary use a
    # piece of infrastructure establishes nothing about whose it is, so malicious use alone
    # never authorizes disruption. The judgement itself is made where the evidence lives; what
    # happens here is the verification of a signed fact, because this plane is forbidden from
    # importing the planes that could compute one, and that prohibition is what makes
    # "attribution is not authorization" true rather than merely stated.
    bound_role = approved.bound_attributes.get(ROLE_ATTRIBUTE)
    role_required = operation not in OBSERVE_AND_PRESERVE_OPERATIONS
    if bound_role is None:
        if role_required:
            return Preflight(
                decision=decision,
                approved_target=approved,
                refusal=EffectOutcome.REFUSED_UNAUTHORIZED,
                detail=(
                    f"no {ROLE_ATTRIBUTE} is bound into this capability, and "
                    f"{operation.value} may not run against a target whose standing nobody "
                    "established. Observing what a target was used for establishes neither "
                    "who owns it nor who controls it; approving an operation without saying "
                    "which of those was found is how a victim's host becomes a takedown "
                    "target. Bind the classification at approval"
                ),
            )
    else:
        try:
            role = InfrastructureRole(bound_role)
        except ValueError:
            return Preflight(
                decision=decision,
                approved_target=approved,
                refusal=EffectOutcome.REFUSED_UNAUTHORIZED,
                detail=(
                    f"the bound {ROLE_ATTRIBUTE} {sanitize(bound_role, limit=64)!r} is not a "
                    "classification this platform recognises; an unrecognised standing is not "
                    "a permissive one"
                ),
            )
        if not is_role_eligible(operation, role):
            permitted = sorted(r.value for r in eligible_roles(operation))
            return Preflight(
                decision=decision,
                approved_target=approved,
                refusal=EffectOutcome.REFUSED_UNAUTHORIZED,
                detail=(
                    f"the target is classified {role.value} and {operation.value} may run "
                    f"only against {', '.join(permitted) or 'no target'}. Malicious use is "
                    "not ownership: this target is somebody else's, shared with somebody "
                    "else, or unclassified, and acting against it would harm a party who is "
                    "not the adversary"
                ),
            )

    uncleared = tuple(
        condition
        for condition in decision.stop_conditions_to_check
        if request.parameters.get(f"{STOP_CONDITION_PARAMETER_PREFIX}{condition}")
        != STOP_CONDITION_CLEARED
    )
    if uncleared:
        return Preflight(
            decision=decision,
            approved_target=approved,
            refusal=EffectOutcome.REFUSED_STOP_CONDITION,
            detail=(
                f"blocking stop condition(s) {', '.join(sanitize(c, limit=80) for c in uncleared)} "
                "were not stated as checked; this adapter cannot observe them and will not "
                "assume they hold"
            ),
        )

    return Preflight(decision=decision, approved_target=approved, granted=granted)


def _adapter_name_or_registry(adapter: EffectsAdapter) -> str:
    """The adapter's own name, or this registry's when asking for it is itself unsafe.

    ``getattr(adapter, "name", REGISTRY_NAME)`` is not enough, and it is worth saying why: the
    default arm answers :class:`AttributeError` alone, so a ``name`` **property** raising
    anything else — a lazily-loaded resource that has gone away, very often the same failure
    that just took the adapter down — propagates straight out of the crash handler and
    destroys the record that handler exists to guarantee.

    The exception is swallowed rather than reported because there is nowhere left to report
    it: this runs while another failure is already being converted into a result, and raising
    here would lose both. The fallback names the registry, which is the component that did
    author the record, and is the honest answer to "who is this?" from an adapter that would
    not say.
    """
    try:
        return str(adapter.name)[:120]
    # Deliberately unnarrowed: the point is to survive *any* answer, including none.
    except Exception:
        return REGISTRY_NAME


class EffectsRegistry:
    """Maps an operation class to the one adapter that may perform it.

    A mutable store rather than a record, and the only mutation point is registration at
    wiring time. Two guards make that point the place where a dangerous change becomes
    visible: an adapter that declares external contact is refused, and an adapter for a
    class outside ``MVP_IMPLEMENTED_OPERATIONS`` is refused. Both refusals are loud,
    because both represent NEMESIS gaining a capability it is not supposed to have.
    """

    def __init__(self, *, verifying_key: CapabilityVerifier, revocations: RevocationOracle) -> None:
        self._anchor = TrustAnchor(verifying_key=verifying_key, revocations=revocations)
        self._adapters: dict[OperationClass, EffectsAdapter] = {}

    def register(self, adapter: EffectsAdapter) -> None:
        """Add an adapter, keyed by the class it declares it implements.

        Keyed by ``adapter.operation`` rather than by a separate argument, so a wiring
        mistake cannot file a takedown drafter under ``simulation``.
        """
        anchor = getattr(adapter, "anchor", None)
        if anchor is None:
            raise ValueError(
                f"adapter {adapter.name!r} declares no trust anchor, so it verifies against "
                "nothing it was wired with; an adapter that cannot name its authorizer "
                "cannot refuse a capability from anyone else"
            )
        if not isinstance(adapter, EffectsAdapter):
            # `EffectsAdapter` is `runtime_checkable` and this check was simply never made, so
            # an object with no `name` and no `execute` registered without complaint and the
            # failure surfaced later — inside the crash handler that exists to *guarantee* a
            # record, which then raised on `adapter.name`. A registry that accepts anything is a
            # registry whose other guards run on objects that cannot satisfy them.
            #
            # Ordered after the anchor check deliberately: an adapter missing only its anchor
            # fails both, and "declares no trust anchor" tells a wirer what to fix while "does
            # not satisfy the protocol" tells them to go looking.
            raise ValueError(
                f"{type(adapter).__name__} does not satisfy the EffectsAdapter protocol; an "
                "object that cannot execute an effect cannot be registered to perform one"
            )

        # Key material, not a self-reported label. `key_id` is a property on the object
        # being registered, so comparing key ids let an adapter carrying a verifier that
        # merely *claimed* the right id — and accepted everything — pass this guard. keys.py
        # says it plainly: the identifier selects which key to check against, the signature
        # is what decides.
        #
        # What this guard is for, stated honestly: catching a **wiring mistake**, an adapter
        # constructed around the wrong authorizer. It is not a defence against a hostile
        # adapter object, and cannot be — such an object lies about `public_pem()` as easily
        # as about `key_id`, and in any case need never be registered to be called.
        if not hmac.compare_digest(
            anchor.verifying_key.public_pem(), self._anchor.verifying_key.public_pem()
        ):
            raise ValueError(
                f"adapter {adapter.name!r} verifies against key "
                f"{anchor.verifying_key.key_id!r}, which is not the key object this registry "
                f"was wired with ({self._anchor.verifying_key.key_id!r}): an adapter that "
                "believes a different authorizer would accept grants this plane must refuse"
            )
        if adapter.makes_external_contact:
            raise ValueError(
                f"adapter {adapter.name!r} declares that it makes external contact; the MVP "
                "acts against no infrastructure it does not own (invariant 15). Registering "
                "one is a product and legal decision, not a wiring change"
            )
        if adapter.operation not in MVP_IMPLEMENTED_OPERATIONS:
            raise ValueError(
                f"{adapter.operation.value} is not in MVP_IMPLEMENTED_OPERATIONS; it is a "
                "REQUIRES_LEGAL_AUTHORITY class and its refusal is the intended behaviour"
            )
        existing = self._adapters.get(adapter.operation)
        if existing is not None:
            raise ValueError(
                f"{adapter.operation.value} is already served by {existing.name!r}; silently "
                f"replacing it with {adapter.name!r} would swap out a reviewed adapter"
            )
        self._adapters[adapter.operation] = adapter

    def adapter_for(self, operation: OperationClass) -> EffectsAdapter | None:
        return self._adapters.get(operation)

    @property
    def adapters(self) -> tuple[EffectsAdapter, ...]:
        """Every registered adapter, for properties that must hold across all of them."""
        return tuple(self._adapters[operation] for operation in sorted(self._adapters))

    @property
    def operations(self) -> frozenset[OperationClass]:
        return frozenset(self._adapters)

    async def execute(
        self, request: EffectRequest, capability: AuthorizationCapability
    ) -> EffectResult:
        """Dispatch to the adapter for the requested class, or refuse.

        The adapter is looked up before the capability is evaluated, so an operation NEMESIS
        cannot perform is refused as unimplemented even when it is fully authorized. An
        analyst reading the record then sees the true reason — we are not permitted to build
        this — rather than an authorization problem they might try to fix.
        """
        adapter = self._adapters.get(request.operation)
        if adapter is None:
            return self._refuse_no_adapter(request, capability)
        try:
            return await adapter.execute(request, capability)
        except Exception as exc:
            # An adapter that raises has violated the port contract, which says refusals are
            # returned and not thrown. Converting it here keeps one uncaught bug from
            # becoming an effect whose outcome nobody recorded.
            #
            # Read the name once, safely, and reuse it. Consulting the object whose failure
            # this block is handling is the recurring defect here: an earlier version called
            # `authorizes()` on the capability that had just crashed, and the repair that
            # followed hardened `adapter_name` with a `getattr` while `detail`, a dozen lines
            # below, still read `adapter.name` bare — so `AttributeError` escaped the very
            # handler that `getattr` was added to protect, and anything other than
            # `AttributeError` escaped the `getattr` too. One read, one name, no second
            # opportunity to raise.
            adapter_name = _adapter_name_or_registry(adapter)
            return EffectResult(
                operation_id=request.operation_id,
                operation=request.operation,
                outcome=EffectOutcome.FAILED,
                executed_at=utcnow(),
                adapter_name=adapter_name,
                # Built locally. This handler exists so that one uncaught adapter bug
                # cannot become an effect whose outcome nobody recorded — and it used to
                # call `authorizes()` on the same untrusted object that had just caused the
                # failure, so a capability whose `authorizes` raised defeated the very
                # guarantee this block is for.
                authorization=refusal_record(
                    request,
                    operation=request.operation,
                    capability_id=NO_CAPABILITY,
                    now=utcnow(),
                    reasons=(f"adapter raised {type(exc).__name__} before any verdict",),
                ),
                detail=(
                    f"adapter {adapter_name!r} raised {type(exc).__name__} instead of "
                    "returning a refusal; treated as a failed operation"
                ),
                external_contact_made=False,
            )

    def _refuse_no_adapter(
        self, request: EffectRequest, capability: AuthorizationCapability
    ) -> EffectResult:
        # No adapter means nothing verified this capability, so nothing may be read off it.
        # The record says what this plane knows: which class was asked for, and that it has
        # no implementation here.
        decision = refusal_record(
            request,
            operation=request.operation,
            capability_id=NO_CAPABILITY,
            now=utcnow(),
            reasons=(f"no adapter is registered for {request.operation.value}",),
        )
        if request.operation in MVP_IMPLEMENTED_OPERATIONS:
            detail = (
                f"{request.operation.value} is implemented but no adapter is registered for "
                "it; this is a wiring defect, not a policy refusal"
            )
        else:
            detail = (
                f"{request.operation.value} is REQUIRES_LEGAL_AUTHORITY: it is a declared "
                "operation class with no implementation, so that the planner can propose it "
                "and NEMESIS cannot perform it"
            )
        return EffectResult(
            operation_id=request.operation_id,
            operation=request.operation,
            outcome=EffectOutcome.REFUSED_NO_ADAPTER,
            executed_at=utcnow(),
            adapter_name=REGISTRY_NAME,
            authorization=decision,
            detail=detail,
            external_contact_made=False,
        )


def default_registry(
    *,
    verifying_key: CapabilityVerifier,
    revocations: RevocationOracle,
    draft_root: Path | None = None,
) -> EffectsRegistry:
    """The registry the platform wires up: every implemented class, nothing else.

    ``verifying_key`` and ``revocations`` are required. There is no way to obtain a registry
    that will act without a key to verify against and an oracle to ask, because the version
    that could was the version that drafted a document from a capability nobody had signed.

    ``draft_root`` defaults to ``None``, which means **no adapter here writes to disk** — a
    draft comes back in the result and nothing touches the filesystem. That is the safe default
    and it is also the honest one: an adversarial review drove a hijacked pilot through a real
    mediator and had a NEMESIS-branded document written to a directory the *pilot* named,
    because the ``output_directory`` parameter was passed to ``Path()`` unconstrained. The
    filename had been hardened against traversal; the parameter choosing the directory had not.

    A deployment that wants drafts on disk supplies the root, and a request may then choose a
    subdirectory of it and nothing else.
    """
    # Imported inside the function so the adapter modules can depend on the guards above
    # without the two importing each other. The dependency runs adapters -> registry.
    from nemesis.effects.drafting import (
        EvidenceExportAdapter,
        ProviderNotificationAdapter,
        TakedownRequestDraftAdapter,
    )
    from nemesis.effects.simulation import SimulationEffectsAdapter

    anchor = TrustAnchor(verifying_key=verifying_key, revocations=revocations)
    registry = EffectsRegistry(verifying_key=verifying_key, revocations=revocations)
    registry.register(SimulationEffectsAdapter(anchor))
    registry.register(ProviderNotificationAdapter(anchor, draft_root=draft_root))
    registry.register(TakedownRequestDraftAdapter(anchor, draft_root=draft_root))
    registry.register(EvidenceExportAdapter(anchor, draft_root=draft_root))
    return registry
