"""Drafting adapters: they produce text, and they cannot send it.

There is no transport in this module and none anywhere below it. A draft is returned to
the caller in the result, or written to a directory the caller named; getting it in front
of a provider, a registrar or a court is a human act performed outside NEMESIS, and the
document says so on its first line.

That first line is the reason this module exists as more than a template renderer. A
NEMESIS-branded notice is an artifact that leaves the system's epistemic controls behind:
whoever reads it has no access to the confidence model, the source diversity, or the
deception assessment that produced it. The controls therefore have to travel *inside* the
document.

**The banner is a constant, not a parameter.** Every draft opens with the same
``SIMULATED`` line and the same statement that its supporting material came from synthetic
fixtures. A caller cannot weaken it, because no caller-supplied value reaches it. A
compromised orchestrator that could set the banner could produce a document reading as
though it rested on real, corroborated evidence — and an unsent document that reads that
way is still dangerous, because someone will send it.

**Every caller string is flattened before it lands in a line.** ``sanitize`` strips control
characters, so a parameter carrying newlines cannot forge a header line and manufacture an
authority reference the capability never granted.

**The filename is derived from the operation id.** No parameter contributes to it. A
caller-supplied path component containing ``..`` would place a NEMESIS-branded document
outside the directory a human chose to review.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from nemesis.core.authorization import (
    AuthorizationCapability,
    AuthorizationDecision,
    OperationClass,
)
from nemesis.core.temporal import utcnow
from nemesis.effects.registry import preflight, sanitize
from nemesis.ports.authorization import TrustAnchor
from nemesis.ports.effects import EffectOutcome, EffectRequest, EffectResult

DRAFT_BANNER: Final = (
    "SIMULATED — DRAFT ONLY. NEMESIS cannot send this document and did not send it."
)
"""First line of every draft. A constant so that no caller can remove or soften it."""

SUPPORTING_MATERIAL_NOTICE: Final = (
    "All supporting material named below is SIMULATED: it was derived from synthetic "
    "fixtures, not from a licensed or authoritative source, and corroborates nothing."
)

NOT_SENT_FOOTER: Final = (
    "This draft has not been reviewed, signed or transmitted. Sending it is a human "
    "action taken outside NEMESIS, and doing so without confirming target ownership "
    "against a non-synthetic source would be acting on unverified attribution."
)

SEPARATOR: Final = "-" * 78

OUTPUT_DIRECTORY_PARAMETER: Final = "output_directory"
"""Where the caller wants the draft written. Absent means "return it in the result"."""

RECIPIENT_PARAMETER: Final = "recipient"
OBSERVED_ACTIVITY_PARAMETER: Final = "observed_activity"
EVIDENCE_IDS_PARAMETER: Final = "evidence_ids"
EXPORT_PURPOSE_PARAMETER: Final = "export_purpose"

MAX_LISTED_EVIDENCE_IDS: Final = 50
"""Ceiling on the identifiers a single request can put in a document.

An unbounded caller-controlled list turns one authorized operation into an arbitrary-size
write on the caller's filesystem; the cap makes the amplification factor a constant.
"""

_UNSPECIFIED_RECIPIENT: Final = "<recipient not stated in the request>"
_UNSPECIFIED: Final = "<not stated in the request>"


class _DraftingAdapter:
    """Shared skeleton for the three adapters that produce documents.

    Subclasses supply a title, a filename slug and a body. They do not get to reorder the
    checks, choose the banner, or decide whether the footer appears: those are the parts a
    reviewer of a future adapter would be least likely to notice were missing.
    """

    name: str
    operation: OperationClass
    document_title: str
    file_slug: str
    makes_external_contact: bool = False

    def __init__(self, anchor: TrustAnchor, *, draft_root: Path | None = None) -> None:
        """The authorizer this adapter believes, and where it may write, both fixed here.

        Required and positional: an adapter with no anchor could verify nothing, and one
        that took the anchor per call would believe whoever called it.

        ``draft_root`` is the same reasoning applied to the filesystem. It defaults to ``None``,
        which means **this adapter writes nothing** and returns the document in the result —
        the honest default, because an adapter that writes nowhere is strictly safer than one
        that writes wherever a request names. A deployment that wants drafts on disk supplies a
        root, and a request may then choose a subdirectory of it and nothing else.
        """
        self._anchor = anchor
        self._draft_root = draft_root

    @property
    def anchor(self) -> TrustAnchor:
        """Exposed so the registry can refuse an adapter wired to a different authorizer."""
        return self._anchor

    async def execute(
        self, request: EffectRequest, capability: AuthorizationCapability
    ) -> EffectResult:
        check = preflight(
            request,
            capability,
            operation=self.operation,
            anchor=self._anchor,
        )
        if check.refusal is not None:
            # Composition happens strictly after the refusal check, so a refused operation
            # leaves no document behind. A draft written before the capability was
            # verified is an artifact nobody authorized, sitting in a directory a human
            # will later treat as reviewed output.
            return self._record(
                request, outcome=check.refusal, decision=check.decision, detail=check.detail
            )

        # From the reconstruction, never from the object handed in. `granted` is non-None
        # here because `check.refusal is None` implies the signature and structure both
        # verified; the assert states that so a future refactor cannot quietly weaken it.
        assert check.granted is not None
        document = self._document(request, check.granted)

        raw_directory = request.parameters.get(OUTPUT_DIRECTORY_PARAMETER)
        if raw_directory is None:
            return self._record(
                request,
                outcome=EffectOutcome.DRAFTED,
                decision=check.decision,
                detail=document,
            )

        try:
            path = self._write(document, raw_directory, request)
        except OSError as exc:
            # Fail closed and visibly. A drafting adapter that swallowed a write error
            # would report DRAFTED for a document that does not exist, and the operator
            # would go looking for a file nobody wrote.
            return self._record(
                request,
                outcome=EffectOutcome.FAILED,
                decision=check.decision,
                detail=(
                    f"{self.document_title} was composed but could not be written: "
                    f"{type(exc).__name__}. No document was produced and nothing was sent."
                ),
            )

        return self._record(
            request,
            outcome=EffectOutcome.DRAFTED,
            decision=check.decision,
            detail=(
                f"SIMULATED: {self.document_title} drafted and written to {path}. Nothing was sent."
            ),
            produced_artifacts=(str(path),),
        )

    # -- composition ----------------------------------------------------------

    def _document(self, request: EffectRequest, capability: AuthorizationCapability) -> str:
        """Banner, provenance header, body, footer — in that order, always.

        The header quotes the capability rather than the request wherever both could
        supply a value. The capability is signed outside this plane; the request is
        whatever the caller handed us, and a document that cited the caller's idea of its
        own legal basis would be citing the attacker.

        ``capability`` here must be the grant **reconstructed from the signed bytes**, which
        is what :class:`~nemesis.effects.registry.Preflight` supplies. For a while it was the
        object passed to ``execute``, and that was the same mistake one level down: a
        ``str`` subclass whose content matched the signed authority reference but whose
        ``__str__`` returned ``"TGI Paris ord. 2026/9999 - seizure authorised"`` put a
        fabricated court order into a document addressed to a provider, under a genuine
        signature over genuinely matching bytes.
        """
        lines = [
            DRAFT_BANNER,
            SUPPORTING_MATERIAL_NOTICE,
            SEPARATOR,
            f"Document: {self.document_title}",
            f"Operation: {self.operation.value}",
            f"Operation id: {request.operation_id}",
            f"Case: {capability.case_id}",
            f"Capability: {capability.capability_id}",
            f"Authorization expires: {capability.expires_at.isoformat()}",
            f"Legal basis: {capability.legal_basis.value}",
            f"Authority reference: {capability.legal_authority_reference or _UNSPECIFIED}",
            f"Jurisdictions: {', '.join(capability.jurisdictions)}",
            f"Approved maximum effect: {sanitize(capability.max_effect_description)}",
            f"Target: {sanitize(request.target_natural_key, limit=120)}",
            f"Target fingerprint: {request.target_fingerprint}",
            f"Prepared for: {sanitize(request.requested_by, limit=120)}",
            f"Prepared at: {utcnow().isoformat()}",
            SEPARATOR,
        ]
        lines.extend(self._body(request, capability))
        lines.extend((SEPARATOR, NOT_SENT_FOOTER))
        return "\n".join(lines)

    def _body(self, request: EffectRequest, capability: AuthorizationCapability) -> tuple[str, ...]:
        raise NotImplementedError

    # -- helpers shared by the bodies -----------------------------------------

    @staticmethod
    def _recipient(request: EffectRequest) -> str:
        return sanitize(
            request.parameters.get(RECIPIENT_PARAMETER, _UNSPECIFIED_RECIPIENT), limit=200
        )

    @staticmethod
    def _evidence_lines(request: EffectRequest) -> tuple[str, ...]:
        """List the evidence the caller named, and refuse to vouch for any of it.

        This plane cannot import the vault (invariant 8, enforced by ``.importlinter``), so
        it has no way to confirm that these identifiers exist, that their hash chain
        verifies, or that they say what the caller claims. Listing them without that
        caveat would let a document borrow the vault's credibility for material the vault
        may never have held.
        """
        raw = request.parameters.get(EVIDENCE_IDS_PARAMETER, "")
        identifiers = [sanitize(part, limit=120) for part in raw.split(",") if part.strip()]
        if not identifiers:
            return ("Supporting material: none supplied with this request.",)

        listed = identifiers[:MAX_LISTED_EVIDENCE_IDS]
        lines = ["Supporting material (SIMULATED, and NOT verified by this plane):"]
        lines.extend(f"  - {identifier}" for identifier in listed)
        if len(identifiers) > len(listed):
            lines.append(
                f"  - [{len(identifiers) - len(listed)} further identifier(s) omitted: a "
                f"single request may list at most {MAX_LISTED_EVIDENCE_IDS}]"
            )
        lines.append(
            "  These identifiers are reproduced as the request supplied them. The Effects "
            "plane holds no vault handle and confirmed neither their existence nor their "
            "integrity."
        )
        return tuple(lines)

    # -- output ---------------------------------------------------------------

    def _write(self, document: str, raw_directory: str, request: EffectRequest) -> Path:
        directory = self._resolve_output_directory(raw_directory)

        # Exclusive creation, not truncation: two requests carrying the same operation id
        # is a replay, and the second one silently overwriting a document a human already
        # reviewed is how an approved draft becomes a different draft.
        path = directory / f"{request.operation_id}-{self.file_slug}.txt"
        with path.open("x", encoding="utf-8") as handle:
            handle.write(document)
        return path

    def _resolve_output_directory(self, raw_directory: str) -> Path:
        """Where a draft may be written, decided by the deployment and never by the request.

        **The filename was hardened and the directory was not.** This module's docstring names
        the harm exactly — "a caller-supplied path component containing ``..`` would place a
        NEMESIS-branded document outside the directory a human chose to review" — and an
        adversarial review pointed out that the parameter *choosing* the directory had no
        constraint at all: ``Path(raw_directory)``, an ``is_dir()`` check, and a write. Driven
        through a real mediator with a hijacked pilot, a draft landed in a directory the pilot
        named, and the recorded artifact locator was the unresolved relative path — an audit
        record that does not say where the file is.

        So the adapter carries a root from construction. A request may choose a *subdirectory*
        of it, which is the useful half of the parameter, and cannot escape it: the resolved
        path must sit under the resolved root. A deployment that configures no root refuses
        every write and returns the document instead, which is the honest default — an adapter
        that writes nowhere is strictly safer than one that writes anywhere.
        """
        if self._draft_root is None:
            raise NotADirectoryError(
                "this deployment configured no draft root, so no document may be written to "
                "disk; the draft is returned in the result instead"
            )
        root = self._draft_root.resolve()
        candidate = (root / raw_directory).resolve() if raw_directory else root
        if candidate != root and root not in candidate.parents:
            raise NotADirectoryError(
                "a draft may only be written inside the configured draft root; "
                f"{raw_directory!r} resolves outside it"
            )
        if not candidate.is_dir():
            raise NotADirectoryError(str(candidate))
        return candidate

    def _record(
        self,
        request: EffectRequest,
        *,
        outcome: EffectOutcome,
        decision: AuthorizationDecision,
        detail: str,
        produced_artifacts: tuple[str, ...] = (),
    ) -> EffectResult:
        """Build the audit record. ``external_contact_made`` is a literal, never a branch."""
        return EffectResult(
            operation_id=request.operation_id,
            operation=request.operation,
            outcome=outcome,
            executed_at=utcnow(),
            adapter_name=self.name,
            authorization=decision,
            detail=detail,
            produced_artifacts=produced_artifacts,
            external_contact_made=False,
        )


class ProviderNotificationAdapter(_DraftingAdapter):
    """Drafts a factual abuse notification for a provider to act on under its own terms.

    The document asserts no obligation. A notification that reads like a demand invites the
    provider to treat it as one, and NEMESIS has no authority to compel anything — the
    lever here is the provider's own terms of service, which is also why the draft states
    what was observed rather than what should be done about it.
    """

    name: str = "provider-notification-drafter"
    operation: OperationClass = OperationClass.PROVIDER_NOTIFICATION
    document_title: str = "Abuse notification (draft)"
    file_slug: str = "provider-notification"

    def _body(self, request: EffectRequest, capability: AuthorizationCapability) -> tuple[str, ...]:
        observed = sanitize(
            request.parameters.get(OBSERVED_ACTIVITY_PARAMETER, _UNSPECIFIED), limit=1200
        )
        return (
            f"To: {self._recipient(request)}",
            f"Subject: Abuse observed on infrastructure you appear to operate — "
            f"{sanitize(request.target_natural_key, limit=120)}",
            "",
            "We are reporting activity observed against infrastructure that public "
            "records associate with you. We ask you to assess it under your own terms of "
            "service. This notification imposes no legal obligation and NEMESIS has no "
            "authority to compel any action.",
            "",
            f"Observed activity: {observed}",
            "",
            *self._evidence_lines(request),
            "",
            "Attribution caveat: the association between this target and the activity "
            "above rests on synthetic sources. Confirm ownership independently before "
            "acting; a name resembling a legitimate business may belong to one.",
        )


class TakedownRequestDraftAdapter(_DraftingAdapter):
    """Drafts a takedown request, together with the reasons not to send it yet.

    A takedown against the wrong target is the failure that ends an investigation and
    possibly the organization, so the draft carries a mandatory ownership-confirmation
    block rather than leaving it to the sender's judgement. It also names the operation as
    a request: NEMESIS holds no order, and a document that blurs the two invites a
    provider to act as though a court had spoken.
    """

    name: str = "takedown-request-drafter"
    operation: OperationClass = OperationClass.TAKEDOWN_REQUEST_DRAFT
    document_title: str = "Takedown request (draft)"
    file_slug: str = "takedown-request"

    def _body(self, request: EffectRequest, capability: AuthorizationCapability) -> tuple[str, ...]:
        target = sanitize(request.target_natural_key, limit=120)
        observed = sanitize(
            request.parameters.get(OBSERVED_ACTIVITY_PARAMETER, _UNSPECIFIED), limit=1200
        )
        return (
            f"To: {self._recipient(request)}",
            f"Subject: Request for action concerning {target}",
            "",
            f"This is a REQUEST, not an order. It is made on the basis recorded above "
            f"({capability.legal_basis.value}) and asks you to consider suspending or "
            f"restricting {target}. NEMESIS holds no instrument compelling you to act.",
            "",
            f"Grounds: {observed}",
            "",
            *self._evidence_lines(request),
            "",
            "BEFORE SENDING — ownership confirmation is required, not advisory:",
            "  - Ownership of this target was established from synthetic sources only.",
            "  - A suspension reaches every service behind the name, including any that "
            "belongs to an uninvolved party.",
            "  - A target whose name resembles a legitimate organization must be "
            "confirmed against a non-synthetic record before this request is sent.",
        )


class EvidenceExportAdapter(_DraftingAdapter):
    """Drafts the manifest of an evidence package for an external recipient.

    It exports a *list*, not the material. The Effects plane cannot reach the vault, so it
    cannot seal a package, cannot verify a hash chain and cannot confirm an anchor — and a
    manifest that implied otherwise would hand a recipient a false assurance of integrity,
    which is worse than handing them nothing. What this adapter can do honestly is state
    what was requested and state, in the document, exactly what it did not check.
    """

    name: str = "evidence-export-drafter"
    operation: OperationClass = OperationClass.EVIDENCE_EXPORT
    document_title: str = "Evidence export manifest (draft)"
    file_slug: str = "evidence-export"

    def _body(self, request: EffectRequest, capability: AuthorizationCapability) -> tuple[str, ...]:
        purpose = sanitize(
            request.parameters.get(EXPORT_PURPOSE_PARAMETER, _UNSPECIFIED), limit=600
        )
        return (
            f"To: {self._recipient(request)}",
            f"Purpose: {purpose}",
            "",
            *self._evidence_lines(request),
            "",
            "INTEGRITY: NOT VERIFIED BY THIS PLANE.",
            "  - The Effects plane holds no vault handle and no standing credentials; it "
            "cannot read the evidence store, recompute a hash chain or check an external "
            "anchor.",
            "  - This manifest is therefore a statement of what was requested, not a "
            "certificate that the material exists or is intact.",
            "  - Verification is performed by the evidence vault against its own "
            "append-only log, and its output — not this document — is what a recipient "
            "should rely on.",
            "",
            "No material is attached. Nothing was transmitted.",
        )
