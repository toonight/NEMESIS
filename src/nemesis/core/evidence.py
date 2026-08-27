"""The Evidence object: material that can be defended outside this system.

Invariant 2 keeps two graphs apart. The Intelligence Graph is where NEMESIS is allowed to
be wrong: hypotheses, weak correlations, model inferences. The Evidence Graph holds only
material whose origin, integrity and handling can be demonstrated to someone who does not
trust us — a provider's abuse desk, a regulator, an investigating magistrate, or an
opposing expert.

The admission test is deliberately hard to pass. A piece of information becomes evidence
only when all of the following hold:

- the original artifact is preserved byte-for-byte and content-addressed;
- the collection mechanism is named, versioned and reproducible in principle;
- the chain of custody is unbroken from collection to now;
- every transformation between the artifact and its interpretation is recorded;
- no step in the derivation chain is an unverifiable model assertion.

The last condition is invariant 1 made mechanical. An LLM reading a forum post and
concluding "this persona is the operator" produces a claim, not evidence. The forum post
itself is evidence. This module refuses to blur that line, and the refusal is enforced in
:meth:`EvidenceObject.admissibility`, not in a prompt.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Final, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.core.ids import EvidenceId, IdPrefix, content_id
from nemesis.core.provenance import ProvenanceChain
from nemesis.core.temporal import TemporalExtent

SHA256_HEX = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class ArtifactKind(StrEnum):
    """What the preserved artifact physically is."""

    RAW_NETWORK_CAPTURE = "raw_network_capture"
    EMAIL_MESSAGE = "email_message"
    HTTP_EXCHANGE = "http_exchange"
    DNS_RECORD = "dns_record"
    TLS_CERTIFICATE = "tls_certificate"
    WHOIS_RDAP_RECORD = "whois_rdap_record"
    BINARY_SAMPLE = "binary_sample"
    SOURCE_CODE = "source_code"
    DOCUMENT = "document"
    IMAGE = "image"
    WEB_PAGE_SNAPSHOT = "web_page_snapshot"
    FORUM_POST = "forum_post"
    MARKETPLACE_LISTING = "marketplace_listing"
    CHAT_TRANSCRIPT = "chat_transcript"
    BLOCKCHAIN_TRANSACTION = "blockchain_transaction"
    PGP_KEY = "pgp_key"
    SSH_KEY = "ssh_key"
    LOG_RECORD = "log_record"
    SCAN_RESULT = "scan_result"
    STRUCTURED_FEED_RECORD = "structured_feed_record"


class ContentSafety(StrEnum):
    """Handling classification for collected material.

    Dark-web collection encounters content that carries legal obligations independent of
    the investigation: in most jurisdictions, child sexual abuse material triggers
    mandatory handling and reporting duties and must not be retained in an ordinary
    evidence store. Treating this as an operational afterthought is not viable; it is a
    schema-level requirement.

    See ``docs/architecture/THREAT_MODEL.md`` for the handling procedure per class.
    """

    ROUTINE = "routine"
    MALICIOUS_CODE = "malicious_code"
    """Live malware. Never executed outside an isolated analysis pipeline."""

    SENSITIVE_PERSONAL_DATA = "sensitive_personal_data"
    """Victim data, credentials, health or financial records found in criminal dumps."""

    LEGALLY_RESTRICTED = "legally_restricted"
    """Retention itself is regulated. Requires a documented handling decision."""

    MANDATORY_REPORT = "mandatory_report"
    """Triggers a legal reporting obligation. Quarantined, never indexed, never exported
    through ordinary channels. Escalation is a human decision, immediately."""


VERIFIED_ANCHOR_TYPES: Final[frozenset[str]] = frozenset()
"""Anchor types this build can actually *verify*, which is currently none.

An allowlist rather than a denylist, and empty rather than optimistic. An anchor is external
when a party with no obligation to us holds it, and the only evidence of that is a proof this
platform checked against that party — not a name in a field.

Adding a member here is a commitment to two things: a verifier that validates the ``proof``
against the named authority, and a registry mapping an authority to the key or certificate that
authenticates it. Adding one without both would restore exactly the defect this constant
replaced. See ``docs/architecture/THREAT_MODEL.md`` on the independence ladder.
"""


class IntegrityAnchor(BaseModel):
    """External proof that this evidence existed, unchanged, at a point in time.

    Invariant 10 puts the vault operator inside the threat model. A hash chain that we
    both generate and store proves nothing against ourselves: an insider with write access
    can recompute it. Only an anchor held by a party that cannot be quietly rewritten —
    a timestamping authority, a transparency log, a public ledger — closes that gap.
    """

    model_config = ConfigDict(frozen=True)

    anchor_type: str
    """e.g. rfc3161_timestamp_token, merkle_inclusion_proof, opentimestamps."""

    anchored_at: datetime
    authority: str
    """The external party whose word this is. Must not be us."""

    proof: str
    """Base64 token or inclusion proof, verifiable without contacting NEMESIS."""

    covers_hash: SHA256_HEX

    @property
    def is_externally_held(self) -> bool:
        """Whether the anchor survives full compromise of NEMESIS.

        The distinction matters: an internal hash chain detects accidental corruption, an
        external anchor detects deliberate rewriting by someone who controls the store.

        **This is an allowlist of verified anchor types, not a denylist of authority strings.**
        It used to be the latter — anything whose ``authority`` was not "nemesis", "self",
        "internal" or empty counted as external — and an adversarial review flipped the vault's
        `is_defensible_against_insider` to True by recording an anchor with
        ``authority="Totally Independent Notary AG"`` and ``proof="not-even-base64"``. Nothing
        validated either field. A string somebody typed decided whether this platform claimed
        its evidence was defensible against itself, which is the single claim it most needs to
        be unable to make falsely.

        :data:`VERIFIED_ANCHOR_TYPES` is empty, deliberately, so this returns ``False`` for every
        anchor this build can produce. Populating it means implementing a verifier for that
        anchor type — an RFC 3161 token checked against the timestamping authority's
        certificate, a transparency-log inclusion proof checked against a signed tree head — and
        until such a verifier exists, "external" is a claim nothing here can check and therefore
        one nothing here should make. `REQUIRES_EXTERNAL_DATA`, as the threat model has always
        said, now enforced rather than described.
        """
        return self.anchor_type in VERIFIED_ANCHOR_TYPES and self.authority.lower() not in {
            "nemesis",
            "self",
            "internal",
            "",
        }


class AdmissibilityDefect(StrEnum):
    """Reasons a candidate fails the evidence admission test."""

    NO_PRESERVED_ARTIFACT = "no_preserved_artifact"
    HASH_MISMATCH = "hash_mismatch"
    BROKEN_CUSTODY_CHAIN = "broken_custody_chain"
    MODEL_IN_DERIVATION_CHAIN = "model_in_derivation_chain"
    SIMULATED_COLLECTION = "simulated_collection"
    NO_EXTERNAL_ANCHOR = "no_external_anchor"
    UNREPRODUCIBLE_COLLECTION = "unreproducible_collection"
    RESTRICTED_CONTENT = "restricted_content"


class EvidenceObject(BaseModel):
    """A preserved artifact with everything needed to defend it.

    The identifier is derived from the artifact's own hash, so the same artifact collected
    twice by two independent collectors yields one object. That is not merely a storage
    optimization: it prevents a single underlying fact from being counted as two
    corroborating observations during fusion.
    """

    model_config = ConfigDict(frozen=True)

    evidence_id: EvidenceId
    artifact_kind: ArtifactKind
    content_hash: SHA256_HEX
    """SHA-256 of the artifact exactly as collected, before any normalization."""

    size_bytes: Annotated[int, Field(ge=0)]
    media_type: str = "application/octet-stream"

    vault_locator: str | None = Field(
        default=None,
        description="Where the sealed artifact lives. None means the object is a reference "
        "to material we have described but do not hold — which is not admissible.",
    )

    provenance: ProvenanceChain
    observed_extent: TemporalExtent
    """When the artifact's *content* was true of the world, distinct from when we got it."""

    content_safety: ContentSafety = ContentSafety.ROUTINE
    anchors: tuple[IntegrityAnchor, ...] = ()

    summary: str | None = Field(
        default=None,
        max_length=2000,
        description="Human-readable gist. A convenience for analysts, never a substitute "
        "for the artifact, and never itself evidence.",
    )

    @model_validator(mode="after")
    def _id_matches_content(self) -> Self:
        expected = f"{IdPrefix.EVIDENCE.value}_sha256-{self.content_hash}"
        if self.evidence_id != expected:
            raise ValueError(
                f"evidence_id does not address its content: {self.evidence_id!r} != {expected!r}"
            )
        return self

    @classmethod
    def seal(
        cls,
        *,
        artifact: bytes,
        artifact_kind: ArtifactKind,
        provenance: ProvenanceChain,
        observed_extent: TemporalExtent,
        media_type: str = "application/octet-stream",
        content_safety: ContentSafety = ContentSafety.ROUTINE,
        vault_locator: str | None = None,
        anchors: tuple[IntegrityAnchor, ...] = (),
        summary: str | None = None,
    ) -> EvidenceObject:
        """Create an evidence object from the artifact bytes, deriving its identity."""
        digest = hashlib.sha256(artifact).hexdigest()
        return cls(
            evidence_id=content_id(IdPrefix.EVIDENCE, artifact),
            artifact_kind=artifact_kind,
            content_hash=digest,
            size_bytes=len(artifact),
            media_type=media_type,
            vault_locator=vault_locator,
            provenance=provenance,
            observed_extent=observed_extent,
            content_safety=content_safety,
            anchors=anchors,
            summary=summary,
        )

    def verify_artifact(self, artifact: bytes) -> bool:
        """Constant-time check that these bytes are the sealed artifact."""
        return hmac.compare_digest(hashlib.sha256(artifact).hexdigest(), self.content_hash)

    def admissibility(self) -> tuple[AdmissibilityDefect, ...]:
        """Every reason this object would fail to be defended, or an empty tuple.

        Returns defects rather than a boolean so an analyst sees *what* is missing and can
        go fix it — an unanchored artifact needs a timestamp, not a different artifact.
        """
        defects: list[AdmissibilityDefect] = []

        if self.vault_locator is None:
            defects.append(AdmissibilityDefect.NO_PRESERVED_ARTIFACT)
        if self.provenance.touched_by_model:
            defects.append(AdmissibilityDefect.MODEL_IN_DERIVATION_CHAIN)
        if self.provenance.is_simulated:
            defects.append(AdmissibilityDefect.SIMULATED_COLLECTION)
        if not self.provenance.custody:
            defects.append(AdmissibilityDefect.BROKEN_CUSTODY_CHAIN)
        if not any(anchor.is_externally_held for anchor in self.anchors):
            defects.append(AdmissibilityDefect.NO_EXTERNAL_ANCHOR)
        if not self.provenance.method.parameters and not self.provenance.method.is_simulated:
            defects.append(AdmissibilityDefect.UNREPRODUCIBLE_COLLECTION)
        if self.content_safety in {
            ContentSafety.MANDATORY_REPORT,
            ContentSafety.LEGALLY_RESTRICTED,
        }:
            defects.append(AdmissibilityDefect.RESTRICTED_CONTENT)

        return tuple(defects)

    @property
    def is_admissible(self) -> bool:
        """Whether this object can enter the Evidence Graph.

        Failing this is normal and expected for most collected material. Inadmissible
        material remains fully usable as intelligence; it simply cannot be presented as
        proof. Conflating the two is the failure this whole module exists to prevent.
        """
        return not self.admissibility()

    @property
    def must_not_be_indexed(self) -> bool:
        """Content that must never reach a search index or an export."""
        return self.content_safety in {
            ContentSafety.MANDATORY_REPORT,
            ContentSafety.LEGALLY_RESTRICTED,
        }
