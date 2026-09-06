"""Portable claim records, without raw artifacts, source identities or store handles.

Status: IMPLEMENTED. The projection in ui.ledger supplies these records; the renderer
receives only these values, never the investigation's stores.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from nemesis.core.claims import ClaimKind, DerivationKind
from nemesis.core.ids import ClaimId, EvidenceId
from nemesis.core.provenance import SourceClass, SourceReliability


class EvidenceDetail(BaseModel):
    model_config = ConfigDict(frozen=True)

    evidence_id: EvidenceId
    source_number: int = Field(ge=1)
    source_class: SourceClass
    reliability: SourceReliability
    origin_number: int | None = Field(default=None, ge=1)
    adversary_influenceable: bool
    collected_at: datetime
    custody_events: int = Field(ge=0)
    processing_steps: int = Field(ge=0)
    lossy_processing: bool
    model_processed: bool
    is_simulated: bool


class ClaimDetail(BaseModel):
    model_config = ConfigDict(frozen=True)

    claim_id: ClaimId
    statement: str | None = None
    kind: ClaimKind | None = None
    derivation: DerivationKind | None = None
    asserted_at: datetime | None = None
    observed_from: datetime | None = None
    observed_until: datetime | None = None
    evidence: tuple[EvidenceDetail, ...] = ()
    missing_evidence: int = Field(default=0, ge=0)
    premise_count: int = Field(default=0, ge=0)
    withheld: bool = False
