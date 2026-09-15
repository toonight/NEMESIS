"""Illegal-content detection shared by the defensive-CTI collectors.

The defensive-CTI module touches adversary-authored free text: a leak-site listing's title, a
crawled KB card's excerpt, a marketplace description. One handling obligation recurs across all
three collectors and lives here once so they cannot drift apart on it.

**Recognising illegal content, so a record can be held rather than indexed.** A ransomware crew's
listing or a marketplace card can name child sexual abuse material. In most jurisdictions that
carries a mandatory handling and reporting duty independent of the investigation, so the material
must be classified :attr:`~nemesis.core.evidence.ContentSafety.MANDATORY_REPORT` — which makes
:attr:`~nemesis.core.evidence.EvidenceObject.must_not_be_indexed` true and routes it into
quarantine with no automated exit, where the engine opens an
:meth:`~nemesis.ports.storage.ObligationSink.incur` duty. This is a blunt keyword indicator, and it
says so: it exists to *escalate* handling, never to decide anything about a person, and a false
positive here costs an over-cautious hold — the cheap direction of the error.

**On credentials, deliberately by omission.** These collectors do *not* redact or represent
credential material, and this module does not import :mod:`nemesis.core.credentials`. That is not an
oversight: invariant AUTH-04 keeps the credential types importable by exactly one module, so that
"discovery" cannot be quietly wired to "use". The collect plane instead borrows the stronger
guarantee the ransomware.live and dark-web connectors already rely on — it never stores
adversary-authored free text in a human- or model-readable field (a victim name is a normalized
node key, a summary is a fixed template, a model rationale is not carried into the graph at all),
so there is nothing to redact and no credential to carry onward. Representing a discovered
credential as a keyed :class:`~nemesis.core.credentials.CredentialIndicator` is the engine's job,
behind the
independent authorization path AUTH-04 protects; a connector that one day collects real credential
material would extend that invariant deliberately, not reach around it here.
"""

from __future__ import annotations

import re
from typing import Final

ILLEGAL_CONTENT_PATTERN: Final = re.compile(
    r"\b(?:cp|pthc|preteen|jailbait|child\s*porn(?:ography)?|lolita|underage|pedo\w*|csam)\b",
    re.IGNORECASE,
)
"""Indicators of child sexual abuse material and adjacent illegal content in free text.

Deliberately the same shape the ``cti-toolkit`` crawler used at capture, kept here so the two agree
on what triggers a hold. A blunt instrument by design — its only job is to *raise* a record's
handling classification to :attr:`~nemesis.core.evidence.ContentSafety.MANDATORY_REPORT`, never to
lower one and never to assert anything about a person. A word-boundary match on ``cp`` will
over-trigger; an over-cautious quarantine hold is the correct direction for this error.
"""


def contains_illegal_indicator(text: str) -> bool:
    """Whether the text carries an indicator that triggers a mandatory-report hold."""
    return ILLEGAL_CONTENT_PATTERN.search(text) is not None


__all__ = [
    "ILLEGAL_CONTENT_PATTERN",
    "contains_illegal_indicator",
]
