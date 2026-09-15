"""The shared illegal-content indicator the defensive-CTI collectors lean on.

One property: an illegal-content indicator is recognised in adversary-authored free text, so a
record carrying one can be classified ``MANDATORY_REPORT`` and held rather than indexed. This
module deliberately does not touch credential material — see :mod:`nemesis.collect.cti_safety`'s
docstring and invariant AUTH-04.
"""

from __future__ import annotations

from nemesis.collect.cti_safety import contains_illegal_indicator


def test_an_illegal_content_indicator_is_detected_case_insensitively() -> None:
    assert contains_illegal_indicator("this listing advertises CSAM for sale")
    assert contains_illegal_indicator("PTHC bundle")
    assert contains_illegal_indicator("child porn")


def test_ordinary_cybercrime_text_is_not_flagged() -> None:
    assert not contains_illegal_indicator("stolen credit cards and stealer logs for sale")
    assert not contains_illegal_indicator("ransomware leak site with victim listings")
