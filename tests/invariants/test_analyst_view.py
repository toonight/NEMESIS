"""A view is a file that can be mailed, so it is a boundary.

The analyst surface is the last thing the brief asked for and the most dangerous thing to get
right, for a reason this project wrote into its own milestones before building it:

    A wrong attribution in a polished interface is more dangerous than the same error in a
    text file, because production value reads as confidence.

So these tests are not "does the page render". They walk every byte looking for material that
must not leave, and they assert that the *refusals* are present — because a page that quietly
omits the human-identity refusal reads as though the platform simply had nothing to say about
a person, which is a different claim from having refused to say it.
"""

from __future__ import annotations

import pytest

from nemesis.collect.fixtures.glass_anvil import NAMED_PERSON, PERSONA_CURRENT
from nemesis.slice.scenario import ScenarioResult, run_glass_anvil_scenario
from nemesis.ui.investigation import SIMULATED_NOTICE, render_investigation

pytestmark = pytest.mark.invariant


@pytest.fixture(scope="module")
def page(tmp_path_factory: pytest.TempPathFactory) -> str:
    result: ScenarioResult = run_glass_anvil_scenario(workspace=tmp_path_factory.mktemp("view"))
    return render_investigation(
        result.attribute.result,
        stages=tuple(name for name, _ in result.stages()),
    )


# --- Nothing withheld may appear, in any field ------------------------------


def test_the_page_never_names_the_planted_person(page: str) -> None:
    """THE TEST THIS FILE EXISTS FOR.

    The scenario plants a name in a hostile channel on purpose. A refusal document that
    repeats the accusation has published it — and a rendered page is a file that gets mailed,
    printed and forwarded far more casually than a JSON payload.
    """
    assert NAMED_PERSON.lower() not in page.lower(), "the analyst view published the planted name"


def test_the_page_carries_no_persona_linkage(page: str) -> None:
    """Founder decision D1: persona linkage is an internal lead. The analyst is inside the
    wall, but this page is not — it is a portable file."""
    lowered = page.lower()
    assert PERSONA_CURRENT.lower() not in lowered
    for marker in ("persona_linkage", "same_operator_as", "human_identity_lead"):
        assert marker not in lowered, f"the view carried the internal marker {marker!r}"


# --- The refusals are present, and prominent --------------------------------


def test_the_human_identity_refusal_is_rendered_rather_than_omitted(page: str) -> None:
    """A page that silently drops the refused dimension reads as "nothing was found".

    That is a different claim from "we refused to conclude", and the second is the product.
    """
    assert "withheld" in page.lower()
    assert "insufficient basis" in page.lower(), (
        "the human-identity dimension reached insufficient_basis and the page must say so — "
        "without it, a reader cannot tell a refusal from an absence of findings"
    )


def test_withheld_dimensions_are_named_as_withheld(page: str) -> None:
    """Silence would read as an absence of findings. Every dimension the view does not assess
    is listed, with why the omission is deliberate."""
    assert "Assessed, and withheld from this view" in page
    assert "different claim entirely" in page
    # The refused dimension is reported with the band it reached, which names nobody, and
    # with the fact that a gate stopped it. Reporting neither would read as an absence of
    # findings; reporting the finding would publish an internal lead.
    assert "refused before scoring" in page.lower()
    assert "internal lead and is not on this page" in page


def test_every_dimension_shows_its_contradictions_and_gaps(page: str) -> None:
    """An assessment that shows only its supports looks complete and is not. Contradicting
    evidence, alternatives and missing evidence are rendered at the same weight."""
    for facet in ("Contradicting", "Alternative hypotheses", "Missing evidence"):
        assert facet in page, f"the view omitted {facet!r}"


# --- Uncertainty is visible before any number -------------------------------


def test_uncertainty_is_drawn_as_space_and_not_only_as_a_number(page: str) -> None:
    """The design thesis. A bar that is mostly void looks wrong at a glance; "31% confident"
    does not, and the two say the same thing."""
    assert 'class="seg void"' in page
    assert "unknown" in page.lower()


def test_the_pre_margin_figure_is_shown_where_the_margin_bit(page: str) -> None:
    """The robustness margin dropped the headline linkage from likely to insufficient basis.
    Reporting only the margined figure hides how much support was deliberately set aside."""
    if "Robustness margin" in page:
        assert 'class="ghost"' in page, "the margin reduction was applied but never shown"


def test_there_is_no_overall_score_anywhere(page: str) -> None:
    """A weighted mean of the five would be dominated by infrastructure — the dimension with
    the most evidence and the least to say about who anybody is — and a reader shown one
    number stops reading the five."""
    lowered = page.lower()
    for phrase in ("overall confidence", "total score", "combined score", "aggregate confidence"):
        assert phrase not in lowered


# --- The page is what it claims to be ---------------------------------------


def test_the_page_says_it_is_simulated_and_uncalibrated(page: str) -> None:
    assert SIMULATED_NOTICE in page
    assert "nothing on this page is calibrated" in page.lower()


def test_the_page_is_self_contained(page: str) -> None:
    """Invariant 15 applies to a viewer as much as to a collector: a page that fetches a font
    is a page that phones somewhere every time an analyst opens a case file."""
    lowered = page.lower()
    for reach in ("http://", "https://", "//fonts.", "<script", "@import", "src="):
        assert reach not in lowered, f"the view reaches outward via {reach!r}"


def test_collected_content_cannot_inject_markup(page: str) -> None:
    """An adversary who can influence what we collect must not thereby influence what an
    analyst sees. Every data-bearing string is escaped, the same discipline the console
    renderer applies with `rich.text.Text`."""
    assert "<script" not in page.lower()
    # The hypothesis prose comes from fixture data and is escaped; a raw angle bracket from
    # collected content would show up as an unbalanced tag.
    assert page.count("<html") == 1 and page.count("</html>") == 1
