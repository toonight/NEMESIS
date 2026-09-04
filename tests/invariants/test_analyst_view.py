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

import re

import pytest

from nemesis.collect.fixtures.glass_anvil import (
    CERT_FINGERPRINT,
    CLUSTER_IP,
    NAMED_PERSON,
    PERSONA_CURRENT,
    PGP_FINGERPRINT,
    SEED_DOMAIN,
)
from nemesis.core.confidence import BAND_RANGES, ConfidenceBand
from nemesis.slice.scenario import STAGE_NAMES, ScenarioResult, run_glass_anvil_scenario
from nemesis.ui.investigation import SIMULATED_NOTICE, render_investigation
from nemesis.ui.ledger import FACT_LABELS, STAGE_META, StageMark, stage_ledger

pytestmark = pytest.mark.invariant


@pytest.fixture(scope="module")
def scenario(tmp_path_factory: pytest.TempPathFactory) -> ScenarioResult:
    return run_glass_anvil_scenario(workspace=tmp_path_factory.mktemp("view"))


@pytest.fixture(scope="module")
def marks(scenario: ScenarioResult) -> tuple[StageMark, ...]:
    return stage_ledger(scenario)


@pytest.fixture(scope="module")
def page(scenario: ScenarioResult, marks: tuple[StageMark, ...]) -> str:
    # The page the CLI writes: the attribution result, the stage names, and the typed ledger.
    # Every leak test below walks *this* page, so anything the ledger adds is under the same
    # scrutiny as the assessments.
    return render_investigation(
        scenario.attribute.result,
        stages=tuple(name for name, _ in scenario.stages()),
        marks=marks,
    )


@pytest.fixture(scope="module")
def bare_page(scenario: ScenarioResult) -> str:
    """The page rendered from stage names alone — the older call shape must keep working."""
    return render_investigation(
        scenario.attribute.result,
        stages=tuple(name for name, _ in scenario.stages()),
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


# --- The course of the investigation is a typed ledger, not a dump ----------


def test_the_ledger_covers_every_stage_in_scenario_order(
    marks: tuple[StageMark, ...], scenario: ScenarioResult
) -> None:
    assert tuple(mark.name for mark in marks) == tuple(name for name, _ in scenario.stages())
    assert tuple(mark.name for mark in marks) == STAGE_NAMES


def test_the_ledger_carries_only_counts_and_flags(marks: tuple[StageMark, ...]) -> None:
    """The renderer never sees the scenario. What crosses from it is a tuple of typed marks
    whose values are integers and booleans under labels chosen in code — there is no field a
    persona, a domain or a name could travel in."""
    for mark in marks:
        for fact in mark.facts:
            assert fact.label in FACT_LABELS, f"unregistered ledger label {fact.label!r}"
            assert type(fact.value) in (int, bool), f"{fact.label!r} carries a {type(fact.value)}"


def test_the_ledger_names_nobody_and_nothing(marks: tuple[StageMark, ...]) -> None:
    dumped = " ".join(mark.model_dump_json() for mark in marks).lower()
    for planted in (
        NAMED_PERSON,
        PERSONA_CURRENT,
        SEED_DOMAIN,
        CLUSTER_IP,
        CERT_FINGERPRINT,
        PGP_FINGERPRINT,
    ):
        assert planted.lower() not in dumped, f"the ledger carried {planted!r}"


def test_every_stage_is_a_station_on_the_rail_in_order(
    page: str, marks: tuple[StageMark, ...]
) -> None:
    positions = [page.index(f'id="stage-{mark.name}"') for mark in marks]
    assert positions == sorted(positions), "the rail does not follow scenario order"


def test_the_rail_encodes_the_loop_and_its_gates(page: str) -> None:
    """Structure is information. The rail is drawn from what the pipeline *is*: where the
    platform refuses is a gate, where a human decides is marked human, where content is
    hostile by default the track is hatched like the void in every confidence bar."""

    def classes_of(stage: str) -> set[str]:
        found = re.search(rf'<li id="stage-{stage}" class="([^"]*)"', page)
        assert found, f"no station for {stage!r}"
        return set(found.group(1).split())

    assert {"gate", "human"} <= classes_of("authorize")
    assert "gate" in classes_of("attribute")
    assert "hostile" in classes_of("darkweb")
    assert "hostile" not in classes_of("evidence")
    # Invariant 14 is drawn, not footnoted: the return path from resurgence to pursuit.
    assert "takedown closes no case" in page.lower()


def test_static_stage_metadata_covers_the_reference_scenario(scenario: ScenarioResult) -> None:
    for name, _ in scenario.stages():
        assert name in STAGE_META, f"no rail metadata for stage {name!r}"


def test_a_page_without_a_ledger_still_renders_the_rail(bare_page: str) -> None:
    for name in STAGE_NAMES:
        assert f'id="stage-{name}"' in bare_page


# --- Everything is typeset; nothing is dumped --------------------------------


def _shown(scenario: ScenarioResult) -> list[object]:
    from nemesis.attribute.disclosure import DELIVERABLE_DIMENSIONS

    return [
        item
        for item in scenario.attribute.result.assessments
        if item.dimension in DELIVERABLE_DIMENSIONS
    ]


def test_alternative_hypotheses_are_typeset_not_dumped(page: str, scenario: ScenarioResult) -> None:
    """The first version fell back to `str(alternative)`: a pydantic repr with `opinion=Opinion(`
    in it. A repr is not an argument an analyst can read, and it prints whatever the object
    happens to carry."""
    import html

    assert "opinion=opinion(" not in page.lower()
    assert "is_deception_hypothesis=" not in page
    for item in _shown(scenario):
        for alt in item.alternatives:  # type: ignore[attr-defined]
            assert html.escape(alt.argument_against, quote=True) in page, (
                f"the argument against {alt.name!r} is not on the page"
            )


def test_a_band_never_appears_without_its_range(page: str, scenario: ScenarioResult) -> None:
    """'Likely' means wildly different numbers to different readers; the project's own rule is
    that a band is never shown without its range. The first version showed the word alone in
    the pill and the range only inside a collapsed disclosure."""
    for item in _shown(scenario):
        if item.band is ConfidenceBand.INSUFFICIENT_BASIS:  # type: ignore[attr-defined]
            continue
        low, high = BAND_RANGES[item.band]  # type: ignore[attr-defined]
        assert f"{low:.0%} to {high:.0%}" in page


def test_source_diversity_is_on_the_card_not_only_in_the_prose(page: str) -> None:
    assert "adversary-influenceable" in page


def test_missing_evidence_carries_its_availability_label(
    page: str, scenario: ScenarioResult
) -> None:
    """The boundary labels are load-bearing. A gap that needs legal authority says so in the
    same words the rest of the repository uses."""
    for item in _shown(scenario):
        for gap in item.missing_evidence:  # type: ignore[attr-defined]
            assert gap.availability.value.upper() in page


# --- Motion and print are promises, so they are pinned -----------------------


def test_motion_is_opt_out_and_the_file_prints(page: str) -> None:
    assert "prefers-reduced-motion" in page
    assert "@media print" in page
