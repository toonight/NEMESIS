"""The analyst view: a case file, not a dashboard.

The brief asks for an analyst-oriented investigation view where "uncertainty is visible" and
"a user must be able to click an attribution claim and understand why NEMESIS believes it",
and warns against "a generic SOC dashboard full of meaningless charts". The project's own
milestone note added the sharper constraint, and it is the one that shaped every choice here:

    A wrong attribution in a polished interface is more dangerous than the same error in a
    text file, because production value reads as confidence.

So the design thesis is an **inversion**. In an ordinary intelligence product the conclusion
gets the visual weight and the caveats get small grey text at the bottom. Here the hierarchy
is reversed, because in this platform the refusal *is* the product. Every ounce of finish on
this page is spent on the parts that say *not known*, *refused*, *withheld*, *hostile* — and
none of it on making a conclusion look settled.

**Uncertainty is rendered as physical space, never as a number.** Every figure is a
three-segment bar — belief, uncertainty, disbelief — and the uncertain part is drawn as a
literal hatched void. A reader sees how much of the bar is *not known* before they read any
percentage, and a mostly-void bar looks wrong at a glance in a way that "31%" does not. The
bar fills in belief-first, so for a moment the reader watches how little there is.

**The margin reduction is shown, not hidden.** Where the robustness margin removed a plantable
fact, the pre-margin opinion is drawn as a ghost behind the real one. The gap between them is
the size of what was deliberately set aside.

**The course of the investigation is a rail, and the rail is drawn from what the pipeline
*is*.** Twelve stations in loop order, bracketed by the loop's phases. Where content crosses
the collection boundary the track is hatched — the same hatch as the void, because in both
places the mark means *do not take this at face value*. Where the platform can refuse, the
station is a barrier in hazard stripes; where a human decides, it wears a ring. The return
path from resurgence to pursuit is drawn, because a takedown closes no case. Under each
station, a typed ledger of what the run recorded there: counts and flags only, from
:mod:`nemesis.ui.ledger`, never a string from the scenario. The renderer imports
:mod:`nemesis.ui.rail` — types and static metadata — and cannot reach the scenario.

**A band never appears without its range.** "Likely" means wildly different numbers to
different readers; the pill says *likely* and *55% to 80%* in the same breath.

**Refusals get the loudest treatment on the page.** The human-identity gate, the withheld
dimensions, the operations the envelope forbade: full-width, high-contrast, hazard-striped,
above the conclusions rather than beneath them.

**Everything is typeset; nothing is dumped.** Alternative hypotheses are arguments with a
name, a description, their own bar and the case against them — not the repr of the object
that carries them.

**What it will not render.** Founder decision D1 makes persona linkage an internal lead. This
surface is local and analyst-facing — the analyst is inside the wall — but the *page* is a file
that can be mailed, so it carries deliverable-class material and marks the withheld bands as
withheld rather than omitting them silently. Silence reads as "nothing was found", which is a
different claim.

Self-contained by construction: one HTML file, no external fonts, no scripts of any kind, no
network. Motion is opt-out via ``prefers-reduced-motion`` and the file prints. Invariant 15
applies to a viewer as much as to a collector.

Status: `IMPLEMENTED` for the attribution, refusal and course-of-investigation surface over a
`SIMULATED` scenario.
"""

from __future__ import annotations

import html
from datetime import datetime
from typing import Final

from nemesis.attribute.dimensions import (
    AlternativeHypothesis,
    AttributionDimension,
    DimensionAssessment,
    MissingEvidence,
    SourceDiversity,
    TemporalConsistency,
)
from nemesis.attribute.disclosure import DELIVERABLE_DIMENSIONS
from nemesis.attribute.engine import AttributionResult
from nemesis.core.confidence import BAND_RANGES, ConfidenceBand, Opinion
from nemesis.core.fusion import summarize_fact
from nemesis.ui.rail import Phase, StageMark, meta_for

SIMULATED_NOTICE: Final = (
    "Every figure on this page comes from a SIMULATED investigation over fixture data. "
    "It is not intelligence about anybody."
)

WITHHELD_NOTE: Final = (
    "Named as withheld rather than omitted. Silence would read as “nothing was found”, "
    "which is a different claim entirely."
)

RETURN_NOTE: Final = (
    "Reappearance closes the loop: resurgence reopens pursuit. "
    "A takedown closes no case; it opens a watch."
)

PHASE_LABELS: Final[dict[Phase | None, str]] = {
    "detect": "Detect",
    "pursue": "Pursue",
    "attribute": "Attribute",
    "disrupt": "Disrupt",
    "watch": "Watch",
    None: "Unphased",
}

_COUNT_WORDS: Final = (
    "no",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
)


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _pct(value: float) -> str:
    return f"{value * 100:.0f}"


def _count(n: int, singular: str, plural: str) -> str:
    word = _COUNT_WORDS[n] if 0 <= n < len(_COUNT_WORDS) else str(n)
    return f"{word} {singular if n == 1 else plural}"


# --- Bands ------------------------------------------------------------------------------------


def _band_range(band: ConfidenceBand) -> str:
    if band is ConfidenceBand.INSUFFICIENT_BASIS:
        return "no range"
    low, high = BAND_RANGES[band]
    return f"{low:.0%} to {high:.0%}"


def _band_tone(band: ConfidenceBand) -> str:
    if band is ConfidenceBand.INSUFFICIENT_BASIS:
        return "refused"
    if band in (
        ConfidenceBand.LIKELY,
        ConfidenceBand.VERY_LIKELY,
        ConfidenceBand.ALMOST_CERTAIN,
    ):
        return "for"
    if band is ConfidenceBand.ROUGHLY_EVEN:
        return "even"
    return "against"


def _band_pill(band: ConfidenceBand) -> str:
    """The word and its range, always together. The word alone is the defect."""
    return (
        f'<span class="band tone-{_band_tone(band)}">'
        f"<b>{_e(band.value.replace('_', ' '))}</b>"
        f"<i>{_e(_band_range(band))}</i></span>"
    )


# --- The bar ----------------------------------------------------------------------------------


def _opinion_bar(opinion: Opinion, *, ghost: Opinion | None = None, compact: bool = False) -> str:
    """The signature element: belief, void, disbelief — with the pre-margin figure behind it.

    The uncertain segment is a hatched void rather than a colour, because the point is that
    nothing is known there. A bar that is mostly void looks wrong immediately; the same fact
    written as "31% confident" does not.
    """
    ghost_layer = ""
    if ghost is not None and abs(ghost.belief - opinion.belief) > 0.005:
        ghost_layer = (
            f'<div class="ghost" style="width:{_pct(ghost.belief)}%" '
            f'title="before the robustness margin: {_pct(ghost.belief)}% belief"></div>'
        )
    belief, void, against = _pct(opinion.belief), _pct(opinion.uncertainty), _pct(opinion.disbelief)
    label = f"belief {belief}%, unknown {void}%, against {against}%"
    bar = (
        f'<div class="bar{" compact" if compact else ""}" role="img" aria-label="{label}">'
        f"{ghost_layer}"
        f'<div class="seg belief" style="width:{belief}%"></div>'
        f'<div class="seg void" style="width:{void}%"></div>'
        f'<div class="seg disbelief" style="width:{against}%"></div>'
        "</div>"
    )
    if compact:
        return bar
    return bar + (
        '<div class="legend">'
        f'<span><i class="k belief"></i>belief {belief}%</span>'
        f'<span><i class="k void"></i>unknown {void}%</span>'
        f'<span><i class="k disbelief"></i>against {against}%</span>'
        "</div>"
    )


# --- Facets -----------------------------------------------------------------------------------


def _sources(diversity: SourceDiversity, temporal: TemporalConsistency) -> str:
    """Where the signals came from, on the card and not only in the prose.

    Feed count is not source count; the ledger says both, and says how many of the origins an
    adversary can write into. When every signal is adversary-influenceable that cell is drawn
    in the alarm colour, because that is the shape of a planted picture.
    """
    total = diversity.total_signals
    plantable = diversity.adversary_influenceable_sources
    all_plantable = total > 0 and plantable >= total
    if temporal.is_coherent:
        when = "temporally coherent"
    else:
        gaps = len(temporal.discontinuities)
        when = f"{gaps} temporal discontinuit{'y' if gaps == 1 else 'ies'}"
    return (
        '<ul class="ledger" aria-label="sources">'
        f"<li><b>{total}</b> signal{'' if total == 1 else 's'}</li>"
        f"<li><b>{diversity.independent_source_count}</b> independent "
        f"origin{'' if diversity.independent_source_count == 1 else 's'}</li>"
        f'<li class="{"refused" if all_plantable else ""}">'
        f"<b>{plantable}</b> adversary-influenceable</li>"
        f"<li>{_e(when)}</li>"
        "</ul>"
    )


def _alternative(alt: AlternativeHypothesis) -> str:
    """An alternative is an argument, so it is typeset as one: what it claims, how strongly the
    evidence supports *it*, and the case against it — never the repr of the object."""
    chip = (
        '<span class="chip deception">deception hypothesis</span>'
        if alt.is_deception_hypothesis
        else ""
    )
    return (
        '<article class="alt">'
        f"<header><h6>{_e(alt.name)}</h6>{_band_pill(alt.band)}{chip}</header>"
        f'<p class="alt-desc">{_e(alt.description)}</p>'
        + _opinion_bar(alt.opinion, ghost=alt.evidential_opinion, compact=True)
        + '<p class="against"><span class="k">Argument against</span>'
        + f"{_e(alt.argument_against)}</p>"
        "</article>"
    )


def _gap(gap: MissingEvidence) -> str:
    """A gap says what would settle it and whether we may go and get it. The availability is
    one of the repository's load-bearing labels and is written in the same words."""
    availability = gap.availability.value
    return (
        '<li class="gap-item">'
        f'<span class="chip avail avail-{_e(availability)}">{_e(availability.upper())}</span>'
        f"<p>{_e(gap.description)}</p>"
        f'<p class="settles"><span class="k">Would settle it</span>{_e(gap.would_settle)}</p>'
        "</li>"
    )


def _claim_ref(claim_id: str) -> str:
    shown = claim_id if len(claim_id) <= 28 else f"{claim_id[:26]}…"
    return f'<li><code class="clm" title="{_e(claim_id)}">{_e(shown)}</code></li>'


def _facet(title: str, body: str, kind: str, *, empty: bool) -> str:
    if empty:
        return f'<div class="facet empty {kind}"><h5>{_e(title)}</h5><p>none recorded</p></div>'
    return f'<div class="facet {kind}"><h5>{_e(title)}</h5>{body}</div>'


# --- One dimension ----------------------------------------------------------------------------


def _assessment(item: DimensionAssessment) -> str:
    """One dimension, with everything needed to argue with it.

    Contradictions, alternatives and missing evidence are rendered at the same weight as the
    supporting count — an assessment that shows only its supports looks complete and is not.
    """
    gate = item.identity_gate
    refused = gate is not None and not gate.passed

    blocks: list[str] = []

    if refused and gate is not None:
        reasons = "".join(
            f"<li>{_e(reason.value.replace('_', ' '))}</li>" for reason in gate.reasons
        )
        blocks.append(
            '<div class="refusal">'
            "<h4>Refused before scoring</h4>"
            "<p>The gate runs <em>before</em> fusion, so no score can reach past it. "
            "A threshold is something an adversary pushes a number over; a gate on the "
            "<em>shape</em> of the evidence is not.</p>"
            f"<ul>{reasons}</ul>"
            "</div>"
        )

    if item.margin_outcome and item.removed_fact:
        blocks.append(
            '<div class="margin">'
            f"<strong>Robustness margin:</strong> {_e(item.margin_outcome)} — the conclusion "
            f"had to survive losing <code>{_e(summarize_fact(item.removed_fact))}</code>. "
            "The ghost edge on the bar is what the evidence gave before that fact was set aside."
            "</div>"
        )

    contradicting = "".join(_claim_ref(claim) for claim in item.contradicting_claims)
    alternatives = "".join(_alternative(alt) for alt in item.alternatives)
    missing = "".join(_gap(gap) for gap in item.missing_evidence)

    facets = (
        _facet(
            "Contradicting",
            f'<ul class="claims">{contradicting}</ul>',
            "against",
            empty=not item.contradicting_claims,
        )
        + _facet("Missing evidence", f'<ul class="gaps">{missing}</ul>', "gap", empty=not missing)
        + _facet(
            "Alternative hypotheses",
            f'<div class="alts">{alternatives}</div>',
            "alt-facet",
            empty=not alternatives,
        )
    )

    warnings = "".join(f"<li>{_e(w)}</li>" for w in item.warnings)
    warn_block = f'<div class="warn"><ul>{warnings}</ul></div>' if warnings else ""

    supports, contradicts = len(item.supporting_claims), len(item.contradicting_claims)
    return (
        f'<section class="dim {"refused" if refused else "held"} tone-{_band_tone(item.band)}">'
        '<header class="dim-head">'
        f'<div class="dim-title"><span class="eyebrow">Dimension</span>'
        f"<h3>{_e(item.dimension.value.replace('_', ' '))}</h3></div>"
        f"{_band_pill(item.band)}</header>"
        f'<p class="hypothesis">{_e(item.hypothesis)}</p>'
        + "".join(blocks)
        + _opinion_bar(item.opinion, ghost=item.evidential_opinion)
        + _sources(item.source_diversity, item.temporal_consistency)
        + '<details class="why"><summary>Why NEMESIS says this</summary>'
        f'<p class="reasoning">{_e(item.reasoning)}</p>'
        f'<p class="counts">{supports} supporting claim{"" if supports == 1 else "s"}, '
        f"{contradicts} contradicting</p>"
        f'<div class="facets">{facets}</div>{warn_block}</details>'
        "</section>"
    )


# --- The rail ---------------------------------------------------------------------------------


def _plane_caption(stage: str, plane: str) -> str:
    """The plane a stage runs in — blank when it only repeats the stage name, so a
    tight column is not spent saying "evidence" under EVIDENCE. The slot keeps its
    reserved height either way, so the ledgers below still align across the row."""
    same = plane.replace(" ", "").lower() == stage.replace("_", "").replace(" ", "").lower()
    return "" if same else plane


def _rail(marks: tuple[StageMark, ...]) -> str:
    """The course of the investigation, drawn from what the pipeline is.

    Stations in loop order; phase brackets above; the track hatched where input is hostile by
    default; a barrier where the platform can refuse; a ring where a human decides; and the
    return path from the last watch station to the first pursuit station, because a takedown
    closes no case. Under each station, the typed ledger of what the run recorded there.
    """
    n = len(marks)
    if n == 0:
        return ""
    metas = [meta_for(mark.name) for mark in marks]

    groups: list[tuple[Phase | None, int]] = []
    for meta in metas:
        if groups and groups[-1][0] == meta.phase:
            groups[-1] = (meta.phase, groups[-1][1] + 1)
        else:
            groups.append((meta.phase, 1))
    phases = "".join(
        f'<li class="phase phase-{_e(phase or "none")}" style="--span:{span}">'
        f"<span>{_e(PHASE_LABELS[phase])}</span></li>"
        for phase, span in groups
    )

    stations: list[str] = []
    for index, (mark, meta) in enumerate(zip(marks, metas, strict=True)):
        classes = ["stage"]
        if meta.hostile:
            classes.append("hostile")
        if meta.gate:
            classes.append("gate")
        if meta.human:
            classes.append("human")
        if mark.refusals:
            classes.append("refused")
        if index == n - 1:
            classes.append("last")
        facts = "".join(
            f'<li class="fact {fact.tone()}">{_e(fact.phrase())}</li>' for fact in mark.facts
        )
        facts_block = f'<ul class="facts">{facts}</ul>' if facts else ""
        badge = (
            f'<span class="refusals" title="{mark.refusals} refusal'
            f'{"" if mark.refusals == 1 else "s"} recorded at this stage">{mark.refusals}</span>'
            if mark.refusals
            else ""
        )
        stations.append(
            f'<li id="stage-{_e(mark.name)}" class="{" ".join(classes)}" style="--i:{index}">'
            '<span class="track" aria-hidden="true"></span>'
            f'<span class="node" aria-hidden="true">{badge}</span>'
            f'<span class="idx">{index + 1:02d}</span>'
            f'<span class="name">{_e(mark.name.replace("_", " "))}</span>'
            f'<span class="plane">{_e(_plane_caption(mark.name, meta.plane))}</span>'
            f"{facts_block}</li>"
        )

    return_path = ""
    pursue_at = next((i for i, meta in enumerate(metas) if meta.phase == "pursue"), None)
    if pursue_at is not None and metas[-1].phase == "watch" and n - 1 > pursue_at:
        return_path = (
            f'<div class="return" style="grid-column:{pursue_at + 1} / {n + 1};'
            f'--span:{n - 1 - pursue_at}" aria-hidden="true"></div>'
            f'<p class="return-note">{_e(RETURN_NOTE)}</p>'
        )

    key = (
        '<ul class="rail-key" aria-label="how to read the rail">'
        '<li><i class="key-node"></i>stage</li>'
        '<li><i class="key-hostile"></i>hostile-by-default input <em>(amber)</em></li>'
        '<li><i class="key-gate"></i>gate the platform can close</li>'
        '<li><i class="key-human"></i>a human decides</li>'
        '<li><i class="key-refused">1</i>refusals recorded here</li>'
        "</ul>"
    )
    return (
        f'<div class="rail-wrap" style="--n:{n}">'
        f'<ol class="phases" aria-hidden="true">{phases}</ol>'
        f'<ol class="rail">{"".join(stations)}</ol>'
        f"{return_path}</div>{key}"
    )


# --- Stylesheet -------------------------------------------------------------------------------

_CSS: Final = """
:root{
  --ink:#0b0e12; --ink2:#11161c; --ink3:#161c24; --rule:#222a34; --rule2:#2f3a47;
  --bone:#e8e2d4; --bone-dim:#9aa3ad; --bone-faint:#5c6774;
  --belief:#5b8f7d; --belief-hi:#86bfa8; --against:#7a4a52; --against-hi:#b0707c;
  --void:#2a323c; --alarm:#d98a3a; --alarm-hi:#f0a85a; --alarm-dim:#6b4a26; --alarm-ink:#1a1208;
  --mono:"SF Mono",Menlo,"Cascadia Mono",Consolas,monospace;
  --disp:"Avenir Next Condensed","Oswald","Arial Narrow","Helvetica Neue",sans-serif;
  --serif:"Iowan Old Style","Hoefler Text",Palatino,Georgia,serif;
  --ease:cubic-bezier(.2,.7,.2,1);
  --hatch-void:repeating-linear-gradient(45deg,var(--void),var(--void) 4px,transparent 4px,
  transparent 8px);
  --hatch-alarm:repeating-linear-gradient(45deg,var(--alarm-dim),var(--alarm-dim) 3px,
  transparent 3px,transparent 7px);
  --hazard:repeating-linear-gradient(135deg,var(--alarm) 0 5px,var(--alarm-ink) 5px 10px);
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--ink);color:var(--bone);font-family:var(--mono);
  font-size:13px;line-height:1.55;-webkit-font-smoothing:antialiased;
  background-image:
    radial-gradient(ellipse at 15% -10%,#18202a 0%,transparent 55%),
    linear-gradient(rgba(232,226,212,.022) 1px,transparent 1px),
    linear-gradient(90deg,rgba(232,226,212,.022) 1px,transparent 1px);
  background-size:auto,28px 28px,28px 28px}
.wrap{max-width:1120px;margin:0 auto;padding:40px 28px 96px}
h1,h2,h3,h4,h5,h6{font-family:var(--disp);font-weight:600;letter-spacing:.04em;margin:0}
code{font-family:var(--mono)}
::selection{background:var(--alarm);color:var(--alarm-ink)}
:focus-visible{outline:2px solid var(--alarm);outline-offset:3px}

/* masthead */
.masthead{display:flex;justify-content:space-between;align-items:flex-end;gap:20px;flex-wrap:wrap;
  padding-bottom:14px}
h1{font-size:38px;text-transform:uppercase;letter-spacing:.16em;line-height:1}
.sub{font-size:11px;color:var(--bone-dim);letter-spacing:.18em;text-transform:uppercase}
.masthead .brand{flex:1 1 280px;min-width:0}
.masthead .sub{overflow-wrap:anywhere}
.masthead .meta{display:flex;flex-direction:column;align-items:flex-end;gap:8px;flex:0 0 auto}
.stamp{display:inline-block;border:1px solid var(--alarm);color:var(--alarm);
  padding:4px 10px;font-size:10px;letter-spacing:.24em;text-transform:uppercase;
  background:linear-gradient(90deg,rgba(217,138,58,.12),transparent)}
.strip{height:2px;
  background:linear-gradient(90deg,var(--bone) 0,var(--bone) 40%,var(--bone-dim) 70%,transparent);
  transform-origin:left}
.notice{background:var(--ink2);border-left:3px solid var(--alarm);padding:12px 16px;
  margin:22px 0 34px;color:var(--bone-dim);font-size:12px}

/* sections */
h2.section{font-size:12px;letter-spacing:.24em;text-transform:uppercase;color:var(--bone-dim);
  border-bottom:1px solid var(--rule);padding-bottom:7px;margin:48px 0 20px;
  display:flex;align-items:baseline;gap:12px}
h2.section::before{content:"";width:8px;height:8px;background:var(--bone-dim);flex:none;
  transform:translateY(-1px)}
.eyebrow{font-size:10px;letter-spacing:.22em;text-transform:uppercase;color:var(--bone-faint);
  display:block;margin-bottom:2px}
.hypothesis{font-family:var(--serif);font-size:15px;line-height:1.5;margin:10px 0 16px;
  color:var(--bone)}
.hypothesis.lead{font-size:26px;line-height:1.25;margin:4px 0 10px;letter-spacing:-.005em}

/* warnings */
.warn{margin-top:14px;border-left:2px solid var(--alarm);padding:2px 0 2px 12px;color:var(--alarm);
  font-size:12px}
.warn ul{margin:0;padding-left:0;list-style:none}
.warn li{position:relative;padding-left:16px;margin:4px 0}
.warn li::before{content:"";position:absolute;left:0;top:7px;width:0;height:0;
  border-left:4px solid transparent;border-right:4px solid transparent;
  border-bottom:7px solid var(--alarm)}

/* ---- the rail ---- */
.rail-wrap{--n:12;display:grid;grid-template-columns:repeat(var(--n),minmax(0,1fr));
  margin:8px 0 4px;position:relative}
.phases,.rail{grid-column:1/-1;display:grid;grid-template-columns:repeat(var(--n),minmax(0,1fr));
  list-style:none;margin:0;padding:0}
.phase{grid-column:span var(--span);position:relative;padding:0 6px 10px;text-align:center}
.phase span{font-family:var(--disp);font-size:11px;letter-spacing:.22em;text-transform:uppercase;
  white-space:nowrap;
  color:var(--bone-dim);display:inline-block;background:var(--ink);padding:0 8px;
  position:relative;z-index:1}
.phase::before{content:"";position:absolute;left:6px;right:6px;top:8px;height:8px;
  border:1px solid var(--rule2);border-bottom:0}
.phase-watch::before{border-color:var(--alarm-dim)}
.phase-watch span{color:var(--alarm)}
.stage{position:relative;text-align:center;padding:14px 2px 6px;margin:0}
.stage .track{position:absolute;left:50%;right:-50%;top:20px;height:2px;background:var(--rule2);
  transform-origin:left}
.stage.hostile .track{background:var(--hatch-alarm);height:6px;top:18px;opacity:.9}
.stage.last .track{display:none}
.stage .node{position:relative;display:block;width:14px;height:14px;margin:0 auto 12px;
  border-radius:50%;background:var(--ink);border:2px solid var(--bone-dim);z-index:1;
  transition:box-shadow .25s var(--ease),border-color .25s var(--ease),transform .25s var(--ease)}
.stage.hostile .node{border-color:var(--alarm-hi)}
.stage.gate .node{width:8px;height:24px;border-radius:2px;margin-top:-5px;margin-bottom:7px;
  border:0;background:var(--hazard);box-shadow:0 0 0 2px var(--ink)}
.stage.human .node::after{content:"";position:absolute;inset:-7px;border-radius:6px;
  border:1px solid var(--alarm);box-shadow:0 0 0 3px var(--ink) inset}
.stage .refusals{position:absolute;top:-10px;right:-14px;min-width:16px;height:16px;padding:0 4px;
  border-radius:8px;background:var(--alarm);color:var(--alarm-ink);font:700 10px/16px var(--mono);
  text-align:center;z-index:2}
.stage .idx{display:block;font-size:10px;letter-spacing:.18em;color:var(--bone-faint)}
.stage .name{display:block;font-family:var(--disp);min-height:1.15em;
  font-size:clamp(10.5px,1.15vw,14px);
  letter-spacing:.08em;
  text-transform:uppercase;color:var(--bone-dim);transition:color .25s var(--ease)}
.stage .plane{display:block;min-height:2.1em;font-size:clamp(8.5px,.75vw,10px);letter-spacing:.1em;
  color:var(--bone-faint);
  text-transform:uppercase;margin-top:1px}
.stage .facts{list-style:none;margin:10px 0 0;padding:8px 0 0;border-top:1px dashed var(--rule);
  font-size:clamp(10px,.85vw,11px);line-height:1.5;letter-spacing:-.02em;color:var(--bone-dim);
  overflow-wrap:break-word;hyphens:manual;transition:color .25s var(--ease)}
.stage .fact{margin:0 0 2px}
.stage .fact.held{color:var(--belief-hi)}
.stage .fact.breach,.stage .fact.refused{color:var(--alarm-hi)}
.stage:hover .node,.stage:focus-within .node{box-shadow:0 0 0 5px rgba(134,191,168,.18),
  0 0 22px rgba(134,191,168,.35);
  border-color:var(--bone);transform:scale(1.08)}
.stage.hostile:hover .node,.stage.gate:hover .node{box-shadow:0 0 0 5px rgba(217,138,58,.18),
  0 0 22px rgba(217,138,58,.4)}
.stage:hover .name{color:var(--bone)}
.stage:hover .facts{color:var(--bone)}
.return{grid-row:3;height:30px;margin:2px calc(50% / (var(--span) + 1)) 0;position:relative;
  border:1px dashed var(--bone-faint);border-top:0;border-radius:0 0 18px 18px}
.return::before{content:"";position:absolute;left:-5px;top:-9px;width:8px;height:8px;
  border-left:1px dashed var(--bone-faint);border-top:1px dashed var(--bone-faint);
  transform:rotate(45deg)}
.return-note{grid-column:1/-1;grid-row:4;margin:10px 0 0;text-align:center;font-family:var(--serif);
  font-size:13px;color:var(--bone-dim)}
.rail-key{list-style:none;display:flex;flex-wrap:wrap;gap:6px 22px;margin:18px 0 0;padding:12px 0 0;
  border-top:1px solid var(--rule);font-size:10.5px;letter-spacing:.06em;color:var(--bone-dim)}
.rail-key li{display:flex;align-items:center;gap:8px}
.rail-key i{display:inline-block;width:12px;height:12px;flex:none}
.key-node{border-radius:50%;border:2px solid var(--bone-dim);background:var(--ink)}
.key-hostile{border-radius:50%;border:2px solid var(--alarm-hi);background:var(--ink)}
.key-gate{width:6px!important;height:16px!important;border-radius:2px;background:var(--hazard)}
.key-human{border-radius:4px;border:1px solid var(--alarm)}
.key-refused{width:auto!important;min-width:16px;height:16px!important;padding:0 4px;
  border-radius:8px;background:var(--alarm);color:var(--alarm-ink);
  font:700 10px/16px var(--mono);text-align:center}
.rail-key em{font-style:normal;color:var(--alarm)}

/* ---- dimensions ---- */
.dims{display:grid;gap:18px}
.dim{border:1px solid var(--rule);background:var(--ink2);padding:20px 22px;position:relative;
  transition:border-color .3s var(--ease),transform .3s var(--ease),box-shadow .3s var(--ease)}
.dim::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--rule2)}
.dim.tone-for::before{background:var(--belief)}
.dim.tone-against::before{background:var(--against)}
.dim.tone-even::before{background:var(--bone-faint)}
.dim.refused,.dim.tone-refused{border-color:var(--alarm)}
.dim.refused::before,.dim.tone-refused::before{background:var(--hazard);width:6px}
.dim:hover{border-color:var(--rule2);box-shadow:0 18px 40px -28px rgba(0,0,0,.9);
  transform:translateY(-1px)}
.dim-head{display:flex;justify-content:space-between;align-items:flex-end;gap:14px;flex-wrap:wrap}
.dim h3{font-size:22px;text-transform:uppercase;letter-spacing:.1em;line-height:1}
.band{display:inline-flex;align-items:baseline;gap:8px;font-size:10px;letter-spacing:.16em;
  text-transform:uppercase;border:1px solid var(--rule2);padding:4px 10px;color:var(--bone-dim);
  white-space:nowrap;background:var(--ink)}
.band b{font-weight:600;color:var(--bone)}
.band i{font-style:normal;color:var(--bone-dim);letter-spacing:.06em}
.band::before{content:"";width:6px;height:6px;border-radius:50%;background:var(--bone-faint);
  align-self:center}
.band.tone-for::before{background:var(--belief-hi)}
.band.tone-against::before{background:var(--against-hi)}
.band.tone-refused{border-color:var(--alarm);color:var(--alarm)}
.band.tone-refused b,
  .band.tone-refused i{color:var(--alarm)} .band.tone-refused::before{background:var(--alarm)}

.bar{position:relative;display:flex;height:28px;border:1px solid var(--rule);overflow:hidden;
  background:var(--ink)}
.bar.compact{height:12px;margin:10px 0 12px}
.seg{height:100%;transform-origin:left}
.seg.belief{background:linear-gradient(180deg,var(--belief-hi),var(--belief) 55%)}
.seg.disbelief{background:linear-gradient(180deg,var(--against-hi),var(--against) 55%)}
.seg.void{background:var(--hatch-void)}
.ghost{position:absolute;inset:0 auto 0 0;height:100%;border-right:2px dashed var(--bone-dim);
  background:rgba(232,226,212,.05);z-index:1;pointer-events:none}
.legend{display:flex;gap:18px;margin:8px 0 0;font-size:11px;color:var(--bone-dim);flex-wrap:wrap}
.legend i.k{display:inline-block;width:9px;height:9px;margin-right:6px;vertical-align:-1px}
.legend i.belief{background:var(--belief)} .legend i.disbelief{background:var(--against)}
.legend i.void{background:var(--hatch-void);border:1px solid var(--rule)}

.ledger{list-style:none;display:flex;flex-wrap:wrap;gap:6px 18px;margin:12px 0 0;padding:10px 0 0;
  border-top:1px dashed var(--rule);font-size:11px;color:var(--bone-dim);letter-spacing:.04em}
.ledger b{color:var(--bone);font-weight:600}
.ledger li.refused,.ledger li.refused b{color:var(--alarm)}

.refusal{position:relative;background:var(--alarm);color:var(--alarm-ink);
  padding:14px 16px 14px 24px;
  margin:4px 0 16px}
.refusal::before{content:"";position:absolute;left:0;top:0;bottom:0;width:8px;
  background:var(--hazard)}
.refusal h4{font-size:15px;text-transform:uppercase;letter-spacing:.1em;margin-bottom:6px}
.refusal p{margin:0 0 8px;font-size:12px}
.refusal ul{margin:0;padding-left:18px;font-size:12px}
.margin{border:1px dashed var(--rule2);padding:10px 13px;margin:0 0 14px;
  color:var(--bone-dim);font-size:12px}
.margin code{color:var(--bone)}

.why{margin-top:16px;border-top:1px solid var(--rule);padding-top:12px}
.why summary{cursor:pointer;font-family:var(--disp);letter-spacing:.12em;text-transform:uppercase;
  font-size:12px;color:var(--bone-dim);list-style:none;display:flex;align-items:center;gap:10px;
  transition:color .2s var(--ease)}
.why summary::-webkit-details-marker{display:none}
.why summary::before{content:"";width:7px;height:7px;border-right:1.5px solid currentColor;
  border-bottom:1.5px solid currentColor;transform:rotate(-45deg);
  transition:transform .25s var(--ease);
  margin-left:2px}
.why[open] summary::before{transform:rotate(45deg)}
.why summary:hover{color:var(--bone)}
.reasoning{font-family:var(--serif);font-size:14px;margin:14px 0;white-space:pre-line}
.counts{color:var(--bone-dim);font-size:11px;margin:0 0 14px}
.facets{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
.facet{border:1px solid var(--rule);padding:12px 14px;background:var(--ink)}
.facet.alt-facet{grid-column:1/-1}
.facet h5{font-size:10px;letter-spacing:.18em;text-transform:uppercase;color:var(--bone-dim);
  margin-bottom:8px}
.facet ul{margin:0;padding-left:0;list-style:none;font-size:12px}
.facet.empty p{margin:0;color:var(--bone-faint);font-size:12px;font-style:italic}
.facet.against{border-left:2px solid var(--against)}
.facet.gap{border-left:2px solid var(--alarm)}
.claims li{margin:2px 0}
.clm{color:var(--against-hi);font-size:11px}
.gaps .gap-item{padding:8px 0;border-top:1px dashed var(--rule)}
.gaps .gap-item:first-child{border-top:0;padding-top:0}
.gap-item p{margin:6px 0 0;font-family:var(--serif);font-size:13px;line-height:1.45}
.gap-item .settles{font-family:var(--mono);font-size:11px;color:var(--bone-dim)}
.k{display:inline-block;font-family:var(--disp);font-size:10px;letter-spacing:.18em;
  text-transform:uppercase;
  color:var(--bone-faint);margin-right:8px}
.chip{display:inline-block;font-size:9.5px;letter-spacing:.16em;text-transform:uppercase;
  padding:2px 7px;border:1px solid var(--rule2);color:var(--bone-dim);vertical-align:middle}
.chip.deception{border-color:var(--alarm-dim);color:var(--alarm)}
.chip.avail{background:var(--ink2)}
.chip.avail-requires_legal_authority,.chip.avail-unobtainable{border-color:var(--alarm);
  color:var(--alarm)}
.chip.avail-requires_external_data{border-color:var(--bone-faint);color:var(--bone-dim)}
.chip.avail-collectable{border-color:var(--belief);color:var(--belief-hi)}
.alts{display:grid;gap:12px}
.alt{border:1px solid var(--rule);border-left:2px solid var(--rule2);padding:12px 14px;
  background:var(--ink2)}
.alt header{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.alt h6{font-size:14px;text-transform:uppercase;letter-spacing:.08em;color:var(--bone);
  margin-right:auto}
.alt header .band{padding:3px 8px}
.alt-desc{font-family:var(--serif);font-size:13.5px;line-height:1.45;margin:8px 0 0}
.against{margin:0;font-size:12px;line-height:1.5;color:var(--bone-dim)}
.against .k{display:block;margin:0 0 3px}

/* withheld */
.refusal.withheld ul li{margin:4px 0}
footer{margin-top:64px;border-top:1px solid var(--rule);padding-top:16px;
  color:var(--bone-dim);font-size:11.5px;font-family:var(--serif);line-height:1.6;max-width:70ch}

/* ---- motion: opt-out by preference, orchestrated as one sequence ---- */
@media (prefers-reduced-motion:no-preference){
  @keyframes draw{from{transform:scaleX(0)}to{transform:scaleX(1)}}
  @keyframes light{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
  @keyframes lower{from{transform:scaleY(0)}to{transform:scaleY(1)}}
  @keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
  @keyframes fill{from{transform:scaleX(0)}to{transform:scaleX(1)}}
  @keyframes appear{from{opacity:0}to{opacity:1}}
  .strip{animation:draw .9s var(--ease) .1s both}
  .phase{animation:appear .6s var(--ease) calc(var(--n) * .09s + .5s) both}
  .stage .track{animation:draw .55s var(--ease) calc(var(--i) * .11s + .3s) both}
  .stage .node,.stage .idx,.stage .name,.stage .plane,.stage .facts{
    animation:light .5s var(--ease) calc(var(--i) * .11s + .2s) both}
  .stage.gate .node{animation:lower .5s var(--ease) calc(var(--i) * .11s + .35s) both;
  transform-origin:top}
  .stage .facts{animation-delay:calc(var(--i) * .11s + .45s)}
  .return,.return-note{animation:appear .8s var(--ease) calc(var(--n) * .11s + .5s) both}
  .rail-key{animation:appear .8s var(--ease) calc(var(--n) * .11s + .7s) both}
  .dims .dim{animation:rise .55s var(--ease) both}
  .dims .dim:nth-child(1){animation-delay:.15s} .dims .dim:nth-child(2){animation-delay:.25s}
  .dims .dim:nth-child(3){animation-delay:.35s} .dims .dim:nth-child(4){animation-delay:.45s}
  .dims .dim:nth-child(5){animation-delay:.55s}
  .dim .bar:not(.compact) .seg.belief{animation:fill .8s var(--ease) .7s both}
  .dim .bar:not(.compact) .seg.void{animation:fill .8s var(--ease) .95s both}
  .dim .bar:not(.compact) .seg.disbelief{animation:fill .6s var(--ease) 1.2s both}
  .dim .bar:not(.compact) .ghost{animation:appear .6s var(--ease) 1.5s both}
  .why[open] .facets,.why[open] .reasoning{animation:rise .35s var(--ease) both}
}

/* ---- narrow screens: the rail stands up ---- */
@media (max-width:880px){
  .wrap{padding:28px 18px 72px}
  h1{font-size:30px}
  .hypothesis.lead{font-size:21px}
  .phases,.return{display:none}
  .rail-wrap,.rail{grid-template-columns:1fr}
  .stage{display:grid;grid-template-columns:34px minmax(0,1fr);
  grid-template-rows:auto auto auto auto;
    column-gap:12px;text-align:left;padding:10px 0 14px}
  .stage .node{grid-column:1;grid-row:1/span 4;margin:3px 0 0 8px;align-self:start}
  .stage.gate .node{margin:0 0 0 11px}
  .stage .track{left:15px;right:auto;top:22px;bottom:-16px;width:2px;height:auto;
  transform-origin:top}
  .stage.hostile .track{width:6px;left:13px;height:auto;top:22px;
    background:repeating-linear-gradient(135deg,var(--alarm-dim),var(--alarm-dim) 3px,
  transparent 3px,transparent 7px)}
  .stage .idx,.stage .name,.stage .plane,.stage .facts{grid-column:2}
  .stage .refusals{right:auto;left:14px}
  .return-note{grid-column:1;grid-row:auto;text-align:left;border-left:1px dashed var(--bone-faint);
    padding-left:14px;margin-left:15px}
  .facets{grid-template-columns:1fr}
  .dim-head{align-items:flex-start;flex-direction:column}
}

/* ---- print: a case file is a thing that gets printed ---- */
@media print{
  :root{--ink:#fff;--ink2:#fff;--ink3:#f4f4f4;--rule:#bbb;--rule2:#999;--bone:#111;--bone-dim:#444;
    --bone-faint:#666;--void:#c9c9c9;--belief:#6f9c8c;--belief-hi:#6f9c8c;--against:#9a6a72;
  --against-hi:#9a6a72;
    --alarm:#b8651a;--alarm-hi:#b8651a;--alarm-dim:#d9a66f;--alarm-ink:#1a1208}
  body{background:#fff;color:#111;background-image:none;font-size:11px}
  .wrap{max-width:none;padding:0}
  .dim,.notice,.alt,.facet,.margin,.bar,.band{background:#fff}
  .refusal{background:#f3c48d;color:#1a1208}
  .dim,.rail-wrap,.alt{break-inside:avoid}
  .dim:hover{transform:none;box-shadow:none}
  .stage .track{background:#999}
  *{animation:none!important;transition:none!important}
  .why summary::before{display:none}
}
"""


# --- The page ---------------------------------------------------------------------------------


def render_investigation(
    result: AttributionResult,
    *,
    stages: tuple[str, ...] = (),
    marks: tuple[StageMark, ...] = (),
    generated_at: datetime | None = None,
) -> str:
    """One self-contained HTML page for one investigation.

    Takes the attribution result, the stage names and — optionally — the typed ledger of
    marks, rather than the whole scenario, for the same reason the HTTP surface takes an
    `InvestigationView`: handed everything, the obvious next commit renders a stage "just to
    see it" and an internal lead leaves through a field nobody thought about. When ``marks``
    is empty the rail is drawn from the names alone.
    """
    # Deliverable-class dimensions only, from the one list that decides — the same set the
    # external product ships. The persona dimension's own *hypothesis* is persona linkage in
    # plain prose ("X and Y are one operator"), so rendering the band while redacting the fact
    # key would have leaked the finding anyway. Whether an analyst surface may show an internal
    # lead is founder decision D1's neighbour; until it is settled this page is portable and
    # therefore deliverable-class, which is the reading that cannot leak by accident.
    shown = tuple(item for item in result.assessments if item.dimension in DELIVERABLE_DIMENSIONS)
    stations = marks or tuple(StageMark(name=name) for name in stages)
    rail = _rail(stations)
    dims = "".join(_assessment(item) for item in shown)

    shipped = {item.dimension for item in shown}
    # Withheld is not silent. Each withheld dimension is reported with the *band it reached*
    # and, where a gate refused it, that it was refused before any scoring — because "we
    # assessed this and refused to conclude" is the product, and dropping it would read as
    # "nothing was found". The band names nobody; only the assessment's content is withheld.
    by_dimension = {item.dimension: item for item in result.assessments}
    rows = ""
    for dimension in AttributionDimension:
        if dimension in shipped:
            continue
        assessed = by_dimension.get(dimension)
        label = _e(dimension.value.replace("_", " "))
        if assessed is None:
            rows += f"<li><b>{label}</b> — not assessed</li>"
            continue
        gate = assessed.identity_gate
        gated = (
            " · refused before scoring, no score could reach past the gate"
            if (gate is not None and not gate.passed)
            else ""
        )
        rows += (
            f"<li><b>{label}</b> — reached "
            f"<em>{_e(assessed.band.value.replace('_', ' '))}</em>"
            f"{gated}; the finding itself is an internal lead and is not on this page</li>"
        )

    withheld_block = ""
    if rows:
        withheld_block = (
            '<h2 class="section">Assessed, and withheld from this view</h2>'
            '<div class="refusal withheld"><h4>Refused or held internal</h4>'
            f"<p>{_e(WITHHELD_NOTE)}</p>"
            f"<ul>{rows}</ul></div>"
        )

    stamped = (generated_at or result.assessed_at).isoformat(timespec="seconds")
    warnings = "".join(f"<li>{_e(w)}</li>" for w in result.warnings)
    warn_block = f'<div class="warn"><ul>{warnings}</ul></div>' if warnings else ""
    assessed_count = _count(len(result.assessments), "dimension", "dimensions")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>NEMESIS — {_e(result.subject)}</title>
<style>{_CSS}</style></head><body><div class="wrap">
<header class="masthead">
  <div class="brand"><h1>Nemesis</h1>
    <div class="sub">Investigation file &middot; {_e(result.attribution_id)}</div></div>
  <div class="meta"><span class="stamp">Simulated</span>
    <span class="sub">assessed {_e(stamped)}</span></div>
</header>
<div class="strip" aria-hidden="true"></div>
<div class="notice">{_e(SIMULATED_NOTICE)}</div>

<h2 class="section">Subject</h2>
<p class="hypothesis lead">{_e(result.subject)}</p>
<div class="sub">{_e(assessed_count)} assessed separately, never one number</div>
{warn_block}

<h2 class="section">Course of the investigation</h2>
{rail}

<h2 class="section">Attribution &mdash; each dimension separately</h2>
<div class="dims">{dims}</div>
{withheld_block}

<footer>
  There is deliberately no overall figure. A weighted mean of these dimensions would be
  dominated by infrastructure — the one with the most evidence and the least to say about who
  anybody is — and a reader shown one number stops reading the five.<br><br>
  Nothing on this page is calibrated. The figures are internally consistent; nothing here
  shows they are correct, and with no ground-truth corpus nothing can.
</footer>
</div></body></html>
"""


__all__ = ["RETURN_NOTE", "SIMULATED_NOTICE", "WITHHELD_NOTE", "render_investigation"]
