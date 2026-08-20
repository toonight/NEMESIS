"""The analyst view: a case file, not a dashboard.

The brief asks for an analyst-oriented investigation view where "uncertainty is visible" and
"a user must be able to click an attribution claim and understand why NEMESIS believes it",
and warns against "a generic SOC dashboard full of meaningless charts". The project's own
milestone note added the sharper constraint, and it is the one that shaped every choice here:

    A wrong attribution in a polished interface is more dangerous than the same error in a
    text file, because production value reads as confidence.

So the design thesis is an **inversion**. In an ordinary intelligence product the conclusion
gets the visual weight and the caveats get small grey text at the bottom. Here the hierarchy
is reversed, because in this platform the refusal *is* the product:

**Uncertainty is rendered as physical space, never as a number.** Every figure is a
three-segment bar — belief, uncertainty, disbelief — and the uncertain part is drawn as a
literal hatched void. A reader sees how much of the bar is *not known* before they read any
percentage, and a mostly-void bar looks wrong at a glance in a way that "31%" does not.

**The margin reduction is shown, not hidden.** Where the robustness margin removed a plantable
fact, the pre-margin opinion is drawn as a ghost behind the real one. The gap between them is
the size of what was deliberately set aside — the demonstration's headline linkage falls from
*likely* to *insufficient basis*, and a reader must be able to see that cost rather than
conclude the evidence was simply weak.

**Refusals get the loudest treatment on the page.** The human-identity gate, the withheld
dimensions, the operations the envelope forbade: full-width, high-contrast, above the
conclusions rather than beneath them.

**What it will not render.** Founder decision D1 makes persona linkage an internal lead. This
surface is local and analyst-facing — the analyst is inside the wall — but the *page* is a file
that can be mailed, so it carries deliverable-class material and marks the withheld bands as
withheld rather than omitting them silently. Silence reads as "nothing was found", which is a
different claim.

Self-contained by construction: one HTML file, no external fonts, no scripts fetched, no
network of any kind. Invariant 15 applies to a viewer as much as to a collector.

Status: `IMPLEMENTED` for the attribution and refusal surface over a `SIMULATED` scenario.
"""

from __future__ import annotations

import html
from datetime import datetime
from typing import Final

from nemesis.attribute.dimensions import AttributionDimension, DimensionAssessment
from nemesis.attribute.disclosure import DELIVERABLE_DIMENSIONS
from nemesis.attribute.engine import AttributionResult
from nemesis.core.confidence import ConfidenceBand, Opinion
from nemesis.core.fusion import summarize_fact

SIMULATED_NOTICE: Final = (
    "Every figure on this page comes from a SIMULATED investigation over fixture data. "
    "It is not intelligence about anybody."
)

WITHHELD_NOTE: Final = (
    "Named as withheld rather than omitted. Silence would read as “nothing was found”, "
    "which is a different claim entirely."
)


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _pct(value: float) -> str:
    return f"{value * 100:.0f}"


def _opinion_bar(opinion: Opinion, *, ghost: Opinion | None = None) -> str:
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
    return (
        '<div class="bar">'
        f"{ghost_layer}"
        f'<div class="seg belief" style="width:{_pct(opinion.belief)}%"></div>'
        f'<div class="seg void" style="width:{_pct(opinion.uncertainty)}%"></div>'
        f'<div class="seg disbelief" style="width:{_pct(opinion.disbelief)}%"></div>'
        "</div>"
        '<div class="legend">'
        f'<span><i class="k belief"></i>belief {_pct(opinion.belief)}%</span>'
        f'<span><i class="k void"></i>unknown {_pct(opinion.uncertainty)}%</span>'
        f'<span><i class="k disbelief"></i>against {_pct(opinion.disbelief)}%</span>'
        "</div>"
    )


def _band_class(band: ConfidenceBand) -> str:
    return "refused" if band is ConfidenceBand.INSUFFICIENT_BASIS else "held"


def _assessment(item: DimensionAssessment) -> str:
    """One dimension, with everything needed to argue with it.

    Contradictions, alternatives and missing evidence are rendered at the same weight as the
    supporting count — an assessment that shows only its supports looks complete and is not.
    """
    gate = item.identity_gate
    refused = gate is not None and not getattr(gate, "passed", True)

    blocks: list[str] = []

    if refused:
        reasons = "".join(f"<li>{_e(reason)}</li>" for reason in getattr(gate, "reasons", ()) or ())
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
            "The ghost bar is "
            "what the evidence gave before that fact was set aside."
            "</div>"
        )

    def _list(title: str, rows: tuple[str, ...], kind: str) -> str:
        if not rows:
            return f'<div class="facet empty"><h5>{_e(title)}</h5><p>none recorded</p></div>'
        items = "".join(f"<li>{_e(row)}</li>" for row in rows)
        return f'<div class="facet {kind}"><h5>{_e(title)}</h5><ul>{items}</ul></div>'

    alternatives = tuple(getattr(alt, "hypothesis", str(alt)) for alt in item.alternatives)
    missing = tuple(getattr(gap, "description", str(gap)) for gap in item.missing_evidence)

    facets = (
        _list("Contradicting", tuple(item.contradicting_claims), "against")
        + _list("Alternative hypotheses", alternatives, "alt")
        + _list("Missing evidence", missing, "gap")
    )

    warnings = "".join(f"<li>{_e(w)}</li>" for w in item.warnings)
    warn_block = f'<div class="warn"><ul>{warnings}</ul></div>' if warnings else ""

    return (
        f'<section class="dim {_band_class(item.band)}">'
        f"<header><h3>{_e(item.dimension.value.replace('_', ' '))}</h3>"
        f'<span class="band">{_e(item.band.value.replace("_", " "))}</span></header>'
        f'<p class="hypothesis">{_e(item.hypothesis)}</p>'
        + "".join(blocks)
        + _opinion_bar(item.opinion, ghost=item.evidential_opinion)
        + f'<details class="why"><summary>Why NEMESIS says this</summary>'
        f'<p class="reasoning">{_e(item.reasoning)}</p>'
        f'<p class="counts">{len(item.supporting_claims)} supporting claim(s), '
        f"{len(item.contradicting_claims)} contradicting</p>"
        f'<div class="facets">{facets}</div>{warn_block}</details>'
        "</section>"
    )


_CSS: Final = """
:root{
  --ink:#0d1014; --ink2:#141920; --rule:#232b35;
  --bone:#e8e2d4; --bone-dim:#9aa3ad;
  --belief:#5b8f7d; --against:#7a4a52; --void:#2a323c;
  --alarm:#d98a3a; --alarm-ink:#1a1208;
  --mono:"SF Mono",Menlo,"Cascadia Mono",monospace;
  --disp:"Avenir Next Condensed","Oswald","Arial Narrow",sans-serif;
  --serif:"Iowan Old Style","Hoefler Text",Palatino,Georgia,serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--ink);color:var(--bone);font-family:var(--mono);
  font-size:13px;line-height:1.55;
  background-image:radial-gradient(circle at 12% -10%,#18202a 0%,transparent 55%);}
.wrap{max-width:1080px;margin:0 auto;padding:40px 28px 96px}
h1,h2,h3,h4,h5{font-family:var(--disp);font-weight:600;letter-spacing:.04em;margin:0}
h1{font-size:34px;text-transform:uppercase;letter-spacing:.14em}
.masthead{border-bottom:2px solid var(--bone);padding-bottom:14px;margin-bottom:8px;
  display:flex;justify-content:space-between;align-items:baseline;gap:20px;flex-wrap:wrap}
.masthead .sub{font-size:11px;color:var(--bone-dim);letter-spacing:.18em;text-transform:uppercase}
.stamp{display:inline-block;border:1px solid var(--alarm);color:var(--alarm);
  padding:3px 9px;font-size:10px;letter-spacing:.2em;text-transform:uppercase}
.notice{background:var(--ink2);border-left:3px solid var(--alarm);padding:12px 16px;
  margin:22px 0 34px;color:var(--bone-dim);font-size:12px}
.spine{border-left:1px solid var(--rule);padding-left:18px;margin:0 0 40px}
.spine li{list-style:none;position:relative;padding:3px 0;color:var(--bone-dim);font-size:12px}
.spine li::before{content:"";position:absolute;left:-23px;top:11px;width:9px;height:1px;
  background:var(--rule)}
.spine li b{color:var(--bone);font-weight:400}
h2.section{font-size:13px;letter-spacing:.22em;text-transform:uppercase;color:var(--bone-dim);
  border-bottom:1px solid var(--rule);padding-bottom:7px;margin:44px 0 20px}
.dim{border:1px solid var(--rule);background:var(--ink2);padding:18px 20px;margin-bottom:16px}
.dim.refused{border-color:var(--alarm)}
.dim header{display:flex;justify-content:space-between;align-items:baseline;gap:14px}
.dim h3{font-size:19px;text-transform:uppercase;letter-spacing:.09em}
.band{font-size:10px;letter-spacing:.16em;text-transform:uppercase;border:1px solid var(--rule);
  padding:2px 8px;color:var(--bone-dim);white-space:nowrap}
.dim.refused .band{border-color:var(--alarm);color:var(--alarm)}
.hypothesis{font-family:var(--serif);font-size:15px;line-height:1.5;margin:10px 0 16px;
  color:var(--bone)}
.bar{position:relative;display:flex;height:26px;border:1px solid var(--rule);overflow:hidden}
.seg{height:100%}
.seg.belief{background:var(--belief)}
.seg.disbelief{background:var(--against)}
.seg.void{background:repeating-linear-gradient(45deg,var(--void),var(--void) 4px,
  transparent 4px,transparent 8px)}
.ghost{position:absolute;inset:0 auto 0 0;height:100%;border-right:2px dashed var(--bone-dim);
  background:rgba(232,226,212,.06)}
.legend{display:flex;gap:18px;margin:7px 0 0;font-size:11px;color:var(--bone-dim)}
.legend i.k{display:inline-block;width:9px;height:9px;margin-right:6px;vertical-align:-1px}
.legend i.belief{background:var(--belief)} .legend i.disbelief{background:var(--against)}
.legend i.void{background:repeating-linear-gradient(45deg,var(--void),var(--void) 3px,
  transparent 3px,transparent 6px);border:1px solid var(--rule)}
.refusal{background:var(--alarm);color:var(--alarm-ink);padding:14px 16px;margin:4px 0 16px}
.refusal h4{font-size:15px;text-transform:uppercase;letter-spacing:.1em;margin-bottom:6px}
.refusal p{margin:0 0 8px;font-size:12px}
.refusal ul{margin:0;padding-left:18px;font-size:12px}
.margin{border:1px dashed var(--rule);padding:10px 13px;margin:0 0 14px;
  color:var(--bone-dim);font-size:12px}
.margin code{color:var(--bone)}
.why{margin-top:16px;border-top:1px solid var(--rule);padding-top:12px}
.why summary{cursor:pointer;font-family:var(--disp);letter-spacing:.1em;text-transform:uppercase;
  font-size:12px;color:var(--bone-dim)}
.why summary:hover{color:var(--bone)}
.reasoning{font-family:var(--serif);font-size:14px;margin:12px 0}
.counts{color:var(--bone-dim);font-size:11px;margin:0 0 14px}
.facets{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}
.facet{border:1px solid var(--rule);padding:10px 12px}
.facet h5{font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--bone-dim);
  margin-bottom:6px}
.facet ul{margin:0;padding-left:16px;font-size:12px}
.facet.empty p{margin:0;color:var(--bone-dim);font-size:12px;font-style:italic}
.facet.against{border-left:2px solid var(--against)}
.facet.gap{border-left:2px solid var(--alarm)}
.warn{margin-top:12px;border-left:2px solid var(--alarm);padding-left:12px;color:var(--alarm);
  font-size:12px}
.warn ul{margin:0;padding-left:16px}
footer{margin-top:56px;border-top:1px solid var(--rule);padding-top:16px;
  color:var(--bone-dim);font-size:11px}
@media(prefers-reduced-motion:no-preference){
  .dim{animation:rise .5s both} .dim:nth-child(2){animation-delay:.05s}
  .dim:nth-child(3){animation-delay:.1s} .dim:nth-child(4){animation-delay:.15s}
  .dim:nth-child(5){animation-delay:.2s}
  @keyframes rise{from{opacity:0;transform:translateY(9px)}to{opacity:1;transform:none}}
}
"""


def render_investigation(
    result: AttributionResult,
    *,
    stages: tuple[str, ...] = (),
    generated_at: datetime | None = None,
) -> str:
    """One self-contained HTML page for one investigation.

    Takes the attribution result and the stage names rather than the whole scenario, for the
    same reason the HTTP surface takes an `InvestigationView`: handed everything, the obvious
    next commit renders a stage "just to see it" and an internal lead leaves through a field
    nobody thought about.
    """
    # Deliverable-class dimensions only, from the one list that decides — the same set the
    # external product ships. The persona dimension's own *hypothesis* is persona linkage in
    # plain prose ("X and Y are one operator"), so rendering the band while redacting the fact
    # key would have leaked the finding anyway. Whether an analyst surface may show an internal
    # lead is founder decision D1's neighbour; until it is settled this page is portable and
    # therefore deliverable-class, which is the reading that cannot leak by accident.
    shown = tuple(item for item in result.assessments if item.dimension in DELIVERABLE_DIMENSIONS)
    spine = "".join(
        f"<li><b>{index:02d}</b> &nbsp;{_e(name)}</li>"
        for index, name in enumerate(stages, start=1)
    )
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
            if (gate is not None and not getattr(gate, "passed", True))
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
            f'<div class="refusal"><h4>Refused or held internal</h4><p>{_e(WITHHELD_NOTE)}</p>'
            f"<ul>{rows}</ul></div>"
        )

    stamped = (generated_at or result.assessed_at).isoformat(timespec="seconds")
    warnings = "".join(f"<li>{_e(w)}</li>" for w in result.warnings)
    warn_block = f'<div class="warn"><ul>{warnings}</ul></div>' if warnings else ""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NEMESIS — {_e(result.subject)}</title>
<style>{_CSS}</style></head><body><div class="wrap">
<div class="masthead">
  <div><h1>Nemesis</h1>
    <div class="sub">Investigation file &middot; {_e(result.attribution_id)}</div></div>
  <div class="stamp">Simulated</div>
</div>
<div class="notice">{_e(SIMULATED_NOTICE)}</div>

<h2 class="section">Subject</h2>
<p class="hypothesis">{_e(result.subject)}</p>
<div class="sub">assessed {_e(stamped)} &middot; five dimensions, never one number</div>
{warn_block}

<h2 class="section">Course of the investigation</h2>
<ul class="spine">{spine}</ul>

<h2 class="section">Attribution &mdash; each dimension separately</h2>
{dims}
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


__all__ = ["SIMULATED_NOTICE", "WITHHELD_NOTE", "render_investigation"]
