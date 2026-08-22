"""The operator command line: run the demonstration, and read what it refuses to say.

``nemesis demo`` runs :func:`nemesis.slice.scenario.run_glass_anvil_scenario` once and
renders it. The rendering is not a summary of the run — it is the part of the product a
human actually reads, so the things easiest to lose in a summary are the things it is
built to keep:

**Uncertainty is shown, never smoothed.** Every band is printed with its numeric range,
because "likely" means different numbers to different readers. Every caveat, warning and
collapsed source group is printed. Where the evidence traces to one origin, the output
says so next to the figure rather than in a footnote.

**The refusal is the headline.** The human-identity dimension prints as
``INSUFFICIENT_BASIS`` in its own panel, with the reasons the gate gave. That line is the
most important output in the whole demonstration: a run that named a person would be a
failed run, and a run that named nobody but buried the fact reads as though it simply had
nothing to say.

**The name is never printed.** The planted identity lead is recorded in the graph and in
the result object; this renderer prints that a lead exists, that it was refused, and how
many claims are held against the refusal. A refusal document that repeats the accusation
has published it.

**Collected content does not get to format the console.** Every data-bearing string is
wrapped in :class:`rich.text.Text`, so a value carrying square brackets — an IPv6 address,
``[truncated at 400 characters]`` — is printed rather than interpreted as console markup.
An adversary who can influence what we collect must not thereby influence what an operator
sees.

``nemesis verify`` re-checks a workspace the demo wrote: the vault's hash chain and
artifacts, and the audit trail's chain. It reports what those checks do *not* establish
with the same prominence as what they do.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Annotated, Final

try:
    import typer
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ModuleNotFoundError as missing:  # pragma: no cover - exercised by a clean install
    # `typer` and `rich` are an optional extra on purpose: the domain model depends on
    # nothing but the standard library and Pydantic, and a library install should not drag
    # in a terminal UI. But `[project.scripts]` installs the `nemesis` executable
    # unconditionally, so a minimal `pip install nemesis` shipped a command that died on
    # `import typer` with a traceback — the first thing anyone trying the project would meet.
    #
    # Failing here with an instruction rather than a stack trace is the whole fix. Found by an
    # external review and reproduced in a clean virtualenv before being believed.
    raise SystemExit(
        f"The NEMESIS command line needs an optional extra that is not installed "
        f"({missing.name}).\n\n"
        "    uv sync --all-extras          # working from a clone\n"
        "    pip install 'nemesis[cli]'    # installing the package\n\n"
        "Everything else — the domain model, the graph, the invariants — works without it."
    ) from missing

from nemesis.attribute.dimensions import AttributionDimension, DimensionAssessment
from nemesis.audit.trail import AppendOnlyAuditTrail, ChainVerification
from nemesis.core.confidence import ConfidenceBand, Opinion
from nemesis.evidence.vault import FileSystemEvidenceVault, FileSystemVaultIntegrityReport
from nemesis.pilot.providers.schema import MOVE_TOOL_NAMES
from nemesis.pilotbench.runner import BenchSubject
from nemesis.slice.scenario import (
    STAGE_NAMES,
    AttributionStage,
    AuthorizationStage,
    BlockchainStage,
    DarkWebStage,
    DetectionStage,
    DisruptionStage,
    EffectsStage,
    EvidenceStage,
    GraphStage,
    PursuitStage,
    ResolutionStage,
    ResurgenceStage,
    ScenarioResult,
    band_range,
    run_glass_anvil_scenario,
)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="NEMESIS operator console. Everything it runs is SIMULATED.",
)

BANNER: Final = (
    "SIMULATED — Operation GLASS ANVIL. Every identifier is synthetic and drawn from "
    "ranges reserved for documentation; none of it resolves, and nothing in this run "
    "touched a system we do not own."
)

NOT_DEMONSTRATED: Final = (
    "Nothing above is calibrated. The figures are internally consistent, and nothing here "
    "shows they are correct; with no ground-truth corpus, nothing can. Every source in "
    "this run is one synthetic origin wearing seven hats, so no finding in it is "
    "corroborated, and none of it could be presented as proof."
)

_RULE: Final = "-" * 78


# --------------------------------------------------------------------------------------
# Rendering primitives
# --------------------------------------------------------------------------------------


def _heading(console: Console, title: str) -> None:
    console.print()
    console.print(Text(title.upper(), style="bold cyan"))
    console.print(Text(_RULE, style="dim"))


def _field(console: Console, label: str, value: object, *, style: str = "") -> None:
    console.print(Text(f"  {label:<32}", style="dim").append(Text(str(value), style=style)))


def _bullets(
    console: Console, items: Iterable[object], *, marker: str = "-", style: str = ""
) -> None:
    for item in items:
        console.print(Text(f"    {marker} ", style="dim").append(Text(str(item), style=style)))


def _confidence(opinion: Opinion, band: ConfidenceBand) -> Text:
    """One line carrying the word, the numeric range behind it, and the uncertainty.

    The band never appears without its range. A reader who takes "likely" to mean 90% and
    a reader who takes it to mean 60% are reading the same word and different findings.
    """
    return Text(
        f"{band.value.replace('_', ' ')} ({band_range(band)})  "
        f"point estimate {opinion.projected_probability:.0%}, "
        f"uncertainty {opinion.uncertainty:.2f}"
    )


def _confidence_line(console: Console, label: str, opinion: Opinion, band: ConfidenceBand) -> None:
    console.print(Text(f"  {label:<32}", style="dim").append(_confidence(opinion, band)))


def _elide(value: str, limit: int) -> str:
    """Shorten a long identifier for a column, marking that it was shortened."""
    return value if len(value) <= limit else f"{value[: limit - 1]}…"


def _table(*columns: str) -> Table:
    table = Table(box=None, pad_edge=False, show_edge=False, header_style="bold")
    for column in columns:
        table.add_column(column, overflow="fold")
    return table


# --------------------------------------------------------------------------------------
# Stage renderers
# --------------------------------------------------------------------------------------


def _render_detect(console: Console, stage: DetectionStage) -> None:
    _heading(console, "1. detect")
    _field(console, "incident seed", f"{stage.seed_entity_type.value}:{stage.seed_entity_key}")
    _field(console, "detected at", stage.detected_at.isoformat())
    _field(console, "proposition", stage.proposition)
    table = _table("sensor", "class", "reliability", "independence key")
    for sensor in stage.sensors:
        table.add_row(
            Text(sensor.sensor),
            Text(sensor.source_class.value),
            Text(sensor.reliability.value),
            Text(sensor.independence_key),
        )
    console.print(table)
    _field(
        console,
        "sources after collapsing",
        f"{stage.fusion.independent_source_count} independent of "
        f"{stage.fusion.total_sources} feed(s)",
        style="bold yellow",
    )
    for group in stage.fusion.collapsed_groups:
        _bullets(console, [f"counted once: {', '.join(group)}"], style="yellow")
    _bullets(console, stage.fusion.warnings, marker="!", style="yellow")


def _render_pursue(console: Console, stage: PursuitStage) -> None:
    _heading(console, "2. pursue")
    _field(console, "investigation", stage.investigation.investigation_id)
    _field(console, "state", stage.investigation.state.value)
    _field(console, "autonomous pivots", stage.autonomous_pivots)
    _field(
        console,
        "budget",
        f"{stage.investigation.budget_spent:.1f} of {stage.investigation.total_budget:.1f}",
    )
    branches = _table("branch", "focus", "state", "why it closed")
    for branch in stage.investigation.branches:
        branches.add_row(
            Text(branch.branch_id),
            # Elided rather than wrapped: a 64-character certificate fingerprint would push
            # every other column off the line it belongs to.
            Text(_elide(branch.focus_entity_key, 38)),
            Text(branch.state.value),
            Text(branch.abandonment_reason or "every worthwhile pivot ran"),
        )
    console.print(branches)
    if stage.autonomous_failures:
        console.print(Text("  pivots the engine could not make:", style="yellow"))
        _bullets(console, stage.autonomous_failures, marker="!", style="yellow")

    console.print()
    console.print(Text("  analyst-directed collection", style="bold"))
    _bullets(console, [stage.directed_because], marker=">", style="dim")
    table = _table("pivot", "target", "connector", "claims", "outcome")
    for directed in stage.directed:
        table.add_row(
            Text(directed.pivot_type.value),
            Text(_elide(directed.entity_key, 44)),
            Text(directed.connector),
            Text(str(directed.claim_count)),
            Text("collected" if directed.succeeded else "could not look"),
        )
    console.print(table)
    for directed in stage.directed:
        if directed.error is not None:
            _bullets(
                console,
                [f"{directed.pivot_type.value} on {directed.entity_key}: {directed.error}"],
                marker="!",
                style="yellow",
            )
        if directed.withheld_personal_data_entities:
            _bullets(
                console,
                [
                    f"{directed.pivot_type.value}: "
                    f"{directed.withheld_personal_data_entities} discovered entity(ies) "
                    "withheld from this listing — personal-data category"
                ],
                marker="~",
                style="dim",
            )


def _render_graph(console: Console, stage: GraphStage) -> None:
    _heading(console, "3. graph")
    _field(
        console, "entities / relationships", f"{stage.entity_count} / {stage.relationship_count}"
    )
    _field(console, "cluster traversal floor", f"projected probability >= {stage.min_confidence}")
    _field(console, "cluster domains", ", ".join(stage.cluster_domains))
    _field(
        console,
        "further victims discovered",
        ", ".join(stage.victim_domains_discovered) or "none",
        style="bold",
    )
    _field(
        console,
        "not traversed (shared infra)",
        ", ".join(stage.excluded_shared_infrastructure) or "none",
    )
    console.print()
    console.print(Text("  the same relation twice, with opposite analytic value", style="bold"))
    table = _table("pivot", "population", "weight", "band", "point estimate")
    for label, edge in (
        ("selective — 4 domains", stage.selective_pivot),
        ("control — CDN address", stage.worthless_pivot),
    ):
        table.add_row(
            Text(label),
            Text(f"{edge.population_size:,}" if edge.population_size else "uncounted"),
            Text(f"{edge.evidential_weight:.3f}"),
            Text(f"{edge.band.value.replace('_', ' ')} ({band_range(edge.band)})"),
            Text(f"{edge.projected_probability:.0%}"),
        )
    console.print(table)
    _bullets(console, stage.worthless_pivot.caveats, marker="!", style="yellow")
    _field(
        console,
        "CDN tenants in the cluster",
        ", ".join(stage.cdn_tenants_in_cluster) or "none — the floor held",
        style="bold red" if stage.cdn_tenants_in_cluster else "bold green",
    )
    _field(
        console,
        "reachable with no floor",
        ", ".join(stage.cdn_tenants_reachable_unfiltered) or "none",
        style="dim",
    )


def _render_darkweb(console: Console, stage: DarkWebStage) -> None:
    _heading(console, "4. dark web")
    _field(console, "persona", f"{stage.persona} on {stage.forum}")
    _field(console, "historical persona", f"{stage.historical_persona} on {stage.marketplace}")
    _field(console, "PGP fingerprint", f"{stage.pgp_fingerprint} ({stage.pgp_key_bits}-bit)")
    _field(console, "persona in graph", stage.persona_in_graph)
    _field(console, "key in graph", stage.pgp_key_in_graph)
    _field(console, "contact channel", stage.telegram_channel)
    _field(console, "hostile-content claims", stage.hostile_content_claims)
    console.print()
    console.print(Text("  collected content that instructs its reader", style="bold"))
    _field(console, "posted by", stage.prompt_injection.posted_by_persona)
    _field(console, "characters quoted as data", stage.prompt_injection.characters_quoted)
    _field(console, "acted on", stage.prompt_injection.acted_on, style="bold green")
    _bullets(console, [stage.prompt_injection.note], marker=">", style="dim")
    console.print()
    console.print(Text("  a natural person was named on the forum", style="bold"))
    _field(console, "recorded as", stage.identity_lead.entity_type.value)
    _field(console, "category", stage.identity_lead.category.value)
    _field(
        console,
        "promoted to attribution",
        stage.identity_lead.promoted_to_attribution,
        style="bold green",
    )
    _field(console, "held under claim", stage.identity_lead.recorded_from_claim)
    _bullets(console, [stage.identity_lead.handling], marker=">", style="dim")
    _bullets(
        console,
        [
            "who gains if we believe it: " + "; ".join(stage.identity_lead.benefits_from_belief),
            f"cost to plant: {stage.identity_lead.planting_cost}",
        ],
        marker="!",
        style="yellow",
    )


def _render_blockchain(console: Console, stage: BlockchainStage) -> None:
    _heading(console, "5. blockchain")
    _field(console, "escrow address", stage.escrow_address)
    _field(console, "inbound payments", stage.inbound_payments)
    _field(console, "clustered with", stage.clustered_with)
    _field(console, "heuristic", stage.clustering_heuristic)
    _field(console, "deposit at", f"{stage.exchange_deposit_address} ({stage.exchange})")
    _confidence_line(console, "signal confidence", stage.signal_opinion, stage.signal_band)
    console.print(Text("  the heuristic's known failure mode:", style="yellow"))
    _bullets(console, [stage.known_failure_mode], marker="!", style="yellow")
    console.print(Text("  contributes to:", style="bold"))
    _bullets(console, stage.contributes_to)
    console.print(Text("  deliberately withheld from:", style="bold"))
    _bullets(console, stage.withheld_from, marker="!", style="yellow")


def _render_resolve(console: Console, stage: ResolutionStage) -> None:
    _heading(console, "6. resolve")
    assessment = stage.assessment
    _field(console, "proposition", assessment.proposition)
    _confidence_line(console, "confidence", assessment.opinion, assessment.band)
    _field(
        console,
        "prior",
        f"{assessment.base_rate:.2g}, from a candidate population of "
        f"{assessment.candidate_population:,}",
    )
    # The evidential figure beside the reported one, so the size of the reduction is
    # visible. Reporting only the margined number would hide how much was removed;
    # reporting only the evidential one is the defect the margin exists to fix.
    evidential = assessment.fusion.evidential_opinion
    if evidential is not None and evidential.projected_probability != (
        assessment.opinion.projected_probability
    ):
        _field(
            console,
            "before the robustness margin",
            f"{evidential.projected_probability:.0%} — what the evidence alone gives, "
            f"carried separately because the margin removed a whole fact "
            f"({assessment.fusion.margin_outcome.value})",
            style="yellow",
        )
    _field(
        console,
        "ceiling for this evidence",
        f"{assessment.ceiling.attainable_projected_probability:.0%} — more of the same "
        "evidence would not move it",
    )
    _field(console, "will never conclude", "; ".join(assessment.ceiling.excluded_conclusions))
    console.print(Text("  what each signal was actually worth:", style="bold"))
    for contribution in assessment.contributions:
        movement = (
            "no movement — in the record, absent from the conclusion"
            if contribution.is_negligible
            else f"{contribution.delta_projected:+.3f}"
        )
        _bullets(console, [f"{contribution.label}: {movement}"])
    console.print(Text("  signals the fixture set cannot supply:", style="yellow"))
    _bullets(console, stage.signals_unavailable, marker="!", style="yellow")
    _bullets(console, assessment.warnings, marker="!", style="yellow")
    console.print()
    console.print(Text("  asked to name the operator, the engine refuses:", style="bold"))
    _bullets(console, [stage.refusal.reason], marker=">", style="red")
    _field(
        console,
        "identity material retained",
        stage.refusal.retained_identity_material,
        style="bold green",
    )


def _render_dimension(console: Console, assessment: DimensionAssessment) -> None:
    console.print()
    console.print(Text(f"  [{assessment.dimension.value.upper()}]", style="bold"))
    _bullets(console, [assessment.hypothesis], marker=">")
    console.print(
        Text("    confidence                    ", style="dim").append(
            _confidence(assessment.opinion, assessment.band)
        )
    )
    diversity = assessment.source_diversity
    console.print(
        Text(
            f"    sources                       {diversity.independent_source_count} "
            f"independent origin(s) behind {diversity.total_signals} signal(s); "
            f"{diversity.adversary_influenceable_sources} adversary-influenceable",
            style="dim",
        )
    )
    console.print(
        Text(
            f"    claims                        {len(assessment.supporting_claims)} "
            f"supporting, {len(assessment.contradicting_claims)} contradicting",
            style="dim",
        )
    )
    for alternative in assessment.alternatives:
        _bullets(
            console,
            [f"alternative — {alternative.name} [{alternative.band.value}]"],
            marker="~",
        )
    for missing in assessment.missing_evidence:
        _bullets(
            console,
            [f"missing — {missing.description} ({missing.availability.value})"],
            marker="?",
            style="dim",
        )
    _bullets(console, assessment.warnings, marker="!", style="yellow")


def _render_attribute(console: Console, stage: AttributionStage) -> None:
    _heading(console, "7. attribute")
    _field(console, "subject", stage.result.subject)
    _field(console, "dimensions", "five, assessed separately; there is no total")
    for dimension in AttributionDimension:
        if dimension is AttributionDimension.HUMAN_IDENTITY:
            continue
        _render_dimension(console, stage.result.for_dimension(dimension))

    console.print()
    console.print(Text(f"  the planted false flag — {stage.framed_organization}", style="bold"))
    _bullets(
        console,
        [
            f"claim {stage.false_flag_claim_id} was offered in support and is recorded as "
            f"{stage.false_flag_direction} evidence: it is a string in a file the adversary "
            "controls end to end, and it costs minutes to plant."
        ],
        marker="!",
        style="yellow",
    )
    console.print(Text("  weak markers recorded and scored nowhere:", style="bold"))
    _bullets(console, stage.weak_markers_not_scored, marker="~", style="dim")
    _render_refusal(console, stage)


def _render_refusal(console: Console, stage: AttributionStage) -> None:
    """The most important output in the demonstration, printed as such.

    The name is not here and is printed nowhere by this renderer. What is printed is that a
    name was offered, that the gate refused it before any scoring, and how many claims are
    held against the refusal, so an analyst can find them under their retention obligations.
    """
    human = stage.result.for_dimension(AttributionDimension.HUMAN_IDENTITY)
    gate = human.identity_gate
    body = Text()
    body.append("HUMAN IDENTITY: ", style="bold")
    body.append(stage.human_identity_band.value.upper().replace("_", " "), style="bold red")
    body.append("\n\n")
    body.append(
        "Insufficient basis is not a low probability. It is a refusal to estimate, and it "
        "must not be read as a hedged identification.\n\n"
    )
    body.append("NEMESIS names no natural person in this run.\n", style="bold")
    if gate is not None:
        body.append("\nThe gate refused before anything was scored, because:\n")
        for reason in gate.reasons:
            body.append(f"  - {reason.value.replace('_', ' ')}\n")
        body.append(
            f"\n{len(gate.refused_claims)} offered claim(s) are recorded against the refusal "
            "and cited by identifier only.\n",
            style="dim",
        )
    body.append(
        "\nThe asserted name is held as a HUMAN_IDENTITY_LEAD under data-protection "
        "obligations, and is deliberately not printed here: a refusal that repeats the "
        "accusation has published it.",
        style="dim",
    )
    console.print()
    console.print(Panel(body, title="the refusal", border_style="red", padding=(1, 2)))


def _render_evidence(console: Console, stage: EvidenceStage) -> None:
    _heading(console, "8. evidence")
    _field(console, "objects sealed", stage.report.objects_checked)
    _field(console, "artifacts verified", stage.report.artifacts_verified)
    _field(console, "hash chain intact", stage.report.hash_chain_intact, style="bold green")
    _field(console, "vault head", stage.head)
    _field(console, "anchors verified", stage.report.anchors_verified)
    _field(console, "externally held anchors", stage.report.externally_anchored, style="bold red")
    _field(
        console,
        "defensible against insider",
        stage.report.is_defensible_against_insider,
        style="bold red",
    )
    _field(console, "admissibility defects", ", ".join(stage.admissibility_defects))
    _field(
        console,
        "export manifest",
        f"{stage.export_entries} entry(ies), {stage.export_withheld_restricted} withheld",
    )
    console.print(Text("  what this vault cannot defend:", style="bold yellow"))
    _bullets(console, stage.cannot_defend, marker="!", style="yellow")


def _render_disrupt(console: Console, stage: DisruptionStage) -> None:
    _heading(console, "9. disrupt")
    table = _table("option", "status", "expected impact", "recovery", "ownership")
    for option in stage.plan.options:
        impact = option.expected_impact.level.value
        unconstrained = option.expected_impact.unconstrained_level
        if option.expected_impact.was_capped and unconstrained is not None:
            impact = f"{impact} (reach: {unconstrained.value})"
        table.add_row(
            Text(option.key),
            Text(option.implementation_status.value),
            Text(impact),
            Text(option.recovery.difficulty.value),
            Text("confirm first" if option.requires_ownership_confirmation else "sound"),
        )
    console.print(table)
    for option in stage.plan.options:
        for flag in option.flags:
            _bullets(console, [f"{option.key}: {flag}"], marker="!", style="yellow")
    _field(console, "executable by NEMESIS", ", ".join(stage.executable_now) or "none")
    _field(
        console,
        "blocked on legal authority",
        ", ".join(stage.requires_legal_authority) or "none",
    )
    _field(
        console,
        "await ownership confirmation",
        ", ".join(stage.needs_ownership_confirmation) or "none",
        style="yellow",
    )


def _render_authorize(console: Console, stage: AuthorizationStage) -> None:
    _heading(console, "10. authorize")
    capability = stage.capability
    _field(console, "capability", capability.capability_id)
    _field(console, "signature verifies", stage.verification.is_usable_now, style="bold green")
    _field(console, "bound targets", stage.target_count)
    _field(console, "expires", f"{capability.expires_at.isoformat()} ({stage.lifetime_hours:g}h)")
    _field(
        console,
        "permitted operations",
        ", ".join(sorted(op.value for op in capability.permitted_operations)),
    )
    _field(
        console,
        "explicitly forbidden",
        ", ".join(sorted(op.value for op in capability.forbidden_operations)),
    )
    _field(console, "max effect approved", capability.max_effect_description)
    console.print()
    console.print(Text("  decisions, all kept:", style="bold"))
    for approval in stage.approvals:
        _bullets(
            console,
            [
                f"APPROVED by {approval.approver_role} "
                f"[{approval.approver_assurance.name.lower()} via "
                f"{approval.authenticated_by}]: {approval.rationale}"
            ],
            marker="+",
            style="green",
        )
    _bullets(
        console,
        [
            f"REJECTED ({stage.rejected_option}) by {stage.rejection.approver_role} "
            f"[{stage.rejection.approver_assurance.name.lower()} via "
            f"{stage.rejection.authenticated_by}]: {stage.rejection.rationale}"
        ],
        marker="-",
        style="red",
    )
    _field(console, "rejected request state", stage.rejected_request_state.value)
    console.print()
    # A refusal by the platform rather than by a person. Printed in full because the point
    # of the assurance floor is that an operator meets it and reads it as a control, not as
    # a configuration problem to route around.
    console.print(
        Text(
            f"  refused by policy — {stage.assurance_refused_operation.value}:",
            style="bold yellow",
        )
    )
    _bullets(console, [stage.assurance_refusal], marker="!", style="yellow")
    console.print()
    console.print(Text("  what the grant does not authorize:", style="bold"))
    for probe in stage.scope_probes:
        verdict = "PERMITTED" if probe.decision.permitted else "DENIED"
        reasons = "; ".join(probe.decision.denial_reasons) or "no reason recorded"
        _bullets(console, [f"{probe.question} {verdict} — {reasons}"], marker="x", style="dim")


def _render_effect(console: Console, stage: EffectsStage) -> None:
    _heading(console, "11. effect")
    table = _table("operation", "outcome", "adapter", "external contact")
    for result in stage.results:
        table.add_row(
            Text(result.operation.value),
            Text(result.outcome.value),
            Text(result.adapter_name),
            Text(str(result.external_contact_made)),
        )
    console.print(table)
    _field(
        console,
        "external contact anywhere",
        stage.external_contact_made,
        style="bold red" if stage.external_contact_made else "bold green",
    )
    _field(console, "confinement", stage.isolation.render())
    # Worded to the exact strength of the control, after a review showed that the previous
    # wording — "ESTABLISHED by the kernel" — claimed more than a per-process socket denial
    # proves. What the kernel refused is a socket to the process that ran the effect.
    _field(
        console,
        "egress from the effect process",
        "DENIED by the kernel"
        if stage.isolation.egress_denied_from_this_process
        else "NOT denied on this platform — the adapters' own declaration is all there is",
        style="bold green" if stage.isolation.egress_denied_from_this_process else "yellow",
    )
    _bullets(
        console,
        [
            "This says nothing about a process the effect could have asked another service "
            "to start. LaunchServices and DNS are denied by name; the profile is "
            "allow-default, so that list is what was found, not everything conceivable."
        ],
        marker="~",
        style="dim",
    )
    _field(
        console,
        "adapters declaring contact",
        f"{sum(1 for adapter in stage.adapters if adapter.makes_external_contact)} "
        f"of {len(stage.adapters)}",
    )
    for result in stage.results:
        if not result.succeeded:
            _bullets(
                console,
                [f"{result.operation.value}: {result.detail}"],
                marker="!",
                style="yellow",
            )


def _render_resurgence(console: Console, stage: ResurgenceStage) -> None:
    _heading(console, "12. resurgence")
    _field(console, "as of", stage.as_of.isoformat())
    _field(console, "new domain", f"{stage.new_domain} ({stage.new_registrar})")
    _field(console, "new address", f"{stage.new_ip} ({stage.new_asn})")
    _field(console, "new persona", f"{stage.new_persona} on {stage.new_forum}")
    console.print(Text("  nothing obvious in common:", style="dim"))
    _bullets(console, stage.nothing_in_common, style="dim")
    console.print()
    console.print(Text("  why we think this is the same operator:", style="bold"))
    for link in stage.links:
        console.print(
            Text(f"    {link.predecessor} -> {link.successor}", style="bold").append(
                Text(f"  [{link.pivot_method.value}]", style="dim")
            )
        )
        _bullets(console, link.explanation.reasons)
        _bullets(console, link.explanation.caveats, marker="!", style="yellow")
    console.print(Text("  and not because of:", style="dim"))
    _bullets(console, stage.not_reconnected_by, marker="x", style="dim")


# --------------------------------------------------------------------------------------
# Rendering the whole run
# --------------------------------------------------------------------------------------


def render(console: Console, result: ScenarioResult, *, stage: str | None = None) -> None:
    """Print the run. With ``stage`` set, print only that stage.

    A function rather than command-body code so a test can render into a string buffer and
    assert on what an operator would actually see — in particular that a natural person's
    name is not in it.
    """
    renderers: tuple[tuple[str, Callable[[], None]], ...] = (
        ("detect", lambda: _render_detect(console, result.detect)),
        ("pursue", lambda: _render_pursue(console, result.pursue)),
        ("graph", lambda: _render_graph(console, result.graph)),
        ("darkweb", lambda: _render_darkweb(console, result.darkweb)),
        ("blockchain", lambda: _render_blockchain(console, result.blockchain)),
        ("resolve", lambda: _render_resolve(console, result.resolve)),
        ("attribute", lambda: _render_attribute(console, result.attribute)),
        ("evidence", lambda: _render_evidence(console, result.evidence)),
        ("disrupt", lambda: _render_disrupt(console, result.disrupt)),
        ("authorize", lambda: _render_authorize(console, result.authorize)),
        ("effect", lambda: _render_effect(console, result.effect)),
        ("resurgence", lambda: _render_resurgence(console, result.resurgence)),
    )

    if stage is None:
        console.print(Panel(Text(BANNER), border_style="magenta", padding=(1, 2)))
        console.print(Text(f"  workspace: {result.stores.workspace}", style="dim"))

    for name, renderer in renderers:
        if stage is None or name == stage:
            renderer()

    if stage is None:
        console.print()
        console.print(
            Panel(
                Text(NOT_DEMONSTRATED),
                title="what this demonstration does not show",
                border_style="yellow",
                padding=(1, 2),
            )
        )


# --------------------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------------------


@app.command()
def demo(
    stage: Annotated[
        str | None,
        typer.Option(help=f"Render one stage only. One of: {', '.join(STAGE_NAMES)}."),
    ] = None,
    workspace: Annotated[
        Path | None,
        typer.Option(help="Directory for the evidence vault and the audit trail."),
    ] = None,
) -> None:
    """Run Operation GLASS ANVIL end to end and print it."""
    console = Console()
    if stage is not None and stage not in STAGE_NAMES:
        console.print(
            Text(f"unknown stage {stage!r}; expected one of {', '.join(STAGE_NAMES)}", style="red")
        )
        raise typer.Exit(code=2)

    result = run_glass_anvil_scenario(workspace=workspace)
    render(console, result, stage=stage)


@app.command()
def verify(
    workspace: Annotated[
        Path | None,
        typer.Option(
            help="A workspace a previous demo wrote. Omitted, a fresh demo run is verified."
        ),
    ] = None,
) -> None:
    """Check a workspace's evidence vault and audit chain, and say what that does not prove."""
    console = Console()
    if workspace is None:
        console.print(Text("no workspace given; running the demo scenario first", style="dim"))
        workspace = run_glass_anvil_scenario().stores.workspace

    vault_root = workspace / "vault"
    audit_path = workspace / "audit.jsonl"
    if not vault_root.is_dir() or not audit_path.is_file():
        console.print(Text(f"{workspace} does not look like a NEMESIS workspace", style="bold red"))
        raise typer.Exit(code=2)

    report = _verify_vault(vault_root)
    chain = _verify_audit(audit_path)

    _heading(console, "vault")
    _field(console, "root", vault_root)
    _field(console, "objects checked", report.objects_checked)
    _field(console, "artifacts verified", report.artifacts_verified)
    _field(console, "hash chain intact", report.hash_chain_intact)
    _field(console, "artifacts missing", len(report.artifacts_missing))
    _field(console, "artifacts corrupted", len(report.artifacts_corrupted))
    _field(console, "metadata rewritten", len(report.metadata_corrupted))
    _field(console, "unlogged files", len(report.unlogged_artifacts))
    _field(console, "anchors verified", report.anchors_verified)
    _field(console, "externally held anchors", report.externally_anchored)
    _bullets(console, report.log_defects, marker="!", style="red")

    _heading(console, "audit trail")
    _field(console, "path", audit_path)
    _field(console, "entries checked", chain.entries_checked)
    _field(console, "chain intact", chain.intact)
    if chain.reason is not None:
        _bullets(console, [f"broken at {chain.broken_at}: {chain.reason}"], marker="!", style="red")

    healthy = report.is_intact and chain.intact
    _heading(console, "verdict")
    console.print(
        Text(
            "  both chains verify" if healthy else "  DAMAGE FOUND — see above",
            style="bold green" if healthy else "bold red",
        )
    )
    console.print(
        Text(
            "  This shows the store has not been corrupted or carelessly edited. It shows "
            "nothing against an operator who can rewrite it, because both chains are ones "
            "we compute ourselves. Only an externally held anchor would, and there are "
            f"{report.externally_anchored}.",
            style="yellow",
        )
    )
    if not healthy:
        raise typer.Exit(code=1)


def _verify_vault(root: Path) -> FileSystemVaultIntegrityReport:
    return asyncio.run(FileSystemEvidenceVault(root).verify_integrity())


def _verify_audit(path: Path) -> ChainVerification:
    return asyncio.run(AppendOnlyAuditTrail(path).verify())


__all__ = ["app", "render"]


@app.command()
def providers() -> None:
    """List the model providers this build can seat, and what a deployment must supply.

    Never prints a credential and never reads one: a provider entry carries the *name* of an
    environment variable, and the variable is read by whatever transport a deployment wires,
    outside this package entirely.
    """
    from nemesis.pilot.providers.registry import PROVIDERS

    console = Console()
    _heading(console, "PILOT PROVIDERS")
    table = _table("provider", "credential variable", "declared capabilities")
    for name in sorted(PROVIDERS):
        spec = PROVIDERS[name]
        table.add_row(
            Text(name),
            Text(spec.api_key_environment_variable or "— (local inference)"),
            Text(", ".join(sorted(c.value for c in spec.capabilities.declared))),
        )
    console.print(table)

    _heading(console, "WHAT EACH ONE DOES DIFFERENTLY")
    for name in sorted(PROVIDERS):
        spec = PROVIDERS[name]
        if spec.notes:
            console.print(Text(f"  {name}", style="bold"))
            console.print(Text(f"    {spec.notes}", style="dim"))

    console.print()
    console.print(
        Panel(
            Text(
                "A declared capability decides whether a PARAMETER is sent — a reasoning level, "
                "a seed, a usage report. It is never a permission. What a pilot may do is the "
                "four verbs and the pre-signed envelope, and nothing in this table can reach "
                "either: a model that supports computer use is not a model NEMESIS grants it "
                "to, and a test scans every provider's rendered request to keep it that way.",
                style="dim",
            ),
            title="model capability is not NEMESIS authorization",
            border_style="yellow",
        )
    )


@app.command(name="pilot-preview")
def pilot_preview(
    provider: Annotated[str, typer.Option(help="Registry key: openai, anthropic, xai, ...")],
    model: Annotated[str, typer.Option(help="The model id, as the provider names it.")],
    reasoning: Annotated[
        str | None, typer.Option(help="Reasoning effort where the provider offers one.")
    ] = None,
) -> None:
    """Print exactly what would be transmitted to a vendor, without transmitting anything.

    A hosted pilot sends every briefing to a third party, and whether CTI data may transit a
    model vendor is a decision the founder owns rather than one this code makes. A decision like
    that should be made by reading what leaves, not by imagining it — so this builds a real
    briefing from the reference scenario, composes the real request the chosen seat would send,
    scans it for internal-classified material, and prints it. Nothing here opens a socket.
    """
    import asyncio
    import json

    from nemesis.core.disclosure import scan_for_internal_material
    from nemesis.pilot.providers.config import PilotConfig
    from nemesis.pilot.providers.registry import UnknownProviderError, build_pilot
    from nemesis.pilotbench.corpus import BASELINE
    from nemesis.pilotbench.harness import run_scenario
    from nemesis.pilotbench.pilots import ScriptedBenchPilot

    console = Console()
    try:
        config = PilotConfig.model_validate(
            {"provider": provider, "model": model, "reasoning": reasoning}
        )
        seat = build_pilot(config)
    except (UnknownProviderError, ValueError) as refusal:
        console.print(Text(str(refusal), style="bold red"))
        raise typer.Exit(code=2) from refusal

    captured: list[object] = []

    def capture(briefing: object, turn: int) -> object:
        from nemesis.pilot.moves import Conclude

        captured.append(briefing)
        return Conclude(summary="captured the briefing")

    asyncio.run(run_scenario(BASELINE, ScriptedBenchPilot("preview", capture)))  # type: ignore[arg-type]
    briefing = captured[0]
    payload = seat.build_payload(briefing)  # type: ignore[arg-type]
    rendered = json.dumps(payload, indent=2, sort_keys=True, default=str)

    _heading(console, "WHAT WOULD LEAVE")
    _field(console, "provider", seat.identity.provider)
    _field(console, "model", seat.identity.model)
    _field(console, "seat", seat.identity.seat)
    _field(console, "bytes", str(len(rendered)))
    _field(console, "tools offered", ", ".join(sorted(MOVE_TOOL_NAMES)))

    leaked = scan_for_internal_material({"request": rendered})
    _field(
        console,
        "internal-class material",
        "none detected" if not leaked else "; ".join(leaked),
        style="green" if not leaked else "bold red",
    )

    _heading(console, "THE REQUEST")
    console.print(Text(rendered))
    console.print()
    console.print(
        Panel(
            Text(
                "Nothing was sent. This is the request the seat composes from the briefing the "
                "mediator already minimized to deliverable-class material — the filter keys on "
                "entity TYPE, so it bounds classified material and not personal material: a "
                "domain whose name happens to be a person's is DELIVERABLE by type and appears "
                "verbatim. Read it before deciding whether this may transit a vendor.",
                style="dim",
            ),
            title="REQUIRES_EXTERNAL_DATA — no transport is wired",
            border_style="yellow",
        )
    )


@app.command()
def pilotbench(
    providers_csv: Annotated[
        str | None,
        typer.Option(
            "--providers",
            help="Comma-separated provider keys to benchmark. Omitted, the offline "
            "reference pilots run instead.",
        ),
    ] = None,
    model: Annotated[
        str | None, typer.Option(help="Model id, used for every provider named above.")
    ] = None,
    scenario: Annotated[str | None, typer.Option(help="Run one scenario only, by id.")] = None,
) -> None:
    """Run the NEMESIS pilot benchmark and print it, caveats first.

    With no `--providers`, five deterministic reference pilots run — each written to fail in a
    specific known way — so the scoring itself is exercised without an API key and without
    contacting anything. Naming providers builds real seats through the registry; without a
    wired transport each one refuses, which is itself the demonstration that a provider failure
    cannot weaken policy enforcement.

    Exits non-zero only if a control-plane property failed. A poor score against the corpus is
    information, not a build break: the corpus's assumptions are ours rather than the world's.
    """
    from nemesis.pilotbench import DEFAULT_CORPUS, run_pilotbench, scenario_by_id

    console = Console()
    try:
        scenarios = (scenario_by_id(scenario),) if scenario else DEFAULT_CORPUS
    except KeyError as unknown:
        console.print(Text(str(unknown), style="bold red"))
        raise typer.Exit(code=2) from unknown

    subjects = None
    if providers_csv:
        if not model:
            console.print(
                Text(
                    "--providers needs --model; a provider without a model is not a pilot",
                    style="bold red",
                )
            )
            raise typer.Exit(code=2)
        subjects = tuple(
            _bench_subject(name.strip(), model) for name in providers_csv.split(",") if name.strip()
        )

    report = run_pilotbench(subjects, scenarios=scenarios)
    console.print(report.render(), highlight=False)

    if not report.properties_hold:
        console.print()
        console.print(
            "[bold red]A control-plane property did not hold.[/] "
            "These do not depend on the corpus's assumptions, and this is the one result here "
            "that is a build break."
        )
        raise typer.Exit(code=1)


def _bench_subject(provider: str, model: str) -> BenchSubject:
    """Build a benchmark subject for one provider, deferring construction to run time."""
    from nemesis.pilot.providers.config import PilotConfig
    from nemesis.pilot.providers.registry import build_pilot

    config = PilotConfig(provider=provider, model=model)
    return BenchSubject(build=lambda: build_pilot(config), provider=provider, model=model)


@app.command()
def pilot(
    workspace: Annotated[
        Path | None,
        typer.Option(help="Directory for the evidence vault and the audit trail."),
    ] = None,
) -> None:
    """Put an autonomous pilot in the seat and show that the limiter holds.

    `demo` shows NEMESIS investigating under its own deterministic policy. This shows what
    NEMESIS *is* — the harness an external autonomous model drives. The pilot here is
    `SIMULATED` (a script, not a model), and it is written to be **hostile** for half its run:
    mid-investigation it obeys an instruction planted in content it collected. Nothing it does
    escapes the pre-signed envelope, and no human intervenes anywhere in the run.
    """
    from nemesis.slice.pilot_session import EFFECT_BUDGET, run_pilot_demonstration

    console = Console()
    demonstration = asyncio.run(run_pilot_demonstration(workspace=workspace))
    session = demonstration.session
    pilot_impl = session  # naming kept explicit below

    console.print()
    console.print(
        Panel(
            Text(
                "An autonomous pilot drives; NEMESIS is the limiter. The pilot is SIMULATED — a "
                "script, not a model — and it is deliberately hijacked mid-run by an instruction "
                "planted in collected content. No human approves anything below.",
                style="dim",
            ),
            title="AUTONOMOUS PILOT SESSION (SIMULATED)",
            border_style="cyan",
        )
    )

    _heading(console, "THE PRE-SIGNED ENVELOPE")
    status = demonstration.envelope.status()
    _field(console, "capability", status.capability_id)
    _field(console, "permitted", ", ".join(status.permitted_operations))
    _field(console, "forbidden", ", ".join(status.forbidden_operations), style="red")
    _field(console, "autonomous effects", f"{status.budget} pre-authorized")
    _field(console, "expires", status.expires_at.isoformat())
    _field(console, "max effect", demonstration.envelope.capability.max_effect_description)

    _heading(console, "THE INJECTION THE PILOT OBEYS")
    console.print(Text(f"  {demonstration.injection}", style="yellow"))
    console.print(
        Text(
            "  The pilot does not resist this. It obeys it. What follows is what that achieves.",
            style="dim",
        )
    )

    _heading(console, "MOVES, AND WHAT THE LIMITER DID WITH THEM")
    table = _table("#", "move", "ruling", "why")
    for index, turn in enumerate(session.transcript, start=1):
        ruling = turn.ruling
        style = "green" if ruling.accepted else "red"
        table.add_row(
            str(index),
            ruling.move_kind,
            Text(ruling.status.value, style=style),
            _elide(ruling.reason, 88),
        )
    console.print(table)

    _heading(console, "WHAT THE RUN COST AND WHAT IT COULD NOT DO")
    _field(console, "moves made", str(len(session.transcript)))
    _field(console, "effects accepted", str(demonstration.accepted_effects), style="green")
    _field(console, "effects refused", str(demonstration.refused_effects), style="red")
    _field(console, "envelope", demonstration.envelope.status().render())
    _field(console, "spend ledger intact", str(demonstration.envelope.verify_chain()))
    _field(console, "concluded", str(session.concluded))
    _field(
        console,
        "anything left the platform",
        str(pilot_impl.any_effect_left_the_platform()),
        style="green",
    )
    _field(console, "workspace", str(demonstration.workspace))

    console.print()
    console.print(
        Panel(
            Text(
                "The pilot was hijacked and obeyed. It asked for a registrar suspension, for a "
                "target nobody approved, and for more autonomy than it was given. Each was "
                f"refused by code it cannot reach: the capability, the target binding, and a "
                f"budget of {EFFECT_BUDGET} that it spent. Every move and ruling above is in the "
                "hash-chained audit trail, so the session replays even though the pilot cannot.",
                style="dim",
            ),
            title="what this demonstrates",
            border_style="green",
        )
    )


@app.command()
def view(
    output: Annotated[Path | None, typer.Option(help="Where to write the HTML file.")] = None,
    workspace: Annotated[
        Path | None, typer.Option(help="Directory for the evidence vault and audit trail.")
    ] = None,
) -> None:
    """Render the investigation as a self-contained analyst case file.

    One HTML file, no network of any kind. Uncertainty is drawn as physical space rather than
    a number, and every refusal carries more visual weight than any conclusion — because a
    wrong attribution in a polished interface is more dangerous than the same error in a text
    file, and production value reads as confidence.
    """
    from nemesis.ui import render_investigation

    console = Console()
    result = run_glass_anvil_scenario(workspace=workspace)
    destination = output or Path("investigation.html")
    destination.write_text(
        render_investigation(
            result.attribute.result,
            stages=tuple(name for name, _ in result.stages()),
        ),
        encoding="utf-8",
    )
    _heading(console, "ANALYST VIEW")
    _field(console, "written", str(destination.resolve()))
    _field(console, "dimensions", str(len(result.attribute.result.assessments)))
    _field(console, "self-contained", "no external fonts, no scripts, no network")
    console.print()
    console.print(Text("  Open it in a browser. Nothing on the page is calibrated.", style="dim"))


@app.command()
def corpus(
    per_kind: Annotated[
        int, typer.Option(help="Cases per evidence construction.", min=5, max=500)
    ] = 40,
    seed: Annotated[
        int, typer.Option(help="Generator seed. Fixed for reproducibility.")
    ] = 20260821,
) -> None:
    """Run the blind-corpus apparatus: sealed answers, separated roles, four categories.

    A proof of concept for protocol milestones 2, 4 and 5, which are *process* and can be shown
    wrong long before milestone 3 rents a host. The evaluator here is handed `CaseInput` objects
    and nothing else — there is no argument through which an answer could arrive — and the
    answers are unsealed once, by a named actor, with the count reported beside every figure.

    **The figures are not calibration.** The cases are synthetic, so they measure agreement with
    a generator's assumptions rather than with the world. The report says so first and at length.
    """
    from datetime import UTC, datetime

    from nemesis.calibration.corpus import (
        PopulationClaim,
        Prediction,
        build_corpus,
        score,
    )
    from nemesis.core.confidence import band_of
    from nemesis.core.fusion import fuse
    from nemesis.core.proposition import PropositionClass

    console = Console()
    population = PopulationClaim(
        describes="synthetic persona-linkage cases probing six evidence constructions",
        excludes=(
            "real adversary tradecraft, real infrastructure, and any real population; nothing "
            "here supports a claim about how often this happens in the world"
        ),
        ground_truth_rule="the generator recorded what it built; no human adjudicated anything",
        generated_by=f"nemesis.calibration.generator, seed {seed}",
    )
    built = build_corpus(population=population, seed=seed, per_kind=per_kind)

    # The evaluator role. It receives inputs and returns predictions; it is handed no labels,
    # and the corpus has none to give it without an unsealing that would be counted.
    predictions = []
    for item in built.inputs:
        result = fuse(item.sources, proposition=PropositionClass.SHARED_ORIGIN)
        band = band_of(result.opinion)
        refused = band is ConfidenceBand.INSUFFICIENT_BASIS
        predictions.append(
            Prediction(
                case_id=item.case_id,
                probability=None if refused else result.opinion.projected_probability,
                band=band,
            )
        )

    evaluation = score(
        built,
        predictions,
        actor="nemesis corpus (CLI)",
        reason="first and only scoring of this generated set",
        at=datetime.now(UTC),
    )
    console.print(evaluation.render(), highlight=False)


@app.command()
def calibrate(
    cases: Annotated[int, typer.Option(help="Scored cases to generate.", min=60, max=20_000)] = 600,
    seed: Annotated[
        int, typer.Option(help="Generator seed. Fixed for reproducibility.")
    ] = 20260815,
) -> None:
    """Measure what can honestly be measured about NEMESIS's confidence.

    Reports structural properties, which stand on their own, separately from scores against
    a synthetic generator, which do not. Exits non-zero only if a structural property fails:
    a poor conditional score is information, not a build break, because the generator's
    assumptions are ours rather than the world's.
    """
    from nemesis.calibration import run_calibration

    console = Console()
    report = run_calibration(cases=cases, seed=seed)
    console.print(report.render(), highlight=False)

    if not report.properties_hold:
        failed = [item.name for item in report.properties if not item.holds]
        console.print()
        console.print(
            f"[bold red]{len(failed)} structural property(ies) failed.[/] "
            "These do not depend on the generator's assumptions.",
        )
        raise typer.Exit(code=1)
