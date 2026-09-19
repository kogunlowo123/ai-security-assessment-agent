"""Markdown report renderer."""

from __future__ import annotations

from aisa.catalog import OWASP_LLM, STRIDE
from aisa.models import AssessmentReport, Finding, Severity

_DISCLAIMER = (
    "This report is generated from a declared system manifest. It measures the controls and "
    "architecture the manifest states, not what is deployed, and it does not replace a penetration "
    "test or an independent audit. Framework identifiers should be verified against the current "
    "published OWASP, NIST and MITRE texts before they are cited."
)


def _cell(text: str) -> str:
    """Make user-controlled text safe inside a Markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")


def _finding(finding: Finding) -> list[str]:
    refs: list[str] = []
    if finding.owasp:
        refs.append(
            "OWASP " + ", ".join(f"{o} {OWASP_LLM.get(o, '')}".strip() for o in finding.owasp)
        )
    if finding.stride:
        refs.append("STRIDE " + ", ".join(STRIDE.get(s, s) for s in finding.stride))
    if finding.nist:
        refs.append("NIST AI RMF " + ", ".join(finding.nist))
    if finding.atlas:
        refs.append("ATLAS " + ", ".join(finding.atlas))
    lines = [
        f"#### {finding.id}: {_cell(finding.title)}",
        "",
        f"Severity: **{finding.severity.value}**. Category: {finding.category}.",
        "",
        finding.description,
        "",
    ]
    if refs:
        lines += [f"- Mapping: {'; '.join(refs)}"]
    lines += [f"- Evidence: {_cell(e)}" for e in finding.evidence]
    lines += [f"- Recommendation: {finding.recommendation}", ""]
    return lines


def render(report: AssessmentReport) -> str:
    """Render ``report`` as a Markdown document."""
    counts = report.counts()
    out: list[str] = [
        f"# AI security assessment: {_cell(report.system)}",
        "",
        f"Generated {report.generated_at.isoformat()} by aisa {report.tool_version}. "
        f"Overall rating: **{report.rating}**. Posture score: **{report.posture_score}/100**.",
        "",
        "## Executive summary",
        "",
        _cell(report.executive_summary),
        "",
        "## Scorecard",
        "",
        "| Severity | Findings |",
        "| --- | --- |",
        *[f"| {sev.value} | {counts[sev.value]} |" for sev in Severity],
        "",
        "## Findings",
        "",
    ]
    if not report.findings:
        out += ["No findings.", ""]
    for severity in Severity:
        group = [f for f in report.findings if f.severity is severity]
        if group:
            out += [f"### {severity.value.capitalize()}", ""]
            for finding in group:
                out += _finding(finding)

    out += [
        "## Threat model (STRIDE)",
        "",
        "| Id | STRIDE | Severity | Threat | Targets | ATLAS |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for t in report.threats:
        out.append(
            f"| {t.id} | {STRIDE.get(t.stride, t.stride)} | {t.severity.value} | {_cell(t.title)} | "
            f"{_cell(', '.join(t.targets))} | {', '.join(t.atlas) or '-'} |"
        )
    if not report.threats:
        out.append("| - | - | - | No threats derived | - | - |")

    out += [
        "",
        "## NIST AI RMF control coverage",
        "",
        "| Function | Coverage | Implemented | Gaps |",
        "| --- | --- | --- | --- |",
    ]
    for name, cov in report.compliance.functions.items():
        gaps = ", ".join(g.control for g in cov.gaps) or "none"
        out.append(
            f"| {name} | {cov.score:.0%} | {cov.controls_implemented}/{cov.controls_total} | {gaps} |"
        )
    out += [
        "",
        f"Overall coverage: {report.compliance.overall:.0%}.",
        "",
        "## Assessment scope",
        "",
    ]
    out += [f"- Frameworks: {', '.join(report.plan.frameworks)}"]
    out += [
        f"- Checks run: {len(report.plan.checks)}; passed: {', '.join(report.passed_checks) or 'none'}"
    ]
    out += [f"- Skipped {cid}: {reason}" for cid, reason in report.plan.skipped.items()]
    profile = report.profile
    out += [
        f"- Components: {profile.component_count}; internet-facing: {', '.join(profile.internet_facing) or 'none'}; "
        f"exposed: {', '.join(profile.exposed) or 'none'}",
        "",
        "## Assessment quality",
        "",
        "Evaluator: " + ("passed" if report.evaluation.passed else "FAILED"),
    ]
    out += [f"- {i.severity}: {_cell(i.message)}" for i in report.evaluation.issues]
    out += ["", "## Notice", "", _DISCLAIMER, ""]
    return "\n".join(out)
