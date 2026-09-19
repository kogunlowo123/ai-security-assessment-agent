"""Compliance agent: scores control coverage against the NIST AI RMF functions."""

from __future__ import annotations

from aisa.agents.state import AssessmentState
from aisa.catalog import CONTROLS, NIST_FUNCTIONS, nist_function
from aisa.models import (
    ComplianceSummary,
    ControlGap,
    ControlStatus,
    FunctionCoverage,
    SystemManifest,
)


def summarize_compliance(manifest: SystemManifest) -> ComplianceSummary:
    """Compute per-function coverage from the declared control statuses.

    Every catalogued control counts, whether or not a check was planned for it, because framework
    coverage is about which safeguards exist, not which risks the architecture happens to trigger.
    """
    functions: dict[str, FunctionCoverage] = {}
    for function in NIST_FUNCTIONS:
        mapped = {
            control: [ref for ref in spec.nist if nist_function(ref) == function]
            for control, spec in CONTROLS.items()
            if any(nist_function(ref) == function for ref in spec.nist)
        }
        statuses = {control: manifest.status_of(control) for control in mapped}
        total = len(statuses)
        score = sum(s.credit for s in statuses.values()) / total if total else 0.0
        gaps = [
            ControlGap(control=c, status=s.value, nist=mapped[c])
            for c, s in statuses.items()
            if s is not ControlStatus.IMPLEMENTED
        ]
        functions[function] = FunctionCoverage(
            score=round(score, 3),
            controls_total=total,
            controls_implemented=sum(
                1 for s in statuses.values() if s is ControlStatus.IMPLEMENTED
            ),
            gaps=gaps,
        )
    scores = [f.score for f in functions.values() if f.controls_total]
    return ComplianceSummary(
        functions=functions, overall=round(sum(scores) / len(scores), 3) if scores else 0.0
    )


class ComplianceAgent:
    """Workflow node that populates ``state.compliance``."""

    def run(self, state: AssessmentState) -> AssessmentState:
        state.compliance = summarize_compliance(state.manifest)
        parts = ", ".join(
            f"{name} {cov.score:.0%}" for name, cov in state.compliance.functions.items()
        )
        state.note = f"overall {state.compliance.overall:.0%} ({parts})"
        return state
