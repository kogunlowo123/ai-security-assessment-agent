"""Evaluator agent: quality-gates the assessment itself before it is reported."""

from __future__ import annotations

from aisa.agents.state import AssessmentState
from aisa.catalog import CONTROL_IDS, NIST_FUNCTIONS, OWASP_LLM, nist_function
from aisa.checks import CheckRegistry
from aisa.models import EvaluationIssue, EvaluationReport


class EvaluatorAgent:
    """Verifies that findings are complete, traceable and consistent with the manifest.

    An assessment tool that emits an unreferenced or unexplained finding is worse than none, so
    structural defects are reported as errors and fail the evaluation.
    """

    def __init__(self, registry: CheckRegistry) -> None:
        self._registry = registry

    def run(self, state: AssessmentState) -> AssessmentState:
        assert state.plan is not None
        issues: list[EvaluationIssue] = []
        component_ids = {c.id for c in state.manifest.components}

        def error(message: str) -> None:
            issues.append(EvaluationIssue(severity="error", message=message))

        seen: set[str] = set()
        for finding in state.findings:
            if finding.id in seen:
                error(f"duplicate finding id {finding.id}")
            seen.add(finding.id)
            if not finding.evidence:
                error(f"{finding.id} has no evidence")
            if not finding.recommendation.strip():
                error(f"{finding.id} has no recommendation")
            for ref in finding.owasp:
                if ref not in OWASP_LLM:
                    error(f"{finding.id} references unknown OWASP id {ref}")
            for ref in finding.nist:
                if nist_function(ref) not in NIST_FUNCTIONS:
                    error(f"{finding.id} references unknown NIST reference {ref}")
            for control in finding.controls:
                if control not in CONTROL_IDS:
                    error(f"{finding.id} references unknown control {control}")
            for target in finding.affected:
                if target not in component_ids:
                    error(f"{finding.id} references unknown component {target}")

        resolved = seen | set(state.passed_checks)
        for planned in state.plan.checks:
            if planned.id not in resolved:
                error(f"planned check {planned.id} produced no result")

        covered = {ref for check in self._registry.all() for ref in check.owasp}
        for missing in sorted(set(OWASP_LLM) - covered):
            issues.append(
                EvaluationIssue(
                    severity="warning",
                    message=f"no registered check covers OWASP {missing} ({OWASP_LLM[missing]})",
                )
            )

        state.evaluation = EvaluationReport(
            passed=not any(i.severity == "error" for i in issues), issues=issues
        )
        state.note = "passed" if state.evaluation.passed else f"{len(issues)} issues"
        return state
