"""Planner agent: selects the checks that apply to the discovered system."""

from __future__ import annotations

from aisa.agents.state import AssessmentState
from aisa.checks import CheckRegistry
from aisa.models import AssessmentPlan, PlannedCheck

FRAMEWORKS = [
    "OWASP Top 10 for LLM Applications 2025",
    "STRIDE",
    "NIST AI RMF 1.0",
    "MITRE ATLAS (reference identifiers)",
]


class PlannerAgent:
    """Chooses applicable checks and records why others were skipped."""

    def __init__(self, registry: CheckRegistry) -> None:
        self._registry = registry

    def run(self, state: AssessmentState) -> AssessmentState:
        assert state.profile is not None, "discovery must run before planning"
        planned: list[PlannedCheck] = []
        skipped: dict[str, str] = {}
        for check in self._registry.all():
            affected = check.applies(state.manifest, state.profile)
            if affected or check.always:
                planned.append(PlannedCheck(id=check.id, affected=affected))
            else:
                skipped[check.id] = check.skip_reason
        state.plan = AssessmentPlan(frameworks=list(FRAMEWORKS), checks=planned, skipped=skipped)
        state.note = f"{len(planned)} checks planned, {len(skipped)} skipped"
        return state
