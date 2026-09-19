"""Workflow wiring: discover, plan, model threats, assess, map compliance, evaluate, report."""

from __future__ import annotations

import time
from collections.abc import Callable
from itertools import pairwise

from aisa.agents import (
    AssessmentState,
    AssessorAgent,
    ComplianceAgent,
    DiscoveryAgent,
    EvaluatorAgent,
    PlannerAgent,
    ReportAgent,
    ThreatModelAgent,
)
from aisa.graph import END, WorkflowGraph
from aisa.logging_setup import get_logger
from aisa.models import AssessmentReport, SystemManifest, TraceEvent

_log = get_logger("pipeline")


class AssessmentPipeline:
    """Runs one manifest through the seven agents in order and returns the report."""

    def __init__(
        self,
        discovery: DiscoveryAgent,
        planner: PlannerAgent,
        threat_model: ThreatModelAgent,
        assessor: AssessorAgent,
        compliance: ComplianceAgent,
        evaluator: EvaluatorAgent,
        reporter: ReportAgent,
    ) -> None:
        stages: list[tuple[str, Callable[[AssessmentState], AssessmentState]]] = [
            ("discover", discovery.run),
            ("plan", planner.run),
            ("threat_model", threat_model.run),
            ("assess", assessor.run),
            ("comply", compliance.run),
            ("evaluate", evaluator.run),
            ("report", reporter.run),
        ]
        graph: WorkflowGraph[AssessmentState] = WorkflowGraph()
        for name, func in stages:
            graph.add_node(name, self._traced(name, func))
        graph.set_entry(stages[0][0])
        for (current, _), (following, _) in pairwise(stages):
            graph.add_edge(current, following)
        graph.add_edge(stages[-1][0], END)
        self._graph = graph

    @staticmethod
    def _traced(
        name: str, func: Callable[[AssessmentState], AssessmentState]
    ) -> Callable[[AssessmentState], AssessmentState]:
        def wrapper(state: AssessmentState) -> AssessmentState:
            start = time.perf_counter()
            state.note = ""
            result = func(state)
            elapsed = round((time.perf_counter() - start) * 1000.0, 3)
            result.trace.append(TraceEvent(node=name, detail=result.note, duration_ms=elapsed))
            return result

        return wrapper

    def run(self, manifest: SystemManifest) -> AssessmentReport:
        """Assess ``manifest`` and return the completed report."""
        state = self._graph.run(AssessmentState(manifest=manifest))
        assert state.report is not None, "report agent must produce a report"
        state.report.trace = list(state.trace)
        _log.info(
            "assessment completed",
            extra={
                "findings": len(state.report.findings),
                "posture": state.report.posture_score,
                "rating": state.report.rating,
            },
        )
        return state.report
