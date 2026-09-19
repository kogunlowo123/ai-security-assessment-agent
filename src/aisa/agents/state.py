"""Shared state threaded through the assessment workflow."""

from __future__ import annotations

from pydantic import BaseModel, Field

from aisa.models import (
    AssessmentPlan,
    AssessmentReport,
    ComplianceSummary,
    EvaluationReport,
    Finding,
    SystemManifest,
    SystemProfile,
    Threat,
    TraceEvent,
)


class AssessmentState(BaseModel):
    """Mutable state passed from agent to agent."""

    manifest: SystemManifest
    profile: SystemProfile | None = None
    plan: AssessmentPlan | None = None
    threats: list[Threat] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    passed_checks: list[str] = Field(default_factory=list)
    compliance: ComplianceSummary | None = None
    evaluation: EvaluationReport | None = None
    report: AssessmentReport | None = None
    trace: list[TraceEvent] = Field(default_factory=list)
    note: str = ""
