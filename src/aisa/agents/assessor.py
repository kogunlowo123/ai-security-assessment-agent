"""Assessment agent: executes the planned checks and produces findings."""

from __future__ import annotations

from aisa.agents.state import AssessmentState
from aisa.catalog import CONTROLS
from aisa.checks import Check, CheckRegistry
from aisa.models import (
    ControlStatus,
    Finding,
    Severity,
    SystemManifest,
    SystemProfile,
    shift_severity,
)

_MIN_CREDIT_FOR_DOWNGRADE = 0.5


def _control_evidence(
    check: Check, manifest: SystemManifest
) -> tuple[float, list[str], dict[str, str]]:
    statuses = {control: manifest.status_of(control) for control in check.controls}
    credit = sum(s.credit for s in statuses.values()) / len(statuses)
    evidence: list[str] = []
    for control, status in statuses.items():
        if status is ControlStatus.IMPLEMENTED:
            continue
        note = "not evidenced in the manifest" if status is ControlStatus.UNKNOWN else status.value
        evidence.append(f"Control '{control}' is {note}: {CONTROLS[control].description}")
    return credit, evidence, {c: s.value for c, s in statuses.items()}


def evaluate_check(
    check: Check, manifest: SystemManifest, profile: SystemProfile, affected: list[str]
) -> Finding | None:
    """Evaluate one check. Returns ``None`` when the check passes."""
    controls: dict[str, str] = {}
    if check.evaluator is not None:
        credit, evidence = check.evaluator(manifest, profile, affected)
    elif check.controls:
        credit, evidence, controls = _control_evidence(check, manifest)
    else:
        credit, evidence = 1.0, []
    if credit >= 1.0:
        return None

    severity = shift_severity(check.base_severity, check.adjust(manifest, profile, affected))
    # Half-implemented controls reduce risk. A flow-level failure (an unauthenticated or unencrypted
    # connection) is a concrete hole however many other flows are fine, so it keeps full severity.
    if check.evaluator is None and credit >= _MIN_CREDIT_FOR_DOWNGRADE:
        severity = shift_severity(severity, -1)

    if affected:
        evidence = [*evidence, f"Affected components: {', '.join(affected)}"]
    nist = sorted({ref for c in check.controls for ref in CONTROLS[c].nist})
    return Finding(
        id=check.id,
        title=check.title,
        category=check.category,
        severity=severity,
        owasp=list(check.owasp),
        stride=list(check.stride),
        nist=nist,
        atlas=list(check.atlas),
        description=check.description,
        evidence=evidence,
        recommendation=check.recommendation,
        affected=affected,
        controls=controls,
    )


class AssessorAgent:
    """Workflow node that runs every planned check."""

    def __init__(self, registry: CheckRegistry) -> None:
        self._registry = registry

    def run(self, state: AssessmentState) -> AssessmentState:
        assert state.profile is not None and state.plan is not None
        findings: list[Finding] = []
        passed: list[str] = []
        for planned in state.plan.checks:
            check = self._registry.get(planned.id)
            finding = evaluate_check(check, state.manifest, state.profile, planned.affected)
            if finding is None:
                passed.append(check.id)
            else:
                findings.append(finding)
        findings.sort(key=lambda f: (-f.severity.rank, f.id))
        state.findings = findings
        state.passed_checks = passed
        worst = findings[0].severity.value if findings else Severity.INFO.value
        state.note = f"{len(findings)} findings ({worst} highest), {len(passed)} checks passed"
        return state
