"""SARIF 2.1.0 renderer for code-scanning dashboards and CI annotations."""

from __future__ import annotations

from typing import Any

from aisa.models import AssessmentReport, Severity

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SCORE = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.5",
}


def render(report: AssessmentReport) -> dict[str, Any]:
    """Return a SARIF 2.1.0 log for ``report``.

    Findings have no source location, so each result is anchored to the affected components as
    logical locations.
    """
    rules = [
        {
            "id": f.id,
            "name": f.id.replace("-", ""),
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description},
            "help": {"text": f.recommendation},
            "properties": {
                "security-severity": _SCORE[f.severity],
                "tags": ["security", *f.owasp, *f.nist, *f.atlas],
            },
        }
        for f in report.findings
    ]
    results = [
        {
            "ruleId": f.id,
            "level": _LEVEL[f.severity],
            "message": {"text": f"{f.title}. {' '.join(f.evidence)}"},
            "locations": [
                {"logicalLocations": [{"name": name, "kind": "module"}]}
                for name in (f.affected or [report.system])
            ],
        }
        for f in report.findings
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {"name": "aisa", "version": report.tool_version, "rules": rules}
                },
                "results": results,
            }
        ],
    }
