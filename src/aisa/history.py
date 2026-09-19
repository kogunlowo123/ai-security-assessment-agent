"""Assessment memory: persists reports and compares runs to show drift over time."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

from pydantic import BaseModel, Field

from aisa.errors import ReportError
from aisa.models import AssessmentReport, Severity


def slugify(name: str) -> str:
    """Filesystem-safe identifier for a system name."""
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60] or "system"


class SeverityChange(BaseModel):
    """A finding whose severity moved between two runs."""

    id: str
    before: Severity
    after: Severity


class ReportDiff(BaseModel):
    """Difference between two assessments of the same system."""

    new: list[str] = Field(default_factory=list)
    resolved: list[str] = Field(default_factory=list)
    changed: list[SeverityChange] = Field(default_factory=list)
    posture_delta: int = 0

    @property
    def regressed(self) -> bool:
        """True when the newer run is worse: new findings, escalations or a lower posture score."""
        escalated = any(c.after.rank > c.before.rank for c in self.changed)
        return bool(self.new) or escalated or self.posture_delta < 0


def diff_reports(old: AssessmentReport, new: AssessmentReport) -> ReportDiff:
    """Compare two reports by finding id."""
    before = {f.id: f for f in old.findings}
    after = {f.id: f for f in new.findings}
    return ReportDiff(
        new=sorted(set(after) - set(before)),
        resolved=sorted(set(before) - set(after)),
        changed=[
            SeverityChange(id=i, before=before[i].severity, after=after[i].severity)
            for i in sorted(set(before) & set(after))
            if before[i].severity is not after[i].severity
        ],
        posture_delta=new.posture_score - old.posture_score,
    )


class HistoryStore:
    """Directory of JSON reports, one file per run, named ``<system>-<timestamp>.json``."""

    def __init__(self, directory: Path) -> None:
        self._dir = directory

    def save(self, report: AssessmentReport) -> Path:
        """Write ``report`` atomically and return its path."""
        stamp = report.generated_at.strftime("%Y%m%dT%H%M%S%fZ")
        target = self._dir / f"{slugify(report.system)}-{stamp}.json"
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self._dir, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(report.model_dump_json(indent=2))
            os.replace(tmp, target)
        except OSError as exc:
            raise ReportError(f"cannot write history to {self._dir}: {exc}") from exc
        return target

    def latest(self, system: str) -> AssessmentReport | None:
        """Return the most recent stored report for ``system`` or ``None``."""
        if not self._dir.is_dir():
            return None
        prefix = f"{slugify(system)}-"
        candidates = sorted(
            p
            for p in self._dir.glob(f"{prefix}*.json")
            if re.fullmatch(r"\d{8}T\d{12}Z", p.stem[len(prefix) :])
        )
        if not candidates:
            return None
        try:
            return AssessmentReport.model_validate_json(candidates[-1].read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ReportError(f"cannot read history file {candidates[-1].name}: {exc}") from exc
