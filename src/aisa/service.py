"""Application service: load and validate manifests, run the pipeline, keep history."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import ValidationError

from aisa.config import Settings
from aisa.errors import ManifestError
from aisa.history import HistoryStore, ReportDiff, diff_reports
from aisa.models import AssessmentReport, SystemManifest
from aisa.pipeline import AssessmentPipeline
from aisa.security import load_manifest_data, redact


def parse_manifest(data: dict[str, Any]) -> SystemManifest:
    """Validate raw manifest data.

    Raises:
        ManifestError: With one line per validation problem, secrets redacted.
    """
    try:
        return SystemManifest.model_validate(data)
    except ValidationError as exc:
        problems = [
            f"{'.'.join(str(p) for p in err['loc']) or 'manifest'}: {err['msg']}"
            for err in exc.errors()
        ]
        raise ManifestError(redact("invalid manifest: " + "; ".join(problems))) from exc


class AssessmentService:
    """Facade over the pipeline and history store."""

    def __init__(
        self, settings: Settings, pipeline: AssessmentPipeline, history: HistoryStore | None = None
    ) -> None:
        self._settings = settings
        self._pipeline = pipeline
        self._history = history or HistoryStore(settings.history_dir)

    def load_manifest(self, path: Path) -> SystemManifest:
        """Read and validate a manifest file."""
        return parse_manifest(load_manifest_data(path, max_bytes=self._settings.max_manifest_bytes))

    def assess(self, manifest: SystemManifest) -> AssessmentReport:
        """Assess a validated manifest."""
        return self._pipeline.run(manifest)

    def assess_file(self, path: Path) -> AssessmentReport:
        """Load, validate and assess the manifest at ``path``."""
        return self.assess(self.load_manifest(path))

    def assess_with_history(
        self, manifest: SystemManifest
    ) -> tuple[AssessmentReport, ReportDiff | None]:
        """Assess, compare against the previous stored run of the same system, then store this run."""
        previous = self._history.latest(manifest.name)
        report = self.assess(manifest)
        self._history.save(report)
        return report, diff_reports(previous, report) if previous else None
