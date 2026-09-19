"""Report renderers and writer."""

from __future__ import annotations

import json
from pathlib import Path

from aisa.errors import ReportError
from aisa.models import AssessmentReport
from aisa.reporting import markdown, sarif

FORMATS = ("md", "json", "sarif")
_FILENAMES = {"md": "assessment.md", "json": "assessment.json", "sarif": "assessment.sarif"}


def render(report: AssessmentReport, fmt: str) -> str:
    """Render ``report`` in ``fmt`` (``md``, ``json`` or ``sarif``)."""
    if fmt == "md":
        return markdown.render(report)
    if fmt == "json":
        return report.model_dump_json(indent=2)
    if fmt == "sarif":
        return json.dumps(sarif.render(report), indent=2)
    raise ReportError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")


def write_reports(report: AssessmentReport, out_dir: Path, formats: list[str]) -> list[Path]:
    """Write each requested format into ``out_dir`` using fixed file names.

    File names never derive from the manifest, so a hostile system name cannot influence paths.
    """
    rendered = {fmt: render(report, fmt) for fmt in formats}
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        paths = []
        for fmt, content in rendered.items():
            path = out_dir / _FILENAMES[fmt]
            path.write_text(content, encoding="utf-8")
            paths.append(path)
    except OSError as exc:
        raise ReportError(f"cannot write reports to {out_dir}: {exc}") from exc
    return paths
