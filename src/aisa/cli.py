"""Command-line interface: ``aisa assess | validate | checks | diff``.

Exit codes: 0 success, 1 findings at or above ``--fail-on`` (or a regression for ``diff``),
2 usage or runtime error.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError

from aisa.catalog import CONTROLS, OWASP_LLM
from aisa.checks import default_registry
from aisa.config import Settings
from aisa.container import build_service
from aisa.errors import AisaError
from aisa.history import ReportDiff, diff_reports
from aisa.logging_setup import configure_logging
from aisa.models import AssessmentReport, Severity
from aisa.reporting import FORMATS, write_reports
from aisa.security import redact


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aisa", description="AI security assessment agent")
    sub = parser.add_subparsers(dest="command", required=True)

    assess = sub.add_parser("assess", help="assess a system manifest")
    assess.add_argument("manifest", type=Path)
    assess.add_argument("--out", type=Path, default=Path("aisa-report"), help="report directory")
    assess.add_argument(
        "--format", default="md,json", help=f"comma list from: {', '.join(FORMATS)}"
    )
    assess.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity if s is not Severity.INFO],
        help="exit 1 when a finding at or above this severity exists",
    )
    assess.add_argument(
        "--history", action="store_true", help="store the run and compare with the last"
    )

    validate = sub.add_parser("validate", help="validate a manifest without assessing it")
    validate.add_argument("manifest", type=Path)

    checks = sub.add_parser("checks", help="list built-in checks and controls")
    checks.add_argument("--json", action="store_true", dest="as_json")

    diff = sub.add_parser("diff", help="compare two JSON reports")
    diff.add_argument("old", type=Path)
    diff.add_argument("new", type=Path)
    return parser


def _load_report(path: Path) -> AssessmentReport:
    try:
        return AssessmentReport.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        raise AisaError(f"cannot read report {path}: {exc}") from exc


def _print_diff(diff: ReportDiff) -> None:
    print(f"Posture change: {diff.posture_delta:+d}")
    print("New findings: " + (", ".join(diff.new) or "none"))
    print("Resolved findings: " + (", ".join(diff.resolved) or "none"))
    for change in diff.changed:
        print(f"Severity change {change.id}: {change.before.value} -> {change.after.value}")


def _cmd_assess(args: argparse.Namespace, settings: Settings) -> int:
    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    unknown = sorted(set(formats) - set(FORMATS))
    if unknown or not formats:
        raise AisaError(f"unknown format(s) {unknown or formats}; choose from {', '.join(FORMATS)}")
    service = build_service(settings)
    manifest = service.load_manifest(args.manifest)
    if args.history:
        report, diff = service.assess_with_history(manifest)
    else:
        report, diff = service.assess(manifest), None
    paths = write_reports(report, args.out, formats)

    counts = report.counts()
    print(f"System: {report.system}")
    print(f"Rating: {report.rating}  Posture: {report.posture_score}/100")
    print("Findings: " + (", ".join(f"{n} {sev}" for sev, n in counts.items() if n) or "none"))
    if not report.evaluation.passed:
        print("Warning: assessment quality gate failed; see the report", file=sys.stderr)
    for path in paths:
        print(f"Wrote {path}")
    if diff is not None:
        _print_diff(diff)

    if args.fail_on:
        threshold = Severity(args.fail_on)
        if any(f.severity.rank >= threshold.rank for f in report.findings):
            return 1
    return 0


def _cmd_checks(as_json: bool) -> int:
    registry = default_registry()
    if as_json:
        payload = {
            "checks": [
                {
                    "id": c.id,
                    "title": c.title,
                    "category": c.category,
                    "owasp": list(c.owasp),
                    "controls": list(c.controls),
                }
                for c in registry.all()
            ],
            "controls": {
                k: {"description": v.description, "nist": list(v.nist)} for k, v in CONTROLS.items()
            },
        }
        print(json.dumps(payload, indent=2))
        return 0
    for check in registry.all():
        owasp = ",".join(check.owasp) or "-"
        print(f"{check.id:<9} {check.base_severity.value:<9} {owasp:<12} {check.title}")
    print("\nControls:")
    for name, spec in CONTROLS.items():
        print(f"  {name:<28} {', '.join(spec.nist):<14} {spec.description}")
    print("\nOWASP LLM Top 10 (2025): " + "; ".join(f"{k} {v}" for k, v in OWASP_LLM.items()))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    args = _parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    try:
        settings = Settings()
        configure_logging(settings.log_level, json_output=settings.log_json)
        if args.command == "assess":
            return _cmd_assess(args, settings)
        if args.command == "validate":
            manifest = build_service(settings).load_manifest(args.manifest)
            print(f"valid: {len(manifest.components)} components, {len(manifest.flows)} flows")
            return 0
        if args.command == "checks":
            return _cmd_checks(args.as_json)
        diff = diff_reports(_load_report(args.old), _load_report(args.new))
        _print_diff(diff)
        return 1 if diff.regressed else 0
    except (AisaError, ValidationError) as exc:
        print(f"error: {redact(str(exc))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
