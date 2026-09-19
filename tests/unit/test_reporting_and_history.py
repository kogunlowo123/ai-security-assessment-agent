"""Unit tests for summaries, posture scoring, renderers and history."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aisa.agents import LLMSummaryWriter, SummaryFacts, TemplateSummaryWriter
from aisa.agents.report import compute_posture
from aisa.config import Settings
from aisa.container import build_service
from aisa.errors import ProviderError, ReportError
from aisa.history import HistoryStore, diff_reports, slugify
from aisa.models import AssessmentReport, Finding, Severity
from aisa.reporting import FORMATS, render, write_reports
from tests.conftest import FIXED_TIME, MANIFESTS, FakeLLM, make_manifest, make_settings


def _finding(severity: Severity, fid: str = "F-1") -> Finding:
    return Finding(
        id=fid,
        title="t",
        category="owasp",
        severity=severity,
        description="d",
        evidence=["e"],
        recommendation="r",
    )


def _facts(**over: object) -> SummaryFacts:
    base: dict[str, object] = {
        "system": "Sys",
        "counts": {"critical": 1, "high": 0, "medium": 2, "low": 0, "info": 0},
        "total_findings": 3,
        "posture_score": 61,
        "rating": "critical",
        "top_findings": [{"id": "LLM01-01", "title": "Injection", "severity": "critical"}],
        "nist_scores": {"GOVERN": 0.25, "MAP": 0.5},
        "threat_count": 7,
        "checks_run": 19,
    }
    base.update(over)
    return SummaryFacts.model_validate(base)


def _report(tmp_path: Path, name: str = "Test System", **controls: str) -> AssessmentReport:
    service = build_service(make_settings(tmp_path), now=lambda: FIXED_TIME)
    return service.assess(make_manifest(name=name, controls=controls))


class TestPosture:
    def test_no_findings_is_perfect(self) -> None:
        assert compute_posture([]) == (100, "none")

    def test_decays_smoothly_and_never_reaches_zero(self) -> None:
        one = compute_posture([_finding(Severity.CRITICAL)])[0]
        many = compute_posture([_finding(Severity.CRITICAL, f"F-{i}") for i in range(10)])[0]
        assert 0 < many < one < 100

    def test_rating_is_worst_severity(self) -> None:
        assert (
            compute_posture([_finding(Severity.LOW), _finding(Severity.HIGH, "F-2")])[1] == "high"
        )
        assert compute_posture([_finding(Severity.INFO)])[1] == "none"


class TestSummaryWriters:
    def test_template_with_findings(self) -> None:
        text = TemplateSummaryWriter().write(_facts())
        assert "19 checks" in text and "3 findings (1 critical, 2 medium)" in text
        assert "GOVERN 25%" in text and "LLM01-01" in text

    def test_template_without_findings(self) -> None:
        facts = _facts(
            counts={s.value: 0 for s in Severity},
            total_findings=0,
            top_findings=[],
            posture_score=100,
            rating="none",
        )
        assert "no findings were raised" in TemplateSummaryWriter().write(facts)

    def test_llm_narrative_accepted_when_grounded(self) -> None:
        llm = FakeLLM("Sys has 3 findings and a posture of 61 out of 100.")
        text = LLMSummaryWriter(llm).write(_facts())
        assert text.startswith("Sys has 3")
        system, user = llm.calls[0]
        assert "not instructions" in system and '"posture_score": 61' in user

    @pytest.mark.parametrize("reply", ["We found 12 critical issues.", "", "x" * 2000])
    def test_llm_narrative_rejected_when_ungrounded(self, reply: str) -> None:
        text = LLMSummaryWriter(FakeLLM(reply)).write(_facts())
        assert text == TemplateSummaryWriter().write(_facts())

    def test_llm_failure_falls_back(self) -> None:
        class Broken:
            def complete(self, system: str, user: str) -> str:
                raise ProviderError("down")

        assert LLMSummaryWriter(Broken()).write(_facts()) == TemplateSummaryWriter().write(_facts())


class TestRenderers:
    def test_markdown_sections_and_escaping(self, tmp_path: Path) -> None:
        report = _report(tmp_path, name="Bad | <script>Name")
        md = render(report, "md")
        for heading in (
            "## Executive summary",
            "## Findings",
            "## Threat model (STRIDE)",
            "## NIST AI RMF control coverage",
            "## Notice",
        ):
            assert heading in md
        assert "<script>" not in md and "Bad \\| &lt;script&gt;Name" in md
        assert "OWASP LLM01 Prompt Injection" in md

    def test_json_round_trips(self, tmp_path: Path) -> None:
        report = _report(tmp_path)
        assert AssessmentReport.model_validate_json(render(report, "json")) == report

    def test_sarif_structure(self, tmp_path: Path) -> None:
        report = _report(tmp_path)
        log = json.loads(render(report, "sarif"))
        run = log["runs"][0]
        assert log["version"] == "2.1.0"
        assert len(run["results"]) == len(report.findings) == len(run["tool"]["driver"]["rules"])
        assert {r["level"] for r in run["results"]} <= {"error", "warning", "note"}
        rule = run["tool"]["driver"]["rules"][0]
        assert float(rule["properties"]["security-severity"]) > 0

    def test_write_reports_uses_fixed_filenames(self, tmp_path: Path) -> None:
        report = _report(tmp_path, name="../../evil/name")
        paths = write_reports(report, tmp_path / "out", list(FORMATS))
        assert sorted(p.name for p in paths) == [
            "assessment.json",
            "assessment.md",
            "assessment.sarif",
        ]
        assert all(p.parent == tmp_path / "out" for p in paths)

    def test_unknown_format_and_unwritable_dir(self, tmp_path: Path) -> None:
        report = _report(tmp_path)
        with pytest.raises(ReportError, match="unknown format"):
            render(report, "pdf")
        blocker = tmp_path / "file"
        blocker.write_text("x", encoding="utf-8")
        with pytest.raises(ReportError, match="cannot write"):
            write_reports(report, blocker / "sub", ["md"])

    def test_empty_report_renders(self, tmp_path: Path) -> None:
        service = build_service(make_settings(tmp_path), now=lambda: FIXED_TIME)
        report = service.assess_file(MANIFESTS / "hardened-research-agent.yaml")
        md = render(report, "md")
        assert "No findings." in md and report.posture_score == 100


class TestHistory:
    def test_slugify(self) -> None:
        assert slugify("Customer Support / Bot!") == "customer-support-bot"
        assert slugify("!!!") == "system"

    def test_save_latest_and_diff(self, tmp_path: Path) -> None:
        store = HistoryStore(tmp_path / "h")
        assert store.latest("Test System") is None
        old = _report(tmp_path)
        path = store.save(old)
        assert path.name.startswith("test-system-") and path.suffix == ".json"
        assert store.latest("Test System") == old

        better = _report(tmp_path, input_filtering="implemented", prompt_isolation="implemented")
        diff = diff_reports(old, better)
        assert "LLM01-01" in diff.resolved and diff.posture_delta > 0 and not diff.regressed
        worse = diff_reports(better, old)
        assert "LLM01-01" in worse.new and worse.regressed

    def test_severity_change_detected(self, tmp_path: Path) -> None:
        old = _report(tmp_path, input_filtering="partial", prompt_isolation="partial")
        new = _report(tmp_path)
        diff = diff_reports(old, new)
        change = next(c for c in diff.changed if c.id == "LLM01-01")
        assert change.after.rank > change.before.rank and diff.regressed

    def test_latest_ignores_unrelated_and_corrupt_files(self, tmp_path: Path) -> None:
        store = HistoryStore(tmp_path / "h")
        (tmp_path / "h").mkdir()
        (tmp_path / "h" / "test-system-notes.json").write_text("{}", encoding="utf-8")
        assert store.latest("Test System") is None
        (tmp_path / "h" / "test-system-20260101T000000000000Z.json").write_text(
            "{bad", encoding="utf-8"
        )
        with pytest.raises(ReportError, match="cannot read history"):
            store.latest("Test System")

    def test_save_failure(self, tmp_path: Path) -> None:
        blocker = tmp_path / "file"
        blocker.write_text("x", encoding="utf-8")
        with pytest.raises(ReportError, match="cannot write history"):
            HistoryStore(blocker / "h").save(_report(tmp_path))


class TestSettings:
    def test_defaults_and_secret_masking(self, tmp_path: Path) -> None:
        settings = make_settings(tmp_path, openai_api_key="sk-secret-value-0000000000")
        assert settings.llm_provider == "none"
        assert "secret-value" not in repr(settings) + settings.model_dump_json()

    def test_env_alias(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "abc")
        key = Settings(_env_file=None).anthropic_api_key
        assert key is not None and key.get_secret_value() == "abc"

    def test_inconsistent_retry_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="retry_max_wait"):
            make_settings(tmp_path, retry_min_wait=5.0, retry_max_wait=1.0)
