"""Unit tests for discovery, planning, threat modelling, assessment, compliance and evaluation."""

from __future__ import annotations

import pytest

from aisa.agents import (
    AssessmentState,
    AssessorAgent,
    ComplianceAgent,
    DiscoveryAgent,
    EvaluatorAgent,
    PlannerAgent,
    ThreatModelAgent,
)
from aisa.agents.assessor import evaluate_check
from aisa.agents.compliance import summarize_compliance
from aisa.agents.discovery import build_profile
from aisa.agents.threat_model import derive_threats
from aisa.catalog import CONTROLS
from aisa.checks import Check, CheckRegistry, default_registry
from aisa.errors import AisaError
from aisa.models import Finding, Severity, SystemManifest
from tests.conftest import make_manifest

AGENT_SYSTEM = {
    "components": [
        {"id": "ui", "name": "UI", "type": "ui", "trust_zone": "internet"},
        {"id": "gw", "name": "GW", "type": "api", "trust_zone": "dmz"},
        {"id": "agent", "name": "Agent", "type": "agent", "data_classes": ["pii"]},
        {"id": "pay", "name": "Pay", "type": "tool", "capabilities": ["payments", "write"]},
        {"id": "island", "name": "Island", "type": "data_store"},
    ],
    "flows": [
        {
            "source": "ui",
            "target": "gw",
            "authenticated": False,
            "encrypted": False,
            "data": ["pii"],
        },
        {"source": "gw", "target": "agent", "authenticated": True, "encrypted": True},
        {"source": "agent", "target": "pay", "authenticated": True, "encrypted": True},
    ],
}


def _run(manifest: SystemManifest, registry: CheckRegistry | None = None) -> AssessmentState:
    registry = registry or default_registry()
    state = AssessmentState(manifest=manifest)
    for agent in (
        DiscoveryAgent(),
        PlannerAgent(registry),
        ThreatModelAgent(),
        AssessorAgent(registry),
        ComplianceAgent(),
        EvaluatorAgent(registry),
    ):
        state = agent.run(state)
    return state


class TestDiscovery:
    def test_profile_of_agentic_system(self) -> None:
        profile = build_profile(make_manifest(**AGENT_SYSTEM))
        assert profile.component_count == 5
        assert profile.internet_facing == ["ui"]
        assert profile.exposed == ["ui", "gw", "agent", "pay"]
        assert "island" not in profile.exposed
        assert profile.sensitive == ["agent"]
        assert profile.agentic and not profile.has_rag and not profile.has_training
        assert profile.high_risk_tools == ["pay"]
        assert [(c.source, c.target) for c in profile.crossings] == [("ui", "gw"), ("gw", "agent")]
        assert profile.data_classes == ["pii"]
        assert profile.counts_by_type["tool"] == 1

    def test_model_to_tool_flow_marks_system_agentic(self) -> None:
        manifest = make_manifest(
            components=[
                {"id": "llm", "name": "LLM", "type": "llm"},
                {"id": "run", "name": "Runner", "type": "code_executor"},
            ],
            flows=[{"source": "llm", "target": "run"}],
        )
        profile = build_profile(manifest)
        assert profile.agentic and profile.high_risk_tools == ["run"]

    def test_rag_and_training_detection(self) -> None:
        manifest = make_manifest(
            components=[
                {"id": "vs", "name": "VS", "type": "vector_store"},
                {"id": "tp", "name": "TP", "type": "training_pipeline"},
            ],
            flows=[],
        )
        profile = build_profile(manifest)
        assert profile.has_rag and profile.has_training


class TestPlanner:
    def test_skips_inapplicable_checks_with_reasons(self) -> None:
        state = _run(make_manifest())
        plan = state.plan
        assert plan is not None
        planned = {c.id for c in plan.checks}
        assert {"LLM01-01", "LLM10-01", "GOV-05"} <= planned
        assert plan.skipped["LLM06-02"] == "No component executes code or commands."
        assert plan.skipped["LLM04-01"] == "No training pipeline or vector store declared."
        assert set(plan.skipped) | planned == {c.id for c in default_registry().all()}

    def test_always_check_is_planned_without_components(self) -> None:
        manifest = make_manifest(components=[{"id": "ui", "name": "UI", "type": "ui"}], flows=[])
        plan = _run(manifest).plan
        assert plan is not None
        assert [c.id for c in plan.checks] == ["GOV-05"]


class TestAssessor:
    def test_all_controls_implemented_passes(self) -> None:
        controls = dict.fromkeys(default_registry().get("LLM01-01").controls, "implemented")
        manifest = make_manifest(controls=controls)
        registry = default_registry()
        finding = evaluate_check(
            registry.get("LLM01-01"), manifest, build_profile(manifest), ["llm"]
        )
        assert finding is None

    def test_exposed_agentic_injection_is_critical(self) -> None:
        state = _run(make_manifest(**AGENT_SYSTEM))
        finding = next(f for f in state.findings if f.id == "LLM01-01")
        assert finding.severity is Severity.CRITICAL
        assert finding.owasp == ["LLM01"] and "AML.T0051" in finding.atlas
        assert finding.controls == {"input_filtering": "unknown", "prompt_isolation": "unknown"}
        assert any("not evidenced" in e for e in finding.evidence)
        assert finding.evidence[-1] == "Affected components: agent"

    def test_partial_controls_downgrade_severity(self) -> None:
        full = _run(make_manifest())
        partial = _run(
            make_manifest(controls={"input_filtering": "partial", "prompt_isolation": "partial"})
        )
        before = next(f for f in full.findings if f.id == "LLM01-01").severity
        after = next(f for f in partial.findings if f.id == "LLM01-01").severity
        assert after.rank == before.rank - 1

    def test_unexposed_model_is_downgraded(self) -> None:
        manifest = make_manifest(components=[{"id": "llm", "name": "LLM", "type": "llm"}], flows=[])
        finding = next(f for f in _run(manifest).findings if f.id == "LLM01-01")
        assert finding.severity is Severity.MEDIUM

    def test_architecture_checks_use_flow_facts(self) -> None:
        state = _run(make_manifest(**AGENT_SYSTEM))
        arch1 = next(f for f in state.findings if f.id == "ARCH-01")
        assert arch1.evidence[0] == "ui -> gw crosses internet to dmz without authentication"
        arch2 = next(f for f in state.findings if f.id == "ARCH-02")
        assert "carries pii" in arch2.evidence[0]
        assert arch2.severity is Severity.HIGH
        assert arch1.controls == {}

    def test_secured_flows_pass_architecture_checks(self) -> None:
        state = _run(make_manifest())
        assert {"ARCH-01", "ARCH-02"} <= set(state.passed_checks)

    def test_findings_sorted_by_severity_then_id(self) -> None:
        findings = _run(make_manifest(**AGENT_SYSTEM)).findings
        keys = [(-f.severity.rank, f.id) for f in findings]
        assert keys == sorted(keys)

    def test_supply_chain_escalates_for_third_party(self) -> None:
        base = _run(make_manifest())
        third = _run(
            make_manifest(
                components=[
                    {"id": "llm", "name": "LLM", "type": "llm", "trust_zone": "third_party"}
                ],
                flows=[],
            )
        )
        b = next(f for f in base.findings if f.id == "LLM03-01").severity
        t = next(f for f in third.findings if f.id == "LLM03-01").severity
        assert t.rank == b.rank + 1

    def test_sandbox_check_is_critical(self) -> None:
        manifest = make_manifest(
            components=[
                {"id": "llm", "name": "LLM", "type": "llm"},
                {"id": "run", "name": "Runner", "type": "code_executor"},
            ],
            flows=[{"source": "llm", "target": "run"}],
        )
        finding = next(f for f in _run(manifest).findings if f.id == "LLM06-02")
        assert finding.severity is Severity.CRITICAL

    def test_regulated_and_secret_escalations(self) -> None:
        manifest = make_manifest(
            components=[
                {"id": "ui", "name": "UI", "type": "ui", "trust_zone": "internet"},
                {"id": "llm", "name": "LLM", "type": "llm", "data_classes": ["phi", "secrets"]},
                {"id": "vs", "name": "VS", "type": "vector_store", "data_classes": ["pii"]},
            ],
            flows=[
                {"source": "ui", "target": "llm", "authenticated": True, "encrypted": True},
                {"source": "llm", "target": "vs", "authenticated": True, "encrypted": True},
            ],
            multi_tenant=True,
            high_stakes=True,
        )
        findings = {f.id: f for f in _run(manifest).findings}
        assert findings["LLM02-01"].severity is Severity.CRITICAL
        assert findings["LLM07-01"].severity is Severity.HIGH
        assert findings["LLM08-01"].severity is Severity.HIGH
        assert findings["LLM09-01"].severity is Severity.HIGH
        assert findings["GOV-04"].severity is Severity.MEDIUM


class TestRegistry:
    def test_duplicate_and_unknown(self) -> None:
        registry = default_registry()
        with pytest.raises(AisaError, match="duplicate"):
            registry.register(registry.get("GOV-01"))
        with pytest.raises(AisaError, match="unknown check"):
            registry.get("NOPE")

    def test_custom_check_runs(self) -> None:
        registry = default_registry()
        registry.register(
            Check(
                id="CUSTOM-01",
                title="Custom",
                category="governance",
                base_severity=Severity.LOW,
                controls=("sbom",),
                applies=lambda m, p: ["llm"],
                description="d",
                recommendation="r",
                skip_reason="s",
            )
        )
        assert "CUSTOM-01" in {f.id for f in _run(make_manifest(), registry).findings}


class TestThreatModel:
    def test_rules_cover_stride_categories(self) -> None:
        manifest = make_manifest(
            **AGENT_SYSTEM,
            controls={"human_approval": "absent"},
        )
        threats = derive_threats(manifest, build_profile(manifest))
        letters = {t.stride for t in threats}
        assert {"S", "T", "I", "D", "E", "R"} <= letters
        assert [t.id for t in threats] == [f"T-{i:03d}" for i in range(1, len(threats) + 1)]
        misuse = next(t for t in threats if t.title.startswith("Model-driven misuse"))
        assert misuse.severity is Severity.CRITICAL

    def test_specialised_threats(self) -> None:
        manifest = make_manifest(
            components=[
                {"id": "ui", "name": "UI", "type": "ui", "trust_zone": "internet"},
                {"id": "llm", "name": "LLM", "type": "llm", "data_classes": ["secrets"]},
                {"id": "tp", "name": "TP", "type": "training_pipeline"},
                {"id": "vs", "name": "VS", "type": "vector_store"},
                {"id": "reg", "name": "Reg", "type": "model_registry", "trust_zone": "third_party"},
            ],
            flows=[
                {"source": "ui", "target": "llm", "authenticated": True, "encrypted": True},
                {"source": "llm", "target": "vs", "authenticated": True, "encrypted": True},
            ],
        )
        atlas = {a for t in derive_threats(manifest, build_profile(manifest)) for a in t.atlas}
        assert {"AML.T0051", "AML.T0056", "AML.T0020", "AML.T0010"} <= atlas
        titles = [t.title for t in derive_threats(manifest, build_profile(manifest))]
        assert any(t.startswith("Index vs poisoned") for t in titles)

    def test_secure_system_has_only_baseline_threat(self) -> None:
        manifest = make_manifest(
            controls={"rate_limiting": "implemented", "logging_monitoring": "implemented"}
        )
        titles = [t.title for t in derive_threats(manifest, build_profile(manifest))]
        assert titles == ["Prompt injection alters behaviour of llm"]


class TestCompliance:
    def test_scores_reflect_statuses(self) -> None:
        empty = summarize_compliance(make_manifest())
        assert empty.overall == 0.0
        assert set(empty.functions) == {"GOVERN", "MAP", "MEASURE", "MANAGE"}
        every = dict.fromkeys(CONTROLS, "implemented")
        full = summarize_compliance(make_manifest(controls=every))
        assert full.overall == 1.0 and all(not f.gaps for f in full.functions.values())

    def test_partial_and_gap_listing(self) -> None:
        summary = summarize_compliance(
            make_manifest(
                controls={"use_case_documented": "implemented", "impact_assessment": "partial"}
            )
        )
        map_cov = summary.functions["MAP"]
        assert map_cov.score == 0.75 and map_cov.controls_implemented == 1
        assert [(g.control, g.status) for g in map_cov.gaps] == [("impact_assessment", "partial")]


class TestEvaluator:
    def _state(self) -> AssessmentState:
        state = _run(make_manifest())
        assert state.evaluation is not None and state.evaluation.passed
        return state

    def _bad_finding(self, **changes: object) -> Finding:
        base = {
            "id": "X-01",
            "title": "t",
            "category": "owasp",
            "severity": Severity.LOW,
            "description": "d",
            "evidence": ["e"],
            "recommendation": "r",
        }
        base.update(changes)
        return Finding.model_validate(base)

    @pytest.mark.parametrize(
        ("changes", "message"),
        [
            ({"evidence": []}, "no evidence"),
            ({"recommendation": " "}, "no recommendation"),
            ({"owasp": ["LLM99"]}, "unknown OWASP"),
            ({"nist": ["BOGUS 1.1"]}, "unknown NIST"),
            ({"controls": {"nope": "absent"}}, "unknown control"),
            ({"affected": ["ghost"]}, "unknown component"),
        ],
    )
    def test_detects_defective_findings(self, changes: dict[str, object], message: str) -> None:
        state = self._state()
        state.findings = [*state.findings, self._bad_finding(**changes)]
        result = EvaluatorAgent(default_registry()).run(state)
        assert result.evaluation is not None and not result.evaluation.passed
        assert any(message in i.message for i in result.evaluation.issues)

    def test_detects_duplicates_and_missing_results(self) -> None:
        state = self._state()
        state.findings = [self._bad_finding(), self._bad_finding()]
        state.passed_checks = []
        result = EvaluatorAgent(default_registry()).run(state)
        messages = " | ".join(i.message for i in result.evaluation.issues)  # type: ignore[union-attr]
        assert "duplicate finding id X-01" in messages and "produced no result" in messages

    def test_warns_when_owasp_category_uncovered(self) -> None:
        registry = CheckRegistry()
        registry.register(default_registry().get("GOV-05"))
        state = _run(make_manifest(), registry)
        assert state.evaluation is not None and state.evaluation.passed
        warnings = [i for i in state.evaluation.issues if i.severity == "warning"]
        assert len(warnings) == 10
