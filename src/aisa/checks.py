"""Check registry and the built-in security checks.

Each :class:`Check` declares when it applies to a system, which controls it requires and how the
severity moves with the system's exposure. Checks are pure functions over the manifest and the
discovery profile, so results are deterministic and every finding can be traced to declared facts.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from aisa.errors import AisaError
from aisa.models import (
    SENSITIVE_DATA,
    ComponentType,
    Severity,
    SystemManifest,
    SystemProfile,
    TrustZone,
)

Applies = Callable[[SystemManifest, SystemProfile], list[str]]
Adjust = Callable[[SystemManifest, SystemProfile, list[str]], int]
Evaluator = Callable[[SystemManifest, SystemProfile, list[str]], tuple[float, list[str]]]

T = ComponentType


def _no_adjust(manifest: SystemManifest, profile: SystemProfile, affected: list[str]) -> int:
    return 0


@dataclass(frozen=True, kw_only=True)
class Check:
    """A single security check."""

    id: str
    title: str
    category: str
    base_severity: Severity
    description: str
    recommendation: str
    skip_reason: str
    applies: Applies
    owasp: tuple[str, ...] = ()
    stride: tuple[str, ...] = ()
    atlas: tuple[str, ...] = ()
    controls: tuple[str, ...] = ()
    adjust: Adjust = _no_adjust
    evaluator: Evaluator | None = None
    always: bool = False


class CheckRegistry:
    """Ordered collection of checks addressable by id."""

    def __init__(self) -> None:
        self._checks: dict[str, Check] = {}

    def register(self, check: Check) -> None:
        """Add ``check``; ids must be unique."""
        if check.id in self._checks:
            raise AisaError(f"duplicate check id: {check.id}")
        self._checks[check.id] = check

    def get(self, check_id: str) -> Check:
        """Return the check with ``check_id``."""
        try:
            return self._checks[check_id]
        except KeyError as exc:
            raise AisaError(f"unknown check id: {check_id}") from exc

    def all(self) -> list[Check]:
        """All checks in registration order."""
        return list(self._checks.values())


# Applicability helpers


def _nothing(manifest: SystemManifest, profile: SystemProfile) -> list[str]:
    return []


def _models(manifest: SystemManifest, profile: SystemProfile) -> list[str]:
    return profile.ids(manifest, T.LLM, T.AGENT)


def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _indirect_targets(manifest: SystemManifest, profile: SystemProfile) -> list[str]:
    models = set(_models(manifest, profile))
    kinds = {
        c.id
        for c in manifest.components
        if c.type in {T.RETRIEVER, T.VECTOR_STORE, T.EXTERNAL_SERVICE, T.TOOL, T.DATA_STORE}
    }
    targets = [f.target for f in manifest.flows if f.target in models and f.source in kinds]
    if not targets and profile.has_rag:
        targets = sorted(models)
    return _unique(targets)


def _sensitive_components(manifest: SystemManifest, profile: SystemProfile) -> list[str]:
    return list(profile.sensitive)


def _sensitive_to_third_party(manifest: SystemManifest, profile: SystemProfile) -> list[str]:
    third = set(profile.third_party)
    return _unique(
        [f.target for f in manifest.flows if f.target in third and SENSITIVE_DATA & set(f.data)]
    )


def _supply_chain(manifest: SystemManifest, profile: SystemProfile) -> list[str]:
    return _unique(
        _models(manifest, profile)
        + profile.ids(manifest, T.MODEL_REGISTRY, T.EXTERNAL_SERVICE, T.TRAINING_PIPELINE)
        + profile.third_party
    )


def _poisonable(manifest: SystemManifest, profile: SystemProfile) -> list[str]:
    return profile.ids(manifest, T.TRAINING_PIPELINE, T.VECTOR_STORE)


def _model_output_sinks(manifest: SystemManifest, profile: SystemProfile) -> list[str]:
    models = set(_models(manifest, profile))
    sinks = {T.UI, T.API, T.TOOL, T.CODE_EXECUTOR}
    by_id = {c.id: c for c in manifest.components}
    return _unique(
        [f.target for f in manifest.flows if f.source in models and by_id[f.target].type in sinks]
    )


def _agency(manifest: SystemManifest, profile: SystemProfile) -> list[str]:
    return profile.ids(manifest, T.AGENT, T.TOOL, T.CODE_EXECUTOR)


def _executors(manifest: SystemManifest, profile: SystemProfile) -> list[str]:
    return [
        c.id for c in manifest.components if c.type is T.CODE_EXECUTOR or "exec" in c.capabilities
    ]


def _retrieval(manifest: SystemManifest, profile: SystemProfile) -> list[str]:
    return profile.ids(manifest, T.VECTOR_STORE, T.RETRIEVER)


def _boundary_targets(manifest: SystemManifest, profile: SystemProfile) -> list[str]:
    return _unique([c.target for c in profile.crossings])


def _sensitive_or_crossing_flows(manifest: SystemManifest, profile: SystemProfile) -> list[str]:
    crossing = {(c.source, c.target) for c in profile.crossings}
    return _unique(
        [
            f.target
            for f in manifest.flows
            if (f.source, f.target) in crossing or SENSITIVE_DATA & set(f.data)
        ]
    )


# Severity adjustments


def _adjust_injection(manifest: SystemManifest, profile: SystemProfile, affected: list[str]) -> int:
    exposed = set(profile.exposed)
    if any(a in exposed for a in affected) and profile.high_risk_tools:
        return 1
    return 0 if any(a in exposed for a in affected) else -1


def _adjust_sensitive(manifest: SystemManifest, profile: SystemProfile, affected: list[str]) -> int:
    exposed = set(profile.exposed)
    regulated = {"phi", "pci"}
    for comp in manifest.components:
        if (
            comp.id in affected
            and comp.id in exposed
            and regulated & {d.value for d in comp.data_classes}
        ):
            return 1
    return 0


def _adjust_supply(manifest: SystemManifest, profile: SystemProfile, affected: list[str]) -> int:
    registries = set(profile.ids(manifest, T.MODEL_REGISTRY)) | set(profile.third_party)
    return 1 if registries & set(affected) else 0


def _adjust_poison(manifest: SystemManifest, profile: SystemProfile, affected: list[str]) -> int:
    zones = {c.id: c.trust_zone for c in manifest.components}
    untrusted = {TrustZone.INTERNET, TrustZone.THIRD_PARTY}
    return int(any(f.target in affected and zones[f.source] in untrusted for f in manifest.flows))


def _adjust_output(manifest: SystemManifest, profile: SystemProfile, affected: list[str]) -> int:
    by_id = {c.id: c for c in manifest.components}
    risky = any(
        by_id[a].type is T.CODE_EXECUTOR or bool({"exec", "write"} & set(by_id[a].capabilities))
        for a in affected
    )
    return int(risky)


def _adjust_agency(manifest: SystemManifest, profile: SystemProfile, affected: list[str]) -> int:
    return int(bool(profile.high_risk_tools))


def _adjust_prompt_leak(
    manifest: SystemManifest, profile: SystemProfile, affected: list[str]
) -> int:
    return int(
        any(
            c.id in affected and "secrets" in {d.value for d in c.data_classes}
            for c in manifest.components
        )
    )


def _adjust_retrieval(manifest: SystemManifest, profile: SystemProfile, affected: list[str]) -> int:
    return int(manifest.multi_tenant or bool(profile.sensitive))


def _adjust_high_stakes(
    manifest: SystemManifest, profile: SystemProfile, affected: list[str]
) -> int:
    return int(manifest.high_stakes)


def _adjust_exposed(manifest: SystemManifest, profile: SystemProfile, affected: list[str]) -> int:
    return int(any(a in set(profile.exposed) for a in affected))


def _adjust_unencrypted_sensitive(
    manifest: SystemManifest, profile: SystemProfile, affected: list[str]
) -> int:
    return int(any(not f.encrypted and SENSITIVE_DATA & set(f.data) for f in manifest.flows))


# Architecture evaluators


def _eval_authentication(
    manifest: SystemManifest, profile: SystemProfile, affected: list[str]
) -> tuple[float, list[str]]:
    total = len(profile.crossings)
    failing = [c for c in profile.crossings if not c.authenticated]
    evidence = [
        f"{c.source} -> {c.target} crosses {c.from_zone.value} to {c.to_zone.value} without authentication"
        for c in failing
    ]
    return (total - len(failing)) / total if total else 1.0, evidence


def _eval_encryption(
    manifest: SystemManifest, profile: SystemProfile, affected: list[str]
) -> tuple[float, list[str]]:
    crossing = {(c.source, c.target) for c in profile.crossings}
    relevant = [
        f
        for f in manifest.flows
        if (f.source, f.target) in crossing or SENSITIVE_DATA & set(f.data)
    ]
    failing = [f for f in relevant if not f.encrypted]
    evidence = [
        f"{f.source} -> {f.target} is not encrypted"
        + (
            " and carries " + ", ".join(sorted(d.value for d in f.data if d in SENSITIVE_DATA))
            if SENSITIVE_DATA & set(f.data)
            else ""
        )
        for f in failing
    ]
    return (len(relevant) - len(failing)) / len(relevant) if relevant else 1.0, evidence


# Built-in checks


def default_registry() -> CheckRegistry:
    """Return a registry containing every built-in check."""
    registry = CheckRegistry()
    for check in _BUILTIN:
        registry.register(check)
    return registry


_BUILTIN: tuple[Check, ...] = (
    Check(
        id="LLM01-01",
        title="Untrusted input reaches the model without injection defenses",
        category="owasp",
        owasp=("LLM01",),
        stride=("T",),
        atlas=("AML.T0051",),
        base_severity=Severity.HIGH,
        controls=("input_filtering", "prompt_isolation"),
        applies=_models,
        adjust=_adjust_injection,
        description="Crafted user input can override instructions and steer model behaviour.",
        recommendation="Screen inputs, keep system instructions separate from user content, and limit what a hijacked model can do.",
        skip_reason="No model or agent component declared.",
    ),
    Check(
        id="LLM01-02",
        title="Indirect prompt injection through retrieved or external content",
        category="owasp",
        owasp=("LLM01",),
        stride=("T",),
        atlas=("AML.T0051",),
        base_severity=Severity.HIGH,
        controls=("prompt_isolation", "rag_content_screening"),
        applies=_indirect_targets,
        description="Documents, web pages and tool results placed in the prompt can carry hidden instructions.",
        recommendation="Label retrieved content as untrusted, screen it before use, and strip active content and instructions.",
        skip_reason="No retrieval, tool or external content flows into a model.",
    ),
    Check(
        id="LLM02-01",
        title="Sensitive data may be disclosed through model responses",
        category="owasp",
        owasp=("LLM02",),
        stride=("I",),
        atlas=("AML.T0057",),
        base_severity=Severity.HIGH,
        controls=("pii_redaction", "data_loss_prevention", "access_control_on_data"),
        applies=_sensitive_components,
        adjust=_adjust_sensitive,
        description="Personal, regulated or secret data reachable by the model can leak in responses or logs.",
        recommendation="Minimise and redact sensitive data, filter by caller authorisation, and scan outputs before release.",
        skip_reason="No component handles sensitive data classes.",
    ),
    Check(
        id="LLM02-02",
        title="Sensitive data is sent to a third party without review or retention controls",
        category="owasp",
        owasp=("LLM02", "LLM03"),
        stride=("I",),
        base_severity=Severity.MEDIUM,
        controls=("third_party_review", "data_retention_policy"),
        applies=_sensitive_to_third_party,
        adjust=_adjust_unencrypted_sensitive,
        description="Data shared with hosted model or service providers leaves your control.",
        recommendation="Complete a provider security and privacy review, restrict retention, and send only the data required.",
        skip_reason="No sensitive data flows to third-party components.",
    ),
    Check(
        id="LLM03-01",
        title="Model and dependency supply chain is not verified",
        category="owasp",
        owasp=("LLM03",),
        stride=("T",),
        atlas=("AML.T0010",),
        base_severity=Severity.MEDIUM,
        controls=("dependency_scanning", "model_provenance", "sbom"),
        applies=_supply_chain,
        adjust=_adjust_supply,
        description="Models, adapters, datasets and libraries can be tampered with or carry known vulnerabilities.",
        recommendation="Pin and verify model artefacts, scan dependencies, and maintain a bill of materials.",
        skip_reason="No model, registry or external dependency declared.",
    ),
    Check(
        id="LLM04-01",
        title="Training, fine-tuning or index data is exposed to poisoning",
        category="owasp",
        owasp=("LLM04",),
        stride=("T",),
        atlas=("AML.T0020",),
        base_severity=Severity.MEDIUM,
        controls=("training_data_validation", "data_integrity_monitoring"),
        applies=_poisonable,
        adjust=_adjust_poison,
        description="Malicious or corrupted data can bias outputs or plant backdoors.",
        recommendation="Vet data sources, validate and version datasets, and monitor for anomalous changes.",
        skip_reason="No training pipeline or vector store declared.",
    ),
    Check(
        id="LLM05-01",
        title="Model output is used downstream without validation or encoding",
        category="owasp",
        owasp=("LLM05",),
        stride=("T", "E"),
        base_severity=Severity.HIGH,
        controls=("output_validation", "output_encoding"),
        applies=_model_output_sinks,
        adjust=_adjust_output,
        description="Output rendered, queried or executed downstream can trigger injection or unsafe actions.",
        recommendation="Treat model output as untrusted input: validate against schemas and encode for the destination.",
        skip_reason="Model output does not flow into a UI, API, tool or executor.",
    ),
    Check(
        id="LLM06-01",
        title="Agent and tool permissions are broader than necessary",
        category="owasp",
        owasp=("LLM06",),
        stride=("E",),
        base_severity=Severity.HIGH,
        controls=("least_privilege_tools", "tool_allowlist", "human_approval"),
        applies=_agency,
        adjust=_adjust_agency,
        description="A model with excess functionality or autonomy can be driven to take damaging actions.",
        recommendation="Grant minimum permissions, allowlist tools and arguments, and require approval for high-impact actions.",
        skip_reason="No agent, tool or executor declared.",
    ),
    Check(
        id="LLM06-02",
        title="Model-driven code or command execution is not sandboxed",
        category="owasp",
        owasp=("LLM05", "LLM06"),
        stride=("E",),
        base_severity=Severity.CRITICAL,
        controls=("sandboxed_execution",),
        applies=_executors,
        description="Executing model-generated code outside isolation gives an attacker code execution.",
        recommendation="Run generated code in an isolated, network-restricted, resource-limited sandbox with no ambient credentials.",
        skip_reason="No component executes code or commands.",
    ),
    Check(
        id="LLM07-01",
        title="System prompt can leak and may contain sensitive material",
        category="owasp",
        owasp=("LLM07",),
        stride=("I",),
        atlas=("AML.T0056",),
        base_severity=Severity.MEDIUM,
        controls=("secrets_out_of_prompts", "prompt_leak_testing"),
        applies=_models,
        adjust=_adjust_prompt_leak,
        description="System prompts are routinely extractable; secrets or access rules placed there are exposed.",
        recommendation="Keep credentials and authorisation logic out of prompts and test extraction resistance.",
        skip_reason="No model or agent component declared.",
    ),
    Check(
        id="LLM08-01",
        title="Vector store lacks per-user access control or tenant isolation",
        category="owasp",
        owasp=("LLM08",),
        stride=("I",),
        base_severity=Severity.MEDIUM,
        controls=("access_control_on_data", "tenant_isolation"),
        applies=_retrieval,
        adjust=_adjust_retrieval,
        description="Shared indexes can return one user's or tenant's content to another.",
        recommendation="Enforce authorisation at retrieval time and isolate embeddings per tenant or permission domain.",
        skip_reason="No vector store or retriever declared.",
    ),
    Check(
        id="LLM09-01",
        title="Answers are not grounded or reviewed",
        category="owasp",
        owasp=("LLM09",),
        stride=("T",),
        base_severity=Severity.MEDIUM,
        controls=("grounding_citations", "human_review_high_stakes"),
        applies=_models,
        adjust=_adjust_high_stakes,
        description="Fluent but incorrect output can mislead users and drive bad decisions.",
        recommendation="Ground answers in cited sources, verify claims and require human review for high-stakes use.",
        skip_reason="No model or agent component declared.",
    ),
    Check(
        id="LLM10-01",
        title="Model usage is not bounded",
        category="owasp",
        owasp=("LLM10",),
        stride=("D",),
        base_severity=Severity.MEDIUM,
        controls=("rate_limiting", "token_budgets", "cost_monitoring"),
        applies=_models,
        adjust=_adjust_exposed,
        description="Unbounded requests, large inputs or agent loops enable denial of service and runaway cost.",
        recommendation="Enforce rate limits, input and output caps and step budgets, and alert on spend.",
        skip_reason="No model or agent component declared.",
    ),
    Check(
        id="ARCH-01",
        title="Flows cross trust boundaries without authentication",
        category="architecture",
        stride=("S",),
        base_severity=Severity.HIGH,
        applies=_boundary_targets,
        evaluator=_eval_authentication,
        description="Unauthenticated calls across trust zones allow spoofed callers and unauthorised use.",
        recommendation="Require mutual authentication or signed tokens on every cross-boundary flow.",
        skip_reason="No flows cross trust boundaries.",
    ),
    Check(
        id="ARCH-02",
        title="Boundary-crossing or sensitive flows are not encrypted",
        category="architecture",
        stride=("T", "I"),
        base_severity=Severity.MEDIUM,
        applies=_sensitive_or_crossing_flows,
        adjust=_adjust_unencrypted_sensitive,
        evaluator=_eval_encryption,
        description="Unencrypted flows can be read or altered in transit.",
        recommendation="Use TLS for every cross-boundary flow and for any flow carrying sensitive data.",
        skip_reason="No cross-boundary or sensitive flows declared.",
    ),
    Check(
        id="GOV-01",
        title="No post-deployment logging and monitoring of model activity",
        category="governance",
        stride=("R",),
        base_severity=Severity.MEDIUM,
        controls=("logging_monitoring",),
        applies=_models,
        description="Without audit trails, abuse and failures cannot be detected or attributed.",
        recommendation="Log prompts, tool calls and decisions with redaction, and alert on anomalies.",
        skip_reason="No model or agent component declared.",
    ),
    Check(
        id="GOV-02",
        title="No AI-specific incident response process",
        category="governance",
        base_severity=Severity.MEDIUM,
        controls=("incident_response",),
        applies=_models,
        description="AI incidents such as prompt injection campaigns or data leaks need defined playbooks.",
        recommendation="Define roles, containment steps (for example disabling a tool) and exercise the process.",
        skip_reason="No model or agent component declared.",
    ),
    Check(
        id="GOV-03",
        title="No adversarial testing programme",
        category="governance",
        base_severity=Severity.MEDIUM,
        controls=("red_team_testing",),
        applies=_models,
        description="Controls are unproven until tested against realistic attacks.",
        recommendation="Run red-team exercises before release and after material changes.",
        skip_reason="No model or agent component declared.",
    ),
    Check(
        id="GOV-04",
        title="Model quality and safety are not evaluated against documented metrics",
        category="governance",
        base_severity=Severity.LOW,
        controls=("model_evaluation",),
        applies=_models,
        adjust=_adjust_high_stakes,
        description="Without metrics, regressions and unsafe behaviour go unnoticed.",
        recommendation="Define and track quality and safety metrics with regression tests.",
        skip_reason="No model or agent component declared.",
    ),
    Check(
        id="GOV-05",
        title="Governance policy, use case and impact are not documented",
        category="governance",
        base_severity=Severity.LOW,
        controls=("governance_policy", "use_case_documented", "impact_assessment"),
        applies=_nothing,
        always=True,
        description="Accountability, intended use and impact assessment underpin every other control.",
        recommendation="Assign an accountable owner, document intended use and complete an impact assessment.",
        skip_reason="Always applicable.",
    ),
)
