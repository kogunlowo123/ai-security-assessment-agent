"""Domain models: system manifest, discovery profile, findings and the assessment report."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aisa.catalog import CONTROL_IDS

_ID_PATTERN = r"^[a-z][a-z0-9_-]{1,40}$"


class Severity(str, Enum):
    """Finding severity, ordered from most to least serious."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Higher is more severe."""
        return _RANK[self]

    @property
    def penalty(self) -> int:
        """Points deducted from the posture score for one finding of this severity."""
        return _PENALTY[self]


_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_PENALTY = {
    Severity.INFO: 0,
    Severity.LOW: 2,
    Severity.MEDIUM: 5,
    Severity.HIGH: 12,
    Severity.CRITICAL: 25,
}
_BY_RANK = {rank: sev for sev, rank in _RANK.items()}


def shift_severity(severity: Severity, delta: int) -> Severity:
    """Move ``severity`` by ``delta`` steps, clamped between LOW and CRITICAL."""
    rank = min(max(severity.rank + delta, Severity.LOW.rank), Severity.CRITICAL.rank)
    return _BY_RANK[rank]


class ControlStatus(str, Enum):
    """How completely a control is implemented."""

    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    ABSENT = "absent"
    UNKNOWN = "unknown"

    @property
    def credit(self) -> float:
        """Share of the control's value counted toward posture (unknown counts as none)."""
        return {"implemented": 1.0, "partial": 0.5}.get(self.value, 0.0)


class ComponentType(str, Enum):
    """Kinds of building block in an AI system."""

    LLM = "llm"
    AGENT = "agent"
    TOOL = "tool"
    RETRIEVER = "retriever"
    VECTOR_STORE = "vector_store"
    DATA_STORE = "data_store"
    TRAINING_PIPELINE = "training_pipeline"
    MODEL_REGISTRY = "model_registry"
    API = "api"
    UI = "ui"
    CODE_EXECUTOR = "code_executor"
    EXTERNAL_SERVICE = "external_service"


class TrustZone(str, Enum):
    """Network and organisational trust zones."""

    INTERNET = "internet"
    DMZ = "dmz"
    INTERNAL = "internal"
    THIRD_PARTY = "third_party"


class DataClass(str, Enum):
    """Data sensitivity classes."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PII = "pii"
    PHI = "phi"
    PCI = "pci"
    SECRETS = "secrets"


SENSITIVE_DATA = frozenset({DataClass.PII, DataClass.PHI, DataClass.PCI, DataClass.SECRETS})
HIGH_RISK_CAPABILITIES = frozenset({"write", "delete", "exec", "payments", "email"})
ALLOWED_CAPABILITIES = frozenset({"read", "network"}) | HIGH_RISK_CAPABILITIES


class Component(BaseModel):
    """One element of the assessed system."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=_ID_PATTERN)
    name: str = Field(min_length=1, max_length=120)
    type: ComponentType
    trust_zone: TrustZone = TrustZone.INTERNAL
    data_classes: list[DataClass] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)

    @field_validator("capabilities")
    @classmethod
    def _known_capabilities(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - ALLOWED_CAPABILITIES)
        if unknown:
            raise ValueError(
                f"unknown capabilities {unknown}; allowed: {sorted(ALLOWED_CAPABILITIES)}"
            )
        return value


class Flow(BaseModel):
    """A directed data flow between two components."""

    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    data: list[DataClass] = Field(default_factory=list)
    authenticated: bool = False
    encrypted: bool = False


class SystemManifest(BaseModel):
    """Declarative description of the AI system under assessment."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)
    multi_tenant: bool = False
    high_stakes: bool = False
    components: list[Component] = Field(min_length=1, max_length=200)
    flows: list[Flow] = Field(default_factory=list, max_length=1000)
    controls: dict[str, ControlStatus] = Field(default_factory=dict)

    @field_validator("controls", mode="before")
    @classmethod
    def _coerce_controls(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            raise ValueError("controls must be a mapping of control id to status")
        unknown = sorted(set(value) - CONTROL_IDS)
        if unknown:
            raise ValueError(f"unknown controls {unknown}; run `aisa checks` to list valid ids")
        return {
            k: ("implemented" if v is True else "absent" if v is False else v)
            for k, v in value.items()
        }

    @model_validator(mode="after")
    def _check_references(self) -> SystemManifest:
        ids = [c.id for c in self.components]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        if duplicates:
            raise ValueError(f"duplicate component ids: {duplicates}")
        known = set(ids)
        for flow in self.flows:
            for endpoint in (flow.source, flow.target):
                if endpoint not in known:
                    raise ValueError(f"flow references unknown component: {endpoint}")
        return self

    def status_of(self, control: str) -> ControlStatus:
        """Return the declared status of ``control`` (UNKNOWN when not declared)."""
        return self.controls.get(control, ControlStatus.UNKNOWN)


class BoundaryCrossing(BaseModel):
    """A flow that crosses between trust zones."""

    source: str
    target: str
    from_zone: TrustZone
    to_zone: TrustZone
    authenticated: bool
    encrypted: bool
    data: list[DataClass] = Field(default_factory=list)


class SystemProfile(BaseModel):
    """Discovery agent output: inventory, exposure and attack surface."""

    component_count: int
    counts_by_type: dict[str, int]
    internet_facing: list[str]
    exposed: list[str]
    third_party: list[str]
    sensitive: list[str]
    agentic: bool
    has_rag: bool
    has_training: bool
    high_risk_tools: list[str]
    crossings: list[BoundaryCrossing]
    data_classes: list[str]

    def ids(self, manifest: SystemManifest, *types: ComponentType) -> list[str]:
        """Ids of components of the given types, in manifest order."""
        return [c.id for c in manifest.components if c.type in types]


class PlannedCheck(BaseModel):
    """A check selected for execution together with the components it concerns."""

    id: str
    affected: list[str]


class AssessmentPlan(BaseModel):
    """Planner agent output."""

    frameworks: list[str]
    checks: list[PlannedCheck]
    skipped: dict[str, str]


class Threat(BaseModel):
    """A STRIDE threat derived from the architecture."""

    id: str
    stride: str
    title: str
    description: str
    targets: list[str]
    severity: Severity
    atlas: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """A control gap or architectural weakness."""

    id: str
    title: str
    category: str
    severity: Severity
    owasp: list[str] = Field(default_factory=list)
    stride: list[str] = Field(default_factory=list)
    nist: list[str] = Field(default_factory=list)
    atlas: list[str] = Field(default_factory=list)
    description: str
    evidence: list[str]
    recommendation: str
    affected: list[str] = Field(default_factory=list)
    controls: dict[str, str] = Field(default_factory=dict)


class ControlGap(BaseModel):
    """A control that is not fully implemented, with its NIST references."""

    control: str
    status: str
    nist: list[str]


class FunctionCoverage(BaseModel):
    """Coverage of one NIST AI RMF function."""

    score: float
    controls_total: int
    controls_implemented: int
    gaps: list[ControlGap]


class ComplianceSummary(BaseModel):
    """Compliance agent output."""

    functions: dict[str, FunctionCoverage]
    overall: float


class EvaluationIssue(BaseModel):
    """A defect found by the evaluator agent in the assessment itself."""

    severity: str
    message: str


class EvaluationReport(BaseModel):
    """Evaluator agent output."""

    passed: bool
    issues: list[EvaluationIssue] = Field(default_factory=list)


class TraceEvent(BaseModel):
    """One executed workflow node."""

    node: str
    detail: str = ""
    duration_ms: float = 0.0


class AssessmentReport(BaseModel):
    """Complete, serialisable assessment result."""

    schema_version: str = "1.0"
    tool_version: str
    system: str
    generated_at: datetime
    profile: SystemProfile
    plan: AssessmentPlan
    threats: list[Threat]
    findings: list[Finding]
    passed_checks: list[str]
    compliance: ComplianceSummary
    posture_score: int
    rating: str
    executive_summary: str
    evaluation: EvaluationReport
    trace: list[TraceEvent] = Field(default_factory=list)

    def counts(self) -> dict[str, int]:
        """Number of findings per severity."""
        result = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            result[finding.severity.value] += 1
        return result
