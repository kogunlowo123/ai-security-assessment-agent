"""Threat-model agent: derives STRIDE threats from the architecture."""

from __future__ import annotations

from aisa.agents.state import AssessmentState
from aisa.models import (
    HIGH_RISK_CAPABILITIES,
    SENSITIVE_DATA,
    ComponentType,
    ControlStatus,
    Severity,
    SystemManifest,
    SystemProfile,
    Threat,
)

T = ComponentType


class _Builder:
    """Accumulates threats with sequential ids."""

    def __init__(self) -> None:
        self.threats: list[Threat] = []

    def add(
        self,
        stride: str,
        title: str,
        description: str,
        targets: list[str],
        severity: Severity,
        atlas: list[str] | None = None,
    ) -> None:
        self.threats.append(
            Threat(
                id=f"T-{len(self.threats) + 1:03d}",
                stride=stride,
                title=title,
                description=description,
                targets=targets,
                severity=severity,
                atlas=atlas or [],
            )
        )


def derive_threats(manifest: SystemManifest, profile: SystemProfile) -> list[Threat]:
    """Apply STRIDE rules to the manifest and profile."""
    out = _Builder()
    exposed = set(profile.exposed)
    by_id = {c.id: c for c in manifest.components}
    models = [c for c in manifest.components if c.type in {T.LLM, T.AGENT}]

    for crossing in profile.crossings:
        if not crossing.authenticated:
            out.add(
                "S",
                f"Unauthenticated flow {crossing.source} to {crossing.target}",
                f"A caller can impersonate {crossing.source} because the flow crossing "
                f"{crossing.from_zone.value} to {crossing.to_zone.value} is not authenticated.",
                [crossing.source, crossing.target],
                Severity.HIGH if crossing.target in exposed else Severity.MEDIUM,
            )
        sensitive = SENSITIVE_DATA & set(crossing.data)
        if not crossing.encrypted:
            out.add(
                "I" if sensitive else "T",
                f"Unencrypted flow {crossing.source} to {crossing.target}",
                "Traffic can be read or modified in transit"
                + (
                    f"; it carries {', '.join(sorted(d.value for d in sensitive))}."
                    if sensitive
                    else "."
                ),
                [crossing.source, crossing.target],
                Severity.HIGH if sensitive else Severity.MEDIUM,
            )

    for model in models:
        out.add(
            "T",
            f"Prompt injection alters behaviour of {model.id}",
            "Instructions embedded in user input or retrieved content can override intended behaviour.",
            [model.id],
            Severity.HIGH if model.id in exposed else Severity.MEDIUM,
            ["AML.T0051"],
        )
        if "secrets" in {d.value for d in model.data_classes}:
            out.add(
                "I",
                f"System prompt of {model.id} exposes secrets",
                "The model's instructions contain secrets that can be extracted by prompting.",
                [model.id],
                Severity.HIGH,
                ["AML.T0056"],
            )
        if (
            model.id in exposed
            and manifest.status_of("rate_limiting") is not ControlStatus.IMPLEMENTED
        ):
            out.add(
                "D",
                f"Resource exhaustion against {model.id}",
                "Unthrottled requests or oversized inputs can exhaust capacity and budget.",
                [model.id],
                Severity.MEDIUM,
            )

    for comp in manifest.components:
        if comp.type is T.TRAINING_PIPELINE:
            out.add(
                "T",
                f"Poisoned data corrupts {comp.id}",
                "Malicious training or fine-tuning data can bias the model or plant backdoors.",
                [comp.id],
                Severity.MEDIUM,
                ["AML.T0020"],
            )
        if comp.type is T.VECTOR_STORE and comp.id in exposed:
            out.add(
                "T",
                f"Index {comp.id} poisoned with hostile content",
                "Content added to the index can inject instructions into later prompts.",
                [comp.id],
                Severity.MEDIUM,
            )
        if SENSITIVE_DATA & set(comp.data_classes) and comp.id in exposed:
            out.add(
                "I",
                f"Sensitive data in {comp.id} disclosed via model output",
                "Data reachable from an internet-originated request can appear in responses.",
                [comp.id],
                Severity.HIGH,
                ["AML.T0057"],
            )
        if comp.type in {T.TOOL, T.CODE_EXECUTOR} and (
            comp.type is T.CODE_EXECUTOR or HIGH_RISK_CAPABILITIES & set(comp.capabilities)
        ):
            unguarded = manifest.status_of("human_approval") is not ControlStatus.IMPLEMENTED
            out.add(
                "E",
                f"Model-driven misuse of {comp.id}",
                "A manipulated model can invoke a high-impact capability"
                + (" without human approval." if unguarded else "."),
                [comp.id],
                Severity.CRITICAL if comp.id in exposed and unguarded else Severity.HIGH,
            )
        if comp.trust_zone.value == "third_party" or comp.type is T.MODEL_REGISTRY:
            out.add(
                "T",
                f"Compromised model or dependency via {comp.id}",
                "A tampered model, adapter or package can alter behaviour or exfiltrate data.",
                [comp.id],
                Severity.MEDIUM,
                ["AML.T0010"],
            )

    if models and manifest.status_of("logging_monitoring") is not ControlStatus.IMPLEMENTED:
        out.add(
            "R",
            "Model actions cannot be attributed",
            "Without audit logging, malicious or erroneous actions cannot be traced to a request or user.",
            [m.id for m in models if m.id in by_id],
            Severity.MEDIUM,
        )
    return out.threats


class ThreatModelAgent:
    """Workflow node that populates ``state.threats``."""

    def run(self, state: AssessmentState) -> AssessmentState:
        assert state.profile is not None, "discovery must run before threat modelling"
        state.threats = derive_threats(state.manifest, state.profile)
        letters = sorted({t.stride for t in state.threats})
        state.note = (
            f"{len(state.threats)} threats across STRIDE categories {''.join(letters) or '-'}"
        )
        return state
