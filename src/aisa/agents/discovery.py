"""Discovery agent: builds the system inventory, exposure map and attack surface."""

from __future__ import annotations

from collections import Counter, deque

from aisa.agents.state import AssessmentState
from aisa.models import (
    HIGH_RISK_CAPABILITIES,
    SENSITIVE_DATA,
    BoundaryCrossing,
    ComponentType,
    SystemManifest,
    SystemProfile,
    TrustZone,
)


def _reachable_from_internet(manifest: SystemManifest) -> list[str]:
    """Components an internet-originated request can reach by following declared flows."""
    graph: dict[str, list[str]] = {c.id: [] for c in manifest.components}
    for flow in manifest.flows:
        graph[flow.source].append(flow.target)
    start = [c.id for c in manifest.components if c.trust_zone is TrustZone.INTERNET]
    seen = set(start)
    queue = deque(start)
    while queue:
        for nxt in graph[queue.popleft()]:
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return [c.id for c in manifest.components if c.id in seen]


def build_profile(manifest: SystemManifest) -> SystemProfile:
    """Derive a :class:`SystemProfile` from the declared manifest."""
    by_id = {c.id: c for c in manifest.components}
    types = {c.type for c in manifest.components}
    acting = {ComponentType.TOOL, ComponentType.CODE_EXECUTOR, ComponentType.AGENT}

    crossings = [
        BoundaryCrossing(
            source=f.source,
            target=f.target,
            from_zone=by_id[f.source].trust_zone,
            to_zone=by_id[f.target].trust_zone,
            authenticated=f.authenticated,
            encrypted=f.encrypted,
            data=f.data,
        )
        for f in manifest.flows
        if by_id[f.source].trust_zone is not by_id[f.target].trust_zone
    ]
    model_to_tool = any(
        by_id[f.source].type in {ComponentType.LLM, ComponentType.AGENT}
        and by_id[f.target].type in {ComponentType.TOOL, ComponentType.CODE_EXECUTOR}
        for f in manifest.flows
    )
    classes = {d.value for c in manifest.components for d in c.data_classes}
    classes |= {d.value for f in manifest.flows for d in f.data}

    return SystemProfile(
        component_count=len(manifest.components),
        counts_by_type=dict(sorted(Counter(c.type.value for c in manifest.components).items())),
        internet_facing=[c.id for c in manifest.components if c.trust_zone is TrustZone.INTERNET],
        exposed=_reachable_from_internet(manifest),
        third_party=[c.id for c in manifest.components if c.trust_zone is TrustZone.THIRD_PARTY],
        sensitive=[c.id for c in manifest.components if SENSITIVE_DATA & set(c.data_classes)],
        agentic=ComponentType.AGENT in types or model_to_tool,
        has_rag=bool({ComponentType.VECTOR_STORE, ComponentType.RETRIEVER} & types),
        has_training=ComponentType.TRAINING_PIPELINE in types,
        high_risk_tools=[
            c.id
            for c in manifest.components
            if c.type is ComponentType.CODE_EXECUTOR
            or (c.type in acting and HIGH_RISK_CAPABILITIES & set(c.capabilities))
        ],
        crossings=crossings,
        data_classes=sorted(classes),
    )


class DiscoveryAgent:
    """Workflow node that populates ``state.profile``."""

    def run(self, state: AssessmentState) -> AssessmentState:
        state.profile = build_profile(state.manifest)
        profile = state.profile
        state.note = (
            f"{profile.component_count} components, {len(profile.exposed)} exposed, "
            f"{len(profile.crossings)} boundary crossings"
        )
        return state
