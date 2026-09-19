"""Composition root: builds an :class:`AssessmentService` from :class:`Settings`."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

import httpx

from aisa.agents import (
    AssessorAgent,
    ComplianceAgent,
    DiscoveryAgent,
    EvaluatorAgent,
    LLMSummaryWriter,
    PlannerAgent,
    ReportAgent,
    SummaryWriter,
    TemplateSummaryWriter,
    ThreatModelAgent,
)
from aisa.checks import CheckRegistry, default_registry
from aisa.config import Settings
from aisa.errors import ConfigurationError
from aisa.pipeline import AssessmentPipeline
from aisa.providers import AnthropicChatClient, JsonClient, LLMClient, OpenAIChatClient
from aisa.service import AssessmentService


def _summary_writer(settings: Settings, http_client: httpx.Client | None) -> SummaryWriter:
    if settings.llm_provider == "none":
        return TemplateSummaryWriter()
    client = JsonClient(
        http_client or httpx.Client(timeout=settings.http_timeout_seconds),
        attempts=settings.retry_attempts,
        min_wait=settings.retry_min_wait,
        max_wait=settings.retry_max_wait,
    )
    llm: LLMClient
    if settings.llm_provider == "openai":
        if settings.openai_api_key is None:
            raise ConfigurationError("AISA_OPENAI_API_KEY must be set when llm_provider=openai")
        llm = OpenAIChatClient(
            client,
            api_key=settings.openai_api_key,
            model=settings.openai_chat_model,
            base_url=settings.openai_base_url,
        )
    else:
        if settings.anthropic_api_key is None:
            raise ConfigurationError(
                "AISA_ANTHROPIC_API_KEY must be set when llm_provider=anthropic"
            )
        llm = AnthropicChatClient(
            client,
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model,
            max_tokens=settings.anthropic_max_tokens,
            base_url=settings.anthropic_base_url,
        )
    return LLMSummaryWriter(llm)


def build_service(
    settings: Settings,
    *,
    registry: CheckRegistry | None = None,
    http_client: httpx.Client | None = None,
    now: Callable[[], datetime] | None = None,
) -> AssessmentService:
    """Assemble the dependency graph.

    Args:
        settings: Validated configuration.
        registry: Custom check registry; defaults to the built-in checks.
        http_client: Optional client, mainly for tests using a mock transport.
        now: Clock override for deterministic reports.

    Raises:
        ConfigurationError: If the selected summary provider is missing its API key.
    """
    checks = registry or default_registry()
    pipeline = AssessmentPipeline(
        DiscoveryAgent(),
        PlannerAgent(checks),
        ThreatModelAgent(),
        AssessorAgent(checks),
        ComplianceAgent(),
        EvaluatorAgent(checks),
        ReportAgent(_summary_writer(settings, http_client), now),
    )
    return AssessmentService(settings, pipeline)
