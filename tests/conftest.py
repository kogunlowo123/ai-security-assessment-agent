"""Shared fixtures and fakes."""

from __future__ import annotations

import copy
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest

from aisa.config import Settings
from aisa.models import SystemManifest
from aisa.providers.http import JsonClient
from aisa.service import parse_manifest

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFESTS = REPO_ROOT / "manifests"
FIXED_TIME = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

BASE_MANIFEST: dict[str, Any] = {
    "name": "Test System",
    "components": [
        {"id": "ui", "name": "UI", "type": "ui", "trust_zone": "internet"},
        {"id": "llm", "name": "LLM", "type": "llm", "trust_zone": "internal"},
    ],
    "flows": [{"source": "ui", "target": "llm", "authenticated": True, "encrypted": True}],
    "controls": {},
}


def manifest_data(**overrides: Any) -> dict[str, Any]:
    """A minimal valid manifest dict with top-level keys replaced by ``overrides``."""
    data = copy.deepcopy(BASE_MANIFEST)
    data.update(overrides)
    return data


def make_manifest(**overrides: Any) -> SystemManifest:
    """A validated manifest built from :func:`manifest_data`."""
    return parse_manifest(manifest_data(**overrides))


def make_settings(tmp_path: Path, **overrides: object) -> Settings:
    """Settings that ignore the developer's environment and .env file."""
    base: dict[str, object] = {
        "history_dir": tmp_path / "history",
        "retry_min_wait": 0.0,
        "retry_max_wait": 0.0,
        "log_level": "CRITICAL",
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


def json_client(
    handler: Callable[[httpx.Request], httpx.Response], attempts: int = 2
) -> JsonClient:
    """A JsonClient backed by an in-process mock transport."""
    return JsonClient(
        httpx.Client(transport=httpx.MockTransport(handler)),
        attempts=attempts,
        min_wait=0.0,
        max_wait=0.0,
    )


class FakeLLM:
    """Scripted LLM that records prompts."""

    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        return self.reply


@pytest.fixture
def weak_manifest_path() -> Path:
    return MANIFESTS / "customer-support-rag.yaml"


@pytest.fixture
def hardened_manifest_path() -> Path:
    return MANIFESTS / "hardened-research-agent.yaml"
