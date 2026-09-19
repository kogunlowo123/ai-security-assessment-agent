"""Manifest loading safeguards, secret redaction and untrusted-text handling.

Manifests are untrusted input: they may be large, malformed, contain credentials, or carry text
crafted to steer a language model that later reads component names. This module bounds size,
parses YAML safely, redacts credentials and neutralises labels before they reach a model.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from aisa.errors import ManifestError

REDACTION = "[REDACTED]"

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{16,}"),
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END "
        r"(?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    ),
    re.compile(
        r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"]?"
        r"(?!\[REDACTED\])[^\s'\",;]{6,}"
    ),
)

_INJECTION = re.compile(
    r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|all|any)\b"
    r"[^.\n]{0,40}\b(instructions?|rules?|prompts?)\b|\byou\s+are\s+now\b|"
    r"\b(reveal|print|show|leak)\b[^.\n]{0,30}\b(system\s+prompt|api\s+key|secret)\b|"
    r"<\s*/?\s*(system|assistant|developer)\s*>",
    re.IGNORECASE,
)
_SAFE_LABEL = re.compile(r"[^A-Za-z0-9 ._\-]")


def redact_secrets(text: str) -> tuple[str, int]:
    """Replace credential-shaped substrings and return the text with the substitution count."""
    total = 0
    for pattern in _SECRET_PATTERNS:
        text, count = pattern.subn(_replacement, text)
        total += count
    return text, total


def _replacement(match: re.Match[str]) -> str:
    key = re.match(r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]", match.group(0))
    return f"{key.group(0)} {REDACTION}" if key else REDACTION


def redact(text: str) -> str:
    """Return ``text`` with credential-shaped substrings replaced."""
    return redact_secrets(text)[0]


def looks_like_injection(text: str) -> bool:
    """True when ``text`` contains phrasing aimed at steering a language model."""
    return bool(_INJECTION.search(text))


def sanitize_label(text: str, *, max_length: int = 60) -> str:
    """Reduce a user-supplied label to a short, inert string safe to embed in a model prompt."""
    if looks_like_injection(text):
        return "[withheld]"
    cleaned = _SAFE_LABEL.sub("", text).strip()
    return cleaned[:max_length] or "[unnamed]"


def load_manifest_data(path: Path, *, max_bytes: int) -> dict[str, Any]:
    """Read and parse a JSON or YAML manifest from disk.

    Raises:
        ManifestError: If the file is missing, too large, unparsable or not a mapping.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ManifestError(f"cannot read manifest {path}: {exc.strerror or exc}") from exc
    if size > max_bytes:
        raise ManifestError(f"manifest is {size} bytes, limit is {max_bytes}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        raise ManifestError(f"cannot read manifest {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ManifestError(f"manifest is not valid YAML or JSON: {redact(str(exc))}") from exc
    if not isinstance(data, dict):
        raise ManifestError("manifest must be a mapping at the top level")
    return data
