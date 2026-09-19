"""Exception hierarchy for the aisa package."""

from __future__ import annotations


class AisaError(Exception):
    """Base class for all errors raised deliberately by aisa."""


class ConfigurationError(AisaError):
    """Raised when settings are missing, inconsistent or invalid."""


class ManifestError(AisaError):
    """Raised when a system manifest cannot be read or fails validation."""


class ProviderError(AisaError):
    """Raised when an upstream model provider returns a non-retryable failure."""


class TransientProviderError(ProviderError):
    """Raised for retryable upstream failures such as rate limits or 5xx responses."""


class GraphError(AisaError):
    """Raised when the workflow graph is mis-wired or exceeds its step budget."""


class ReportError(AisaError):
    """Raised when a report cannot be rendered or written."""
