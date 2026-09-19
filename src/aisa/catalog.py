"""Framework catalog: OWASP LLM risks, STRIDE, NIST AI RMF functions and security controls.

Framework identifiers follow OWASP Top 10 for LLM Applications (2025), NIST AI RMF 1.0 and MITRE
ATLAS. Where a control maps to a whole NIST function rather than a specific subcategory, the
reference is the bare function name (for example ``MANAGE``). Verify identifiers against the
current published framework text before citing them in an audit.
"""

from __future__ import annotations

from typing import NamedTuple

OWASP_LLM: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

NIST_FUNCTIONS: tuple[str, ...] = ("GOVERN", "MAP", "MEASURE", "MANAGE")

STRIDE: dict[str, str] = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information disclosure",
    "D": "Denial of service",
    "E": "Elevation of privilege",
}


class ControlSpec(NamedTuple):
    """A security control an assessed system may or may not implement."""

    description: str
    owasp: tuple[str, ...]
    nist: tuple[str, ...]


def nist_function(reference: str) -> str:
    """Return the NIST AI RMF function (``GOVERN``...``MANAGE``) of a reference like ``MEASURE 2.7``."""
    return reference.split()[0]


CONTROLS: dict[str, ControlSpec] = {
    "input_filtering": ControlSpec(
        "User input is screened for injection and abuse patterns before reaching the model",
        ("LLM01",),
        ("MEASURE 2.7",),
    ),
    "prompt_isolation": ControlSpec(
        "System instructions, user input and retrieved content are separated and labelled untrusted",
        ("LLM01", "LLM07"),
        ("MEASURE 2.7",),
    ),
    "rag_content_screening": ControlSpec(
        "Retrieved and third-party content is screened before it enters the prompt",
        ("LLM01", "LLM08"),
        ("MEASURE 2.7",),
    ),
    "output_validation": ControlSpec(
        "Model output is validated against a schema or policy before downstream use",
        ("LLM05",),
        ("MEASURE 2.7",),
    ),
    "output_encoding": ControlSpec(
        "Model output is encoded or escaped for the context it is rendered or executed in",
        ("LLM05",),
        ("MEASURE 2.7",),
    ),
    "pii_redaction": ControlSpec(
        "Personal and regulated data is redacted or minimised before prompts and logs",
        ("LLM02",),
        ("MEASURE 2.10",),
    ),
    "data_loss_prevention": ControlSpec(
        "Responses are scanned for sensitive data before leaving the trust boundary",
        ("LLM02",),
        ("MEASURE 2.10",),
    ),
    "access_control_on_data": ControlSpec(
        "Data available to the model is filtered by the caller's authorisation",
        ("LLM02", "LLM08"),
        ("MEASURE 2.10",),
    ),
    "data_retention_policy": ControlSpec(
        "Retention and deletion rules cover prompts, outputs, embeddings and logs",
        ("LLM02",),
        ("MEASURE 2.10",),
    ),
    "third_party_review": ControlSpec(
        "Third-party model and data providers are reviewed for security and data handling",
        ("LLM02", "LLM03"),
        ("GOVERN 6.1",),
    ),
    "dependency_scanning": ControlSpec(
        "Libraries and containers are scanned for known vulnerabilities",
        ("LLM03",),
        ("GOVERN 6.1",),
    ),
    "model_provenance": ControlSpec(
        "Model artefacts are pinned and verified by hash or signature from a trusted source",
        ("LLM03",),
        ("GOVERN 6.1",),
    ),
    "sbom": ControlSpec(
        "A software and model bill of materials is maintained",
        ("LLM03",),
        ("GOVERN 6.1",),
    ),
    "training_data_validation": ControlSpec(
        "Training, fine-tuning and indexing data is validated and its sources vetted",
        ("LLM04",),
        ("MEASURE 2.5",),
    ),
    "data_integrity_monitoring": ControlSpec(
        "Changes to training data and indexes are tracked and anomalies are detected",
        ("LLM04",),
        ("MEASURE 2.5",),
    ),
    "least_privilege_tools": ControlSpec(
        "Tools and agents hold only the permissions their task requires",
        ("LLM06",),
        ("MEASURE 2.7",),
    ),
    "tool_allowlist": ControlSpec(
        "Only an approved set of tools and arguments can be invoked by the model",
        ("LLM06",),
        ("MEASURE 2.7",),
    ),
    "human_approval": ControlSpec(
        "High-impact actions require explicit human approval",
        ("LLM06",),
        ("MANAGE",),
    ),
    "sandboxed_execution": ControlSpec(
        "Model-generated code and commands run in an isolated, resource-limited sandbox",
        ("LLM05", "LLM06"),
        ("MEASURE 2.7",),
    ),
    "secrets_out_of_prompts": ControlSpec(
        "Credentials and sensitive logic are kept out of system prompts",
        ("LLM07",),
        ("MEASURE 2.7",),
    ),
    "prompt_leak_testing": ControlSpec(
        "System prompt extraction is tested for and mitigated",
        ("LLM07",),
        ("MEASURE 2.7",),
    ),
    "tenant_isolation": ControlSpec(
        "Embeddings and indexes are isolated per tenant or authorisation domain",
        ("LLM08",),
        ("MEASURE 2.10",),
    ),
    "grounding_citations": ControlSpec(
        "Answers are grounded in sources and cite them",
        ("LLM09",),
        ("MEASURE 2.5",),
    ),
    "human_review_high_stakes": ControlSpec(
        "Outputs used in high-stakes decisions are reviewed by a person",
        ("LLM09",),
        ("MANAGE",),
    ),
    "rate_limiting": ControlSpec(
        "Per-user and per-key request rate limits are enforced",
        ("LLM10",),
        ("MEASURE 2.7",),
    ),
    "token_budgets": ControlSpec(
        "Input size, output size and agent step budgets are capped",
        ("LLM10",),
        ("MEASURE 2.7",),
    ),
    "cost_monitoring": ControlSpec(
        "Usage and spend are monitored with alerts",
        ("LLM10",),
        ("MANAGE 4.1",),
    ),
    "logging_monitoring": ControlSpec(
        "Prompts, tool calls and decisions are logged and monitored after deployment",
        (),
        ("MANAGE 4.1",),
    ),
    "incident_response": ControlSpec(
        "An AI-specific incident response process exists and is exercised",
        (),
        ("MANAGE",),
    ),
    "red_team_testing": ControlSpec(
        "Adversarial testing is performed before release and on a schedule",
        (),
        ("MEASURE 2.7",),
    ),
    "model_evaluation": ControlSpec(
        "Model quality and safety are evaluated against documented metrics",
        (),
        ("MEASURE 2.5",),
    ),
    "governance_policy": ControlSpec(
        "An AI governance policy assigns accountability and risk acceptance",
        (),
        ("GOVERN",),
    ),
    "use_case_documented": ControlSpec(
        "Intended purpose, users and deployment context are documented",
        (),
        ("MAP 1.1",),
    ),
    "impact_assessment": ControlSpec(
        "Potential impacts on people and the organisation are assessed",
        (),
        ("MAP",),
    ),
}

CONTROL_IDS: frozenset[str] = frozenset(CONTROLS)
