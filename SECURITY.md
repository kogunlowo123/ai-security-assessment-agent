# Security Policy

## Supported versions

Security fixes are released for the latest minor version on the `main` branch.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

Do not open a public issue for security reports. Use GitHub's private vulnerability reporting (the
**Report a vulnerability** button on this repository's **Security** tab) and include:

- a description of the issue and its impact,
- the affected version or commit,
- a minimal reproduction (manifest, command, configuration),
- any suggested mitigation.

You can expect an acknowledgement within 3 business days and a triage decision within 10 business days.
Confirmed issues are fixed on a private branch, released with an advisory, and credited to the reporter
unless they prefer otherwise.

## Scope

In scope: the `aisa` package, its Docker image and the CI configuration in this repository. Out of
scope: vulnerabilities in third-party model providers or Python itself; report those upstream.

Not a vulnerability: a system receiving a clean report while being insecure. The tool assesses the
declared manifest and states that limit; see the README.

## Security controls

| Threat | Control | Location |
| ------ | ------- | -------- |
| Code execution through YAML | `yaml.safe_load` only | `security.load_manifest_data` |
| Resource exhaustion by large input | Manifest size cap; bounded component, flow and string sizes | `security.py`, `models.py` |
| Malformed or hostile structure | Strict schema, unknown fields rejected, references validated | `models.py` |
| Credentials in manifests | Redacted from errors and logs | `security.redact_secrets`, `logging_setup.py` |
| Prompt injection through manifest text | Labels sanitised; injection-like text withheld; model receives aggregate facts only | `security.sanitize_label`, `agents/report.py` |
| Fabricated model output | Narrative accepted only if every number is in the supplied facts | `LLMSummaryWriter` |
| Path traversal via system name | Fixed report file names; history file names are slugified | `reporting/__init__.py`, `history.py` |
| Markdown or HTML injection in reports | Table cells escaped | `reporting/markdown.py` |
| Upstream instability | Bounded retries on 429 and 5xx only | `retry.py`, `providers/http.py` |
| Vulnerable dependencies | `pip-audit`, CodeQL | `.github/` |
| Container | Multi-stage build, non-root user | `Dockerfile` |

## Known limitations

- Redaction is pattern based and can miss unusual credential formats.
- Injection detection for labels is heuristic; the safer property is that raw manifest text is never
  sent to a model at all.
- Reports contain component names and architecture details. Treat them as sensitive and store them
  accordingly. The history directory is not encrypted.
- `AISA_OPENAI_BASE_URL` and `AISA_ANTHROPIC_BASE_URL` are trusted configuration. Do not let untrusted
  parties set them.
