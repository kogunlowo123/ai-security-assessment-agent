# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-09-19

### Added

- Seven-agent assessment pipeline: discovery, planner, threat model, assessor, compliance, evaluator
  and report.
- 20 built-in checks: 13 mapped to the OWASP Top 10 for LLM Applications (2025), 2 architecture checks
  on authentication and encryption of flows, and 5 governance checks.
- Catalog of 34 controls mapped to OWASP LLM and NIST AI RMF references.
- STRIDE threat derivation with MITRE ATLAS reference tags.
- Exposure-aware severity, exponential posture score and NIST AI RMF per-function coverage.
- Evaluator quality gate that flags untraceable or incomplete findings.
- Markdown, JSON and SARIF 2.1.0 reports; history store with diff and regression detection.
- Optional OpenAI or Anthropic narrative summary, accepted only when grounded in the supplied facts.
- `aisa` CLI (`assess`, `validate`, `checks`, `diff`) with CI-friendly exit codes.
- Sample manifests, Dockerfile, Makefile and GitHub Actions workflows for lint, format, types, tests,
  dependency audit, CodeQL and build validation.
