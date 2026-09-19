# Contributing

Thanks for helping improve this project. This guide covers the workflow and the quality bar.

## Development setup

```bash
git clone <repository-url>
cd ai-security-assessment-agent
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
```

## Checks

Every change must pass the gates CI enforces:

```bash
make lint        # ruff check + ruff format --check
make typecheck   # mypy --strict
make cov         # pytest with a coverage gate of 80%
```

`make format` applies safe autofixes and formatting.

## Workflow

1. Open an issue for anything larger than a small fix so the design can be discussed first.
2. Branch from `main`: `feature/<short-name>` or `fix/<short-name>`.
3. Keep commits focused, with imperative subjects ("Add EU AI Act risk-class mapping").
4. Add or update tests. Bug fixes need a regression test that fails without the fix.
5. Update `CHANGELOG.md` under **Unreleased** and any affected documentation.
6. Open a pull request describing the problem, the approach and how you verified it.

## Code standards

- Python 3.10+, fully type-annotated, `mypy --strict` clean.
- Docstrings explain behaviour, not restate names.
- Errors raised deliberately derive from `AisaError`.
- Never log or persist secrets. Route user-visible error text through `security.redact`.
- Tests run offline. Use `httpx.MockTransport` (see `tests/conftest.py`) rather than real network calls.

## Adding a control

1. Add a `ControlSpec` to `catalog.CONTROLS` with a description, OWASP ids and NIST references. Use a
   NIST subcategory only if you have verified it; otherwise use the function name.
2. Reference it from the relevant check's `controls`.
3. The catalog test validates every reference automatically. Add a manifest test if behaviour changes.

## Adding a check

Create a `Check` in `checks.py` (or register one at runtime) with:

- `applies`: returns the affected component ids, or an empty list when not applicable,
- `controls` or an `evaluator`,
- an `adjust` function if severity depends on exposure,
- a description, a concrete recommendation and a skip reason.

Add tests for applicability, passing, failing and any severity adjustment. The evaluator agent will
flag findings that lack evidence or valid references.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not file public issues for vulnerabilities.

## License

By contributing you agree that your contributions are licensed under the MIT License.
