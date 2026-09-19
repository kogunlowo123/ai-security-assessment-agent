# ADR 0001: Deterministic, manifest-driven assessment

- Status: Accepted
- Date: 2026-09-19

## Context

An assessment tool for AI systems can be built as language-model agents that explore a system and write
findings, or as rules over a structured description. Model-driven agents are flexible but
non-deterministic, hard to test, and require sending architecture details to a provider.

## Decision

Assess a declarative manifest with rule-based agents. A language model is used only to draft the
optional executive summary, and only from aggregate facts.

## Consequences

- The same manifest always produces the same findings, so results can be diffed, gated in CI and
  reviewed in pull requests.
- Every finding is explainable by the declared facts it rests on.
- No architecture data leaves the environment in the default configuration.
- The tool cannot find risks outside its rule set, and it trusts the declaration. Both limits are
  stated in the README. Evidence ingestion (infrastructure-as-code, SBOMs) is the planned route to
  verify declarations.

## Alternatives considered

- **LLM-driven agents that read architecture documents.** Rejected for v0.1: unreproducible output and
  data-handling concerns outweigh the flexibility.
