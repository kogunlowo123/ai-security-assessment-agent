# ADR 0003: Exposure-aware severity and exponential posture score

- Status: Accepted
- Date: 2026-09-19

## Context

A fixed severity per check misranks real systems: prompt injection against an internal batch job and
against an internet-facing agent that can issue payments are not the same risk. A linear score that
subtracts penalties from 100 also saturates at zero, so it cannot distinguish bad from catastrophic.

## Decision

Each check has a base severity and an `adjust` function that moves it for exposure, data sensitivity,
agent capabilities and tenancy. Half-implemented controls lower severity by one level, but flow-level
architecture failures do not. Posture is `100 * exp(-penalty / 80)`.

## Consequences

- Severity reflects the system's context and stays explainable, since every adjustment is a small named
  function.
- Scores remain monotonic and comparable for systems with many findings.
- Weights and adjustments are judgement calls. They are isolated in `models.py` and `checks.py` so an
  organisation can change them, and calibration against incident data is on the roadmap.
- The rule that architecture failures keep full severity was added after a sample showed a system with
  two of four unauthenticated boundary flows being rated one level too low.
