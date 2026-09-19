# ADR 0002: Control catalog as the single source of framework mappings

- Status: Accepted
- Date: 2026-09-19

## Context

Findings must reference OWASP, NIST AI RMF, STRIDE and MITRE ATLAS. Scattering those references across
checks invites inconsistency, and inaccurate references undermine an audit artefact.

## Decision

Define 34 controls once in `catalog.py`, each with a description and its OWASP and NIST references.
Checks reference controls by id. A finding's NIST references are derived from the controls it
consulted, and manifests are validated against the control ids. NIST references use a specific
subcategory only where the mapping is clear and otherwise the bare function name.

## Consequences

- One place to review and correct framework mappings, covered by a test that validates every reference.
- The compliance agent scores coverage from the same data the checks use, so the two cannot disagree.
- References are the author's mapping, not an official crosswalk. The report and README tell readers to
  verify identifiers against the current published texts before citing them.
- Adding a framework means adding a field to `ControlSpec`, not editing every check.
