# MFA Control Graph

Status: accepted design gate
Date: 2026-06-15

## Decision

`django_mfa_toolkit.security_invariants` now exposes a machine-readable MFA
control graph through `get_mfa_control_graph()`. The graph extends the existing
flat `ControlRequirement` list without replacing it, so current local invariant
checks and tests remain backward-compatible.

The graph is intentionally static and local. It does not inspect deployments,
accept target URLs, accept credentials, accept payload lists, or run network
checks.

## Graph Shape

The graph contains:

- `ControlGraphNode`, with `id`, `kind`, `label`, and `description`;
- `ControlGraphRelationship`, with `source`, `target`, `kind`, and
  `description`;
- `ControlGraph`, with immutable `nodes` and `relationships`.

Node kinds are:

- `control`;
- `implementation`;
- `verification`;
- `compensating-control`.

Relationship kinds are:

- `requires`;
- `implemented-by`;
- `verified-by`;
- `satisfied-by-any`.

The `satisfied-by-any` relationship represents acceptable compensating-control
sets. For example, repeated TOTP and HOTP attempts may be controlled by package
throttling or by a documented local lockout boundary.

## Covered Controls

The graph includes the existing MVP controls:

- `secret-storage.encrypted-at-rest`;
- `comparison.constant-time`;
- `totp.replay-prevention`;
- `hotp.counter-advance`;
- `hotp.replay-prevention`;
- `hotp.audit`;
- `hotp.resync-bounded`;
- `django-persistence.stateful-verification`;
- `django-throttling.lockout`;
- `django-session-elevation.boundary`;
- `verification-surface.not-targetable`.

It also adds graph-level grouping and implementation nodes:

- `mfa.seed-confidentiality`;
- `totp.verification`;
- `hotp.verification`;
- `hotp.audit-persistence`;
- `compensating-control.documented-lockout`;
- `implementation.secret-storage`;
- `implementation.device-adapters`;
- `implementation.audit-model`;
- `implementation.session-elevation`;
- `verification.local-tests`.

## Agent Interpretation

Agents and downstream helpers should interpret the graph as a local reasoning
model:

1. If a `requires` target is missing, report the missing prerequisite as a
   security gap.
2. If a group has multiple `satisfied-by-any` relationships, report a gap only
   when none of the alternatives is present or documented.
3. If an `implemented-by` target is missing, report an implementation gap rather
   than a protocol failure.
4. If a `verified-by` target is missing, report missing local verification and
   suggest a fixture-bound test or helper.
5. Never convert graph analysis into arbitrary probing of external URLs, hosts,
   credentials, or payload lists.

## Validation

Local tests assert that:

- every existing `ControlRequirement` has a graph node;
- every graph relationship references existing nodes;
- TOTP and HOTP verification represent throttling and documented lockout as
  compensating alternatives;
- HOTP audit persistence requires HOTP audit records and is implemented by the
  audit model;
- existing invariant checks continue to pass.
