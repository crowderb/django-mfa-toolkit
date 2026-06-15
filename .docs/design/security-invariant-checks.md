# Local Security Invariant Checks

Status: accepted MVP verification primitive
Date: 2026-06-13

## Scope

The MVP security invariant checks are local, fixture-bound, and in-process. They are implemented as pytest tests, the static control requirement representation, and the machine-readable control graph in `django_mfa_toolkit.security_invariants`.

They do not accept target URLs, hosts, credentials, arbitrary payloads, or network destinations.

## Covered Controls

The first control-dependency representation covers:

- encrypted MFA secret storage;
- constant-time OTP comparison through vetted helpers;
- TOTP replay prevention through accepted timecode tracking;
- HOTP counter advancement only on success;
- HOTP replay rejection for spent counters;
- HOTP audit records for verification and resynchronization attempts;
- bounded HOTP resynchronization with consecutive submissions.
- Django session elevation as a separate post-MFA boundary;
- optional HOTP audit persistence;
- non-targetable verification helpers.

The graph representation is documented in `.docs/design/control-graph.md`.

## Verification Model

Dynamic checks use synthetic Django settings, synthetic TOTP/HOTP enrollments, direct service calls, and pytest fixtures.

The checks intentionally do not provide a CLI, scanner, URL input, host input, credential input, or arbitrary payload input. Future agent-facing verification helpers must keep the same boundary unless a later design record documents an equivalent non-targetable interface.

Session-boundary controls are not implemented in the MVP service surface yet. When session elevation behavior is added, it must be represented here with local Django test-client checks.
