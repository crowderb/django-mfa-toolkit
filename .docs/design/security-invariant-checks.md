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

Downstream projects can reuse the local Django integration helper surface in
`django_mfa_toolkit.integration_checks`. The helper surface is designed for
pytest or Django test cases that already create synthetic users, synthetic MFA
devices, and in-process Django test-client responses.

Reusable helpers include:

- `run_local_django_mfa_integration_checks()`, which returns structured local
  results for synthetic TOTP and HOTP device replay checks;
- `MFALocalIntegrationCheckMixin.assert_totp_device_rejects_replay()`;
- `MFALocalIntegrationCheckMixin.assert_hotp_device_rejects_replay_without_counter_advance()`;
- `MFALocalIntegrationCheckMixin.assert_mfa_required_session_boundary()`;
- `MFALocalIntegrationCheckMixin.assert_local_security_invariants_pass()`.

These helpers intentionally accept local objects and response objects only. They
do not accept URLs, hosts, credentials, arbitrary payload lists, or network
destinations.
