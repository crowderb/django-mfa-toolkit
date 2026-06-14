# Django MFA Device Persistence Contracts

Status: accepted design gate
Date: 2026-06-14

## Decision

The Django integration layer will ship concrete package-owned models for the
MVP TOTP and HOTP device state before adding login-flow helpers.

The models will keep protocol verification in the existing service modules and
will store only the state required to make those services safe across requests.
They will not store raw MFA seeds, submitted OTPs, provisioning URIs, recovery
codes, Fernet keys, or production credentials.

## Rejected Alternatives

Abstract base models are not the first MVP target. They would give integrating
applications more schema control, but they would also make it harder for the
package to provide a complete local verification story for replay prevention,
counter updates, throttling, and session elevation.

Adapters without package-owned models are also rejected for the next milestone.
That approach would repeat the current service-only boundary and leave each
application to invent its own transaction and replay-state persistence rules.

The package can revisit abstract models or custom storage adapters after the
concrete model behavior is tested.

## Shared Device Fields

Each concrete device model should include:

- user ownership through the configured Django user model;
- `persisted_secret`, containing the serialized encrypted secret returned by
  `django_mfa_toolkit.secret_storage`;
- `name`, for user-facing device identification;
- `confirmed_at`, nullable until enrollment verification succeeds;
- `is_active`, so devices can be disabled without deleting audit history;
- `created_at` and `updated_at` timestamps.

The `persisted_secret` field stores values shaped like
`v1:<key-id>:<fernet-token>`. It is secret-bearing ciphertext and should not be
logged, displayed, or copied into fixtures except as synthetic test data.

The model layer must preserve `secret-storage.encrypted-at-rest` by storing only
encrypted persistence values. Raw seeds remain transient enrollment material.

## TOTP Device State

TOTP devices should persist:

- `persisted_secret`;
- `digits`;
- `interval`;
- `last_accepted_timecode`, nullable before the first successful verification;
- shared ownership, confirmation, activity, and timestamp fields.

`last_accepted_timecode` supports `totp.replay-prevention`. Verification
adapters must pass the current value to
`verify_totp(last_accepted_timecode=...)` and persist a new value only when the
service result is accepted.

The model must not persist submitted TOTP codes, provisioning URIs, or raw seed
material.

## HOTP Device State

HOTP devices should persist:

- `persisted_secret`;
- `digits`;
- `hotp_counter`, with a non-negative database constraint;
- shared ownership, confirmation, activity, and timestamp fields.

`hotp_counter` supports `hotp.counter-advance` and
`hotp.replay-prevention`. Verification adapters must pass the current value to
`verify_hotp(server_counter=...)` or `resync_hotp(server_counter=...)` and
persist `next_counter` only when the result is accepted.

Failed, invalid, replayed, and excessive-drift HOTP attempts must leave
`hotp_counter` unchanged.

## Audit Boundary

HOTP verification and resynchronization service calls already return structured
audit records. The first model milestone should keep audit persistence separate
from device state so counter safety can be validated independently.

Future audit models may persist:

- factor type;
- device reference;
- submitted outcome;
- result classification;
- server counter;
- matched counter;
- next counter;
- window settings;
- attempted timestamp.

Audit persistence must preserve `hotp.audit` and must not store submitted OTPs
or raw secrets.

## Transaction and Locking Expectations

State-changing verification adapters must run inside a database transaction and
lock the device row before reading replay or counter state. The expected pattern
is:

1. Select the device row with `select_for_update()` inside `transaction.atomic()`.
2. Reject inactive or unconfirmed devices before protocol verification.
3. Call the relevant service with state read from the locked row.
4. Persist replay or counter state only when the service result is accepted.
5. Return the service result and any audit record without storing submitted OTPs.

This boundary prevents concurrent accepted submissions from reusing the same
TOTP timecode or advancing an HOTP counter from stale state.

## Validation Mapping

The persistence layer must preserve these existing controls:

- `secret-storage.encrypted-at-rest`: store only encrypted `persisted_secret`
  values.
- `totp.replay-prevention`: persist and reuse `last_accepted_timecode`.
- `hotp.counter-advance`: update `hotp_counter` only after accepted HOTP
  verification or resynchronization.
- `hotp.replay-prevention`: treat lower counters as spent through the service
  replay window.
- `hotp.audit`: keep structured audit records available without storing OTPs.
- `hotp.resync-bounded`: persist only accepted bounded resynchronization
  outcomes.

The next implementation task must include Django database tests for model
creation, non-negative HOTP counters, no raw secret persistence, and migration
importability before adding login-flow behavior.
