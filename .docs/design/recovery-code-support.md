# Recovery Code Support

Status: accepted design gate
Date: 2026-06-15

## Decision

Recovery codes are accepted into post-MVP implementation scope as a first-class
MFA recovery factor. They must be implemented after the TOTP/HOTP Django device
surface because recovery-code verification changes authentication outcomes and
must preserve the same security controls: one-time use, replay prevention,
throttling, auditability, and explicit session elevation.

Recovery codes are not backup passwords. They are single-use MFA factors for
account recovery when a user cannot access their normal MFA device. The package
must not store raw recovery codes, submitted recovery-code values, displayable
code batches, Fernet keys, passwords, production credentials, raw MFA seeds, or
provisioning URIs. No raw recovery codes are stored by any accepted design path.

## Generation and Display Boundary

The implementation should generate a batch of high-entropy recovery codes with
Django or Python cryptographic randomness. Codes should be displayed exactly
once at creation or reset time, then only hashed metadata should remain
persisted.

Generation should return:

- displayable recovery codes for the current response only;
- a batch identifier suitable for local audit and replacement behavior;
- enough metadata to show count and creation time after the response.

The display boundary must be explicit:

1. Generate the codes inside an authenticated, recently MFA-elevated flow.
2. Hash each generated code before persistence.
3. Return the plaintext codes to the caller once.
4. Never persist plaintext codes in models, fixtures, logs, audit events, or
   session data.
5. Do not expose an API that later retrieves plaintext recovery codes.

Resetting recovery codes should revoke or mark all previous unused codes as
replaced before creating the new batch. The package should support replacement
without deleting historical audit events.

## Storage Contract

Recovery-code storage should use package-owned Django models unless a later
implementation task finds a concrete reason to reuse a broader device model.

Persisted recovery-code state should include:

- user ownership through the configured Django user model;
- a batch identifier;
- a per-code hash generated with a slow password-hashing primitive or an
  equivalent keyed construction approved in the implementation task;
- `used_at`, nullable until successful verification;
- `replaced_at`, nullable until batch reset;
- `created_at` and `updated_at` timestamps.

The preferred baseline is Django's password hasher framework through
`make_password()` and `check_password()`, with an implementation-specific
normalization step for display formatting. If the implementation selects a
keyed HMAC design instead, it must document the key-management boundary and add
focused tests proving constant-time comparison through `hmac.compare_digest()`
or a Django equivalent.

Database uniqueness should prevent duplicate active hashes inside the same
batch where possible, but correctness must not depend on hashes being
queryable. Verification may iterate over a user's active unused codes because
the batch size must be small and bounded.

## Verification Contract

Recovery-code verification must be stateful and atomic:

1. Lock the candidate user's active unused recovery-code rows with
   `select_for_update()` inside `transaction.atomic()`.
2. Apply throttling before comparing submitted code values.
3. Compare the submitted value with persisted hashes using constant-time
   verification provided by the selected hashing primitive.
4. Mark exactly one matching code `used_at` only after successful comparison.
5. Reject previously used or replaced codes as replay.
6. Persist an audit event for success, invalid, replay, throttled, and reset
   outcomes when audit persistence is requested or enabled for recovery flows.

The verification API should return a structured result instead of raising for
normal invalid, replay, or throttled outcomes. The result should include:

- `accepted`;
- `failure_reason`, such as `invalid`, `replay`, or `throttled`;
- the matched code identifier only when accepted;
- a recovery audit record without the submitted code.

The verification API must not accept target URLs, hosts, credentials, arbitrary
payload lists, or scanner-like inputs.

## Throttling and Lockout

Recovery-code attempts are high-value because they bypass possession of the
normal MFA device. The implementation must support throttling with scopes that
identify the local user and recovery flow. Integrations may layer additional
account lockout, support review, notification, or step-up controls.

The default package guidance should require throttling on recovery-code
verification. If an adapter supports disabling package throttling, the
integration must document a compensating local lockout control in the control
graph or integration docs.

Throttle state must not store raw recovery-code submissions.

## Audit Boundary

Recovery-code audit persistence should follow the HOTP audit boundary: local
security outcomes are persisted without submitted secrets.

Audit records should include:

- user;
- recovery-code batch identifier or code record reference;
- event type, such as `verification` or `reset`;
- submitted outcome;
- result classification, including `success`, `invalid`, `replay`,
  `throttled`, and `reset`;
- attempted timestamp;
- created timestamp.

Audit rows must not contain raw recovery codes, normalized submitted codes,
hashes, passwords, Fernet keys, production credentials, raw MFA seeds,
provisioning URIs, or encrypted secret values.

## Session Elevation

Successful recovery-code verification may satisfy the MFA challenge for the
current login or sensitive action, but it should mark the session with
`factor="recovery-code"` rather than pretending a TOTP or HOTP device was
verified.

Applications should decide whether recovery-code success grants the same max
age as normal MFA. The package helper should support a conservative default and
document that some applications may require immediate MFA device replacement
after recovery-code use.

Recovery-code reset must require an already authenticated and MFA-elevated
session. A password-only session should not be enough to generate replacement
codes unless a later design records a stricter account-recovery workflow with
equivalent safeguards.

## Control Mapping

Recovery-code support adds these controls to the package model:

- `recovery-code.hashed-at-rest`: raw recovery codes are never persisted.
- `recovery-code.constant-time`: submitted values are compared through the
  selected hash verifier or constant-time comparison helper.
- `recovery-code.one-time-use`: accepted codes are marked used exactly once.
- `recovery-code.replay-prevention`: used and replaced codes cannot be accepted
  again.
- `recovery-code.throttling`: repeated attempts require package throttling or a
  documented compensating lockout.
- `recovery-code.audit`: verification and reset outcomes are auditable without
  storing submitted codes.
- `recovery-code.session-elevation`: accepted recovery-code verification marks
  a distinct post-MFA session boundary.

The machine-readable control graph should be extended when recovery-code
implementation begins so downstream helpers can reason about these controls
alongside TOTP and HOTP.

## Validation Requirements

Implementation tasks derived from this design must add focused tests proving:

- generated plaintext codes are returned only from creation or reset helpers;
- no raw recovery codes are stored in models, audit rows, fixtures, logs, or
  documentation examples;
- verification uses constant-time hash verification or a documented
  constant-time keyed comparison;
- a successful code is marked used exactly once inside an atomic transaction;
- replayed, replaced, invalid, and throttled submissions are rejected;
- throttled attempts do not compare or consume codes;
- audit events cover success, invalid, replay, throttled, and reset outcomes;
- successful recovery-code verification can mark a session as
  `factor="recovery-code"`;
- local verification helpers remain fixture-bound and non-targetable.

## Follow-Up Implementation Scope

Recovery codes are in post-MVP scope. The work should be split into separate
implementation tasks so each step can be validated independently:

1. Add recovery-code generation, hashing, package-owned models, and migrations.
2. Add atomic verification adapters with throttling, one-time use, replay
   prevention, audit records, and optional audit persistence.
3. Add recovery-code session-elevation guidance, integration docs, control
   graph coverage, and local integration checks.
