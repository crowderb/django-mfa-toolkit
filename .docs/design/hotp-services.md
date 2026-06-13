# HOTP Enrollment, Verification, and Audit

Status: accepted MVP primitive
Date: 2026-06-13

## Service Boundary

HOTP behavior lives in `django_mfa_toolkit.hotp`.

Enrollment returns encrypted persistence material and an `otpauth://hotp` provisioning URI. The provisioning URI necessarily contains the HOTP seed and initial counter so the hardware-token setup flow can complete. Application code must treat it as sensitive setup material and avoid logging it.

## Counter State

`verify_hotp` accepts the caller's current `server_counter` and returns `next_counter`.

Integrations must persist `next_counter` only when `accepted` is true. Failed and replayed attempts return the original server counter unchanged.

Look-ahead matching is bounded by `look_ahead`. A code that matches a counter inside the window is accepted and advances the next counter to `matched_counter + 1`.

## Replay Handling

All counters lower than the current server counter are considered spent. The service performs bounded replay classification with `replay_window`; matching a spent counter inside that window is rejected as `replay`. Older spent codes outside the replay window are rejected as `invalid` so verification does not require unbounded counter searches.

## Resynchronization

`resync_hotp` accepts multiple consecutive HOTP submissions and searches for the sequence inside a bounded `search_window` starting at the current server counter.

On success, integrations should persist `next_counter`, which is the matched counter plus the number of submitted codes. On failure, integrations must keep the original server counter.

Resynchronization rejects replayed consecutive codes inside the bounded `replay_window`. Codes that do not fit the allowed forward search are rejected without extending the search beyond the configured bound.

## Audit Records

Every verification attempt returns an `HOTPAuditRecord` containing:

- `submitted_outcome`: `accepted` or `rejected`;
- `result_classification`: `success`, `counter_window_match`, `invalid`, or `replay`;
- `server_counter`: the counter value supplied by the caller;
- `matched_counter`: the matched counter when applicable;
- `next_counter`: the counter the caller should persist only after success;
- `look_ahead` and `replay_window`;
- `attempted_at`.

The audit record intentionally does not include the submitted OTP.

Every resynchronization attempt returns an `HOTPResyncAuditRecord` containing the same counter outcome fields plus `submitted_count` and `search_window`.

Future storage work may persist these records in Django models. The MVP service keeps audit creation in-process so device persistence choices remain separate from protocol verification.
