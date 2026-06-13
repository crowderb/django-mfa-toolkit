# MVP Integration Guide

Status: agent-followable MVP guide
Date: 2026-06-13

## What This Guide Covers

Use the current MVP as a small service boundary:

- encrypt MFA seeds before persistence;
- enroll TOTP and HOTP devices;
- verify TOTP and HOTP codes;
- resynchronize HOTP counters with bounded drift;
- keep all verification local, fixture-bound, and in-process.

This guide does not define a custom scanner, remote probe, or arbitrary target interface.

## Required Setup

Install the project with uv and run the local checks through the same toolchain used by the repo:

```bash
uv sync
uv run pytest
```

Add the MFA encryption settings to Django:

```python
DJANGO_MFA_TOOLKIT_SECRET_ENCRYPTION_KEYS = {
    "local-dev": "FERNET_KEY_FROM_KEY_MANAGEMENT_OR_GENERATED_FOR_LOCAL_DEV",
}
DJANGO_MFA_TOOLKIT_PRIMARY_SECRET_ENCRYPTION_KEY_ID = "local-dev"
```

Use a real secret manager in production. Keep local values in ignored environment files or deployment-local settings. Do not commit raw seeds, Fernet keys, recovery codes, or production credentials.

## Enrollment Flow

Use enrollment to generate the provisioning material, then persist the encrypted secret and the minimum state the verifier needs.

### TOTP

```python
from django_mfa_toolkit.totp import enroll_totp

enrollment = enroll_totp(
    account_name="alice@example.test",
    issuer_name="Django MFA Toolkit",
)

device_record = {
    "persisted_secret": enrollment.persisted_secret,
    "issuer_name": enrollment.issuer_name,
    "account_name": enrollment.account_name,
    "digits": enrollment.digits,
    "interval": enrollment.interval,
    "last_accepted_timecode": None,
}
provisioning_uri = enrollment.provisioning_uri
```

Persist `persisted_secret`. Show `provisioning_uri` to the user as a QR code or manual setup URI. Do not log either value.

### HOTP

```python
from django_mfa_toolkit.hotp import enroll_hotp

enrollment = enroll_hotp(
    account_name="hardware-token@example.test",
    issuer_name="Django MFA Toolkit",
    initial_counter=0,
)

device_record = {
    "persisted_secret": enrollment.persisted_secret,
    "issuer_name": enrollment.issuer_name,
    "account_name": enrollment.account_name,
    "digits": enrollment.digits,
    "hotp_counter": enrollment.initial_counter,
}
provisioning_uri = enrollment.provisioning_uri
```

Persist `hotp_counter` only when verification or resynchronization succeeds.

## Verification Flow

### TOTP

```python
from django_mfa_toolkit.totp import verify_totp

result = verify_totp(
    encrypted_secret=device_record["persisted_secret"],
    submitted_code=submitted_code,
    valid_window=1,
    last_accepted_timecode=device_record["last_accepted_timecode"],
)

if result.accepted:
    device_record["last_accepted_timecode"] = result.matched_timecode
elif result.failure_reason == "replay":
    # Treat as a spent code. Do not advance state.
    pass
else:
    # Invalid code. Apply throttling or lockout at the call site.
    pass
```

Persist `matched_timecode` only after acceptance. Reject replayed timecodes by passing the last accepted value back into the verifier.

### HOTP

```python
from django_mfa_toolkit.hotp import verify_hotp

result = verify_hotp(
    encrypted_secret=device_record["persisted_secret"],
    submitted_code=submitted_code,
    server_counter=device_record["hotp_counter"],
    look_ahead=10,
    replay_window=10,
)

if result.accepted:
    device_record["hotp_counter"] = result.next_counter
    audit = result.audit_record
elif result.audit_record.result_classification == "replay":
    # Spent counter. Keep the current counter value.
    audit = result.audit_record
else:
    # Invalid code. Keep the current counter value.
    audit = result.audit_record
```

Use the audit record for logging or persistence if your application needs it. Do not persist the submitted OTP itself.

## Resynchronization Flow

Use resynchronization when a hardware token drifts out of sync and the user can provide consecutive codes.

```python
from django_mfa_toolkit.hotp import resync_hotp

result = resync_hotp(
    encrypted_secret=device_record["persisted_secret"],
    submitted_codes=[code_1, code_2],
    server_counter=device_record["hotp_counter"],
    search_window=100,
    replay_window=10,
)

if result.accepted:
    device_record["hotp_counter"] = result.next_counter
    audit = result.audit_record
elif result.audit_record.result_classification == "replay":
    audit = result.audit_record
else:
    audit = result.audit_record
```

Treat `excessive_drift` as a signal that the device is too far out of sync for the configured window. Do not widen the window without a reasoned security review.

## Troubleshooting

- If TOTP verification returns `replay`, you likely did not persist `last_accepted_timecode` after the previous success.
- If HOTP verification returns `replay`, the code was already used for a lower counter. Keep the counter unchanged and ask for a fresh code.
- If HOTP verification returns `invalid` but you expected success, confirm that the caller passed the current `hotp_counter` back into the service.
- If HOTP resynchronization returns `excessive_drift`, the submitted sequence is outside the configured search window or the wrong token is being used.
- If audit logs are missing, persist `audit_record` from the service result at the application boundary.

## Required Controls

- Wrap the service calls in throttling or lockout at the application boundary.
- Keep MFA state transitions local to the application and do not expose arbitrary target URLs, hosts, credentials, or payloads.
- Treat pre-MFA to post-MFA session elevation as a separate boundary when you add login-flow integration.
- Keep verification fixtures synthetic and in-process.

## Verification Commands

Run the narrow test sets while integrating:

```bash
uv run pytest tests/test_secret_storage.py tests/test_totp.py tests/test_hotp.py tests/test_security_invariants.py
```

Run the full suite before merging:

```bash
uv run pytest
uv lock --check
```
