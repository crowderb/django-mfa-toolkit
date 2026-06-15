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
- validate Django persistence, throttling, and session-elevation behavior with local synthetic fixtures.

This guide does not define a custom scanner, remote probe, or arbitrary target interface.
The verification checks do not accept target URLs, hosts, credentials, or arbitrary payload lists.

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

## End-to-End Django Flow

Use the model-backed adapters for a normal Django integration. They create
`TOTPDevice` and `HOTPDevice` rows, keep encrypted seeds in `persisted_secret`,
lock device rows during verification, apply optional throttling before OTP
checks, and update replay or counter state only after successful verification.

The application remains responsible for:

- authenticating the user with Django's normal authentication stack before MFA;
- showing provisioning URIs without logging them;
- displaying generated recovery codes exactly once and never logging them;
- confirming a newly enrolled device only after an initial successful MFA code;
- choosing throttle scopes that identify the user, device, and flow;
- calling `mark_mfa_elevated()` only after an accepted verification result;
- persisting audit records without raw OTP submissions, raw recovery codes, or
  raw secret material.

### TOTP Enrollment

```python
from django.utils import timezone

from django_mfa_toolkit.device_adapters import enroll_totp_device, verify_totp_device
from django_mfa_toolkit.models import TOTPDevice


def begin_totp_enrollment(request):
    enrolled = enroll_totp_device(
        user=request.user,
        account_name=request.user.get_username(),
        issuer_name="Django MFA Toolkit",
        name="Authenticator app",
    )
    request.session["pending_totp_device_id"] = enrolled.device.pk
    return enrolled.enrollment.provisioning_uri


def confirm_totp_enrollment(request):
    device = TOTPDevice.objects.get(
        pk=request.session["pending_totp_device_id"],
        user=request.user,
        confirmed_at__isnull=True,
    )
    result = verify_totp_device(
        device=device,
        submitted_code=request.POST["code"],
        valid_window=1,
        throttle_scope=f"user:{request.user.pk}:totp-enroll:{device.pk}",
    )
    if result.accepted:
        device.confirmed_at = timezone.now()
        device.save(update_fields=["confirmed_at", "updated_at"])
        return True
    return False
```

`enroll_totp_device()` stores only encrypted seed material. The provisioning URI
is setup material for the user; do not write it to logs, fixtures, or analytics.

### HOTP Enrollment

```python
from django.utils import timezone

from django_mfa_toolkit.device_adapters import enroll_hotp_device, verify_hotp_device
from django_mfa_toolkit.models import HOTPDevice


def begin_hotp_enrollment(request):
    enrolled = enroll_hotp_device(
        user=request.user,
        account_name=request.user.get_username(),
        issuer_name="Django MFA Toolkit",
        name="Hardware token",
        initial_counter=0,
    )
    request.session["pending_hotp_device_id"] = enrolled.device.pk
    return enrolled.enrollment.provisioning_uri


def confirm_hotp_enrollment(request):
    device = HOTPDevice.objects.get(
        pk=request.session["pending_hotp_device_id"],
        user=request.user,
        confirmed_at__isnull=True,
    )
    result = verify_hotp_device(
        device=device,
        submitted_code=request.POST["code"],
        look_ahead=10,
        replay_window=10,
        throttle_scope=f"user:{request.user.pk}:hotp-enroll:{device.pk}",
        persist_audit=True,
    )
    if result.accepted:
        device.confirmed_at = timezone.now()
        device.save(update_fields=["confirmed_at", "updated_at"])
        return True
    return False
```

`verify_hotp_device()` advances `hotp_counter` only after acceptance. Keep the
returned `audit_record` if the application has an audit sink, but do not store
the submitted OTP.

### Recovery-Code Enrollment and Reset

```python
from django_mfa_toolkit.recovery_codes import (
    create_recovery_code_batch,
    reset_recovery_code_batch,
)


def create_initial_recovery_codes(request):
    enrolled = create_recovery_code_batch(user=request.user)
    return enrolled.codes


def replace_recovery_codes(request):
    enrolled = reset_recovery_code_batch(
        user=request.user,
        persist_audit=True,
    )
    return enrolled.codes
```

Display `enrolled.codes` exactly once in the current response. The package
persists only password hashes and batch state. Do not store the returned codes
in the session, fixtures, audit rows, logs, analytics, support tickets, or email.
Recovery-code reset should run only from an authenticated, recently MFA-elevated
flow.

### Post-Enrollment Verification

```python
from django.http import HttpResponse
from django.shortcuts import redirect

from django_mfa_toolkit.device_adapters import verify_totp_device
from django_mfa_toolkit.models import TOTPDevice
from django_mfa_toolkit.session_elevation import mark_mfa_elevated, mfa_required


def verify_mfa_view(request):
    device = TOTPDevice.objects.get(
        pk=request.POST["device_id"],
        user=request.user,
        confirmed_at__isnull=False,
        is_active=True,
    )
    result = verify_totp_device(
        device=device,
        submitted_code=request.POST["code"],
        throttle_scope=f"user:{request.user.pk}:totp-verify:{device.pk}",
    )
    if result.accepted:
        mark_mfa_elevated(request, factor="totp", device_id=device.pk)
        return redirect("account")
    if result.failure_reason == "throttled":
        return HttpResponse("Too many MFA attempts.", status=429)
    return HttpResponse("MFA code rejected.", status=403)


@mfa_required(max_age=900)
def protected_view(request):
    ...
```

Use equivalent HOTP verification with `verify_hotp_device()` when the selected
device is a hardware token. The post-MFA session marker is separate from the
Django authenticated session and should expire independently.

### Recovery-Code Verification

```python
from django.http import HttpResponse
from django.shortcuts import redirect

from django_mfa_toolkit.recovery_codes import verify_recovery_code
from django_mfa_toolkit.session_elevation import mark_mfa_elevated


def verify_recovery_code_view(request):
    result = verify_recovery_code(
        user=request.user,
        submitted_code=request.POST["code"],
        throttle_scope=f"user:{request.user.pk}:recovery-code",
        persist_audit=True,
    )
    if result.accepted:
        mark_mfa_elevated(
            request,
            factor="recovery-code",
            device_id=result.matched_recovery_code_id,
        )
        return redirect("account")
    if result.failure_reason == "throttled":
        return HttpResponse("Too many recovery-code attempts.", status=429)
    return HttpResponse("Recovery code rejected.", status=403)
```

`verify_recovery_code()` locks the user's active recovery-code rows, applies
throttling before password-hash comparison, marks one accepted code used, and
classifies used or replaced codes as `replay`. Keep recovery-code verification
local and in-process. Do not build a remote recovery-code checker or support
tool that accepts arbitrary targets, credentials, payload lists, or production
submissions.

### Reusable Local Integration Checks

Downstream projects can import fixture-bound helpers for their own pytest or
Django test suites:

```python
from django_mfa_toolkit.integration_checks import (
    MFALocalIntegrationCheckMixin,
    run_local_django_mfa_integration_checks,
)


def test_mfa_device_replay_controls(
    synthetic_totp_device,
    synthetic_hotp_device,
    synthetic_user,
    synthetic_recovery_code_enrollment,
):
    results = run_local_django_mfa_integration_checks(
        totp_device=synthetic_totp_device,
        hotp_device=synthetic_hotp_device,
        recovery_code_user=synthetic_user,
        recovery_code_enrollment=synthetic_recovery_code_enrollment,
    )

    assert all(result.passed for result in results)


class TestMFASessionBoundary(MFALocalIntegrationCheckMixin):
    def test_mfa_boundary(self, local_client_flow):
        self.assert_mfa_required_session_boundary(
            anonymous_response=local_client_flow.anonymous_response,
            verified_response=local_client_flow.verified_response,
            protected_response=local_client_flow.protected_response,
            replay_response=local_client_flow.replay_response,
        )
```

The helpers must be called from local tests that create synthetic users,
synthetic devices, and in-process Django test-client responses. They intentionally
do not accept URLs, hosts, credentials, arbitrary payload lists, or network
destinations.

Run the toolkit helper tests with:

```bash
uv run pytest tests/test_integration_checks.py tests/test_security_invariants.py
uv run pytest tests/test_recovery_codes.py
```

Run the complete local verification suite with:

```bash
uv run pytest
```

### HOTP Resynchronization

```python
from django.http import HttpResponse

from django_mfa_toolkit.device_adapters import resync_hotp_device
from django_mfa_toolkit.models import HOTPDevice


def resync_hotp_view(request):
    device = HOTPDevice.objects.get(
        pk=request.POST["device_id"],
        user=request.user,
        confirmed_at__isnull=False,
        is_active=True,
    )
    result = resync_hotp_device(
        device=device,
        submitted_codes=[request.POST["first_code"], request.POST["second_code"]],
        search_window=100,
        replay_window=10,
        throttle_scope=f"user:{request.user.pk}:hotp-resync:{device.pk}",
        persist_audit=True,
    )
    audit = result.audit_record
    if result.accepted:
        return HttpResponse("HOTP token resynchronized.", status=204)
    if audit.result_classification == "throttled":
        return HttpResponse("Too many resynchronization attempts.", status=429)
    return HttpResponse("HOTP resynchronization rejected.", status=403)
```

Resynchronization requires consecutive codes and a bounded search window. Treat
`excessive_drift` as a failed local recovery attempt rather than a reason to
perform unbounded search.

## Service Boundary Flow

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
- If recovery-code verification returns `replay`, the submitted code was already
  used or belongs to a replaced batch. Keep other recovery codes unchanged and
  require a different active code.
- If recovery-code verification returns `throttled`, the package rejected the
  attempt before password-hash comparison and did not consume a code.

## Required Controls

- Wrap the service calls in throttling or lockout at the application boundary.
- Keep MFA state transitions local to the application and do not expose arbitrary target URLs, hosts, credentials, or payloads.
- Treat pre-MFA to post-MFA session elevation as a separate boundary when you add login-flow integration.
- Keep verification fixtures synthetic and in-process.

## Session Elevation

MFA elevation is stored in the existing Django session as a timestamped
post-MFA marker. It is not a replacement for password authentication and should
expire independently from the authenticated session. Clear the marker with
`clear_mfa_elevation(request)` when a flow needs to return to pre-MFA state;
Django logout also clears it because logout flushes the session.

Do not disable Django authentication middleware, session middleware, CSRF
protection, password handling, or secure cookie settings to use these helpers.
The helpers assume the application is already using Django's normal session and
authentication protections.

## Operational Guidance

- Audit records: persist HOTP `audit_record` and resynchronization
  `audit_record` fields that classify the result, counter window, and timestamp.
  Pass `persist_audit=True` to the HOTP device adapters when the package should
  create local `MFAAuditEvent` rows in the same transaction as counter updates.
  Pass `persist_audit=True` to recovery-code reset and verification helpers when
  the package should create local `MFAAuditEvent` rows for `success`, `invalid`,
  `replay`, `throttled`, and `reset` outcomes. Do not persist raw submitted OTP
  values or raw recovery codes.
- Lockout handling: use stable throttle scopes per user, device, and flow, such
  as `user:{request.user.pk}:totp-verify:{device.pk}`. A successful verification
  resets the matching throttle scope.
- Key rotation: configure
  `DJANGO_MFA_TOOLKIT_SECRET_ENCRYPTION_KEYS` with all active decryption keys
  and set `DJANGO_MFA_TOOLKIT_PRIMARY_SECRET_ENCRYPTION_KEY_ID` to the key used
  for new enrollment. Keep key material in a secret manager or deployment-local
  settings, never in committed files.
- Logging: redact `request.POST["code"]`, provisioning URIs, raw seeds, Fernet
  keys, recovery material, and encrypted secret values from application logs.
- Recovery and support: keep local verification helpers fixture-bound. Do not
  build support tools that accept arbitrary target hosts, credentials, payload
  lists, or production OTP submissions.

## Verification Commands

Validate each integration layer with the narrowest relevant local checks:

```bash
uv run pytest tests/test_models.py
uv run pytest tests/test_device_adapters.py
uv run pytest tests/test_throttling.py
uv run pytest tests/test_session_elevation.py
uv run pytest tests/test_django_integration_checks.py
uv run pytest tests/test_security_invariants.py
uv run pytest tests/test_integration_checks.py
uv run pytest tests/test_recovery_codes.py
```

Validate the lower-level TOTP, HOTP, and encrypted-secret service boundary:

```bash
uv run pytest tests/test_secret_storage.py tests/test_totp.py tests/test_hotp.py
```

Run the full suite before merging:

```bash
uv run pytest
uv lock --check
```
