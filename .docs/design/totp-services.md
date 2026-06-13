# TOTP Enrollment and Verification

Status: accepted MVP primitive
Date: 2026-06-13

## Service Boundary

TOTP behavior lives in `django_mfa_toolkit.totp`.

Enrollment returns:

- `encrypted_secret`: the encrypted value to persist through the secret-storage boundary;
- `persisted_secret`: the serialized encrypted value for model fields;
- `provisioning_uri`: the `otpauth://` URI to show as a QR code or manual setup value;
- metadata for issuer, account name, digits, and interval.

The provisioning URI necessarily contains the TOTP seed so the authenticator app can enroll. Application code must treat it as sensitive setup material and avoid logging it.

## Verification

Verification decrypts the stored secret in process, uses `pyotp` TOTP generation, and compares submitted codes with `pyotp.utils.strings_equal`.

`verify_totp` returns `matched_timecode` on success. Integrations should persist the latest accepted timecode for each TOTP device and pass it as `last_accepted_timecode` on the next verification attempt. Codes for an already accepted timecode are rejected as replay.

## Window Policy

The default verification window accepts the current time step plus one adjacent step before or after the current step. Callers may set `valid_window=0` for stricter tests or deployments.

Future throttling or lockout work must wrap this service so repeated invalid attempts cannot be made without a compensating control.
