# Outbound Credential Safety Review

Status: triage complete — no outbound-authenticating call path
Date: 2026-07-11
Related: AgentEngine item `django-mfa-toolkit-11`; admin-site design doc
`outbound-credential-safety` (portable fail-fast placeholder guard pattern);
admin-site item `admin-site-49` (original SMTP fix).

## Why this review happened

Sibling project `admin_site` had an incident: `EMAIL_HOST_PASSWORD` defaulted to
the placeholder `"changeme"`, and nothing stopped the app from opening a real
SMTP connection with that literal value. The mail host's intrusion-detection
system read the resulting auth failures as an attack and locked the account.

The generalized failure mode is specific to **outbound** credentials: a wrong or
placeholder value does not fail closed inside your own process — it fails by
actively transacting with a third party's system, which that system may punish
(lockout, IDS trigger, rate-limit ban). The portable fix is a runtime fail-fast
guard at the single choke point where the credential reaches the wire, raising
`ImproperlyConfigured` before any network call.

This review asks whether `django-mfa-toolkit` has any such outbound call path,
and — since it is a reusable library consumed by other Django projects
(`admin_site`, `authserver-app`, etc.) — whether a guard here would protect every
consumer at once.

## What was reviewed

Full scan of `django_mfa_toolkit/` for outbound network or authenticated-call
surfaces:

- Network/transport imports and calls: `requests`, `urllib`, `httpx`,
  `http.client`, `smtplib`, `socket`, `aiohttp`, `urlopen`, `send_mail`,
  `EmailMessage`, `connect()`/`open()`/`.send()` — **none found**.
- External MFA verification services (the obvious candidates named in the item):
  Yubico OTP validation API, external WebAuthn/FIDO2 relying-party verification —
  **none present**. These factors are explicitly listed as *not* first-build
  targets in `README.md`, and no client code for them exists.
- Config-supplied credentials with placeholder defaults
  (`os.getenv("X", "changeme")` style) on anything that authenticates outbound —
  **none found**. There is no `os.getenv`/`os.environ` usage in the package at
  all.

### Third-party dependencies (both local-only)

- `pyotp` — computes/validates TOTP and HOTP codes locally; no network.
- `cryptography` (Fernet) — symmetric encryption of MFA secret material at rest;
  no network.

Everything else is Django plus the Python standard library (`hashlib`,
`secrets`, `base64`, `uuid`, etc.).

## The one settings-supplied secret is internal, not outbound

The only credential this library reads from Django settings is
`DJANGO_MFA_TOOLKIT_SECRET_ENCRYPTION_KEYS` — the Fernet key(s) used to encrypt
MFA secrets **at rest** (`secret_storage.py`). Per the `outbound-credential-safety`
doc's own distinction, this is an *internal* secret: a weak or missing value is
an integrity risk to this app's own stored data, not something inflicted on a
third party's system. A bad value can never cause an outbound authenticated call.

It is also already handled fail-closed: `_configured_keys()`, `_primary_key_id()`,
and `_fernet_for_key_id()` each raise `django.core.exceptions.ImproperlyConfigured`
when the key mapping is unset, empty, non-string, or not a valid Fernet key
(`secret_storage.py`). No placeholder-default sentinel is used, so there is no
"still the placeholder" state to guard against.

## Architectural constraint reinforces the finding

The library encodes a **test-enforced** security invariant that its verification
surface is non-targetable: `verification-surface.not-targetable` in
`security_invariants.py` asserts that verification helpers expose no URL, host,
credential, target, or payload parameters (see `FORBIDDEN_TARGET_PARAMETER_NAMES`
and the `_verification_surface_is_not_targetable()` check, exercised by
`tests/test_security_invariants.py`). `AGENTS.md` and `README.md` state the same
boundary: verification runs against local Django fixtures and in-process
functions only, and no tool accepts arbitrary target URLs/hosts/credentials.

In other words, the absence of an outbound call path here is not incidental — it
is a deliberate, checked design property. Introducing an outbound-authenticating
call would itself be flagged as a security-invariant regression.

## Decision

**Outcome (b): this library has no outbound-authenticating call path.**

No follow-up implementation item is filed. There is no choke point at which a
config- or client-supplied credential reaches an external system, so there is
nothing for the `outbound-credential-safety` fail-fast guard to protect. Porting
the pattern here would add a guard around a code path that does not exist.

If a future factor that *does* make outbound authenticated calls is added to the
toolkit — most plausibly **Yubico OTP validation** (calls Yubico's API with a
client id + API key) or **remote WebAuthn/FIDO2 attestation/metadata fetching** —
this decision must be revisited. At that point the correct move is to port the
`outbound-credential-safety` pattern into the library itself (guard at the single
client choke point, raise `ImproperlyConfigured` before the network call, test
that the transport is never constructed when the credential is unset/placeholder).
Because the toolkit is shared, a guard baked in here would protect every consumer
at once, which is the stronger layer for the fix. A porting checklist already
exists in the admin-site `outbound-credential-safety` design doc.

## Consumer guidance

This library holding no outbound credentials does **not** relieve its consumers
of their own outbound-credential guards. `admin_site` and any other consuming
project remain responsible for guarding the outbound credentials they own (SMTP,
broker AUTH, third-party API keys) at their own choke points, per the
`outbound-credential-safety` pattern.
