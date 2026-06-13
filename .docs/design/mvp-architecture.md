# MVP Architecture and Dependency Strategy

Status: accepted foundation decision
Date: 2026-06-13

## Decision

The MVP will use a custom Django service API and storage boundary rather than building directly on `django-otp` device models.

The service API will still use vetted protocol and cryptographic libraries. The project must not implement OATH TOTP, OATH HOTP, random secret generation, encryption, signing, or constant-time comparison logic from scratch.

## Rationale

`django-otp` is the main interoperable Django abstraction for OTP devices and remains the most important comparison point. Building directly on it would provide a known device model and ecosystem compatibility.

The initial differentiator for this project is stricter secure-by-construction behavior around encrypted secret storage, HOTP replay prevention, audit records, counter resynchronization, and agent-followable verification. A custom service boundary gives the MVP one place to enforce those invariants without exposing integration code to lower-level device state transitions too early.

The project should revisit a `django-otp` adapter after the MVP service contracts are tested. Compatibility is valuable, but the first milestone should prove the security model and verification workflow before committing to another package's persistence API.

## Rejected Alternative

The MVP will not subclass or wrap `django-otp` models as its primary implementation surface.

Reason: that approach risks spreading the core project guarantees across third-party model behavior, plugin settings, and integration conventions before this package has its own tests for replay prevention, storage boundaries, throttling expectations, audit semantics, and HOTP resynchronization.

## Dependency Strategy

Foundation packaging currently adds only development dependencies through uv's `dev` dependency group. Runtime dependencies for MFA behavior will be added in the implementation tasks that need them.

Planned vetted primitives:

- Django: app configuration, models, migrations, settings, checks, cache integration, auth/session integration points, and `django.utils.crypto.constant_time_compare`.
- `pyotp`: standards-compliant OATH TOTP and HOTP generation and verification primitives.
- Python standard library `secrets`: cryptographically secure random values where library-specific generation is not used.
- Python standard library `hmac.compare_digest`: constant-time comparison when Django's comparison helper is not the better local fit.
- `cryptography`: authenticated encryption for MFA secret material at rest, behind a project-owned storage abstraction.
- pytest and pytest-django: local, fixture-bound verification and Django integration tests.

Any future runtime dependency addition must be explicit in the relevant task and reviewed against maintenance quality, Django compatibility, and security posture.

## Required Security Invariants

Implementation tasks must preserve these invariants unless a later design record documents a safer replacement.

- Raw MFA secrets are never stored in plaintext in models, migrations, fixtures, examples, logs, or documentation.
- OTPs, recovery codes, tokens, and secret-derived values are compared with Django or standard-library constant-time helpers, or through vetted library verification APIs that provide equivalent safety.
- Accepted OTPs cannot be replayed.
- HOTP counters advance only after successful verification and never move through an unbounded search.
- HOTP resynchronization requires multiple related submissions, bounded search windows, replay protection, and audit records.
- Verification attempts integrate with throttling, lockout, or a documented compensating control.
- Enrollment, verification success, verification failure, replay detection, counter-window matches, and resynchronization outcomes are auditable.
- Session elevation from pre-MFA to post-MFA is treated as an authentication boundary.
- Local verification helpers operate only against synthetic users, synthetic devices, Django test clients, and direct in-process service calls.
- No verification helper accepts arbitrary target URLs, hosts, credentials, or payloads.

## Required Tests

The MVP implementation must include focused tests for:

- encrypted secret storage, including a failure if raw secret material is persisted directly;
- constant-time comparison use for OTPs, recovery codes, tokens, and secret-derived values;
- TOTP valid-code acceptance, invalid-code rejection, and configured time-window boundaries;
- HOTP counter advancement on success and no advancement on failure;
- HOTP replay prevention for previously accepted codes;
- HOTP bounded look-ahead behavior;
- HOTP audit records for success, failure, replay attempts, and counter-window matches;
- HOTP resynchronization success, failed resynchronization, replay during resynchronization, and excessive drift rejection;
- throttling, lockout, or documented compensating-control integration;
- local verification tooling remaining fixture-bound and in-process.
