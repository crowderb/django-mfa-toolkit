# django-otp Compatibility Evaluation

Status: accepted compatibility decision
Date: 2026-06-15

## Decision

Do not add a runtime `django-otp` dependency or adapter in the current package
surface. Compatibility is worth preserving as a future optional bridge, but the
adapter should be deferred until a separate dependency-review task and bridge
design can prove that the package security invariants remain intact.

The recommended next step is not to subclass the
built-in `django-otp` `TOTPDevice`, `HOTPDevice`, or `StaticDevice` models. A future compatibility
bridge should instead be optional and should map between this package's
model-backed verification results and django-otp's verified-session concepts.

## Sources Reviewed

- `django-otp` 1.7.0 documentation, Overview and Key Concepts:
  `https://django-otp-official.readthedocs.io/en/stable/overview.html`
- `django-otp` 1.7.0 documentation, Authentication and Authorization:
  `https://django-otp-official.readthedocs.io/en/stable/auth.html`
- `django-otp` 1.7.0 documentation, Extending Django-OTP:
  `https://django-otp-official.readthedocs.io/en/stable/extend.html`
- Local design notes:
  `.docs/design/mvp-architecture.md`,
  `.docs/design/device-persistence-contracts.md`,
  `.docs/design/audit-persistence-contracts.md`,
  `.docs/design/recovery-code-support.md`, and
  `.docs/design/control-graph.md`.

## Current Package Guarantees

The current package owns its persistence and verification boundary:

- TOTP and HOTP seeds are stored through `EncryptedSecret`, not as plaintext or
  hex-encoded model fields.
- TOTP replay prevention is explicit through `last_accepted_timecode`.
- HOTP counter advancement and resynchronization are explicit, atomic, and
  tested through model-backed adapters.
- HOTP audit persistence can run in the same transaction as accepted counter
  updates when explicitly enabled.
- Recovery codes are stored as Django password hashes and consumed exactly once.
- Throttling is applied before verification when configured.
- Session elevation is a package-owned timestamped boundary and can distinguish
  `totp`, `hotp`, and `recovery-code` factors.
- Local verification helpers are fixture-bound and non-targetable.

These are the invariants an adapter must preserve. Compatibility cannot require
raw MFA seeds, raw recovery codes, submitted OTPs, provisioning URIs, or
production credentials to be copied into django-otp models, migrations, logs, or
fixtures.

## django-otp Fit

`django-otp` is a mature ecosystem abstraction. Its documented model is useful:

- `OTPMiddleware` augments authenticated users with a verified device marker.
- Plugins are Django apps containing models that subclass `django_otp.models.Device`.
- Low-level APIs can verify a specific device inside a transaction, and
  `devices_for_user(..., for_verify=True)` / `Device.from_persistent_id(...,
  for_verify=True)` use `select_for_update()`.
- `Device.verify_token()` is explicitly stateful: a successful token should no
  longer be valid.
- Built-in TOTP/HOTP plugins provide replay and counter state; built-in static
  tokens are consumed on use.
- `ThrottlingMixin` provides exponential backoff through model fields.

Those extension points make a bridge plausible. They do not make the built-in
plugin models a drop-in replacement for this package's current models.

## Compatibility Gaps

### Encrypted Storage

The documented built-in TOTP and HOTP plugins store `key` as a hex-encoded
secret field. This does not preserve `secret-storage.encrypted-at-rest` as
currently implemented.

An adapter must not migrate or duplicate package-managed encrypted seeds into
django-otp's built-in `key` fields. A custom django-otp `Device` subclass could
delegate to this package's encrypted models, but that is a new optional
compatibility package surface, not a small wrapper around built-in models.

### HOTP Resynchronization

The package has an explicit bounded HOTP resynchronization service with
consecutive-code requirements and structured audit classifications. The
documented django-otp HOTP device exposes normal token verification and counter
tolerance, but not this package's resynchronization workflow or audit semantics.

An adapter must keep `hotp.resync-bounded` in the package service layer.

### Audit Semantics

django-otp's core `verify_token()` returns booleans or a device, while this
package exposes structured audit classifications such as `success`, `invalid`,
`replay`, `throttled`, `resync_success`, `excessive_drift`, and recovery-code
`reset`.

An adapter that only calls django-otp built-ins would lose package audit
vocabulary. A future bridge must keep package verification as the source of
truth and then mark django-otp-compatible session state.

### Throttling

django-otp provides exponential throttling fields and mixins. This package uses
cache-backed throttle scopes that avoid storing raw OTPs and can be keyed by
local flow/user/device boundaries.

The two can coexist, but a bridge must define a single source of truth per
factor to avoid double-throttling surprises or a disabled package throttle being
mistaken for a documented compensating lockout.

### Recovery Codes

django-otp static tokens are documented as random token rows that are deleted on
use. This package stores recovery codes as password hashes and tracks batch
replacement state. The built-in static plugin does not preserve
`recovery-code.hashed-at-rest` or reset audit semantics.

Recovery-code compatibility should be treated as a separate bridge problem from
TOTP/HOTP compatibility.

## Recommendation

Defer a runtime adapter and dependency.

Pursue compatibility only as an optional bridge after two prerequisites:

1. A dependency review that pins supported `django-otp` versions, evaluates
   migration impact, and documents middleware/session interactions.
2. A bridge design that keeps this package's encrypted models and verification
   services as the source of truth while exposing a django-otp-compatible
   verified-session/device facade.

The bridge should not use django-otp built-in TOTP, HOTP, or static-token models
as canonical storage for package-managed factors.

## Preserved Invariants for a Future Bridge

A future compatibility bridge must preserve:

- `secret-storage.encrypted-at-rest`;
- `comparison.constant-time`;
- `totp.replay-prevention`;
- `hotp.counter-advance`;
- `hotp.replay-prevention`;
- `hotp.resync-bounded`;
- `hotp.audit` and `hotp.audit-persistence`;
- `django-throttling.lockout` or a documented compensating lockout;
- `django-session-elevation.boundary`;
- `recovery-code.hashed-at-rest`;
- `recovery-code.one-time-use`;
- `recovery-code.replay-prevention`;
- `recovery-code.audit`;
- `verification-surface.not-targetable`.

If any bridge design weakens one of these controls, it must be rejected or split
behind an explicit threat-model decision.

## Follow-Up Tasks

No runtime dependency is added by this evaluation. Follow-up work should be split into
separate tasks:

1. Review and pin optional `django-otp` dependency support.
2. Design an optional django-otp bridge that delegates verification to this
   package and exposes compatible session/device semantics without copying raw
   secrets or recovery codes.
3. Implement the bridge only after the dependency review and bridge design are
   accepted.
