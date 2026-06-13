# django-mfa-toolkit Agent Guidance

## Project Guardrails

- If the user asks to implement a feature, process, data model, protocol flow, or integration pattern in a way that appears inconsistent with a relevant standard or idiom, pause and ask for clarification before implementing it.
- When pausing for standards clarification, name the concern concretely and suggest a standards-compliant or idiomatic alternative.
- Relevant standards and idioms include Django conventions, django-tenants patterns when applicable, OATH TOTP, OATH HOTP, WebAuthn/FIDO2, YubiKey OTP conventions, Python packaging norms, and Django security best practices.
- If the user asks for a change that appears to add security risk, pause before implementing it, explain the security concern, and suggest a more secure option.
- Treat security-sensitive MFA behavior as requiring explicit design clarity before implementation. This includes token validation, replay handling, throttling, recovery flows, device enrollment, secret storage, session elevation, audit logging, and self-test tooling.
- Store all secrets in a secure, encrypted manner. Do not store raw MFA secrets, API keys, private keys, tokens, passwords, or production credentials in plaintext files, fixtures, logs, migrations, examples, or documentation.
- Before committing or preparing commit-ready changes, review new and modified files for secrets. Never add real secrets to the repository.
- Keep local environment files such as `.env` ignored. When configuration examples are needed, commit `.env.example` with pseudo values only.
- Pushes to the git server must be made from a new feature branch. Never push directly to `main`.

## Security Development Rules

- Prefer standard library, Django, or well-maintained security libraries for cryptographic and protocol behavior. Do not hand-roll OTP generation, secret comparison, random secret generation, encryption, signing, or WebAuthn/FIDO2 protocol logic when a vetted implementation exists.
- Use constant-time comparison for OTPs, recovery codes, tokens, and other secret-derived values.
- Treat MFA replay prevention, throttling, lockout, audit logging, and session elevation as required security controls unless an explicit design decision documents a compensating control.
- Any change to token validation, device enrollment, secret storage, authentication flow, session state, or recovery behavior must include or update focused tests for the relevant security invariant.
- Do not add generalized offensive or scanner-like tooling. Verification tools must be fixture-bound, local, and in-process; they must not accept arbitrary target URLs, hosts, credentials, or payloads.
- Keep dynamic security checks limited to synthetic users, synthetic devices, Django test clients, and local test fixtures. Timing checks should prefer static analysis or direct in-process function checks, not network timing probes.
- Any self-test, adversarial test, or verification helper must be gated to development or CI usage and must not be enabled by default in production.
- Document security assumptions near the code or test that depends on them. If a control is intentionally omitted, document the compensating control and the threat model assumption.
- Do not weaken Django security defaults, authentication middleware, CSRF behavior, password handling, session handling, or cookie security settings without pausing for explicit user confirmation.
