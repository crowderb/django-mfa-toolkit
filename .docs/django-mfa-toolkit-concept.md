# Concept Proposal: Agent-Native MFA Toolkit for Django

**Status:** Exploratory concept capture; not yet scoped, not yet implemented
**Created:** 2026-06-13
**Intent:** Project design seed for continued discussion and eventual implementation

---

## 1. Project Purpose

`django-mfa-toolkit` should explore whether Django needs an MFA package designed to be easy to integrate correctly, including by AI coding agents, while also providing mechanisms to detect insecure or incomplete integrations.

The project should prioritize:

- secure-by-construction model and service APIs
- strong support for TOTP authenticator apps
- strong support for HOTP counter-based hardware tokens
- first-class HOTP audit logging and counter resynchronization flows
- agent-legible documentation and implementation guides
- local verification tools that detect security gaps without becoming general-purpose scanners

The initial MVP should focus on TOTP and HOTP. Other MFA factors may be considered later, but the first build should stay narrow enough to produce a secure, well-tested foundation.

---

## 2. Existing Landscape

Several Django MFA packages already exist. This project should avoid duplicating them without a clear reason.

| Package | Covers | Notes |
|---|---|---|
| **django-otp** | TOTP, HOTP, static backup codes, email OTP via plugins; Yubico OTP and WebAuthn through separately maintained plugins | Foundational `Device` abstraction for much of the ecosystem. Plugin-based and interoperable, but assembling a complete MFA experience requires multiple packages and integration decisions. |
| **django-two-factor-auth** | Setup and login wizard UI on top of django-otp | UI layer, not a device framework itself. |
| **allauth.mfa** | TOTP, WebAuthn, recovery codes | Tied to django-allauth account and email-verification flows. Does not provide HOTP resync/audit support. |
| **django-mfa2** | TOTP, FIDO2/U2F, email, SMS, trusted devices | Broadly featured, but HOTP support and audit/resync tooling are not the central differentiator. |

Two gaps appear worth exploring:

- **HOTP counter desynchronization handling:** A polished audit log and resynchronization workflow is not commonly available as a turnkey Django feature.
- **Agent-readable secure integration:** Existing packages often document feature availability, but not always the exact decision paths an AI coding agent or developer needs to integrate MFA safely.

This project should not become a broad replacement for every existing package unless the design work proves that a cohesive standalone toolkit is justified.

---

## 3. Core Differentiator

The project should combine three artifacts that evolve together:

1. **Constrained core APIs and models**
   - Make insecure configurations difficult or impossible to express.
   - Keep security-sensitive behavior in well-tested service boundaries.
   - Prefer explicit state transitions for enrollment, verification, resync, and recovery flows.

2. **Implementation guides written for agent consumption**
   - Use decision-tree-style guidance rather than vague prose.
   - Show exact integration steps, expected settings, and verification commands.
   - Include examples of correct and incorrect integration patterns.

3. **Agentic gap detection with compensating-control reasoning**
   - Go beyond flat checklists where possible.
   - Represent relationships such as `TOTP requires rate limiting OR lockout OR an explicitly documented compensating control`.
   - Report missing controls in terms of the risk and the available secure remedies.

The long-term goal is a package where code, documentation, tests, and agent-facing guidance reinforce each other.

---

## 4. Co-Evolution Architecture

The project should maintain three related layers:

1. **Core implementation layer**
   - Django models, services, validators, and settings.
   - Security invariants should live here, not only in documentation.

2. **Machine-readable control graph**
   - Encodes required controls and acceptable compensating controls.
   - Example: `HOTP verification requires replay prevention, counter-window limits, audit logging, and throttling or lockout`.
   - New risks should become graph nodes or edges when practical.

3. **Agent skill, MCP tool, or equivalent verification surface**
   - Runs local checks and tests.
   - Parses results.
   - Explains findings against the control graph.
   - Does not generate arbitrary probes or accept arbitrary remote targets.

When a new integration risk is found, it should become:

- a documented design note
- a test or check
- a control-graph relationship when applicable
- an agent-facing instruction or troubleshooting path

---

## 5. Active Verification Loop

Static configuration checks are useful but insufficient. The project should verify that important controls hold when exercised.

Examples of desired local checks:

- replay a used HOTP code and confirm it is rejected
- verify HOTP counter advancement and resynchronization behavior
- attempt excessive OTP submissions and confirm throttling or lockout behavior
- verify OTP and token comparisons use constant-time comparison
- test the pre-MFA to post-MFA session transition for session fixation risks
- confirm audit records are created for security-relevant verification outcomes

Dynamic checks should run only against synthetic users, synthetic devices, local fixtures, and Django's in-process test client.

---

## 6. Dual-Use Design Constraints

MFA verification tooling can become dual-use if it is too general. This project should gate on capability generality, not stated intent.

### Core principle

A tool whose interface has no concept of an arbitrary target cannot be repointed at an arbitrary target. Narrow interfaces are both a maintainability property and a security property.

### Required design rules

- **Fixture-bound tests, not generic scanners:** All adversarial or verification checks must operate against users and devices created by the test suite.
- **No arbitrary target input:** No verification tool should accept a target URL, host, credential, or arbitrary payload.
- **Use Django in-process testing:** Prefer Django's test client and direct service calls over network requests.
- **Timing-safety via static or in-process checks:** Prefer checking for `hmac.compare_digest` or Django's `constant_time_compare`. Do not ship network timing probes.
- **Hard environment gating:** Self-test and adversarial verification helpers must be gated to development and CI use. They must not be enabled by default in production.
- **Narrow agent tool surface:** Agent-facing tools should run fixed checks, parse results, and explain findings. They should not synthesize novel probes.
- **Library-first distribution:** Prefer library code, pytest plugins, and Django test mixins over standalone CLIs with target arguments.

The project may document attack classes to explain defenses, but it must not package reusable, retargetable offensive tooling.

---

## 7. Security Design Rules

The implementation should follow these rules unless an explicit design record documents a safer alternative:

- Use vetted cryptographic and protocol libraries rather than hand-rolled implementations.
- Use standards-compliant OATH TOTP and OATH HOTP behavior.
- Generate secrets with cryptographically secure randomness.
- Store MFA secrets securely and encrypted.
- Compare OTPs, recovery codes, and secret-derived values using constant-time comparison.
- Prevent OTP replay.
- Rate-limit or lock out repeated verification attempts.
- Audit enrollment, verification success, verification failure, replay detection, and HOTP resynchronization outcomes.
- Treat session elevation from pre-MFA to post-MFA as a security boundary.
- Keep examples free of real secrets and production identifiers.

---

## 8. Open Questions

These decisions should be made deliberately before implementation expands:

- **Build on django-otp or provide a custom device model?**
  - Building on django-otp improves interoperability.
  - A custom API may better enforce secure-by-construction behavior.
  - The project should not default to either option without documenting the tradeoff.

- **How narrow should the MVP remain?**
  - The current MVP target is TOTP and HOTP.
  - HOTP audit logging and counter resynchronization are the clearest differentiators.

- **How should agent-facing tooling be packaged?**
  - Options include Codex skills, MCP tools, pytest plugins, Django test mixins, or a combination.
  - Packaging should preserve the no-generic-scanner constraint.

- **Which compensating controls are acceptable?**
  - Some protections may be satisfied by multiple controls together.
  - The project should document these relationships explicitly rather than relying on implicit judgment.

---

## 9. Initial Implementation Direction

The first implementation phase should aim for a small, secure Django package that includes:

- project packaging and test infrastructure
- TOTP secret enrollment and verification services
- HOTP secret enrollment and verification services
- HOTP usage audit records
- HOTP counter resynchronization flow
- constant-time comparison tests
- replay-prevention tests
- throttling or lockout integration points
- documentation written as agent-followable integration paths

The first milestone should prove that the toolkit can make TOTP and HOTP integration clearer, safer, and easier to verify than hand-rolled project-specific MFA code.
