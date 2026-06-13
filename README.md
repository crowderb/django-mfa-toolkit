# django-mfa-toolkit

`django-mfa-toolkit` is an exploratory Django project for building a multi-factor authentication toolkit that is secure by construction, practical to integrate, and designed from the beginning for agent-assisted development.

This repository is currently a placeholder and concept workspace. It does not yet provide an installable package or production-ready MFA implementation.

## Purpose

The project explores whether Django needs an MFA package that is easier to integrate correctly than today's fragmented ecosystem of MFA libraries, plugins, and application-specific glue code.

The long-term goal is not only to support common MFA factors, but to make secure integration the default path:

- clear model and service boundaries
- safe defaults that are hard to misconfigure
- focused implementation guides that coding agents can follow reliably
- verification tools that help detect insecure or incomplete integrations
- security checks that reason about compensating controls instead of only reporting flat pass/fail configuration results

## Initial MVP

The initial MVP is expected to focus on:

- TOTP support for authenticator apps
- HOTP support for counter-based hardware tokens
- HOTP audit logging and counter resynchronization flows

HOTP support is a deliberate early target because counter desynchronization is a real operational problem and is not handled as a polished, turnkey workflow by much of the current Django MFA ecosystem.

Other factors, such as WebAuthn/FIDO2, YubiKey OTP, email OTP, and recovery codes, may be considered later, but they are not the first build target.

## Agent-Focused Approach

This project is intended to be agent-native, not merely agent-documented.

That means the project should evolve around artifacts that AI coding agents can inspect, follow, and verify:

- implementation guides written as concrete decision paths
- examples that show exact integration steps and expected outcomes
- machine-readable security control relationships
- Django checks, pytest helpers, or test mixins that verify real integration behavior
- narrow tool surfaces that avoid becoming general-purpose security scanners

The agent-facing goal is to help a developer answer questions such as:

- Is MFA actually enforced at the right point in the login flow?
- Are OTP attempts rate-limited or otherwise compensated by another control?
- Are used HOTP codes rejected on replay?
- Can the system detect and recover from HOTP counter drift?
- Does the implementation match the documented security assumptions?

The intended result is a toolkit where the code, documentation, tests, and agent guidance co-evolve. When a new integration risk is found, it should become part of the control model, the test suite, and the agent-facing guidance.

## Safety Boundaries

Because MFA verification tooling can become dual-use if it is too general, this project should keep its defensive checks narrow:

- verification should run against local Django tests and fixtures
- no tool should accept arbitrary target URLs
- adversarial checks should be fixture-bound and in-process
- timing-safety checks should prefer static analysis or direct in-process validation
- self-test behavior should be gated to development and CI environments

The intent is to help developers verify their own Django integrations without shipping reusable offensive tooling.

## Project Status

Status: exploratory concept repo.

No public API, package structure, compatibility promise, or release schedule exists yet. The next step is to turn the concept into a small, testable Django package centered on TOTP and HOTP primitives.

## Design Notes

The initial concept document lives in:

- `.docs/django-mfa-toolkit-concept.md`
- `.docs/design/mvp-integration-guide.md`
