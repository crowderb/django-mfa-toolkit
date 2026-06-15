"""Reusable local MFA integration checks for downstream Django test suites."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import pyotp
from django.utils import timezone

from django_mfa_toolkit.device_adapters import verify_hotp_device, verify_totp_device
from django_mfa_toolkit.models import HOTPDevice, TOTPDevice
from django_mfa_toolkit.secret_storage import decrypt_secret_text


@dataclass(frozen=True)
class LocalIntegrationCheckResult:
    id: str
    passed: bool
    detail: str


class MFALocalIntegrationCheckMixin:
    """Assertion helpers for fixture-bound downstream MFA integration tests."""

    def assert_local_security_invariants_pass(self) -> None:
        from django_mfa_toolkit.security_invariants import run_local_security_invariant_checks

        failed = [check for check in run_local_security_invariant_checks() if not check.passed]
        if failed:
            details = "; ".join(f"{check.id}: {check.detail}" for check in failed)
            raise AssertionError(f"Local MFA security invariant checks failed: {details}")

    def assert_totp_device_rejects_replay(
        self,
        device: TOTPDevice,
        *,
        at_time: datetime | None = None,
        valid_window: int = 0,
    ) -> None:
        timestamp = at_time or timezone.now()
        submitted_code = pyotp.TOTP(decrypt_secret_text(device.persisted_secret), digits=device.digits).at(timestamp)

        accepted = verify_totp_device(
            device=device,
            submitted_code=submitted_code,
            at_time=timestamp,
            valid_window=valid_window,
        )
        replayed = verify_totp_device(
            device=device,
            submitted_code=submitted_code,
            at_time=timestamp,
            valid_window=valid_window,
        )

        if not accepted.accepted:
            raise AssertionError(f"Expected synthetic TOTP device check to accept the first code: {accepted}")
        if replayed.accepted or replayed.failure_reason != "replay":
            raise AssertionError(f"Expected synthetic TOTP device check to reject replay: {replayed}")

    def assert_hotp_device_rejects_replay_without_counter_advance(
        self,
        device: HOTPDevice,
        *,
        look_ahead: int = 0,
        replay_window: int = 1,
    ) -> None:
        starting_counter = device.hotp_counter
        submitted_code = pyotp.HOTP(decrypt_secret_text(device.persisted_secret), digits=device.digits).at(starting_counter)

        accepted = verify_hotp_device(
            device=device,
            submitted_code=submitted_code,
            look_ahead=look_ahead,
            replay_window=replay_window,
        )
        replayed = verify_hotp_device(
            device=device,
            submitted_code=submitted_code,
            look_ahead=look_ahead,
            replay_window=replay_window,
        )

        device.refresh_from_db()

        if not accepted.accepted or accepted.next_counter != starting_counter + 1:
            raise AssertionError(f"Expected synthetic HOTP device check to accept and advance once: {accepted}")
        if replayed.accepted or replayed.audit_record.result_classification != "replay":
            raise AssertionError(f"Expected synthetic HOTP device check to reject replay: {replayed}")
        if device.hotp_counter != starting_counter + 1:
            raise AssertionError(
                "Expected synthetic HOTP device check to leave the persisted counter unchanged after replay."
            )

    def assert_mfa_required_session_boundary(
        self,
        *,
        anonymous_response,
        verified_response,
        protected_response,
        replay_response,
        forbidden_status: int = 403,
        verified_status: int = 204,
        protected_status: int = 200,
    ) -> None:
        if anonymous_response.status_code != forbidden_status:
            raise AssertionError("Expected protected view to reject the pre-MFA in-process client request.")
        if verified_response.status_code != verified_status:
            raise AssertionError("Expected local MFA verification response to mark the session elevated.")
        if protected_response.status_code != protected_status:
            raise AssertionError("Expected protected view to accept the MFA-elevated in-process client request.")
        if replay_response.status_code != forbidden_status:
            raise AssertionError("Expected protected view to reject the replayed or non-elevated client request.")


def run_local_django_mfa_integration_checks(
    *,
    totp_device: TOTPDevice | None = None,
    hotp_device: HOTPDevice | None = None,
    at_time: datetime | None = None,
) -> tuple[LocalIntegrationCheckResult, ...]:
    """Run local integration checks against caller-provided synthetic devices."""

    mixin = MFALocalIntegrationCheckMixin()
    results = [_check_result("security-invariants.pass", mixin.assert_local_security_invariants_pass)]
    if totp_device is not None:
        results.append(
            _check_result(
                "django-integration.totp-replay",
                lambda: mixin.assert_totp_device_rejects_replay(totp_device, at_time=at_time),
            )
        )
    if hotp_device is not None:
        results.append(
            _check_result(
                "django-integration.hotp-replay-counter",
                lambda: mixin.assert_hotp_device_rejects_replay_without_counter_advance(hotp_device),
            )
        )
    return tuple(results)


def _check_result(check_id: str, assertion) -> LocalIntegrationCheckResult:
    try:
        assertion()
    except AssertionError as exc:
        return LocalIntegrationCheckResult(id=check_id, passed=False, detail=str(exc))
    return LocalIntegrationCheckResult(id=check_id, passed=True, detail="Local fixture-bound check passed.")
