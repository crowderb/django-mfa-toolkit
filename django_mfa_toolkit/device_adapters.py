from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from django.db import transaction
from django.utils import timezone

from django_mfa_toolkit.hotp import (
    DEFAULT_HOTP_DIGITS,
    DEFAULT_HOTP_LOOK_AHEAD,
    DEFAULT_HOTP_REPLAY_WINDOW,
    DEFAULT_HOTP_RESYNC_SEARCH_WINDOW,
    HOTPEnrollment,
    HOTPResyncResult,
    HOTPVerificationResult,
    enroll_hotp,
    resync_hotp,
    verify_hotp,
)
from django_mfa_toolkit.models import HOTPDevice, TOTPDevice
from django_mfa_toolkit.totp import (
    DEFAULT_TOTP_DIGITS,
    DEFAULT_TOTP_INTERVAL,
    DEFAULT_TOTP_VALID_WINDOW,
    TOTPEnrollment,
    TOTPVerificationResult,
    enroll_totp,
    verify_totp,
)


@dataclass(frozen=True)
class TOTPDeviceEnrollment:
    device: TOTPDevice
    enrollment: TOTPEnrollment


@dataclass(frozen=True)
class HOTPDeviceEnrollment:
    device: HOTPDevice
    enrollment: HOTPEnrollment


def enroll_totp_device(
    *,
    user,
    account_name: str,
    issuer_name: str,
    name: str = "",
    digits: int = DEFAULT_TOTP_DIGITS,
    interval: int = DEFAULT_TOTP_INTERVAL,
    secret_length: int | None = None,
) -> TOTPDeviceEnrollment:
    enrollment_kwargs = {
        "account_name": account_name,
        "issuer_name": issuer_name,
        "digits": digits,
        "interval": interval,
    }
    if secret_length is not None:
        enrollment_kwargs["secret_length"] = secret_length
    enrollment = enroll_totp(**enrollment_kwargs)
    device = TOTPDevice.objects.create(
        user=user,
        persisted_secret=enrollment.persisted_secret,
        name=name,
        digits=enrollment.digits,
        interval=enrollment.interval,
    )

    return TOTPDeviceEnrollment(device=device, enrollment=enrollment)


def enroll_hotp_device(
    *,
    user,
    account_name: str,
    issuer_name: str,
    name: str = "",
    initial_counter: int = 0,
    digits: int = DEFAULT_HOTP_DIGITS,
    secret_length: int | None = None,
) -> HOTPDeviceEnrollment:
    enrollment_kwargs = {
        "account_name": account_name,
        "issuer_name": issuer_name,
        "initial_counter": initial_counter,
        "digits": digits,
    }
    if secret_length is not None:
        enrollment_kwargs["secret_length"] = secret_length
    enrollment = enroll_hotp(**enrollment_kwargs)
    device = HOTPDevice.objects.create(
        user=user,
        persisted_secret=enrollment.persisted_secret,
        name=name,
        digits=enrollment.digits,
        hotp_counter=enrollment.initial_counter,
    )

    return HOTPDeviceEnrollment(device=device, enrollment=enrollment)


def verify_totp_device(
    *,
    device: TOTPDevice,
    submitted_code: str,
    at_time: datetime | None = None,
    valid_window: int = DEFAULT_TOTP_VALID_WINDOW,
) -> TOTPVerificationResult:
    with transaction.atomic():
        locked_device = TOTPDevice.objects.select_for_update().get(pk=device.pk)
        if not _device_can_verify(locked_device):
            return TOTPVerificationResult(accepted=False, failure_reason="invalid")

        result = verify_totp(
            encrypted_secret=locked_device.persisted_secret,
            submitted_code=submitted_code,
            at_time=at_time,
            valid_window=valid_window,
            last_accepted_timecode=locked_device.last_accepted_timecode,
            digits=locked_device.digits,
            interval=locked_device.interval,
        )
        if result.accepted:
            locked_device.last_accepted_timecode = result.matched_timecode
            locked_device.save(update_fields=["last_accepted_timecode", "updated_at"])

    return result


def verify_hotp_device(
    *,
    device: HOTPDevice,
    submitted_code: str,
    look_ahead: int = DEFAULT_HOTP_LOOK_AHEAD,
    replay_window: int = DEFAULT_HOTP_REPLAY_WINDOW,
    attempted_at: datetime | None = None,
) -> HOTPVerificationResult:
    with transaction.atomic():
        locked_device = HOTPDevice.objects.select_for_update().get(pk=device.pk)
        timestamp = attempted_at or timezone.now()
        if not _device_can_verify(locked_device):
            return _inactive_hotp_result(locked_device, look_ahead, replay_window, timestamp)

        result = verify_hotp(
            encrypted_secret=locked_device.persisted_secret,
            submitted_code=submitted_code,
            server_counter=locked_device.hotp_counter,
            look_ahead=look_ahead,
            replay_window=replay_window,
            digits=locked_device.digits,
            attempted_at=timestamp,
        )
        if result.accepted:
            locked_device.hotp_counter = result.next_counter
            locked_device.save(update_fields=["hotp_counter", "updated_at"])

    return result


def resync_hotp_device(
    *,
    device: HOTPDevice,
    submitted_codes: Sequence[str],
    search_window: int = DEFAULT_HOTP_RESYNC_SEARCH_WINDOW,
    replay_window: int = DEFAULT_HOTP_REPLAY_WINDOW,
    attempted_at: datetime | None = None,
) -> HOTPResyncResult:
    with transaction.atomic():
        locked_device = HOTPDevice.objects.select_for_update().get(pk=device.pk)
        timestamp = attempted_at or timezone.now()
        if not _device_can_verify(locked_device):
            return _inactive_hotp_resync_result(
                locked_device,
                submitted_codes,
                search_window,
                replay_window,
                timestamp,
            )

        result = resync_hotp(
            encrypted_secret=locked_device.persisted_secret,
            submitted_codes=submitted_codes,
            server_counter=locked_device.hotp_counter,
            search_window=search_window,
            replay_window=replay_window,
            digits=locked_device.digits,
            attempted_at=timestamp,
        )
        if result.accepted:
            locked_device.hotp_counter = result.next_counter
            locked_device.save(update_fields=["hotp_counter", "updated_at"])

    return result


def _device_can_verify(device: TOTPDevice | HOTPDevice) -> bool:
    return device.is_active and device.confirmed_at is not None


def _inactive_hotp_result(
    device: HOTPDevice,
    look_ahead: int,
    replay_window: int,
    attempted_at: datetime,
) -> HOTPVerificationResult:
    return verify_hotp(
        encrypted_secret=device.persisted_secret,
        submitted_code="",
        server_counter=device.hotp_counter,
        look_ahead=look_ahead,
        replay_window=replay_window,
        digits=device.digits,
        attempted_at=attempted_at,
    )


def _inactive_hotp_resync_result(
    device: HOTPDevice,
    submitted_codes: Sequence[str],
    search_window: int,
    replay_window: int,
    attempted_at: datetime,
) -> HOTPResyncResult:
    synthetic_count = len(submitted_codes) if not isinstance(submitted_codes, (str, bytes)) else 1
    return resync_hotp(
        encrypted_secret=device.persisted_secret,
        submitted_codes=["", ""][: max(2, synthetic_count)],
        server_counter=device.hotp_counter,
        search_window=search_window,
        replay_window=replay_window,
        digits=device.digits,
        attempted_at=attempted_at,
    )
