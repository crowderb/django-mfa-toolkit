from datetime import datetime, timezone

import pyotp
import pytest
from django.db import connection
from django.db.models.query import QuerySet
from django.utils import timezone as django_timezone

from django_mfa_toolkit.device_adapters import (
    enroll_hotp_device,
    enroll_totp_device,
    resync_hotp_device,
    verify_hotp_device,
    verify_totp_device,
)
from django_mfa_toolkit.models import HOTPDevice, TOTPDevice
from django_mfa_toolkit.secret_storage import decrypt_secret_text


@pytest.mark.django_db
def test_totp_device_enrollment_creates_unconfirmed_device_without_plaintext(
    synthetic_mfa_settings_override,
    django_user_model,
):
    user = django_user_model.objects.create_user(username="totp-enroll-user")

    enrolled = enroll_totp_device(
        user=user,
        account_name="totp@example.test",
        issuer_name="Toolkit",
        name="Authenticator app",
    )
    raw_secret = decrypt_secret_text(enrolled.enrollment.persisted_secret)

    assert enrolled.device.pk is not None
    assert enrolled.device.user == user
    assert enrolled.device.name == "Authenticator app"
    assert enrolled.device.confirmed_at is None
    assert enrolled.device.is_active is True
    assert enrolled.device.persisted_secret == enrolled.enrollment.persisted_secret
    assert raw_secret not in enrolled.device.persisted_secret


@pytest.mark.django_db
def test_hotp_device_enrollment_creates_unconfirmed_device_without_plaintext(
    synthetic_mfa_settings_override,
    django_user_model,
):
    user = django_user_model.objects.create_user(username="hotp-enroll-user")

    enrolled = enroll_hotp_device(
        user=user,
        account_name="hotp@example.test",
        issuer_name="Toolkit",
        name="Hardware token",
        initial_counter=3,
    )
    raw_secret = decrypt_secret_text(enrolled.enrollment.persisted_secret)

    assert enrolled.device.pk is not None
    assert enrolled.device.user == user
    assert enrolled.device.name == "Hardware token"
    assert enrolled.device.confirmed_at is None
    assert enrolled.device.is_active is True
    assert enrolled.device.hotp_counter == 3
    assert enrolled.device.persisted_secret == enrolled.enrollment.persisted_secret
    assert raw_secret not in enrolled.device.persisted_secret


@pytest.mark.django_db
def test_totp_device_verification_updates_replay_state_atomically(
    synthetic_mfa_settings_override,
    django_user_model,
    monkeypatch,
):
    at_time = datetime(2026, 6, 14, 18, 0, tzinfo=timezone.utc)
    user = django_user_model.objects.create_user(username="totp-verify-user")
    enrolled = enroll_totp_device(
        user=user,
        account_name="totp@example.test",
        issuer_name="Toolkit",
    )
    TOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    secret = decrypt_secret_text(enrolled.device.persisted_secret)
    code = pyotp.TOTP(secret).at(at_time)

    lock_calls = _record_select_for_update_calls(monkeypatch)
    result = verify_totp_device(device=enrolled.device, submitted_code=code, at_time=at_time, valid_window=0)

    enrolled.device.refresh_from_db()

    assert lock_calls
    assert result.accepted is True
    assert enrolled.device.last_accepted_timecode == result.matched_timecode


@pytest.mark.django_db
def test_totp_device_replay_and_invalid_attempts_do_not_advance_state(
    synthetic_mfa_settings_override,
    django_user_model,
):
    at_time = datetime(2026, 6, 14, 18, 0, tzinfo=timezone.utc)
    user = django_user_model.objects.create_user(username="totp-replay-user")
    enrolled = enroll_totp_device(
        user=user,
        account_name="totp@example.test",
        issuer_name="Toolkit",
    )
    TOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    secret = decrypt_secret_text(enrolled.device.persisted_secret)
    code = pyotp.TOTP(secret).at(at_time)

    accepted = verify_totp_device(device=enrolled.device, submitted_code=code, at_time=at_time, valid_window=0)
    replayed = verify_totp_device(device=enrolled.device, submitted_code=code, at_time=at_time, valid_window=0)
    invalid = verify_totp_device(device=enrolled.device, submitted_code="000000", at_time=at_time, valid_window=0)

    enrolled.device.refresh_from_db()

    assert accepted.accepted is True
    assert replayed.accepted is False
    assert replayed.failure_reason == "replay"
    assert invalid.accepted is False
    assert enrolled.device.last_accepted_timecode == accepted.matched_timecode


@pytest.mark.django_db
def test_hotp_device_verification_updates_counter_atomically(
    synthetic_mfa_settings_override,
    django_user_model,
    monkeypatch,
):
    user = django_user_model.objects.create_user(username="hotp-verify-user")
    enrolled = enroll_hotp_device(
        user=user,
        account_name="hotp@example.test",
        issuer_name="Toolkit",
    )
    HOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    secret = decrypt_secret_text(enrolled.device.persisted_secret)
    code = pyotp.HOTP(secret).at(0)

    lock_calls = _record_select_for_update_calls(monkeypatch)
    result = verify_hotp_device(device=enrolled.device, submitted_code=code, look_ahead=0)

    enrolled.device.refresh_from_db()

    assert lock_calls
    assert result.accepted is True
    assert result.next_counter == 1
    assert enrolled.device.hotp_counter == 1


@pytest.mark.django_db
def test_hotp_device_failed_and_replayed_attempts_do_not_advance_counter(
    synthetic_mfa_settings_override,
    django_user_model,
):
    user = django_user_model.objects.create_user(username="hotp-replay-user")
    enrolled = enroll_hotp_device(
        user=user,
        account_name="hotp@example.test",
        issuer_name="Toolkit",
    )
    HOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    secret = decrypt_secret_text(enrolled.device.persisted_secret)
    code = pyotp.HOTP(secret).at(0)

    accepted = verify_hotp_device(device=enrolled.device, submitted_code=code, look_ahead=0)
    invalid = verify_hotp_device(device=enrolled.device, submitted_code="000000", look_ahead=0)
    replayed = verify_hotp_device(device=enrolled.device, submitted_code=code, look_ahead=0, replay_window=1)

    enrolled.device.refresh_from_db()

    assert accepted.accepted is True
    assert invalid.accepted is False
    assert replayed.accepted is False
    assert replayed.audit_record.result_classification == "replay"
    assert enrolled.device.hotp_counter == accepted.next_counter


@pytest.mark.django_db
def test_hotp_device_resync_updates_counter_only_on_success(
    synthetic_mfa_settings_override,
    django_user_model,
):
    user = django_user_model.objects.create_user(username="hotp-resync-user")
    enrolled = enroll_hotp_device(
        user=user,
        account_name="hotp@example.test",
        issuer_name="Toolkit",
        initial_counter=3,
    )
    HOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    secret = decrypt_secret_text(enrolled.device.persisted_secret)
    hotp = pyotp.HOTP(secret)

    failed = resync_hotp_device(
        device=enrolled.device,
        submitted_codes=[hotp.at(10), hotp.at(12)],
        search_window=20,
    )
    accepted = resync_hotp_device(
        device=enrolled.device,
        submitted_codes=[hotp.at(10), hotp.at(11)],
        search_window=20,
    )

    enrolled.device.refresh_from_db()

    assert failed.accepted is False
    assert accepted.accepted is True
    assert accepted.next_counter == 12
    assert enrolled.device.hotp_counter == 12


@pytest.mark.django_db
def test_unconfirmed_devices_reject_verification_without_state_changes(
    synthetic_mfa_settings_override,
    django_user_model,
):
    at_time = datetime(2026, 6, 14, 18, 0, tzinfo=timezone.utc)
    user = django_user_model.objects.create_user(username="unconfirmed-user")
    enrolled = enroll_totp_device(
        user=user,
        account_name="totp@example.test",
        issuer_name="Toolkit",
    )
    secret = decrypt_secret_text(enrolled.device.persisted_secret)
    code = pyotp.TOTP(secret).at(at_time)

    result = verify_totp_device(device=enrolled.device, submitted_code=code, at_time=at_time, valid_window=0)

    enrolled.device.refresh_from_db()

    assert result.accepted is False
    assert enrolled.device.last_accepted_timecode is None


def _record_select_for_update_calls(monkeypatch):
    calls = []
    original = QuerySet.select_for_update

    def recording_select_for_update(self, *args, **kwargs):
        calls.append(self.model)
        assert connection.in_atomic_block is True
        return original(self, *args, **kwargs)

    monkeypatch.setattr(QuerySet, "select_for_update", recording_select_for_update)
    return calls
