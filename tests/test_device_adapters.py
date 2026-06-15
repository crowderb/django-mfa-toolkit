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
from django_mfa_toolkit.models import HOTPDevice, MFAAuditEvent, TOTPDevice
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
def test_hotp_device_verification_persists_success_audit_when_requested(
    synthetic_mfa_settings_override,
    django_user_model,
):
    user = django_user_model.objects.create_user(username="hotp-audit-success-user")
    enrolled = enroll_hotp_device(
        user=user,
        account_name="hotp@example.test",
        issuer_name="Toolkit",
    )
    HOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    secret = decrypt_secret_text(enrolled.device.persisted_secret)
    code = pyotp.HOTP(secret).at(0)

    result = verify_hotp_device(
        device=enrolled.device,
        submitted_code=code,
        look_ahead=0,
        persist_audit=True,
    )

    event = MFAAuditEvent.objects.get(device=enrolled.device)

    assert result.accepted is True
    assert event.event_type == MFAAuditEvent.EventType.VERIFICATION
    assert event.submitted_outcome == "accepted"
    assert event.result_classification == "success"
    assert event.server_counter == 0
    assert event.next_counter == 1


@pytest.mark.django_db
def test_hotp_device_verification_does_not_persist_audit_by_default(
    synthetic_mfa_settings_override,
    django_user_model,
):
    user = django_user_model.objects.create_user(username="hotp-no-default-audit-user")
    enrolled = enroll_hotp_device(
        user=user,
        account_name="hotp@example.test",
        issuer_name="Toolkit",
    )
    HOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    secret = decrypt_secret_text(enrolled.device.persisted_secret)
    code = pyotp.HOTP(secret).at(0)

    result = verify_hotp_device(device=enrolled.device, submitted_code=code, look_ahead=0)

    assert result.accepted is True
    assert MFAAuditEvent.objects.filter(device=enrolled.device).exists() is False


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
def test_hotp_device_verification_persists_failed_and_replayed_audits_without_otp(
    synthetic_mfa_settings_override,
    django_user_model,
):
    user = django_user_model.objects.create_user(username="hotp-audit-failure-user")
    enrolled = enroll_hotp_device(
        user=user,
        account_name="hotp@example.test",
        issuer_name="Toolkit",
    )
    HOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    secret = decrypt_secret_text(enrolled.device.persisted_secret)
    code = pyotp.HOTP(secret).at(0)

    accepted = verify_hotp_device(
        device=enrolled.device,
        submitted_code=code,
        look_ahead=0,
        persist_audit=True,
    )
    invalid = verify_hotp_device(
        device=enrolled.device,
        submitted_code="000000",
        look_ahead=0,
        persist_audit=True,
    )
    replayed = verify_hotp_device(
        device=enrolled.device,
        submitted_code=code,
        look_ahead=0,
        replay_window=1,
        persist_audit=True,
    )

    events = list(MFAAuditEvent.objects.filter(device=enrolled.device).order_by("id"))
    stored_values = " ".join(
        str(value)
        for event in events
        for value in (
            event.submitted_outcome,
            event.result_classification,
            event.server_counter,
            event.matched_counter,
            event.next_counter,
            event.look_ahead,
            event.replay_window,
        )
    )

    assert accepted.accepted is True
    assert invalid.accepted is False
    assert replayed.accepted is False
    assert [event.result_classification for event in events] == ["success", "invalid", "replay"]
    assert "000000" not in stored_values
    assert code not in stored_values
    assert secret not in stored_values
    assert enrolled.device.persisted_secret not in stored_values


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
def test_hotp_device_resync_persists_audit_when_requested(
    synthetic_mfa_settings_override,
    django_user_model,
):
    user = django_user_model.objects.create_user(username="hotp-resync-audit-user")
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
        persist_audit=True,
    )
    accepted = resync_hotp_device(
        device=enrolled.device,
        submitted_codes=[hotp.at(10), hotp.at(11)],
        search_window=20,
        persist_audit=True,
    )

    events = list(MFAAuditEvent.objects.filter(device=enrolled.device).order_by("id"))

    assert failed.accepted is False
    assert accepted.accepted is True
    assert [event.event_type for event in events] == [
        MFAAuditEvent.EventType.RESYNCHRONIZATION,
        MFAAuditEvent.EventType.RESYNCHRONIZATION,
    ]
    assert [event.result_classification for event in events] == ["invalid", "resync_success"]
    assert events[0].submitted_count == 2
    assert events[1].search_window == 20
    assert events[1].next_counter == 12


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


@pytest.mark.django_db
def test_totp_device_throttle_blocks_before_otp_verification_and_resets_on_success(
    synthetic_mfa_settings_override,
    django_user_model,
    monkeypatch,
):
    at_time = datetime(2026, 6, 14, 18, 0, tzinfo=timezone.utc)
    user = django_user_model.objects.create_user(username="totp-throttle-user")
    enrolled = enroll_totp_device(
        user=user,
        account_name="totp@example.test",
        issuer_name="Toolkit",
    )
    TOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    secret = decrypt_secret_text(enrolled.device.persisted_secret)
    valid_code = pyotp.TOTP(secret).at(at_time)
    throttle_scope = f"totp:{enrolled.device.pk}"

    invalid = verify_totp_device(
        device=enrolled.device,
        submitted_code="000000",
        at_time=at_time,
        valid_window=0,
        throttle_scope=throttle_scope,
        throttle_limit=1,
    )

    from django_mfa_toolkit import device_adapters

    def fail_if_called(**kwargs):
        raise AssertionError("TOTP verification should not run after throttle lockout.")

    monkeypatch.setattr(device_adapters, "verify_totp", fail_if_called)
    throttled = verify_totp_device(
        device=enrolled.device,
        submitted_code=valid_code,
        at_time=at_time,
        valid_window=0,
        throttle_scope=throttle_scope,
        throttle_limit=1,
    )

    monkeypatch.undo()
    accepted = verify_totp_device(
        device=enrolled.device,
        submitted_code=valid_code,
        at_time=at_time,
        valid_window=0,
        throttle_scope="totp-reset-scope",
        throttle_limit=2,
    )
    after_reset_invalid = verify_totp_device(
        device=enrolled.device,
        submitted_code="000000",
        at_time=at_time,
        valid_window=0,
        throttle_scope="totp-reset-scope",
        throttle_limit=2,
    )

    assert invalid.accepted is False
    assert invalid.failure_reason == "invalid"
    assert throttled.accepted is False
    assert throttled.failure_reason == "throttled"
    assert accepted.accepted is True
    assert after_reset_invalid.failure_reason == "invalid"


@pytest.mark.django_db
def test_hotp_device_throttle_returns_typed_lockout_without_advancing_counter(
    synthetic_mfa_settings_override,
    django_user_model,
    monkeypatch,
):
    user = django_user_model.objects.create_user(username="hotp-throttle-user")
    enrolled = enroll_hotp_device(
        user=user,
        account_name="hotp@example.test",
        issuer_name="Toolkit",
    )
    HOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    secret = decrypt_secret_text(enrolled.device.persisted_secret)
    valid_code = pyotp.HOTP(secret).at(0)
    throttle_scope = f"hotp:{enrolled.device.pk}"

    verify_hotp_device(
        device=enrolled.device,
        submitted_code="000000",
        look_ahead=0,
        throttle_scope=throttle_scope,
        throttle_limit=1,
    )

    from django_mfa_toolkit import device_adapters

    def fail_if_called(**kwargs):
        raise AssertionError("HOTP verification should not run after throttle lockout.")

    monkeypatch.setattr(device_adapters, "verify_hotp", fail_if_called)
    throttled = verify_hotp_device(
        device=enrolled.device,
        submitted_code=valid_code,
        look_ahead=0,
        throttle_scope=throttle_scope,
        throttle_limit=1,
    )

    enrolled.device.refresh_from_db()

    assert throttled.accepted is False
    assert throttled.audit_record.result_classification == "throttled"
    assert throttled.next_counter == 0
    assert enrolled.device.hotp_counter == 0


@pytest.mark.django_db
def test_hotp_device_throttle_persists_audit_without_advancing_counter(
    synthetic_mfa_settings_override,
    django_user_model,
):
    user = django_user_model.objects.create_user(username="hotp-throttle-audit-user")
    enrolled = enroll_hotp_device(
        user=user,
        account_name="hotp@example.test",
        issuer_name="Toolkit",
    )
    HOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    throttle_scope = f"hotp-audit:{enrolled.device.pk}"

    verify_hotp_device(
        device=enrolled.device,
        submitted_code="000000",
        look_ahead=0,
        throttle_scope=throttle_scope,
        throttle_limit=1,
    )
    throttled = verify_hotp_device(
        device=enrolled.device,
        submitted_code="111111",
        look_ahead=0,
        throttle_scope=throttle_scope,
        throttle_limit=1,
        persist_audit=True,
    )

    enrolled.device.refresh_from_db()
    event = MFAAuditEvent.objects.get(device=enrolled.device)

    assert throttled.accepted is False
    assert event.result_classification == "throttled"
    assert event.next_counter == 0
    assert enrolled.device.hotp_counter == 0


@pytest.mark.django_db
def test_hotp_resync_throttle_returns_typed_lockout_without_advancing_counter(
    synthetic_mfa_settings_override,
    django_user_model,
    monkeypatch,
):
    user = django_user_model.objects.create_user(username="hotp-resync-throttle-user")
    enrolled = enroll_hotp_device(
        user=user,
        account_name="hotp@example.test",
        issuer_name="Toolkit",
        initial_counter=3,
    )
    HOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    secret = decrypt_secret_text(enrolled.device.persisted_secret)
    hotp = pyotp.HOTP(secret)
    throttle_scope = f"hotp-resync:{enrolled.device.pk}"

    resync_hotp_device(
        device=enrolled.device,
        submitted_codes=[hotp.at(10), hotp.at(12)],
        search_window=20,
        throttle_scope=throttle_scope,
        throttle_limit=1,
    )

    from django_mfa_toolkit import device_adapters

    def fail_if_called(**kwargs):
        raise AssertionError("HOTP resync should not run after throttle lockout.")

    monkeypatch.setattr(device_adapters, "resync_hotp", fail_if_called)
    throttled = resync_hotp_device(
        device=enrolled.device,
        submitted_codes=[hotp.at(10), hotp.at(11)],
        search_window=20,
        throttle_scope=throttle_scope,
        throttle_limit=1,
    )

    enrolled.device.refresh_from_db()

    assert throttled.accepted is False
    assert throttled.audit_record.result_classification == "throttled"
    assert throttled.next_counter == 3
    assert enrolled.device.hotp_counter == 3


@pytest.mark.django_db
def test_hotp_resync_throttle_persists_audit_without_advancing_counter(
    synthetic_mfa_settings_override,
    django_user_model,
):
    user = django_user_model.objects.create_user(username="hotp-resync-throttle-audit-user")
    enrolled = enroll_hotp_device(
        user=user,
        account_name="hotp@example.test",
        issuer_name="Toolkit",
        initial_counter=3,
    )
    HOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    secret = decrypt_secret_text(enrolled.device.persisted_secret)
    hotp = pyotp.HOTP(secret)
    throttle_scope = f"hotp-resync-audit:{enrolled.device.pk}"

    resync_hotp_device(
        device=enrolled.device,
        submitted_codes=[hotp.at(10), hotp.at(12)],
        search_window=20,
        throttle_scope=throttle_scope,
        throttle_limit=1,
    )
    throttled = resync_hotp_device(
        device=enrolled.device,
        submitted_codes=[hotp.at(10), hotp.at(11)],
        search_window=20,
        throttle_scope=throttle_scope,
        throttle_limit=1,
        persist_audit=True,
    )

    enrolled.device.refresh_from_db()
    event = MFAAuditEvent.objects.get(device=enrolled.device)

    assert throttled.accepted is False
    assert event.event_type == MFAAuditEvent.EventType.RESYNCHRONIZATION
    assert event.result_classification == "throttled"
    assert event.next_counter == 3
    assert enrolled.device.hotp_counter == 3


@pytest.mark.django_db
def test_hotp_audit_persistence_failure_rolls_back_counter_update(
    synthetic_mfa_settings_override,
    django_user_model,
    monkeypatch,
):
    user = django_user_model.objects.create_user(username="hotp-audit-rollback-user")
    enrolled = enroll_hotp_device(
        user=user,
        account_name="hotp@example.test",
        issuer_name="Toolkit",
    )
    HOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    secret = decrypt_secret_text(enrolled.device.persisted_secret)
    code = pyotp.HOTP(secret).at(0)

    from django_mfa_toolkit import device_adapters

    def fail_audit_persistence(**kwargs):
        raise RuntimeError("audit persistence failed")

    monkeypatch.setattr(device_adapters, "create_hotp_audit_event", fail_audit_persistence)

    with pytest.raises(RuntimeError, match="audit persistence failed"):
        verify_hotp_device(
            device=enrolled.device,
            submitted_code=code,
            look_ahead=0,
            persist_audit=True,
        )

    enrolled.device.refresh_from_db()

    assert enrolled.device.hotp_counter == 0


@pytest.mark.django_db
def test_hotp_resync_audit_persistence_failure_rolls_back_counter_update(
    synthetic_mfa_settings_override,
    django_user_model,
    monkeypatch,
):
    user = django_user_model.objects.create_user(username="hotp-resync-audit-rollback-user")
    enrolled = enroll_hotp_device(
        user=user,
        account_name="hotp@example.test",
        issuer_name="Toolkit",
        initial_counter=3,
    )
    HOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    secret = decrypt_secret_text(enrolled.device.persisted_secret)
    hotp = pyotp.HOTP(secret)

    from django_mfa_toolkit import device_adapters

    def fail_audit_persistence(**kwargs):
        raise RuntimeError("resync audit persistence failed")

    monkeypatch.setattr(device_adapters, "create_hotp_resync_audit_event", fail_audit_persistence)

    with pytest.raises(RuntimeError, match="resync audit persistence failed"):
        resync_hotp_device(
            device=enrolled.device,
            submitted_codes=[hotp.at(10), hotp.at(11)],
            search_window=20,
            persist_audit=True,
        )

    enrolled.device.refresh_from_db()

    assert enrolled.device.hotp_counter == 3


def _record_select_for_update_calls(monkeypatch):
    calls = []
    original = QuerySet.select_for_update

    def recording_select_for_update(self, *args, **kwargs):
        calls.append(self.model)
        assert connection.in_atomic_block is True
        return original(self, *args, **kwargs)

    monkeypatch.setattr(QuerySet, "select_for_update", recording_select_for_update)
    return calls
