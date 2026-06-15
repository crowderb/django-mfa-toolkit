from datetime import datetime, timezone

import pyotp
import pytest
from django.db import connection
from django.db.migrations.loader import MigrationLoader
from django.utils import timezone as django_timezone

from django_mfa_toolkit.audit import create_hotp_audit_event, create_hotp_resync_audit_event
from django_mfa_toolkit.device_adapters import enroll_hotp_device
from django_mfa_toolkit.hotp import HOTPAuditRecord, HOTPResyncAuditRecord, resync_hotp, verify_hotp
from django_mfa_toolkit.models import HOTPDevice, MFAAuditEvent
from django_mfa_toolkit.secret_storage import decrypt_secret_text


@pytest.mark.django_db
def test_hotp_verification_audit_event_maps_service_record(
    synthetic_mfa_settings_override,
    django_user_model,
):
    attempted_at = datetime(2026, 6, 15, 16, 0, tzinfo=timezone.utc)
    user = django_user_model.objects.create_user(username="hotp-audit-user")
    enrolled = enroll_hotp_device(
        user=user,
        account_name="hotp-audit@example.test",
        issuer_name="Toolkit",
    )
    HOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    secret = decrypt_secret_text(enrolled.device.persisted_secret)
    code = pyotp.HOTP(secret).at(3)
    result = verify_hotp(
        encrypted_secret=enrolled.device.persisted_secret,
        submitted_code=code,
        server_counter=0,
        look_ahead=5,
        replay_window=2,
        attempted_at=attempted_at,
    )

    event = create_hotp_audit_event(device=enrolled.device, audit_record=result.audit_record)

    assert event.user == user
    assert event.device == enrolled.device
    assert event.factor == MFAAuditEvent.Factor.HOTP
    assert event.event_type == MFAAuditEvent.EventType.VERIFICATION
    assert event.submitted_outcome == "accepted"
    assert event.result_classification == "counter_window_match"
    assert event.server_counter == 0
    assert event.matched_counter == 3
    assert event.next_counter == 4
    assert event.look_ahead == 5
    assert event.search_window is None
    assert event.replay_window == 2
    assert event.submitted_count is None
    assert event.attempted_at == attempted_at


@pytest.mark.django_db
def test_hotp_resync_audit_event_maps_service_record(
    synthetic_mfa_settings_override,
    django_user_model,
):
    attempted_at = datetime(2026, 6, 15, 16, 30, tzinfo=timezone.utc)
    user = django_user_model.objects.create_user(username="hotp-resync-audit-user")
    enrolled = enroll_hotp_device(
        user=user,
        account_name="hotp-resync-audit@example.test",
        issuer_name="Toolkit",
        initial_counter=3,
    )
    HOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    secret = decrypt_secret_text(enrolled.device.persisted_secret)
    hotp = pyotp.HOTP(secret)
    result = resync_hotp(
        encrypted_secret=enrolled.device.persisted_secret,
        submitted_codes=[hotp.at(15), hotp.at(16)],
        server_counter=3,
        search_window=20,
        replay_window=4,
        attempted_at=attempted_at,
    )

    event = create_hotp_resync_audit_event(device=enrolled.device, audit_record=result.audit_record)

    assert event.user == user
    assert event.device == enrolled.device
    assert event.factor == MFAAuditEvent.Factor.HOTP
    assert event.event_type == MFAAuditEvent.EventType.RESYNCHRONIZATION
    assert event.submitted_outcome == "accepted"
    assert event.result_classification == "resync_success"
    assert event.server_counter == 3
    assert event.matched_counter == 15
    assert event.next_counter == 17
    assert event.look_ahead is None
    assert event.search_window == 20
    assert event.replay_window == 4
    assert event.submitted_count == 2
    assert event.attempted_at == attempted_at


@pytest.mark.django_db
def test_audit_event_rejects_failed_code_metadata_without_secret_or_otp_persistence(
    synthetic_mfa_settings_override,
    django_user_model,
):
    user = django_user_model.objects.create_user(username="hotp-audit-nondisclosure-user")
    enrolled = enroll_hotp_device(
        user=user,
        account_name="hotp-nondisclosure@example.test",
        issuer_name="Toolkit",
    )
    raw_secret = decrypt_secret_text(enrolled.device.persisted_secret)
    submitted_code = "000000"
    result = verify_hotp(
        encrypted_secret=enrolled.device.persisted_secret,
        submitted_code=submitted_code,
        server_counter=2,
        look_ahead=1,
    )

    event = create_hotp_audit_event(device=enrolled.device, audit_record=result.audit_record)
    stored_values = " ".join(str(value) for value in _audit_event_values(event))

    assert event.submitted_outcome == "rejected"
    assert event.result_classification == "invalid"
    assert submitted_code not in stored_values
    assert raw_secret not in stored_values
    assert enrolled.device.persisted_secret not in stored_values
    assert enrolled.enrollment.provisioning_uri not in stored_values


@pytest.mark.django_db
@pytest.mark.parametrize(
    "classification",
    ["success", "counter_window_match", "invalid", "replay", "throttled"],
)
def test_hotp_verification_audit_event_persists_all_current_classifications(
    synthetic_mfa_settings_override,
    django_user_model,
    classification,
):
    device = _synthetic_hotp_device(django_user_model)
    record = HOTPAuditRecord(
        submitted_outcome="accepted" if classification in {"success", "counter_window_match"} else "rejected",
        result_classification=classification,
        server_counter=1,
        matched_counter=1 if classification in {"success", "counter_window_match", "replay"} else None,
        next_counter=2,
        look_ahead=10,
        replay_window=10,
        attempted_at=datetime(2026, 6, 15, 17, 0, tzinfo=timezone.utc),
    )

    event = create_hotp_audit_event(device=device, audit_record=record)

    assert event.event_type == MFAAuditEvent.EventType.VERIFICATION
    assert event.result_classification == classification


@pytest.mark.django_db
@pytest.mark.parametrize(
    "classification",
    ["resync_success", "invalid", "replay", "excessive_drift", "throttled"],
)
def test_hotp_resync_audit_event_persists_all_current_classifications(
    synthetic_mfa_settings_override,
    django_user_model,
    classification,
):
    device = _synthetic_hotp_device(django_user_model)
    record = HOTPResyncAuditRecord(
        submitted_outcome="accepted" if classification == "resync_success" else "rejected",
        result_classification=classification,
        server_counter=3,
        matched_counter=5 if classification in {"resync_success", "invalid", "replay"} else None,
        next_counter=7,
        submitted_count=2,
        search_window=20,
        replay_window=10,
        attempted_at=datetime(2026, 6, 15, 17, 30, tzinfo=timezone.utc),
    )

    event = create_hotp_resync_audit_event(device=device, audit_record=record)

    assert event.event_type == MFAAuditEvent.EventType.RESYNCHRONIZATION
    assert event.result_classification == classification


@pytest.mark.django_db
def test_audit_event_model_migration_is_importable():
    loader = MigrationLoader(connection)
    migration = loader.get_migration("django_mfa_toolkit", "0002_mfaauditevent")
    created_models = {operation.name for operation in migration.operations if hasattr(operation, "name")}

    assert "MFAAuditEvent" in created_models


def _audit_event_values(event):
    return [
        event.user_id,
        event.device_id,
        event.factor,
        event.event_type,
        event.submitted_outcome,
        event.result_classification,
        event.server_counter,
        event.matched_counter,
        event.next_counter,
        event.look_ahead,
        event.search_window,
        event.replay_window,
        event.submitted_count,
        event.attempted_at,
        event.created_at,
    ]


def _synthetic_hotp_device(django_user_model):
    user = django_user_model.objects.create_user(username="hotp-audit-classification-user")
    enrolled = enroll_hotp_device(
        user=user,
        account_name="hotp-classification@example.test",
        issuer_name="Toolkit",
    )
    HOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    enrolled.device.refresh_from_db()
    return enrolled.device
