import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, connection, transaction
from django.db.migrations.loader import MigrationLoader

from django_mfa_toolkit.hotp import enroll_hotp
from django_mfa_toolkit.models import HOTPDevice, TOTPDevice
from django_mfa_toolkit.secret_storage import decrypt_secret_text
from django_mfa_toolkit.totp import enroll_totp


@pytest.mark.django_db
def test_totp_device_persists_encrypted_state_without_plaintext(
    synthetic_mfa_settings_override,
    django_user_model,
):
    user = django_user_model.objects.create_user(username="totp-user")
    enrollment = enroll_totp(account_name="totp@example.test", issuer_name="Toolkit")
    raw_secret = decrypt_secret_text(enrollment.persisted_secret)

    device = TOTPDevice.objects.create(
        user=user,
        persisted_secret=enrollment.persisted_secret,
        name="Authenticator app",
        digits=enrollment.digits,
        interval=enrollment.interval,
    )
    device.full_clean()

    persisted = TOTPDevice.objects.values("persisted_secret").get(pk=device.pk)["persisted_secret"]

    assert persisted == enrollment.persisted_secret
    assert raw_secret not in persisted
    assert device.last_accepted_timecode is None
    assert device.confirmed_at is None
    assert device.is_active is True
    assert device.digits == enrollment.digits
    assert device.interval == enrollment.interval


@pytest.mark.django_db
def test_hotp_device_persists_encrypted_state_and_counter_without_plaintext(
    synthetic_mfa_settings_override,
    django_user_model,
):
    user = django_user_model.objects.create_user(username="hotp-user")
    enrollment = enroll_hotp(account_name="hotp@example.test", issuer_name="Toolkit")
    raw_secret = decrypt_secret_text(enrollment.persisted_secret)

    device = HOTPDevice.objects.create(
        user=user,
        persisted_secret=enrollment.persisted_secret,
        name="Hardware token",
        digits=enrollment.digits,
        hotp_counter=enrollment.initial_counter,
    )
    device.full_clean()

    persisted = HOTPDevice.objects.values("persisted_secret").get(pk=device.pk)["persisted_secret"]

    assert persisted == enrollment.persisted_secret
    assert raw_secret not in persisted
    assert device.hotp_counter == enrollment.initial_counter
    assert device.confirmed_at is None
    assert device.is_active is True
    assert device.digits == enrollment.digits


@pytest.mark.django_db
def test_device_models_reject_malformed_persisted_secret(django_user_model):
    user = django_user_model.objects.create_user(username="invalid-secret-user")
    device = TOTPDevice(user=user, persisted_secret="not-a-valid-secret")

    with pytest.raises(ValidationError) as exc_info:
        device.full_clean()

    assert "persisted_secret" in exc_info.value.message_dict


@pytest.mark.django_db
def test_hotp_device_rejects_negative_counter(
    synthetic_mfa_settings_override,
    django_user_model,
):
    user = django_user_model.objects.create_user(username="negative-counter-user")
    enrollment = enroll_hotp(account_name="hotp@example.test", issuer_name="Toolkit")

    with pytest.raises(IntegrityError), transaction.atomic():
        HOTPDevice.objects.create(
            user=user,
            persisted_secret=enrollment.persisted_secret,
            hotp_counter=-1,
        )


@pytest.mark.django_db
def test_device_model_migration_is_importable():
    loader = MigrationLoader(connection)
    migration = loader.get_migration("django_mfa_toolkit", "0001_initial")
    created_models = {operation.name for operation in migration.operations if hasattr(operation, "name")}

    assert {"TOTPDevice", "HOTPDevice"}.issubset(created_models)
