from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pyotp
import pytest
from cryptography.fernet import Fernet
from django.test import override_settings

from django_mfa_toolkit.secret_storage import decrypt_secret_text
from django_mfa_toolkit.totp import (
    TOTPConfigurationError,
    enroll_totp,
    verify_totp,
)


def encryption_settings(key_id="totp-test-key", key=None):
    key = key or Fernet.generate_key().decode("ascii")
    return {
        "DJANGO_MFA_TOOLKIT_SECRET_ENCRYPTION_KEYS": {key_id: key},
        "DJANGO_MFA_TOOLKIT_PRIMARY_SECRET_ENCRYPTION_KEY_ID": key_id,
    }


def test_enroll_totp_returns_encrypted_secret_and_provisioning_metadata():
    with override_settings(**encryption_settings()):
        enrollment = enroll_totp(
            account_name="agent@example.test",
            issuer_name="Django MFA Toolkit",
        )
        persisted = enrollment.persisted_secret
        decrypted_secret = decrypt_secret_text(persisted)

    parsed_uri = urlparse(enrollment.provisioning_uri)
    query = parse_qs(parsed_uri.query)

    assert persisted.startswith("v1:totp-test-key:")
    assert decrypted_secret not in persisted
    assert parsed_uri.scheme == "otpauth"
    assert parsed_uri.netloc == "totp"
    assert query["issuer"] == ["Django MFA Toolkit"]
    assert query["secret"] == [decrypted_secret]
    assert enrollment.account_name == "agent@example.test"
    assert enrollment.issuer_name == "Django MFA Toolkit"


def test_verify_totp_accepts_valid_current_code():
    at_time = datetime(2026, 6, 13, 16, 0, tzinfo=timezone.utc)

    with override_settings(**encryption_settings()):
        enrollment = enroll_totp(account_name="agent@example.test", issuer_name="Toolkit")
        secret = decrypt_secret_text(enrollment.persisted_secret)
        code = pyotp.TOTP(secret).at(at_time)

        result = verify_totp(
            encrypted_secret=enrollment.persisted_secret,
            submitted_code=code,
            at_time=at_time,
            valid_window=0,
        )

    assert result.accepted is True
    assert result.failure_reason is None
    assert result.matched_timecode == pyotp.TOTP(secret).timecode(at_time)


def test_verify_totp_rejects_invalid_code():
    at_time = datetime(2026, 6, 13, 16, 0, tzinfo=timezone.utc)

    with override_settings(**encryption_settings()):
        enrollment = enroll_totp(account_name="agent@example.test", issuer_name="Toolkit")

        result = verify_totp(
            encrypted_secret=enrollment.persisted_secret,
            submitted_code="000000",
            at_time=at_time,
            valid_window=0,
        )

    assert result.accepted is False
    assert result.failure_reason == "invalid"
    assert result.matched_timecode is None


def test_verify_totp_accepts_code_inside_allowed_time_window():
    at_time = datetime(2026, 6, 13, 16, 0, tzinfo=timezone.utc)
    previous_step = at_time - timedelta(seconds=30)

    with override_settings(**encryption_settings()):
        enrollment = enroll_totp(account_name="agent@example.test", issuer_name="Toolkit")
        secret = decrypt_secret_text(enrollment.persisted_secret)
        code = pyotp.TOTP(secret).at(previous_step)

        result = verify_totp(
            encrypted_secret=enrollment.persisted_secret,
            submitted_code=code,
            at_time=at_time,
            valid_window=1,
        )

    assert result.accepted is True
    assert result.matched_timecode == pyotp.TOTP(secret).timecode(previous_step)


def test_verify_totp_rejects_code_outside_allowed_time_window():
    at_time = datetime(2026, 6, 13, 16, 0, tzinfo=timezone.utc)
    outside_window = at_time - timedelta(seconds=60)

    with override_settings(**encryption_settings()):
        enrollment = enroll_totp(account_name="agent@example.test", issuer_name="Toolkit")
        secret = decrypt_secret_text(enrollment.persisted_secret)
        code = pyotp.TOTP(secret).at(outside_window)

        result = verify_totp(
            encrypted_secret=enrollment.persisted_secret,
            submitted_code=code,
            at_time=at_time,
            valid_window=1,
        )

    assert result.accepted is False
    assert result.failure_reason == "invalid"


def test_verify_totp_rejects_replayed_timecode():
    at_time = datetime(2026, 6, 13, 16, 0, tzinfo=timezone.utc)

    with override_settings(**encryption_settings()):
        enrollment = enroll_totp(account_name="agent@example.test", issuer_name="Toolkit")
        secret = decrypt_secret_text(enrollment.persisted_secret)
        totp = pyotp.TOTP(secret)
        code = totp.at(at_time)
        accepted_timecode = totp.timecode(at_time)

        result = verify_totp(
            encrypted_secret=enrollment.persisted_secret,
            submitted_code=code,
            at_time=at_time,
            valid_window=0,
            last_accepted_timecode=accepted_timecode,
        )

    assert result.accepted is False
    assert result.failure_reason == "replay"
    assert result.matched_timecode == accepted_timecode


def test_enroll_totp_validates_labels():
    with override_settings(**encryption_settings()):
        with pytest.raises(TOTPConfigurationError):
            enroll_totp(account_name="", issuer_name="Toolkit")


def test_verify_totp_uses_constant_time_pyotp_comparison(monkeypatch):
    at_time = datetime(2026, 6, 13, 16, 0, tzinfo=timezone.utc)
    calls = []

    def recording_compare(left, right):
        calls.append((left, right))
        return original_compare(left, right)

    from django_mfa_toolkit import totp as totp_module

    original_compare = totp_module.pyotp_utils.strings_equal

    with override_settings(**encryption_settings()):
        enrollment = enroll_totp(account_name="agent@example.test", issuer_name="Toolkit")
        secret = decrypt_secret_text(enrollment.persisted_secret)
        code = pyotp.TOTP(secret).at(at_time)

        monkeypatch.setattr(totp_module.pyotp_utils, "strings_equal", recording_compare)
        result = verify_totp(
            encrypted_secret=enrollment.persisted_secret,
            submitted_code=code,
            at_time=at_time,
            valid_window=0,
        )

    assert result.accepted is True
    assert calls
