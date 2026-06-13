from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

import pyotp
import pytest
from cryptography.fernet import Fernet
from django.test import override_settings

from django_mfa_toolkit.hotp import (
    DEFAULT_HOTP_LOOK_AHEAD_MAX,
    DEFAULT_HOTP_REPLAY_WINDOW_MAX,
    DEFAULT_HOTP_RESYNC_SEARCH_WINDOW_MAX,
    DEFAULT_HOTP_SECRET_LENGTH_MAX,
    HOTPConfigurationError,
    enroll_hotp,
    resync_hotp,
    verify_hotp,
)
from django_mfa_toolkit.secret_storage import decrypt_secret_text


def encryption_settings(key_id="hotp-test-key", key=None):
    key = key or Fernet.generate_key().decode("ascii")
    return {
        "DJANGO_MFA_TOOLKIT_SECRET_ENCRYPTION_KEYS": {key_id: key},
        "DJANGO_MFA_TOOLKIT_PRIMARY_SECRET_ENCRYPTION_KEY_ID": key_id,
    }


def test_enroll_hotp_returns_encrypted_secret_and_provisioning_metadata():
    with override_settings(**encryption_settings()):
        enrollment = enroll_hotp(
            account_name="hardware-token@example.test",
            issuer_name="Django MFA Toolkit",
            initial_counter=7,
        )
        persisted = enrollment.persisted_secret
        decrypted_material = decrypt_secret_text(persisted)

    parsed_uri = urlparse(enrollment.provisioning_uri)
    query = parse_qs(parsed_uri.query)

    assert persisted.startswith("v1:hotp-test-key:")
    assert decrypted_material not in persisted
    assert parsed_uri.scheme == "otpauth"
    assert parsed_uri.netloc == "hotp"
    assert query["issuer"] == ["Django MFA Toolkit"]
    assert query["secret"] == [decrypted_material]
    assert query["counter"] == ["7"]
    assert enrollment.initial_counter == 7


def test_verify_hotp_accepts_current_counter_and_advances_once():
    attempted_at = datetime(2026, 6, 13, 16, 0, tzinfo=timezone.utc)

    with override_settings(**encryption_settings()):
        enrollment = enroll_hotp(account_name="token@example.test", issuer_name="Toolkit")
        material = decrypt_secret_text(enrollment.persisted_secret)
        code = pyotp.HOTP(material).at(0)

        result = verify_hotp(
            encrypted_secret=enrollment.persisted_secret,
            submitted_code=code,
            server_counter=0,
            look_ahead=0,
            attempted_at=attempted_at,
        )

    assert result.accepted is True
    assert result.matched_counter == 0
    assert result.next_counter == 1
    assert result.audit_record.submitted_outcome == "accepted"
    assert result.audit_record.result_classification == "success"
    assert result.audit_record.server_counter == 0
    assert result.audit_record.matched_counter == 0
    assert result.audit_record.next_counter == 1
    assert result.audit_record.attempted_at == attempted_at


def test_verify_hotp_accepts_bounded_look_ahead_match_and_advances_to_next_counter():
    with override_settings(**encryption_settings()):
        enrollment = enroll_hotp(account_name="token@example.test", issuer_name="Toolkit")
        material = decrypt_secret_text(enrollment.persisted_secret)
        code = pyotp.HOTP(material).at(3)

        result = verify_hotp(
            encrypted_secret=enrollment.persisted_secret,
            submitted_code=code,
            server_counter=0,
            look_ahead=3,
        )

    assert result.accepted is True
    assert result.matched_counter == 3
    assert result.next_counter == 4
    assert result.audit_record.result_classification == "counter_window_match"
    assert result.audit_record.server_counter == 0
    assert result.audit_record.matched_counter == 3


def test_verify_hotp_rejects_code_outside_bounded_look_ahead_without_advancing():
    with override_settings(**encryption_settings()):
        enrollment = enroll_hotp(account_name="token@example.test", issuer_name="Toolkit")
        material = decrypt_secret_text(enrollment.persisted_secret)
        code = pyotp.HOTP(material).at(4)

        result = verify_hotp(
            encrypted_secret=enrollment.persisted_secret,
            submitted_code=code,
            server_counter=0,
            look_ahead=3,
        )

    assert result.accepted is False
    assert result.next_counter == 0
    assert result.audit_record.submitted_outcome == "rejected"
    assert result.audit_record.result_classification == "invalid"
    assert result.audit_record.server_counter == 0
    assert result.audit_record.matched_counter is None


def test_verify_hotp_rejects_failed_code_without_advancing_and_records_audit():
    with override_settings(**encryption_settings()):
        enrollment = enroll_hotp(account_name="token@example.test", issuer_name="Toolkit")

        result = verify_hotp(
            encrypted_secret=enrollment.persisted_secret,
            submitted_code="000000",
            server_counter=2,
            look_ahead=1,
        )

    assert result.accepted is False
    assert result.next_counter == 2
    assert result.audit_record.submitted_outcome == "rejected"
    assert result.audit_record.result_classification == "invalid"
    assert result.audit_record.server_counter == 2
    assert result.audit_record.matched_counter is None


def test_verify_hotp_rejects_previously_accepted_code_as_replay():
    with override_settings(**encryption_settings()):
        enrollment = enroll_hotp(account_name="token@example.test", issuer_name="Toolkit")
        material = decrypt_secret_text(enrollment.persisted_secret)
        code = pyotp.HOTP(material).at(0)

        accepted = verify_hotp(
            encrypted_secret=enrollment.persisted_secret,
            submitted_code=code,
            server_counter=0,
            look_ahead=0,
        )
        replayed = verify_hotp(
            encrypted_secret=enrollment.persisted_secret,
            submitted_code=code,
            server_counter=accepted.next_counter,
            look_ahead=0,
            replay_window=1,
        )

    assert accepted.accepted is True
    assert replayed.accepted is False
    assert replayed.next_counter == accepted.next_counter
    assert replayed.matched_counter == 0
    assert replayed.audit_record.result_classification == "replay"
    assert replayed.audit_record.submitted_outcome == "rejected"
    assert replayed.audit_record.server_counter == 1
    assert replayed.audit_record.matched_counter == 0


def test_verify_hotp_replay_detection_is_bounded():
    with override_settings(**encryption_settings()):
        enrollment = enroll_hotp(account_name="token@example.test", issuer_name="Toolkit")
        material = decrypt_secret_text(enrollment.persisted_secret)
        code = pyotp.HOTP(material).at(1)

        result = verify_hotp(
            encrypted_secret=enrollment.persisted_secret,
            submitted_code=code,
            server_counter=10,
            look_ahead=0,
            replay_window=3,
        )

    assert result.accepted is False
    assert result.audit_record.result_classification == "invalid"
    assert result.audit_record.matched_counter is None


def test_enroll_hotp_validates_labels_and_counter():
    with override_settings(**encryption_settings()):
        with pytest.raises(HOTPConfigurationError):
            enroll_hotp(account_name="", issuer_name="Toolkit")
        with pytest.raises(HOTPConfigurationError):
            enroll_hotp(account_name="token@example.test", issuer_name="Toolkit", initial_counter=-1)


def test_enroll_hotp_validates_secret_length():
    with override_settings(**encryption_settings()):
        with pytest.raises(HOTPConfigurationError):
            enroll_hotp(account_name="token@example.test", issuer_name="Toolkit", secret_length=16)
        with pytest.raises(HOTPConfigurationError):
            enroll_hotp(
                account_name="token@example.test",
                issuer_name="Toolkit",
                secret_length=DEFAULT_HOTP_SECRET_LENGTH_MAX + 1,
            )


def test_verify_hotp_validates_windows():
    with override_settings(**encryption_settings()):
        enrollment = enroll_hotp(account_name="token@example.test", issuer_name="Toolkit")

        with pytest.raises(HOTPConfigurationError):
            verify_hotp(
                encrypted_secret=enrollment.persisted_secret,
                submitted_code="000000",
                server_counter=0,
                look_ahead=-1,
            )
        with pytest.raises(HOTPConfigurationError):
            verify_hotp(
                encrypted_secret=enrollment.persisted_secret,
                submitted_code="000000",
                server_counter=0,
                replay_window=-1,
            )


def test_verify_hotp_validates_window_upper_bounds():
    with override_settings(**encryption_settings()):
        enrollment = enroll_hotp(account_name="token@example.test", issuer_name="Toolkit")

        with pytest.raises(HOTPConfigurationError):
            verify_hotp(
                encrypted_secret=enrollment.persisted_secret,
                submitted_code="000000",
                server_counter=0,
                look_ahead=DEFAULT_HOTP_LOOK_AHEAD_MAX + 1,
            )
        with pytest.raises(HOTPConfigurationError):
            verify_hotp(
                encrypted_secret=enrollment.persisted_secret,
                submitted_code="000000",
                server_counter=0,
                replay_window=DEFAULT_HOTP_REPLAY_WINDOW_MAX + 1,
            )


def test_verify_hotp_uses_constant_time_pyotp_comparison(monkeypatch):
    calls = []

    def recording_compare(left, right):
        calls.append((left, right))
        return original_compare(left, right)

    from django_mfa_toolkit import hotp as hotp_module

    original_compare = hotp_module.pyotp_utils.strings_equal

    with override_settings(**encryption_settings()):
        enrollment = enroll_hotp(account_name="token@example.test", issuer_name="Toolkit")
        material = decrypt_secret_text(enrollment.persisted_secret)
        code = pyotp.HOTP(material).at(0)

        monkeypatch.setattr(hotp_module.pyotp_utils, "strings_equal", recording_compare)
        result = verify_hotp(
            encrypted_secret=enrollment.persisted_secret,
            submitted_code=code,
            server_counter=0,
            look_ahead=0,
        )

    assert result.accepted is True
    assert calls


def test_resync_hotp_accepts_multiple_consecutive_codes_and_advances_counter():
    attempted_at = datetime(2026, 6, 13, 16, 0, tzinfo=timezone.utc)

    with override_settings(**encryption_settings()):
        enrollment = enroll_hotp(account_name="token@example.test", issuer_name="Toolkit")
        material = decrypt_secret_text(enrollment.persisted_secret)
        hotp = pyotp.HOTP(material)
        submitted_codes = [hotp.at(15), hotp.at(16)]

        result = resync_hotp(
            encrypted_secret=enrollment.persisted_secret,
            submitted_codes=submitted_codes,
            server_counter=3,
            search_window=20,
            attempted_at=attempted_at,
        )

    assert result.accepted is True
    assert result.matched_counter == 15
    assert result.next_counter == 17
    assert result.audit_record.submitted_outcome == "accepted"
    assert result.audit_record.result_classification == "resync_success"
    assert result.audit_record.server_counter == 3
    assert result.audit_record.matched_counter == 15
    assert result.audit_record.next_counter == 17
    assert result.audit_record.submitted_count == 2
    assert result.audit_record.search_window == 20
    assert result.audit_record.attempted_at == attempted_at


def test_resync_hotp_rejects_non_consecutive_codes_without_advancing():
    with override_settings(**encryption_settings()):
        enrollment = enroll_hotp(account_name="token@example.test", issuer_name="Toolkit")
        material = decrypt_secret_text(enrollment.persisted_secret)
        hotp = pyotp.HOTP(material)
        submitted_codes = [hotp.at(8), hotp.at(10)]

        result = resync_hotp(
            encrypted_secret=enrollment.persisted_secret,
            submitted_codes=submitted_codes,
            server_counter=3,
            search_window=20,
        )

    assert result.accepted is False
    assert result.next_counter == 3
    assert result.matched_counter == 8
    assert result.audit_record.submitted_outcome == "rejected"
    assert result.audit_record.result_classification == "invalid"
    assert result.audit_record.server_counter == 3
    assert result.audit_record.matched_counter == 8


def test_resync_hotp_rejects_replayed_consecutive_codes():
    with override_settings(**encryption_settings()):
        enrollment = enroll_hotp(account_name="token@example.test", issuer_name="Toolkit")
        material = decrypt_secret_text(enrollment.persisted_secret)
        hotp = pyotp.HOTP(material)
        submitted_codes = [hotp.at(1), hotp.at(2)]

        result = resync_hotp(
            encrypted_secret=enrollment.persisted_secret,
            submitted_codes=submitted_codes,
            server_counter=5,
            search_window=20,
            replay_window=5,
        )

    assert result.accepted is False
    assert result.next_counter == 5
    assert result.matched_counter == 1
    assert result.audit_record.result_classification == "replay"
    assert result.audit_record.submitted_outcome == "rejected"
    assert result.audit_record.server_counter == 5
    assert result.audit_record.matched_counter == 1


def test_resync_hotp_rejects_excessive_drift_without_unbounded_search():
    with override_settings(**encryption_settings()):
        enrollment = enroll_hotp(account_name="token@example.test", issuer_name="Toolkit")
        material = decrypt_secret_text(enrollment.persisted_secret)
        hotp = pyotp.HOTP(material)
        submitted_codes = [hotp.at(50), hotp.at(51)]

        result = resync_hotp(
            encrypted_secret=enrollment.persisted_secret,
            submitted_codes=submitted_codes,
            server_counter=5,
            search_window=10,
            replay_window=5,
        )

    assert result.accepted is False
    assert result.next_counter == 5
    assert result.matched_counter is None
    assert result.audit_record.result_classification == "excessive_drift"
    assert result.audit_record.search_window == 10


def test_resync_hotp_requires_multiple_codes_and_valid_windows():
    with override_settings(**encryption_settings()):
        enrollment = enroll_hotp(account_name="token@example.test", issuer_name="Toolkit")

        with pytest.raises(HOTPConfigurationError):
            resync_hotp(
                encrypted_secret=enrollment.persisted_secret,
                submitted_codes=["000000"],
                server_counter=0,
            )
        with pytest.raises(HOTPConfigurationError):
            resync_hotp(
                encrypted_secret=enrollment.persisted_secret,
                submitted_codes="000000",
                server_counter=0,
            )
        with pytest.raises(HOTPConfigurationError):
            resync_hotp(
                encrypted_secret=enrollment.persisted_secret,
                submitted_codes=["000000", "111111"],
                server_counter=0,
                search_window=-1,
            )
        with pytest.raises(HOTPConfigurationError):
            resync_hotp(
                encrypted_secret=enrollment.persisted_secret,
                submitted_codes=["000000", "111111"],
                server_counter=0,
                replay_window=-1,
            )


def test_resync_hotp_validates_window_upper_bounds():
    with override_settings(**encryption_settings()):
        enrollment = enroll_hotp(account_name="token@example.test", issuer_name="Toolkit")

        with pytest.raises(HOTPConfigurationError):
            resync_hotp(
                encrypted_secret=enrollment.persisted_secret,
                submitted_codes=["000000", "111111"],
                server_counter=0,
                search_window=DEFAULT_HOTP_RESYNC_SEARCH_WINDOW_MAX + 1,
            )
        with pytest.raises(HOTPConfigurationError):
            resync_hotp(
                encrypted_secret=enrollment.persisted_secret,
                submitted_codes=["000000", "111111"],
                server_counter=0,
                replay_window=DEFAULT_HOTP_REPLAY_WINDOW_MAX + 1,
            )


def test_resync_hotp_rejects_blank_codes_with_audit_record():
    with override_settings(**encryption_settings()):
        enrollment = enroll_hotp(account_name="token@example.test", issuer_name="Toolkit")

        result = resync_hotp(
            encrypted_secret=enrollment.persisted_secret,
            submitted_codes=["000000", ""],
            server_counter=4,
            search_window=10,
        )

    assert result.accepted is False
    assert result.next_counter == 4
    assert result.matched_counter is None
    assert result.audit_record.result_classification == "invalid"
    assert result.audit_record.submitted_count == 2
