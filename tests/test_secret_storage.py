import secrets

import pytest
from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings

from django_mfa_toolkit.secret_storage import (
    EncryptedSecret,
    SecretDecryptionError,
    SecretEncryptionError,
    decrypt_secret,
    decrypt_secret_text,
    encrypt_secret,
    generate_encryption_key,
)


def encryption_settings(key_id="test-key", key=None):
    key = key or Fernet.generate_key().decode("ascii")
    return {
        "DJANGO_MFA_TOOLKIT_SECRET_ENCRYPTION_KEYS": {key_id: key},
        "DJANGO_MFA_TOOLKIT_PRIMARY_SECRET_ENCRYPTION_KEY_ID": key_id,
    }


def synthetic_secret():
    return secrets.token_urlsafe(24)


def test_encrypt_secret_returns_persistable_value_without_plaintext():
    material = synthetic_secret()

    with override_settings(**encryption_settings()):
        encrypted = encrypt_secret(material)

    persisted = encrypted.serialize()

    assert isinstance(encrypted, EncryptedSecret)
    assert persisted.startswith("v1:test-key:")
    assert persisted != material
    assert material not in persisted


def test_decrypt_secret_round_trips_text_and_serialized_value():
    material = synthetic_secret()

    with override_settings(**encryption_settings()):
        persisted = encrypt_secret(material).serialize()

        assert decrypt_secret_text(persisted) == material


def test_decrypt_secret_round_trips_bytes():
    material = secrets.token_bytes(24)

    with override_settings(**encryption_settings()):
        persisted = encrypt_secret(material)

        assert decrypt_secret(persisted) == material


def test_missing_encryption_settings_fail_closed():
    with override_settings(
        DJANGO_MFA_TOOLKIT_SECRET_ENCRYPTION_KEYS=None,
        DJANGO_MFA_TOOLKIT_PRIMARY_SECRET_ENCRYPTION_KEY_ID=None,
    ):
        with pytest.raises(ImproperlyConfigured):
            encrypt_secret(synthetic_secret())


def test_invalid_key_material_fails_configuration():
    with override_settings(**encryption_settings(key="not-a-fernet-key")):
        with pytest.raises(ImproperlyConfigured):
            encrypt_secret(synthetic_secret())


def test_empty_secret_is_rejected():
    with override_settings(**encryption_settings()):
        with pytest.raises(SecretEncryptionError):
            encrypt_secret("")


def test_tampered_ciphertext_is_rejected():
    with override_settings(**encryption_settings()):
        persisted = encrypt_secret(synthetic_secret()).serialize()
        prefix, ciphertext = persisted.rsplit(":", 1)
        replacement = "A" if ciphertext[-1] != "A" else "B"
        tampered = f"{prefix}:{ciphertext[:-1]}{replacement}"

        with pytest.raises(SecretDecryptionError):
            decrypt_secret_text(tampered)


def test_malformed_ciphertext_charset_is_rejected():
    with override_settings(**encryption_settings()):
        with pytest.raises(SecretDecryptionError):
            EncryptedSecret.parse("v1:test-key:not base64url!!")


def test_malformed_ciphertext_padding_is_rejected_by_parse():
    with override_settings(**encryption_settings()):
        with pytest.raises(SecretDecryptionError):
            EncryptedSecret.parse("v1:test-key:A===")


def test_decrypt_secret_text_rejects_non_ascii_ciphertext():
    with override_settings(**encryption_settings()):
        with pytest.raises(SecretDecryptionError):
            decrypt_secret_text("v1:test-key:café")


def test_key_ids_allow_decrypting_older_key_after_primary_rotates():
    old_key = Fernet.generate_key().decode("ascii")
    new_key = Fernet.generate_key().decode("ascii")
    material = synthetic_secret()

    with override_settings(
        DJANGO_MFA_TOOLKIT_SECRET_ENCRYPTION_KEYS={"old": old_key},
        DJANGO_MFA_TOOLKIT_PRIMARY_SECRET_ENCRYPTION_KEY_ID="old",
    ):
        persisted = encrypt_secret(material).serialize()

    with override_settings(
        DJANGO_MFA_TOOLKIT_SECRET_ENCRYPTION_KEYS={"old": old_key, "new": new_key},
        DJANGO_MFA_TOOLKIT_PRIMARY_SECRET_ENCRYPTION_KEY_ID="new",
    ):
        newer = encrypt_secret(material).serialize()

        assert persisted.startswith("v1:old:")
        assert newer.startswith("v1:new:")
        assert decrypt_secret_text(persisted) == material


def test_generate_encryption_key_returns_valid_fernet_key():
    key = generate_encryption_key()

    Fernet(key.encode("ascii"))
