"""Encrypted storage boundary for MFA secret material."""

from __future__ import annotations

import re
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


_SERIALIZED_VERSION = "v1"
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class SecretStorageError(Exception):
    """Base exception for MFA secret storage failures."""


class SecretEncryptionError(SecretStorageError):
    """Raised when secret material cannot be encrypted."""


class SecretDecryptionError(SecretStorageError):
    """Raised when encrypted secret material cannot be decrypted."""


@dataclass(frozen=True)
class EncryptedSecret:
    """Versioned encrypted MFA secret suitable for persistence."""

    version: str
    key_id: str
    ciphertext: str

    def serialize(self) -> str:
        return f"{self.version}:{self.key_id}:{self.ciphertext}"

    @classmethod
    def parse(cls, value: str) -> "EncryptedSecret":
        try:
            version, key_id, ciphertext = value.split(":", 2)
        except ValueError as exc:
            raise SecretDecryptionError("Encrypted secret has an invalid format.") from exc

        if version != _SERIALIZED_VERSION:
            raise SecretDecryptionError("Encrypted secret uses an unsupported version.")
        _validate_key_id(key_id)
        if not ciphertext:
            raise SecretDecryptionError("Encrypted secret ciphertext is empty.")

        return cls(version=version, key_id=key_id, ciphertext=ciphertext)


def generate_encryption_key() -> str:
    """Return a Fernet key for local setup or key-management provisioning."""

    return Fernet.generate_key().decode("ascii")


def encrypt_secret(secret: str | bytes) -> EncryptedSecret:
    """Encrypt MFA secret material for persistence."""

    secret_bytes = _coerce_secret_bytes(secret)
    key_id = _primary_key_id()
    fernet = _fernet_for_key_id(key_id)

    try:
        ciphertext = fernet.encrypt(secret_bytes).decode("ascii")
    except Exception as exc:  # pragma: no cover - defensive wrapper
        raise SecretEncryptionError("Could not encrypt MFA secret.") from exc

    return EncryptedSecret(
        version=_SERIALIZED_VERSION,
        key_id=key_id,
        ciphertext=ciphertext,
    )


def decrypt_secret(value: EncryptedSecret | str) -> bytes:
    """Decrypt persisted MFA secret material."""

    encrypted = value if isinstance(value, EncryptedSecret) else EncryptedSecret.parse(value)
    fernet = _fernet_for_key_id(encrypted.key_id)

    try:
        return fernet.decrypt(encrypted.ciphertext.encode("ascii"))
    except InvalidToken as exc:
        raise SecretDecryptionError("Encrypted secret could not be authenticated.") from exc


def decrypt_secret_text(value: EncryptedSecret | str) -> str:
    """Decrypt persisted MFA secret material as UTF-8 text."""

    return decrypt_secret(value).decode("utf-8")


def _coerce_secret_bytes(secret: str | bytes) -> bytes:
    if isinstance(secret, str):
        if not secret:
            raise SecretEncryptionError("MFA secret must not be empty.")
        return secret.encode("utf-8")
    if isinstance(secret, bytes):
        if not secret:
            raise SecretEncryptionError("MFA secret must not be empty.")
        return secret
    raise SecretEncryptionError("MFA secret must be text or bytes.")


def _configured_keys() -> dict[str, str]:
    keys = getattr(settings, "DJANGO_MFA_TOOLKIT_SECRET_ENCRYPTION_KEYS", None)
    if not isinstance(keys, dict) or not keys:
        raise ImproperlyConfigured(
            "DJANGO_MFA_TOOLKIT_SECRET_ENCRYPTION_KEYS must be a non-empty "
            "mapping of key IDs to Fernet keys."
        )

    normalized = {}
    for key_id, key in keys.items():
        if not isinstance(key_id, str):
            raise ImproperlyConfigured("MFA secret encryption key IDs must be strings.")
        _validate_key_id(key_id)
        if isinstance(key, bytes):
            key = key.decode("ascii")
        if not isinstance(key, str) or not key:
            raise ImproperlyConfigured("MFA secret encryption keys must be non-empty strings.")
        normalized[key_id] = key
    return normalized


def _primary_key_id() -> str:
    key_id = getattr(settings, "DJANGO_MFA_TOOLKIT_PRIMARY_SECRET_ENCRYPTION_KEY_ID", None)
    if not isinstance(key_id, str) or not key_id:
        raise ImproperlyConfigured(
            "DJANGO_MFA_TOOLKIT_PRIMARY_SECRET_ENCRYPTION_KEY_ID must name "
            "the active MFA secret encryption key."
        )
    _validate_key_id(key_id)
    if key_id not in _configured_keys():
        raise ImproperlyConfigured("Primary MFA secret encryption key ID is not configured.")
    return key_id


def _fernet_for_key_id(key_id: str) -> Fernet:
    keys = _configured_keys()
    try:
        key = keys[key_id]
    except KeyError as exc:
        raise SecretDecryptionError("MFA secret encryption key ID is not configured.") from exc

    try:
        return Fernet(key.encode("ascii"))
    except Exception as exc:
        raise ImproperlyConfigured("MFA secret encryption key is not a valid Fernet key.") from exc


def _validate_key_id(key_id: str) -> None:
    if not _KEY_ID_RE.fullmatch(key_id):
        raise ImproperlyConfigured(
            "MFA secret encryption key IDs may contain only letters, digits, "
            "underscores, periods, and hyphens."
        )
