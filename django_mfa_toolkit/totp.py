"""TOTP enrollment and verification services."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

import pyotp
from django.utils import timezone
from pyotp import utils as pyotp_utils

from django_mfa_toolkit.secret_storage import EncryptedSecret, decrypt_secret_text, encrypt_secret


DEFAULT_TOTP_DIGITS = 6
DEFAULT_TOTP_INTERVAL = 30
DEFAULT_TOTP_VALID_WINDOW = 1
DEFAULT_TOTP_VALID_WINDOW_MAX = 10
DEFAULT_TOTP_SECRET_LENGTH = 32
DEFAULT_TOTP_SECRET_LENGTH_MAX = 320

TOTPFailureReason = Literal["invalid", "replay"]


class TOTPError(Exception):
    """Base exception for TOTP service errors."""


class TOTPConfigurationError(TOTPError):
    """Raised when TOTP service parameters are invalid."""


@dataclass(frozen=True)
class TOTPEnrollment:
    """TOTP enrollment material returned to integration code."""

    encrypted_secret: EncryptedSecret
    provisioning_uri: str
    issuer_name: str
    account_name: str
    digits: int
    interval: int

    @property
    def persisted_secret(self) -> str:
        return self.encrypted_secret.serialize()


@dataclass(frozen=True)
class TOTPVerificationResult:
    accepted: bool
    matched_timecode: int | None = None
    failure_reason: TOTPFailureReason | None = None


def enroll_totp(
    *,
    account_name: str,
    issuer_name: str,
    digits: int = DEFAULT_TOTP_DIGITS,
    interval: int = DEFAULT_TOTP_INTERVAL,
    secret_length: int = DEFAULT_TOTP_SECRET_LENGTH,
) -> TOTPEnrollment:
    """Create encrypted TOTP enrollment material and provisioning metadata."""

    _validate_label("account_name", account_name)
    _validate_label("issuer_name", issuer_name)
    _validate_totp_parameters(digits=digits, interval=interval)
    if secret_length < DEFAULT_TOTP_SECRET_LENGTH:
        raise TOTPConfigurationError(
            f"TOTP secret length must be at least {DEFAULT_TOTP_SECRET_LENGTH} base32 characters."
        )
    if secret_length > DEFAULT_TOTP_SECRET_LENGTH_MAX:
        raise TOTPConfigurationError(
            f"TOTP secret length must not exceed {DEFAULT_TOTP_SECRET_LENGTH_MAX} base32 characters."
        )

    secret = pyotp.random_base32(length=secret_length)
    totp = pyotp.TOTP(secret, digits=digits, interval=interval, name=account_name, issuer=issuer_name)

    return TOTPEnrollment(
        encrypted_secret=encrypt_secret(secret),
        provisioning_uri=totp.provisioning_uri(name=account_name, issuer_name=issuer_name),
        issuer_name=issuer_name,
        account_name=account_name,
        digits=digits,
        interval=interval,
    )


def verify_totp(
    *,
    encrypted_secret: EncryptedSecret | str,
    submitted_code: str,
    at_time: datetime | None = None,
    valid_window: int = DEFAULT_TOTP_VALID_WINDOW,
    last_accepted_timecode: int | None = None,
    digits: int = DEFAULT_TOTP_DIGITS,
    interval: int = DEFAULT_TOTP_INTERVAL,
) -> TOTPVerificationResult:
    """Verify a submitted TOTP code and return replay-tracking metadata."""

    _validate_totp_parameters(digits=digits, interval=interval)
    if valid_window < 0:
        raise TOTPConfigurationError("TOTP valid_window must not be negative.")
    if valid_window > DEFAULT_TOTP_VALID_WINDOW_MAX:
        raise TOTPConfigurationError(
            f"TOTP valid_window must not exceed {DEFAULT_TOTP_VALID_WINDOW_MAX}."
        )
    if not isinstance(submitted_code, str) or not submitted_code.strip():
        return TOTPVerificationResult(accepted=False, failure_reason="invalid")

    for_time = at_time or timezone.now()
    secret = decrypt_secret_text(encrypted_secret)
    totp = pyotp.TOTP(secret, digits=digits, interval=interval)
    matched_timecode = _find_matching_timecode(
        totp=totp,
        submitted_code=submitted_code,
        for_time=for_time,
        valid_window=valid_window,
    )

    if matched_timecode is None:
        return TOTPVerificationResult(accepted=False, failure_reason="invalid")

    if last_accepted_timecode is not None and matched_timecode <= last_accepted_timecode:
        return TOTPVerificationResult(
            accepted=False,
            matched_timecode=matched_timecode,
            failure_reason="replay",
        )

    return TOTPVerificationResult(accepted=True, matched_timecode=matched_timecode)


def _find_matching_timecode(
    *,
    totp: pyotp.TOTP,
    submitted_code: str,
    for_time: datetime,
    valid_window: int,
) -> int | None:
    base_timecode = totp.timecode(for_time)

    for offset in range(-valid_window, valid_window + 1):
        candidate = totp.at(for_time, offset)
        if pyotp_utils.strings_equal(str(submitted_code), str(candidate)):
            return base_timecode + offset

    return None


def _validate_label(field_name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise TOTPConfigurationError(f"TOTP {field_name} must be a non-empty string.")


def _validate_totp_parameters(*, digits: int, interval: int) -> None:
    if digits < 6 or digits > 8:
        raise TOTPConfigurationError("TOTP digits must be between 6 and 8.")
    if interval <= 0:
        raise TOTPConfigurationError("TOTP interval must be positive.")
