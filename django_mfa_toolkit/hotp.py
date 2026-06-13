"""HOTP enrollment and verification services."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

import pyotp
from django.utils import timezone
from pyotp import utils as pyotp_utils

from django_mfa_toolkit.secret_storage import EncryptedSecret, decrypt_secret_text, encrypt_secret


DEFAULT_HOTP_DIGITS = 6
DEFAULT_HOTP_LOOK_AHEAD = 10
DEFAULT_HOTP_LOOK_AHEAD_MAX = 100
DEFAULT_HOTP_REPLAY_WINDOW = 10
DEFAULT_HOTP_REPLAY_WINDOW_MAX = 100
DEFAULT_HOTP_RESYNC_SEARCH_WINDOW = 100
DEFAULT_HOTP_RESYNC_SEARCH_WINDOW_MAX = 1000
DEFAULT_HOTP_SECRET_LENGTH = 32
DEFAULT_HOTP_SECRET_LENGTH_MAX = 320

HOTPResultClassification = Literal["success", "counter_window_match", "invalid", "replay"]
HOTPResyncClassification = Literal[
    "resync_success",
    "invalid",
    "replay",
    "excessive_drift",
]
HOTPSubmittedOutcome = Literal["accepted", "rejected"]


class HOTPError(Exception):
    """Base exception for HOTP service errors."""


class HOTPConfigurationError(HOTPError):
    """Raised when HOTP service parameters are invalid."""


@dataclass(frozen=True)
class HOTPEnrollment:
    """HOTP enrollment material returned to integration code."""

    encrypted_secret: EncryptedSecret
    provisioning_uri: str
    issuer_name: str
    account_name: str
    initial_counter: int
    digits: int

    @property
    def persisted_secret(self) -> str:
        return self.encrypted_secret.serialize()


@dataclass(frozen=True)
class HOTPAuditRecord:
    """Audit details for one HOTP verification attempt."""

    submitted_outcome: HOTPSubmittedOutcome
    result_classification: HOTPResultClassification
    server_counter: int
    matched_counter: int | None
    next_counter: int
    look_ahead: int
    replay_window: int
    attempted_at: datetime


@dataclass(frozen=True)
class HOTPVerificationResult:
    accepted: bool
    next_counter: int
    matched_counter: int | None
    audit_record: HOTPAuditRecord


@dataclass(frozen=True)
class HOTPResyncAuditRecord:
    """Audit details for one HOTP resynchronization attempt."""

    submitted_outcome: HOTPSubmittedOutcome
    result_classification: HOTPResyncClassification
    server_counter: int
    matched_counter: int | None
    next_counter: int
    submitted_count: int
    search_window: int
    replay_window: int
    attempted_at: datetime


@dataclass(frozen=True)
class HOTPResyncResult:
    accepted: bool
    next_counter: int
    matched_counter: int | None
    audit_record: HOTPResyncAuditRecord


def enroll_hotp(
    *,
    account_name: str,
    issuer_name: str,
    initial_counter: int = 0,
    digits: int = DEFAULT_HOTP_DIGITS,
    secret_length: int = DEFAULT_HOTP_SECRET_LENGTH,
) -> HOTPEnrollment:
    """Create encrypted HOTP enrollment material and provisioning metadata."""

    _validate_label("account_name", account_name)
    _validate_label("issuer_name", issuer_name)
    _validate_hotp_parameters(digits=digits, counter=initial_counter)
    if secret_length < DEFAULT_HOTP_SECRET_LENGTH:
        raise HOTPConfigurationError(
            f"HOTP secret length must be at least {DEFAULT_HOTP_SECRET_LENGTH} base32 characters."
        )
    if secret_length > DEFAULT_HOTP_SECRET_LENGTH_MAX:
        raise HOTPConfigurationError(
            f"HOTP secret length must not exceed {DEFAULT_HOTP_SECRET_LENGTH_MAX} base32 characters."
        )

    secret = pyotp.random_base32(length=secret_length)
    hotp = pyotp.HOTP(
        secret,
        digits=digits,
        name=account_name,
        issuer=issuer_name,
        initial_count=initial_counter,
    )

    return HOTPEnrollment(
        encrypted_secret=encrypt_secret(secret),
        provisioning_uri=hotp.provisioning_uri(
            name=account_name,
            initial_count=initial_counter,
            issuer_name=issuer_name,
        ),
        issuer_name=issuer_name,
        account_name=account_name,
        initial_counter=initial_counter,
        digits=digits,
    )


def resync_hotp(
    *,
    encrypted_secret: EncryptedSecret | str,
    submitted_codes: Sequence[str],
    server_counter: int,
    search_window: int = DEFAULT_HOTP_RESYNC_SEARCH_WINDOW,
    replay_window: int = DEFAULT_HOTP_REPLAY_WINDOW,
    digits: int = DEFAULT_HOTP_DIGITS,
    attempted_at: datetime | None = None,
) -> HOTPResyncResult:
    """Resynchronize an HOTP counter with multiple consecutive submissions."""

    _validate_hotp_parameters(digits=digits, counter=server_counter)
    if search_window < 0:
        raise HOTPConfigurationError("HOTP resync search_window must not be negative.")
    if search_window > DEFAULT_HOTP_RESYNC_SEARCH_WINDOW_MAX:
        raise HOTPConfigurationError(
            f"HOTP resync search_window must not exceed {DEFAULT_HOTP_RESYNC_SEARCH_WINDOW_MAX}."
        )
    if replay_window < 0:
        raise HOTPConfigurationError("HOTP replay_window must not be negative.")
    if replay_window > DEFAULT_HOTP_REPLAY_WINDOW_MAX:
        raise HOTPConfigurationError(
            f"HOTP replay_window must not exceed {DEFAULT_HOTP_REPLAY_WINDOW_MAX}."
        )
    if isinstance(submitted_codes, (str, bytes)):
        raise HOTPConfigurationError("HOTP resynchronization requires a sequence of codes.")
    if len(submitted_codes) < 2:
        raise HOTPConfigurationError("HOTP resynchronization requires at least two codes.")

    timestamp = attempted_at or timezone.now()
    normalized_codes = [str(code) for code in submitted_codes]
    if any(not code.strip() for code in normalized_codes):
        return _rejected_resync_result(
            result_classification="invalid",
            server_counter=server_counter,
            next_counter=server_counter,
            matched_counter=None,
            submitted_count=len(normalized_codes),
            search_window=search_window,
            replay_window=replay_window,
            attempted_at=timestamp,
        )

    secret = decrypt_secret_text(encrypted_secret)
    hotp = pyotp.HOTP(secret, digits=digits)
    matched_counter = _find_matching_sequence(
        hotp=hotp,
        submitted_codes=normalized_codes,
        start_counter=server_counter,
        end_counter=server_counter + search_window,
    )

    if matched_counter is not None:
        next_counter = matched_counter + len(normalized_codes)
        audit_record = HOTPResyncAuditRecord(
            submitted_outcome="accepted",
            result_classification="resync_success",
            server_counter=server_counter,
            matched_counter=matched_counter,
            next_counter=next_counter,
            submitted_count=len(normalized_codes),
            search_window=search_window,
            replay_window=replay_window,
            attempted_at=timestamp,
        )
        return HOTPResyncResult(
            accepted=True,
            next_counter=next_counter,
            matched_counter=matched_counter,
            audit_record=audit_record,
        )

    replay_counter = _find_matching_sequence(
        hotp=hotp,
        submitted_codes=normalized_codes,
        start_counter=max(0, server_counter - replay_window),
        end_counter=server_counter - 1,
    )
    if replay_counter is not None:
        return _rejected_resync_result(
            result_classification="replay",
            server_counter=server_counter,
            next_counter=server_counter,
            matched_counter=replay_counter,
            submitted_count=len(normalized_codes),
            search_window=search_window,
            replay_window=replay_window,
            attempted_at=timestamp,
        )

    first_code_counter = _find_matching_counter(
        hotp=hotp,
        submitted_code=normalized_codes[0],
        start_counter=server_counter,
        end_counter=server_counter + search_window,
    )
    classification: Literal["invalid", "excessive_drift"]
    if first_code_counter is None:
        classification = "excessive_drift"
    else:
        classification = "invalid"

    return _rejected_resync_result(
        result_classification=classification,
        server_counter=server_counter,
        next_counter=server_counter,
        matched_counter=first_code_counter,
        submitted_count=len(normalized_codes),
        search_window=search_window,
        replay_window=replay_window,
        attempted_at=timestamp,
    )


def verify_hotp(
    *,
    encrypted_secret: EncryptedSecret | str,
    submitted_code: str,
    server_counter: int,
    look_ahead: int = DEFAULT_HOTP_LOOK_AHEAD,
    replay_window: int = DEFAULT_HOTP_REPLAY_WINDOW,
    digits: int = DEFAULT_HOTP_DIGITS,
    attempted_at: datetime | None = None,
) -> HOTPVerificationResult:
    """Verify an HOTP code with bounded look-ahead and replay detection."""

    _validate_hotp_parameters(digits=digits, counter=server_counter)
    if look_ahead < 0:
        raise HOTPConfigurationError("HOTP look_ahead must not be negative.")
    if look_ahead > DEFAULT_HOTP_LOOK_AHEAD_MAX:
        raise HOTPConfigurationError(
            f"HOTP look_ahead must not exceed {DEFAULT_HOTP_LOOK_AHEAD_MAX}."
        )
    if replay_window < 0:
        raise HOTPConfigurationError("HOTP replay_window must not be negative.")
    if replay_window > DEFAULT_HOTP_REPLAY_WINDOW_MAX:
        raise HOTPConfigurationError(
            f"HOTP replay_window must not exceed {DEFAULT_HOTP_REPLAY_WINDOW_MAX}."
        )

    timestamp = attempted_at or timezone.now()
    if not isinstance(submitted_code, str) or not submitted_code.strip():
        return _rejected_result(
            result_classification="invalid",
            server_counter=server_counter,
            next_counter=server_counter,
            matched_counter=None,
            look_ahead=look_ahead,
            replay_window=replay_window,
            attempted_at=timestamp,
        )

    secret = decrypt_secret_text(encrypted_secret)
    hotp = pyotp.HOTP(secret, digits=digits)
    matched_counter = _find_matching_counter(
        hotp=hotp,
        submitted_code=submitted_code,
        start_counter=server_counter,
        end_counter=server_counter + look_ahead,
    )

    if matched_counter is not None:
        next_counter = matched_counter + 1
        classification: HOTPResultClassification
        if matched_counter == server_counter:
            classification = "success"
        else:
            classification = "counter_window_match"
        audit_record = HOTPAuditRecord(
            submitted_outcome="accepted",
            result_classification=classification,
            server_counter=server_counter,
            matched_counter=matched_counter,
            next_counter=next_counter,
            look_ahead=look_ahead,
            replay_window=replay_window,
            attempted_at=timestamp,
        )
        return HOTPVerificationResult(
            accepted=True,
            next_counter=next_counter,
            matched_counter=matched_counter,
            audit_record=audit_record,
        )

    replay_counter = _find_matching_counter(
        hotp=hotp,
        submitted_code=submitted_code,
        start_counter=max(0, server_counter - replay_window),
        end_counter=server_counter - 1,
    )
    if replay_counter is not None:
        return _rejected_result(
            result_classification="replay",
            server_counter=server_counter,
            next_counter=server_counter,
            matched_counter=replay_counter,
            look_ahead=look_ahead,
            replay_window=replay_window,
            attempted_at=timestamp,
        )

    return _rejected_result(
        result_classification="invalid",
        server_counter=server_counter,
        next_counter=server_counter,
        matched_counter=None,
        look_ahead=look_ahead,
        replay_window=replay_window,
        attempted_at=timestamp,
    )


def _find_matching_counter(
    *,
    hotp: pyotp.HOTP,
    submitted_code: str,
    start_counter: int,
    end_counter: int,
) -> int | None:
    if end_counter < start_counter:
        return None

    for counter in range(start_counter, end_counter + 1):
        if pyotp_utils.strings_equal(str(submitted_code), str(hotp.at(counter))):
            return counter

    return None


def _find_matching_sequence(
    *,
    hotp: pyotp.HOTP,
    submitted_codes: Sequence[str],
    start_counter: int,
    end_counter: int,
) -> int | None:
    if end_counter < start_counter:
        return None

    last_start = end_counter - len(submitted_codes) + 1
    if last_start < start_counter:
        return None

    for counter in range(start_counter, last_start + 1):
        if all(
            pyotp_utils.strings_equal(str(code), str(hotp.at(counter + offset)))
            for offset, code in enumerate(submitted_codes)
        ):
            return counter

    return None


def _rejected_result(
    *,
    result_classification: Literal["invalid", "replay"],
    server_counter: int,
    next_counter: int,
    matched_counter: int | None,
    look_ahead: int,
    replay_window: int,
    attempted_at: datetime,
) -> HOTPVerificationResult:
    audit_record = HOTPAuditRecord(
        submitted_outcome="rejected",
        result_classification=result_classification,
        server_counter=server_counter,
        matched_counter=matched_counter,
        next_counter=next_counter,
        look_ahead=look_ahead,
        replay_window=replay_window,
        attempted_at=attempted_at,
    )
    return HOTPVerificationResult(
        accepted=False,
        next_counter=next_counter,
        matched_counter=matched_counter,
        audit_record=audit_record,
    )


def _rejected_resync_result(
    *,
    result_classification: Literal["invalid", "replay", "excessive_drift"],
    server_counter: int,
    next_counter: int,
    matched_counter: int | None,
    submitted_count: int,
    search_window: int,
    replay_window: int,
    attempted_at: datetime,
) -> HOTPResyncResult:
    audit_record = HOTPResyncAuditRecord(
        submitted_outcome="rejected",
        result_classification=result_classification,
        server_counter=server_counter,
        matched_counter=matched_counter,
        next_counter=next_counter,
        submitted_count=submitted_count,
        search_window=search_window,
        replay_window=replay_window,
        attempted_at=attempted_at,
    )
    return HOTPResyncResult(
        accepted=False,
        next_counter=next_counter,
        matched_counter=matched_counter,
        audit_record=audit_record,
    )


def _validate_label(field_name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise HOTPConfigurationError(f"HOTP {field_name} must be a non-empty string.")


def _validate_hotp_parameters(*, digits: int, counter: int) -> None:
    if digits < 6 or digits > 8:
        raise HOTPConfigurationError("HOTP digits must be between 6 and 8.")
    if counter < 0:
        raise HOTPConfigurationError("HOTP counters must not be negative.")
