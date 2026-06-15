from __future__ import annotations

import secrets
import string
from dataclasses import dataclass
from datetime import datetime

from django.contrib.auth.hashers import check_password, make_password
from django.db import transaction
from django.utils import timezone

from django_mfa_toolkit.models import MFAAuditEvent, RecoveryCode, RecoveryCodeBatch
from django_mfa_toolkit.throttling import (
    DEFAULT_MFA_THROTTLE_CACHE_ALIAS,
    DEFAULT_MFA_THROTTLE_LIMIT,
    DEFAULT_MFA_THROTTLE_PERIOD,
    MFAThrottleConfig,
    check_mfa_throttle,
    record_mfa_throttle_failure,
    reset_mfa_throttle,
)


DEFAULT_RECOVERY_CODE_COUNT = 10
DEFAULT_RECOVERY_CODE_GROUPS = 4
DEFAULT_RECOVERY_CODE_GROUP_LENGTH = 4
RECOVERY_CODE_ALPHABET = "".join(sorted(set(string.ascii_uppercase + string.digits) - {"0", "1", "I", "O"}))


class RecoveryCodeConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class RecoveryCodeBatchEnrollment:
    batch: RecoveryCodeBatch
    codes: tuple[str, ...]
    audit_record: RecoveryCodeAuditRecord | None = None


@dataclass(frozen=True)
class RecoveryCodeAuditRecord:
    event_type: str
    submitted_outcome: str
    result_classification: str
    recovery_code_batch_id: int | None
    recovery_code_id: int | None
    attempted_at: datetime


@dataclass(frozen=True)
class RecoveryCodeVerificationResult:
    accepted: bool
    failure_reason: str | None
    matched_recovery_code_id: int | None
    audit_record: RecoveryCodeAuditRecord


def create_recovery_code_batch(
    *,
    user,
    count: int = DEFAULT_RECOVERY_CODE_COUNT,
    groups: int = DEFAULT_RECOVERY_CODE_GROUPS,
    group_length: int = DEFAULT_RECOVERY_CODE_GROUP_LENGTH,
) -> RecoveryCodeBatchEnrollment:
    _validate_generation_parameters(count=count, groups=groups, group_length=group_length)
    codes = _generate_unique_codes(count=count, groups=groups, group_length=group_length)

    with transaction.atomic():
        batch = RecoveryCodeBatch.objects.create(user=user)
        RecoveryCode.objects.bulk_create(
            RecoveryCode(
                user=user,
                batch=batch,
                code_hash=make_password(normalize_recovery_code(code)),
            )
            for code in codes
        )

    return RecoveryCodeBatchEnrollment(batch=batch, codes=codes)


def reset_recovery_code_batch(
    *,
    user,
    count: int = DEFAULT_RECOVERY_CODE_COUNT,
    groups: int = DEFAULT_RECOVERY_CODE_GROUPS,
    group_length: int = DEFAULT_RECOVERY_CODE_GROUP_LENGTH,
    attempted_at: datetime | None = None,
    persist_audit: bool = False,
) -> RecoveryCodeBatchEnrollment:
    _validate_generation_parameters(count=count, groups=groups, group_length=group_length)
    codes = _generate_unique_codes(count=count, groups=groups, group_length=group_length)
    replaced_at = attempted_at or timezone.now()

    with transaction.atomic():
        active_batches = RecoveryCodeBatch.objects.select_for_update().filter(user=user, replaced_at__isnull=True)
        active_batches.update(replaced_at=replaced_at)
        RecoveryCode.objects.select_for_update().filter(
            user=user,
            used_at__isnull=True,
            replaced_at__isnull=True,
        ).update(replaced_at=replaced_at)

        batch = RecoveryCodeBatch.objects.create(user=user)
        RecoveryCode.objects.bulk_create(
            RecoveryCode(
                user=user,
                batch=batch,
                code_hash=make_password(normalize_recovery_code(code)),
            )
            for code in codes
        )
        audit_record = RecoveryCodeAuditRecord(
            event_type=MFAAuditEvent.EventType.RESET,
            submitted_outcome=MFAAuditEvent.SubmittedOutcome.ACCEPTED,
            result_classification="reset",
            recovery_code_batch_id=batch.pk,
            recovery_code_id=None,
            attempted_at=replaced_at,
        )
        if persist_audit:
            MFAAuditEvent.objects.create(
                user=user,
                factor=MFAAuditEvent.Factor.RECOVERY_CODE,
                event_type=audit_record.event_type,
                submitted_outcome=audit_record.submitted_outcome,
                result_classification=audit_record.result_classification,
                recovery_code_batch=batch,
                attempted_at=audit_record.attempted_at,
            )

    return RecoveryCodeBatchEnrollment(batch=batch, codes=codes, audit_record=audit_record)


def verify_recovery_code(
    *,
    user,
    submitted_code: str,
    attempted_at: datetime | None = None,
    throttle_scope: str | None = None,
    throttle_limit: int = DEFAULT_MFA_THROTTLE_LIMIT,
    throttle_period: int = DEFAULT_MFA_THROTTLE_PERIOD,
    throttle_cache_alias: str = DEFAULT_MFA_THROTTLE_CACHE_ALIAS,
    persist_audit: bool = False,
) -> RecoveryCodeVerificationResult:
    timestamp = attempted_at or timezone.now()
    normalized_code = normalize_recovery_code(submitted_code)

    with transaction.atomic():
        throttle_config = _throttle_config(
            throttle_scope,
            throttle_limit,
            throttle_period,
            throttle_cache_alias,
        )
        if throttle_config is not None and not check_mfa_throttle(throttle_config).allowed:
            result = _recovery_code_result(
                accepted=False,
                failure_reason="throttled",
                result_classification="throttled",
                code=None,
                attempted_at=timestamp,
            )
            _persist_recovery_code_audit_if_requested(persist_audit=persist_audit, user=user, result=result)
            return result

        active_codes = tuple(
            RecoveryCode.objects.select_for_update()
            .select_related("batch")
            .filter(
                user=user,
                batch__replaced_at__isnull=True,
                used_at__isnull=True,
                replaced_at__isnull=True,
            )
            .order_by("pk")
        )
        matched_code = next((code for code in active_codes if check_password(normalized_code, code.code_hash)), None)

        if matched_code is not None:
            matched_code.used_at = timestamp
            matched_code.save(update_fields=["used_at", "updated_at"])
            if throttle_config is not None:
                reset_mfa_throttle(throttle_config)
            result = _recovery_code_result(
                accepted=True,
                failure_reason=None,
                result_classification="success",
                code=matched_code,
                attempted_at=timestamp,
            )
            _persist_recovery_code_audit_if_requested(persist_audit=persist_audit, user=user, result=result)
            return result

        replay_code = _find_replayed_recovery_code(user=user, normalized_code=normalized_code)
        if replay_code is not None:
            classification = "replay"
            failure_reason = "replay"
            code = replay_code
        else:
            classification = "invalid"
            failure_reason = "invalid"
            code = None

        if throttle_config is not None:
            record_mfa_throttle_failure(throttle_config)
        result = _recovery_code_result(
            accepted=False,
            failure_reason=failure_reason,
            result_classification=classification,
            code=code,
            attempted_at=timestamp,
        )
        _persist_recovery_code_audit_if_requested(persist_audit=persist_audit, user=user, result=result)
        return result


def normalize_recovery_code(code: str) -> str:
    return "".join(character for character in code.upper() if character in RECOVERY_CODE_ALPHABET)


def _find_replayed_recovery_code(*, user, normalized_code: str) -> RecoveryCode | None:
    historical_codes = (
        RecoveryCode.objects.select_for_update()
        .select_related("batch")
        .filter(user=user)
        .exclude(used_at__isnull=True, replaced_at__isnull=True, batch__replaced_at__isnull=True)
        .order_by("pk")
    )
    return next((code for code in historical_codes if check_password(normalized_code, code.code_hash)), None)


def _recovery_code_result(
    *,
    accepted: bool,
    failure_reason: str | None,
    result_classification: str,
    code: RecoveryCode | None,
    attempted_at: datetime,
) -> RecoveryCodeVerificationResult:
    return RecoveryCodeVerificationResult(
        accepted=accepted,
        failure_reason=failure_reason,
        matched_recovery_code_id=code.pk if code is not None and accepted else None,
        audit_record=RecoveryCodeAuditRecord(
            event_type=MFAAuditEvent.EventType.VERIFICATION,
            submitted_outcome=(
                MFAAuditEvent.SubmittedOutcome.ACCEPTED if accepted else MFAAuditEvent.SubmittedOutcome.REJECTED
            ),
            result_classification=result_classification,
            recovery_code_batch_id=code.batch_id if code is not None else None,
            recovery_code_id=code.pk if code is not None else None,
            attempted_at=attempted_at,
        ),
    )


def _persist_recovery_code_audit_if_requested(
    *,
    persist_audit: bool,
    user,
    result: RecoveryCodeVerificationResult,
) -> MFAAuditEvent | None:
    if not persist_audit:
        return None
    return MFAAuditEvent.objects.create(
        user=user,
        factor=MFAAuditEvent.Factor.RECOVERY_CODE,
        event_type=result.audit_record.event_type,
        submitted_outcome=result.audit_record.submitted_outcome,
        result_classification=result.audit_record.result_classification,
        recovery_code_batch_id=result.audit_record.recovery_code_batch_id,
        recovery_code_id=result.audit_record.recovery_code_id,
        attempted_at=result.audit_record.attempted_at,
    )


def _throttle_config(
    scope: str | None,
    limit: int,
    period: int,
    cache_alias: str,
) -> MFAThrottleConfig | None:
    if scope is None:
        return None
    return MFAThrottleConfig(scope=scope, limit=limit, period=period, cache_alias=cache_alias)


def _generate_unique_codes(*, count: int, groups: int, group_length: int) -> tuple[str, ...]:
    codes: set[str] = set()
    while len(codes) < count:
        groups_of_characters = (
            "".join(secrets.choice(RECOVERY_CODE_ALPHABET) for _ in range(group_length)) for _ in range(groups)
        )
        codes.add("-".join(groups_of_characters))
    return tuple(codes)


def _validate_generation_parameters(*, count: int, groups: int, group_length: int) -> None:
    if count < 1 or count > 50:
        raise RecoveryCodeConfigurationError("Recovery code count must be between 1 and 50.")
    if groups < 2 or groups > 8:
        raise RecoveryCodeConfigurationError("Recovery code groups must be between 2 and 8.")
    if group_length < 2 or group_length > 8:
        raise RecoveryCodeConfigurationError("Recovery code group length must be between 2 and 8.")
