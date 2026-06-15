from __future__ import annotations

import secrets
import string
from dataclasses import dataclass

from django.contrib.auth.hashers import make_password
from django.db import transaction
from django.utils import timezone

from django_mfa_toolkit.models import RecoveryCode, RecoveryCodeBatch


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
) -> RecoveryCodeBatchEnrollment:
    _validate_generation_parameters(count=count, groups=groups, group_length=group_length)
    codes = _generate_unique_codes(count=count, groups=groups, group_length=group_length)
    replaced_at = timezone.now()

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

    return RecoveryCodeBatchEnrollment(batch=batch, codes=codes)


def normalize_recovery_code(code: str) -> str:
    return "".join(character for character in code.upper() if character in RECOVERY_CODE_ALPHABET)


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
