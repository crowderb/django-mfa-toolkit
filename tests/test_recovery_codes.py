from inspect import signature

import pytest
from django.contrib.auth.hashers import check_password
from django.db import connection
from django.db.migrations.loader import MigrationLoader
from django.utils import timezone

from django_mfa_toolkit.models import RecoveryCode, RecoveryCodeBatch
from django_mfa_toolkit.recovery_codes import (
    RecoveryCodeConfigurationError,
    create_recovery_code_batch,
    normalize_recovery_code,
    reset_recovery_code_batch,
)
from django_mfa_toolkit.security_invariants import FORBIDDEN_TARGET_PARAMETER_NAMES


@pytest.mark.django_db
def test_create_recovery_code_batch_returns_plaintext_once_and_persists_only_hashes(django_user_model):
    user = django_user_model.objects.create_user(username="recovery-storage-user")

    enrolled = create_recovery_code_batch(user=user, count=3, groups=2, group_length=4)

    persisted_codes = list(RecoveryCode.objects.filter(batch=enrolled.batch).order_by("pk"))
    persisted_batches = list(RecoveryCodeBatch.objects.filter(user=user))

    assert len(enrolled.codes) == 3
    assert len(set(enrolled.codes)) == 3
    assert len(persisted_codes) == 3
    assert persisted_batches == [enrolled.batch]
    assert enrolled.batch.user == user
    assert enrolled.batch.replaced_at is None

    for displayed_code in enrolled.codes:
        normalized_code = normalize_recovery_code(displayed_code)

        assert displayed_code not in {persisted.code_hash for persisted in persisted_codes}
        assert normalized_code not in {persisted.code_hash for persisted in persisted_codes}
        assert any(check_password(normalized_code, persisted.code_hash) for persisted in persisted_codes)


@pytest.mark.django_db
def test_reset_recovery_code_batch_marks_previous_unused_codes_replaced(django_user_model):
    user = django_user_model.objects.create_user(username="recovery-reset-user")
    original = create_recovery_code_batch(user=user, count=2)
    used_code = original.batch.codes.order_by("pk").first()
    assert used_code is not None
    used_code.used_at = timezone.now()
    used_code.save(update_fields=["used_at", "updated_at"])

    replacement = reset_recovery_code_batch(user=user, count=2)

    original.batch.refresh_from_db()
    used_code.refresh_from_db()
    replaced_unused_codes = RecoveryCode.objects.filter(batch=original.batch, used_at__isnull=True)
    active_codes = RecoveryCode.objects.filter(batch=replacement.batch)

    assert original.batch.replaced_at is not None
    assert replacement.batch.replaced_at is None
    assert used_code.used_at is not None
    assert used_code.replaced_at is None
    assert replaced_unused_codes.count() == 1
    assert replaced_unused_codes.get().replaced_at is not None
    assert active_codes.count() == 2
    assert all(code.used_at is None and code.replaced_at is None for code in active_codes)
    assert set(original.codes).isdisjoint(replacement.codes)


@pytest.mark.django_db
def test_recovery_code_rows_can_represent_unused_used_and_replaced_states(django_user_model):
    user = django_user_model.objects.create_user(username="recovery-state-user")
    enrolled = create_recovery_code_batch(user=user, count=3)
    unused_code, used_code, replaced_code = enrolled.batch.codes.order_by("pk")

    used_code.used_at = timezone.now()
    used_code.save(update_fields=["used_at", "updated_at"])
    replaced_code.replaced_at = timezone.now()
    replaced_code.save(update_fields=["replaced_at", "updated_at"])

    unused_code.refresh_from_db()
    used_code.refresh_from_db()
    replaced_code.refresh_from_db()

    assert unused_code.used_at is None
    assert unused_code.replaced_at is None
    assert used_code.used_at is not None
    assert used_code.replaced_at is None
    assert replaced_code.used_at is None
    assert replaced_code.replaced_at is not None


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"count": 0}, "count"),
        ({"count": 51}, "count"),
        ({"groups": 1}, "groups"),
        ({"groups": 9}, "groups"),
        ({"group_length": 1}, "group length"),
        ({"group_length": 9}, "group length"),
    ],
)
def test_recovery_code_generation_rejects_unbounded_parameters(django_user_model, kwargs, message):
    user = django_user_model(username="recovery-bounds-user")

    with pytest.raises(RecoveryCodeConfigurationError, match=message):
        create_recovery_code_batch(user=user, **kwargs)


@pytest.mark.django_db
def test_recovery_code_model_migration_is_importable():
    loader = MigrationLoader(connection)
    migration = loader.get_migration("django_mfa_toolkit", "0003_recoverycodebatch_recoverycode_and_more")
    created_models = {operation.name for operation in migration.operations if hasattr(operation, "name")}

    assert {"RecoveryCodeBatch", "RecoveryCode"}.issubset(created_models)


def test_recovery_code_storage_helpers_are_non_targetable():
    surfaces = (
        create_recovery_code_batch,
        reset_recovery_code_batch,
        normalize_recovery_code,
    )

    for surface in surfaces:
        parameter_names = {name.lower() for name in signature(surface).parameters}

        assert parameter_names.isdisjoint(FORBIDDEN_TARGET_PARAMETER_NAMES)
