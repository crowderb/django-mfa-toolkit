from inspect import signature

import pytest
from django.contrib.auth.hashers import check_password
from django.db import connection
from django.db.migrations.loader import MigrationLoader
from django.utils import timezone

from django_mfa_toolkit.models import MFAAuditEvent, RecoveryCode, RecoveryCodeBatch
from django_mfa_toolkit.recovery_codes import (
    RecoveryCodeConfigurationError,
    create_recovery_code_batch,
    normalize_recovery_code,
    reset_recovery_code_batch,
    verify_recovery_code,
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
def test_verify_recovery_code_accepts_once_and_rejects_replay(django_user_model):
    user = django_user_model.objects.create_user(username="recovery-verify-user")
    enrolled = create_recovery_code_batch(user=user, count=2)
    submitted_code = enrolled.codes[0]

    accepted = verify_recovery_code(user=user, submitted_code=submitted_code, persist_audit=True)
    replayed = verify_recovery_code(user=user, submitted_code=submitted_code, persist_audit=True)

    consumed_code = RecoveryCode.objects.get(pk=accepted.matched_recovery_code_id)
    audit_events = list(MFAAuditEvent.objects.filter(factor=MFAAuditEvent.Factor.RECOVERY_CODE).order_by("pk"))

    assert accepted.accepted is True
    assert accepted.failure_reason is None
    assert accepted.audit_record.result_classification == "success"
    assert consumed_code.used_at is not None
    assert replayed.accepted is False
    assert replayed.failure_reason == "replay"
    assert replayed.audit_record.result_classification == "replay"
    assert RecoveryCode.objects.filter(user=user, used_at__isnull=False).count() == 1
    assert [event.result_classification for event in audit_events] == ["success", "replay"]
    assert audit_events[0].recovery_code == consumed_code
    assert audit_events[0].server_counter is None
    assert audit_events[0].replay_window is None


@pytest.mark.django_db
def test_verify_recovery_code_rejects_replaced_code_without_consuming_active_code(django_user_model):
    user = django_user_model.objects.create_user(username="recovery-replaced-user")
    original = create_recovery_code_batch(user=user, count=1)
    replaced_code = original.codes[0]
    replacement = reset_recovery_code_batch(user=user, count=1)

    result = verify_recovery_code(user=user, submitted_code=replaced_code, persist_audit=True)

    assert result.accepted is False
    assert result.failure_reason == "replay"
    assert RecoveryCode.objects.filter(batch=replacement.batch, used_at__isnull=True, replaced_at__isnull=True).count() == 1
    assert MFAAuditEvent.objects.get(result_classification="replay").recovery_code_batch == original.batch


@pytest.mark.django_db
def test_verify_recovery_code_rejects_invalid_code_without_consuming_codes(django_user_model):
    user = django_user_model.objects.create_user(username="recovery-invalid-user")
    create_recovery_code_batch(user=user, count=2)

    result = verify_recovery_code(user=user, submitted_code="ZZZZ-ZZZZ", persist_audit=True)

    event = MFAAuditEvent.objects.get(result_classification="invalid")

    assert result.accepted is False
    assert result.failure_reason == "invalid"
    assert RecoveryCode.objects.filter(user=user, used_at__isnull=True, replaced_at__isnull=True).count() == 2
    assert event.recovery_code is None
    assert event.recovery_code_batch is None


@pytest.mark.django_db
def test_verify_recovery_code_throttles_before_code_comparison_without_consuming_code(django_user_model):
    user = django_user_model.objects.create_user(username="recovery-throttle-user")
    enrolled = create_recovery_code_batch(user=user, count=1)
    throttle_scope = f"recovery-code:{user.pk}"

    invalid = verify_recovery_code(
        user=user,
        submitted_code="ZZZZ-ZZZZ",
        throttle_scope=throttle_scope,
        throttle_limit=1,
        persist_audit=True,
    )
    throttled = verify_recovery_code(
        user=user,
        submitted_code=enrolled.codes[0],
        throttle_scope=throttle_scope,
        throttle_limit=1,
        persist_audit=True,
    )

    assert invalid.failure_reason == "invalid"
    assert throttled.accepted is False
    assert throttled.failure_reason == "throttled"
    assert RecoveryCode.objects.filter(user=user, used_at__isnull=True, replaced_at__isnull=True).count() == 1
    assert list(MFAAuditEvent.objects.order_by("pk").values_list("result_classification", flat=True)) == [
        "invalid",
        "throttled",
    ]


@pytest.mark.django_db
def test_reset_recovery_code_batch_can_persist_reset_audit_without_code_material(django_user_model):
    user = django_user_model.objects.create_user(username="recovery-reset-audit-user")
    original = create_recovery_code_batch(user=user, count=1)

    replacement = reset_recovery_code_batch(user=user, count=1, persist_audit=True)

    event = MFAAuditEvent.objects.get(result_classification="reset")
    stored_values = " ".join(str(value) for value in _recovery_audit_values(event))

    assert replacement.audit_record is not None
    assert replacement.audit_record.result_classification == "reset"
    assert event.factor == MFAAuditEvent.Factor.RECOVERY_CODE
    assert event.event_type == MFAAuditEvent.EventType.RESET
    assert event.recovery_code_batch == replacement.batch
    assert original.codes[0] not in stored_values
    assert replacement.codes[0] not in stored_values


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


@pytest.mark.django_db
def test_recovery_code_audit_migration_is_importable():
    loader = MigrationLoader(connection)
    migration = loader.get_migration("django_mfa_toolkit", "0004_mfaauditevent_recovery_code_and_more")
    operation_names = {operation.__class__.__name__ for operation in migration.operations}

    assert {"AddField", "AlterField", "AddIndex"}.issubset(operation_names)


def test_recovery_code_storage_helpers_are_non_targetable():
    surfaces = (
        create_recovery_code_batch,
        reset_recovery_code_batch,
        verify_recovery_code,
        normalize_recovery_code,
    )

    for surface in surfaces:
        parameter_names = {name.lower() for name in signature(surface).parameters}

        assert parameter_names.isdisjoint(FORBIDDEN_TARGET_PARAMETER_NAMES)


def _recovery_audit_values(event):
    return [
        event.user_id,
        event.device_id,
        event.recovery_code_batch_id,
        event.recovery_code_id,
        event.factor,
        event.event_type,
        event.submitted_outcome,
        event.result_classification,
        event.server_counter,
        event.matched_counter,
        event.next_counter,
        event.look_ahead,
        event.search_window,
        event.replay_window,
        event.submitted_count,
        event.attempted_at,
        event.created_at,
    ]
