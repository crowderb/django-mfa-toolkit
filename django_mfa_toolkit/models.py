from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import models

from django_mfa_toolkit.hotp import DEFAULT_HOTP_DIGITS
from django_mfa_toolkit.secret_storage import EncryptedSecret, SecretDecryptionError
from django_mfa_toolkit.totp import DEFAULT_TOTP_DIGITS, DEFAULT_TOTP_INTERVAL


class MFADeviceBase(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="%(app_label)s_%(class)s_set",
    )
    persisted_secret = models.TextField()
    name = models.CharField(max_length=150, blank=True)
    confirmed_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

    def clean(self) -> None:
        super().clean()
        try:
            EncryptedSecret.parse(self.persisted_secret)
        except (ImproperlyConfigured, SecretDecryptionError) as exc:
            raise ValidationError({"persisted_secret": "Persisted MFA secret is invalid."}) from exc

    def __str__(self) -> str:
        label = self.name or self.__class__.__name__
        return f"{label} for user {self.user_id}"


class TOTPDevice(MFADeviceBase):
    digits = models.PositiveSmallIntegerField(default=DEFAULT_TOTP_DIGITS)
    interval = models.PositiveIntegerField(default=DEFAULT_TOTP_INTERVAL)
    last_accepted_timecode = models.BigIntegerField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "is_active"]),
            models.Index(fields=["user", "confirmed_at"]),
        ]


class HOTPDevice(MFADeviceBase):
    digits = models.PositiveSmallIntegerField(default=DEFAULT_HOTP_DIGITS)
    hotp_counter = models.PositiveBigIntegerField(default=0)

    class Meta:
        indexes = [
            models.Index(fields=["user", "is_active"]),
            models.Index(fields=["user", "confirmed_at"]),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(hotp_counter__gte=0),
                name="django_mfa_hotp_counter_non_negative",
            ),
        ]


class MFAAuditEvent(models.Model):
    class Factor(models.TextChoices):
        HOTP = "hotp", "HOTP"

    class EventType(models.TextChoices):
        VERIFICATION = "verification", "Verification"
        RESYNCHRONIZATION = "resynchronization", "Resynchronization"

    class SubmittedOutcome(models.TextChoices):
        ACCEPTED = "accepted", "Accepted"
        REJECTED = "rejected", "Rejected"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="django_mfa_toolkit_audit_events",
    )
    device = models.ForeignKey(
        HOTPDevice,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_events",
    )
    factor = models.CharField(max_length=16, choices=Factor.choices, default=Factor.HOTP)
    event_type = models.CharField(max_length=32, choices=EventType.choices)
    submitted_outcome = models.CharField(max_length=16, choices=SubmittedOutcome.choices)
    result_classification = models.CharField(max_length=32)
    server_counter = models.PositiveBigIntegerField()
    matched_counter = models.PositiveBigIntegerField(null=True, blank=True)
    next_counter = models.PositiveBigIntegerField()
    look_ahead = models.PositiveIntegerField(null=True, blank=True)
    search_window = models.PositiveIntegerField(null=True, blank=True)
    replay_window = models.PositiveIntegerField()
    submitted_count = models.PositiveIntegerField(null=True, blank=True)
    attempted_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "attempted_at"]),
            models.Index(fields=["device", "attempted_at"]),
            models.Index(fields=["event_type", "result_classification"]),
            models.Index(fields=["attempted_at"]),
        ]


class RecoveryCodeBatch(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="django_mfa_toolkit_recovery_code_batches",
    )
    batch_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    replaced_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "replaced_at"]),
            models.Index(fields=["batch_id"]),
        ]

    def __str__(self) -> str:
        return f"Recovery code batch {self.batch_id} for user {self.user_id}"


class RecoveryCode(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="django_mfa_toolkit_recovery_codes",
    )
    batch = models.ForeignKey(
        RecoveryCodeBatch,
        on_delete=models.CASCADE,
        related_name="codes",
    )
    code_hash = models.CharField(max_length=255)
    used_at = models.DateTimeField(null=True, blank=True)
    replaced_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "used_at", "replaced_at"]),
            models.Index(fields=["batch", "used_at"]),
        ]

    def __str__(self) -> str:
        return f"Recovery code {self.pk} for user {self.user_id}"
