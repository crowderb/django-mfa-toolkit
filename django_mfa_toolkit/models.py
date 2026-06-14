from __future__ import annotations

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
