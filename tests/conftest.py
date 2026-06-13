from dataclasses import dataclass

import pytest
from cryptography.fernet import Fernet
from django.test import override_settings


@dataclass(frozen=True)
class SyntheticMFASettings:
    key_id: str
    key: str

    def as_django_settings(self):
        return {
            "DJANGO_MFA_TOOLKIT_SECRET_ENCRYPTION_KEYS": {self.key_id: self.key},
            "DJANGO_MFA_TOOLKIT_PRIMARY_SECRET_ENCRYPTION_KEY_ID": self.key_id,
        }


@pytest.fixture
def synthetic_mfa_settings():
    return SyntheticMFASettings(
        key_id="synthetic-test-key",
        key=Fernet.generate_key().decode("ascii"),
    )


@pytest.fixture
def synthetic_mfa_settings_override(synthetic_mfa_settings):
    with override_settings(**synthetic_mfa_settings.as_django_settings()):
        yield synthetic_mfa_settings
