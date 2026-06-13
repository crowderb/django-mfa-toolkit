from django.apps import apps

import django_mfa_toolkit


def test_package_imports():
    assert django_mfa_toolkit.__version__ == "0.1.0"


def test_django_app_config_is_registered():
    config = apps.get_app_config("django_mfa_toolkit")

    assert config.name == "django_mfa_toolkit"
    assert config.verbose_name == "Django MFA Toolkit"
