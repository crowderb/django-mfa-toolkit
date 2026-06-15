from datetime import datetime, timezone
from inspect import signature

import pyotp
import pytest
from django.http import HttpResponse
from django.test import Client
from django.urls import path
from django.utils import timezone as django_timezone

from django_mfa_toolkit.device_adapters import enroll_hotp_device, enroll_totp_device, verify_totp_device
from django_mfa_toolkit.integration_checks import MFALocalIntegrationCheckMixin, run_local_django_mfa_integration_checks
from django_mfa_toolkit.models import HOTPDevice, TOTPDevice
from django_mfa_toolkit.secret_storage import decrypt_secret_text
from django_mfa_toolkit.security_invariants import FORBIDDEN_TARGET_PARAMETER_NAMES
from django_mfa_toolkit.session_elevation import mark_mfa_elevated, mfa_required


FIXED_TOTP_TIME = datetime(2026, 6, 15, 18, 0, tzinfo=timezone.utc)


@mfa_required(max_age=60)
def protected_view(request):
    return HttpResponse("protected")


def verify_totp_view(request, device_id):
    device = TOTPDevice.objects.get(pk=device_id, user=request.user)
    result = verify_totp_device(
        device=device,
        submitted_code=request.POST.get("code", ""),
        at_time=FIXED_TOTP_TIME,
        valid_window=0,
    )
    if result.accepted:
        mark_mfa_elevated(request, factor="totp", device_id=device.pk)
        return HttpResponse(status=204)
    return HttpResponse("rejected", status=403)


urlpatterns = [
    path("protected/", protected_view),
    path("verify-totp/<int:device_id>/", verify_totp_view),
]


@pytest.fixture
def synthetic_user(django_user_model):
    return django_user_model.objects.create_user(username="integration-check-user")


@pytest.fixture
def synthetic_totp_device(synthetic_mfa_settings_override, synthetic_user):
    enrolled = enroll_totp_device(
        user=synthetic_user,
        account_name="totp-helper@example.test",
        issuer_name="Toolkit",
    )
    TOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    enrolled.device.refresh_from_db()
    return enrolled.device


@pytest.fixture
def synthetic_hotp_device(synthetic_mfa_settings_override, synthetic_user):
    enrolled = enroll_hotp_device(
        user=synthetic_user,
        account_name="hotp-helper@example.test",
        issuer_name="Toolkit",
    )
    HOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    enrolled.device.refresh_from_db()
    return enrolled.device


@pytest.mark.django_db
def test_local_django_mfa_integration_checks_run_against_synthetic_devices(
    synthetic_totp_device,
    synthetic_hotp_device,
):
    results = run_local_django_mfa_integration_checks(
        totp_device=synthetic_totp_device,
        hotp_device=synthetic_hotp_device,
        at_time=FIXED_TOTP_TIME,
    )

    assert {result.id for result in results} == {
        "security-invariants.pass",
        "django-integration.totp-replay",
        "django-integration.hotp-replay-counter",
    }
    assert all(result.passed for result in results)


@pytest.mark.django_db
def test_local_integration_check_mixin_validates_in_process_client_session_boundary(
    settings,
    synthetic_user,
    synthetic_totp_device,
):
    settings.ROOT_URLCONF = __name__
    client = Client()
    client.force_login(synthetic_user)
    code = pyotp.TOTP(decrypt_secret_text(synthetic_totp_device.persisted_secret)).at(FIXED_TOTP_TIME)

    anonymous_response = client.get("/protected/")
    verified_response = client.post(f"/verify-totp/{synthetic_totp_device.pk}/", {"code": code})
    protected_response = client.get("/protected/")
    client.session.flush()
    client.force_login(synthetic_user)
    client.post(f"/verify-totp/{synthetic_totp_device.pk}/", {"code": code})
    replay_response = client.get("/protected/")

    MFALocalIntegrationCheckMixin().assert_mfa_required_session_boundary(
        anonymous_response=anonymous_response,
        verified_response=verified_response,
        protected_response=protected_response,
        replay_response=replay_response,
    )


def test_local_integration_check_helpers_are_non_targetable():
    surfaces = (
        run_local_django_mfa_integration_checks,
        MFALocalIntegrationCheckMixin.assert_local_security_invariants_pass,
        MFALocalIntegrationCheckMixin.assert_totp_device_rejects_replay,
        MFALocalIntegrationCheckMixin.assert_hotp_device_rejects_replay_without_counter_advance,
        MFALocalIntegrationCheckMixin.assert_mfa_required_session_boundary,
    )

    for surface in surfaces:
        parameter_names = {name.lower() for name in signature(surface).parameters}

        assert parameter_names.isdisjoint(FORBIDDEN_TARGET_PARAMETER_NAMES)
