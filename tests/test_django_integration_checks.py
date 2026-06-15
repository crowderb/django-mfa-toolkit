from datetime import datetime, timezone
from inspect import signature

import pyotp
import pytest
from django.core.cache import caches
from django.http import HttpResponse
from django.test import Client
from django.urls import path
from django.utils import timezone as django_timezone

from django_mfa_toolkit.device_adapters import (
    enroll_hotp_device,
    enroll_totp_device,
    resync_hotp_device,
    verify_hotp_device,
    verify_totp_device,
)
from django_mfa_toolkit.models import HOTPDevice, TOTPDevice
from django_mfa_toolkit.secret_storage import decrypt_secret_text
from django_mfa_toolkit.security_invariants import (
    FORBIDDEN_TARGET_PARAMETER_NAMES,
    get_mvp_control_requirements,
    run_local_security_invariant_checks,
)
from django_mfa_toolkit.session_elevation import mark_mfa_elevated, mfa_required


FIXED_TOTP_TIME = datetime(2026, 6, 15, 12, 0, tzinfo=timezone.utc)


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
        throttle_scope=f"local-integration:totp:{request.user.pk}:{device.pk}",
        throttle_limit=1,
    )
    if result.accepted:
        mark_mfa_elevated(request, factor="totp", device_id=device.pk)
        return HttpResponse(status=204)
    if result.failure_reason == "throttled":
        return HttpResponse("throttled", status=429)
    return HttpResponse("rejected", status=403)


urlpatterns = [
    path("protected/", protected_view),
    path("verify-totp/<int:device_id>/", verify_totp_view),
]


@pytest.fixture(autouse=True)
def clear_local_throttle_cache():
    caches["default"].clear()


@pytest.fixture
def synthetic_user(django_user_model):
    return django_user_model.objects.create_user(username="local-integration-user")


@pytest.fixture
def synthetic_totp_device(synthetic_mfa_settings_override, synthetic_user):
    enrolled = enroll_totp_device(
        user=synthetic_user,
        account_name="totp-local@example.test",
        issuer_name="Toolkit",
    )
    TOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    enrolled.device.refresh_from_db()
    return enrolled.device


@pytest.fixture
def synthetic_hotp_device(synthetic_mfa_settings_override, synthetic_user):
    enrolled = enroll_hotp_device(
        user=synthetic_user,
        account_name="hotp-local@example.test",
        issuer_name="Toolkit",
    )
    HOTPDevice.objects.filter(pk=enrolled.device.pk).update(confirmed_at=django_timezone.now())
    enrolled.device.refresh_from_db()
    return enrolled.device


@pytest.mark.django_db
def test_local_totp_client_flow_enforces_mfa_replay_and_session_boundary(
    settings,
    synthetic_user,
    synthetic_totp_device,
):
    settings.ROOT_URLCONF = __name__
    client = _logged_in_client(synthetic_user)
    code = _totp_code(synthetic_totp_device)

    pre_mfa_response = client.get("/protected/")
    accepted_response = client.post(f"/verify-totp/{synthetic_totp_device.pk}/", {"code": code})
    post_mfa_response = client.get("/protected/")

    client.session.flush()
    client.force_login(synthetic_user)
    replayed_response = client.post(f"/verify-totp/{synthetic_totp_device.pk}/", {"code": code})
    replayed_protected_response = client.get("/protected/")

    assert pre_mfa_response.status_code == 403
    assert accepted_response.status_code == 204
    assert post_mfa_response.status_code == 200
    assert post_mfa_response.content == b"protected"
    assert replayed_response.status_code == 403
    assert replayed_protected_response.status_code == 403


@pytest.mark.django_db
def test_local_totp_client_flow_enforces_throttle_before_session_elevation(
    settings,
    synthetic_user,
    synthetic_totp_device,
):
    settings.ROOT_URLCONF = __name__
    client = _logged_in_client(synthetic_user)
    valid_code = _totp_code(synthetic_totp_device)

    rejected_response = client.post(f"/verify-totp/{synthetic_totp_device.pk}/", {"code": "000000"})
    throttled_response = client.post(f"/verify-totp/{synthetic_totp_device.pk}/", {"code": valid_code})
    protected_response = client.get("/protected/")

    synthetic_totp_device.refresh_from_db()

    assert rejected_response.status_code == 403
    assert throttled_response.status_code == 429
    assert protected_response.status_code == 403
    assert synthetic_totp_device.last_accepted_timecode is None


@pytest.mark.django_db
def test_local_hotp_persisted_device_rejects_replay_without_counter_advance(synthetic_hotp_device):
    hotp = pyotp.HOTP(decrypt_secret_text(synthetic_hotp_device.persisted_secret))
    code = hotp.at(0)

    accepted = verify_hotp_device(device=synthetic_hotp_device, submitted_code=code, look_ahead=0)
    replayed = verify_hotp_device(
        device=synthetic_hotp_device,
        submitted_code=code,
        look_ahead=0,
        replay_window=1,
    )

    synthetic_hotp_device.refresh_from_db()

    assert accepted.accepted is True
    assert accepted.next_counter == 1
    assert replayed.accepted is False
    assert replayed.audit_record.result_classification == "replay"
    assert synthetic_hotp_device.hotp_counter == 1


@pytest.mark.django_db
def test_local_hotp_resync_throttle_blocks_before_counter_update(synthetic_hotp_device):
    hotp = pyotp.HOTP(decrypt_secret_text(synthetic_hotp_device.persisted_secret))
    throttle_scope = f"local-integration:hotp-resync:{synthetic_hotp_device.pk}"

    failed = resync_hotp_device(
        device=synthetic_hotp_device,
        submitted_codes=[hotp.at(10), hotp.at(12)],
        search_window=20,
        throttle_scope=throttle_scope,
        throttle_limit=1,
    )
    throttled = resync_hotp_device(
        device=synthetic_hotp_device,
        submitted_codes=[hotp.at(10), hotp.at(11)],
        search_window=20,
        throttle_scope=throttle_scope,
        throttle_limit=1,
    )

    synthetic_hotp_device.refresh_from_db()

    assert failed.accepted is False
    assert throttled.accepted is False
    assert throttled.audit_record.result_classification == "throttled"
    assert synthetic_hotp_device.hotp_counter == 0


def test_django_integration_controls_are_represented_as_local_invariants():
    requirement_ids = {requirement.id for requirement in get_mvp_control_requirements()}
    check_ids = {check.id for check in run_local_security_invariant_checks()}

    assert {
        "django-persistence.stateful-verification",
        "django-throttling.lockout",
        "django-session-elevation.boundary",
    }.issubset(requirement_ids)
    assert {
        "verification-surface.not-targetable",
        "control-requirements.represented",
    }.issubset(check_ids)
    assert all(check.passed for check in run_local_security_invariant_checks())


def test_local_integration_verification_surfaces_do_not_accept_network_targets_or_credentials():
    surfaces = (
        enroll_totp_device,
        verify_totp_device,
        enroll_hotp_device,
        verify_hotp_device,
        resync_hotp_device,
        mark_mfa_elevated,
        mfa_required,
        run_local_security_invariant_checks,
    )

    for surface in surfaces:
        parameter_names = {name.lower() for name in signature(surface).parameters}

        assert parameter_names.isdisjoint(FORBIDDEN_TARGET_PARAMETER_NAMES)


def _logged_in_client(user):
    client = Client()
    client.force_login(user)
    return client


def _totp_code(device):
    return pyotp.TOTP(decrypt_secret_text(device.persisted_secret)).at(FIXED_TOTP_TIME)
