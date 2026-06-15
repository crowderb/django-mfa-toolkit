from datetime import timedelta

import pytest
from django.contrib.auth import logout
from django.http import HttpResponse
from django.test import Client
from django.urls import path
from django.utils import timezone

from django_mfa_toolkit.session_elevation import (
    clear_mfa_elevation,
    mark_mfa_elevated,
    mfa_required,
)


@mfa_required(max_age=60)
def protected_view(request):
    return HttpResponse("ok")


def elevate_view(request):
    mark_mfa_elevated(request, factor="totp", device_id="synthetic-device")
    return HttpResponse(status=204)


def stale_elevate_view(request):
    mark_mfa_elevated(
        request,
        factor="totp",
        device_id="synthetic-device",
        at_time=timezone.now() - timedelta(seconds=120),
    )
    return HttpResponse(status=204)


def reset_view(request):
    clear_mfa_elevation(request)
    return HttpResponse(status=204)


def logout_view(request):
    logout(request)
    return HttpResponse(status=204)


urlpatterns = [
    path("protected/", protected_view),
    path("elevate/", elevate_view),
    path("stale-elevate/", stale_elevate_view),
    path("reset/", reset_view),
    path("logout/", logout_view),
]


@pytest.mark.django_db
def test_protected_view_rejects_pre_mfa_session(settings, django_user_model):
    settings.ROOT_URLCONF = __name__
    client = _logged_in_client(django_user_model)

    response = client.get("/protected/")

    assert response.status_code == 403


@pytest.mark.django_db
def test_protected_view_accepts_post_mfa_session(settings, django_user_model):
    settings.ROOT_URLCONF = __name__
    client = _logged_in_client(django_user_model)

    elevate_response = client.get("/elevate/")
    protected_response = client.get("/protected/")

    assert elevate_response.status_code == 204
    assert protected_response.status_code == 200
    assert protected_response.content == b"ok"


@pytest.mark.django_db
def test_protected_view_rejects_stale_mfa_elevation(settings, django_user_model):
    settings.ROOT_URLCONF = __name__
    client = _logged_in_client(django_user_model)

    client.get("/stale-elevate/")
    response = client.get("/protected/")

    assert response.status_code == 403


@pytest.mark.django_db
def test_explicit_reset_clears_mfa_elevation(settings, django_user_model):
    settings.ROOT_URLCONF = __name__
    client = _logged_in_client(django_user_model)

    client.get("/elevate/")
    assert client.get("/protected/").status_code == 200

    reset_response = client.get("/reset/")
    protected_response = client.get("/protected/")

    assert reset_response.status_code == 204
    assert protected_response.status_code == 403


@pytest.mark.django_db
def test_logout_cleans_up_mfa_elevation(settings, django_user_model):
    settings.ROOT_URLCONF = __name__
    client = _logged_in_client(django_user_model)

    client.get("/elevate/")
    assert client.get("/protected/").status_code == 200

    logout_response = client.get("/logout/")
    protected_response = client.get("/protected/")

    assert logout_response.status_code == 204
    assert protected_response.status_code == 403


def _logged_in_client(django_user_model):
    user = django_user_model.objects.create_user(username="session-user")
    client = Client()
    client.force_login(user)
    return client
