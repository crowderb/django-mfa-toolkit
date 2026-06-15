from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any

from django.conf import settings
from django.http import HttpResponseForbidden
from django.utils import timezone


MFA_SESSION_KEY = "django_mfa_toolkit.mfa_elevation"
DEFAULT_MFA_SESSION_AGE = 900


def mark_mfa_elevated(
    request,
    *,
    factor: str,
    device_id: str | int | None = None,
    at_time=None,
) -> None:
    elevated_at = at_time or timezone.now()
    request.session[MFA_SESSION_KEY] = {
        "elevated_at": elevated_at.isoformat(),
        "factor": factor,
        "device_id": str(device_id) if device_id is not None else None,
    }
    request.session.modified = True


def is_mfa_elevated(request, *, max_age: int | None = None, now=None) -> bool:
    state = request.session.get(MFA_SESSION_KEY)
    if not isinstance(state, dict):
        return False

    elevated_at = _parse_elevated_at(state.get("elevated_at"))
    if elevated_at is None:
        clear_mfa_elevation(request)
        return False

    age_limit = _mfa_session_age(max_age)
    current_time = now or timezone.now()
    if elevated_at > current_time:
        clear_mfa_elevation(request)
        return False
    if (current_time - elevated_at).total_seconds() > age_limit:
        clear_mfa_elevation(request)
        return False

    return True


def clear_mfa_elevation(request) -> None:
    if MFA_SESSION_KEY in request.session:
        del request.session[MFA_SESSION_KEY]
        request.session.modified = True


def mfa_required(view_func: Callable[..., Any] | None = None, *, max_age: int | None = None):
    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            if not is_mfa_elevated(request, max_age=max_age):
                return HttpResponseForbidden("MFA elevation required.")
            return func(request, *args, **kwargs)

        return wrapper

    if view_func is None:
        return decorator
    return decorator(view_func)


def _mfa_session_age(max_age: int | None) -> int:
    age = max_age
    if age is None:
        age = getattr(settings, "DJANGO_MFA_TOOLKIT_MFA_SESSION_AGE", DEFAULT_MFA_SESSION_AGE)
    if age <= 0:
        raise ValueError("MFA session age must be positive.")
    return age


def _parse_elevated_at(value) -> Any | None:
    if not isinstance(value, str):
        return None
    try:
        elevated_at = timezone.datetime.fromisoformat(value)
    except ValueError:
        return None
    if timezone.is_naive(elevated_at):
        return timezone.make_aware(elevated_at, timezone.get_current_timezone())
    return elevated_at
