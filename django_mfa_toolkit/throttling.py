from __future__ import annotations

import hashlib
from dataclasses import dataclass

from django.core.cache import caches


DEFAULT_MFA_THROTTLE_LIMIT = 5
DEFAULT_MFA_THROTTLE_PERIOD = 300
DEFAULT_MFA_THROTTLE_CACHE_ALIAS = "default"


class MFAThrottleConfigurationError(Exception):
    """Raised when MFA throttle settings are invalid."""


@dataclass(frozen=True)
class MFAThrottleConfig:
    scope: str
    limit: int = DEFAULT_MFA_THROTTLE_LIMIT
    period: int = DEFAULT_MFA_THROTTLE_PERIOD
    cache_alias: str = DEFAULT_MFA_THROTTLE_CACHE_ALIAS


@dataclass(frozen=True)
class MFAThrottleState:
    allowed: bool
    attempts: int
    limit: int


def check_mfa_throttle(config: MFAThrottleConfig) -> MFAThrottleState:
    key = _cache_key(config)
    attempts = int(caches[config.cache_alias].get(key, 0))

    return MFAThrottleState(
        allowed=attempts < config.limit,
        attempts=attempts,
        limit=config.limit,
    )


def record_mfa_throttle_failure(config: MFAThrottleConfig) -> MFAThrottleState:
    key = _cache_key(config)
    cache = caches[config.cache_alias]
    cache.add(key, 0, timeout=config.period)

    try:
        attempts = cache.incr(key)
    except ValueError:
        cache.set(key, 1, timeout=config.period)
        attempts = 1

    return MFAThrottleState(
        allowed=attempts < config.limit,
        attempts=attempts,
        limit=config.limit,
    )


def reset_mfa_throttle(config: MFAThrottleConfig) -> None:
    caches[config.cache_alias].delete(_cache_key(config))


def _cache_key(config: MFAThrottleConfig) -> str:
    if not isinstance(config.scope, str) or not config.scope.strip():
        raise MFAThrottleConfigurationError("MFA throttle scope must be a non-empty string.")
    if config.limit <= 0:
        raise MFAThrottleConfigurationError("MFA throttle limit must be positive.")
    if config.period <= 0:
        raise MFAThrottleConfigurationError("MFA throttle period must be positive.")

    scope_digest = hashlib.sha256(config.scope.encode("utf-8")).hexdigest()
    return f"django_mfa_toolkit:mfa-throttle:{scope_digest}"
