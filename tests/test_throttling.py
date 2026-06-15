from django.core.cache import caches

from django_mfa_toolkit.throttling import (
    MFAThrottleConfig,
    check_mfa_throttle,
    record_mfa_throttle_failure,
    reset_mfa_throttle,
)


def test_mfa_throttle_allows_records_blocks_and_resets(settings):
    config = MFAThrottleConfig(scope="user:1:device:2", limit=2, period=60)
    reset_mfa_throttle(config)

    assert check_mfa_throttle(config).allowed is True

    first = record_mfa_throttle_failure(config)
    second = record_mfa_throttle_failure(config)

    assert first.allowed is True
    assert second.allowed is False
    assert check_mfa_throttle(config).allowed is False

    reset_mfa_throttle(config)

    assert check_mfa_throttle(config).allowed is True


def test_mfa_throttle_cache_key_and_value_do_not_store_raw_scope_or_otp(settings):
    submitted_code = "123456"
    config = MFAThrottleConfig(scope=f"user:1:device:2:otp:{submitted_code}", limit=2, period=60)
    cache = caches[config.cache_alias]
    reset_mfa_throttle(config)

    record_mfa_throttle_failure(config)

    cache_keys = " ".join(str(key) for key in getattr(cache, "_cache", {}).keys())
    cache_values = " ".join(str(value) for value in getattr(cache, "_cache", {}).values())

    assert submitted_code not in cache_keys
    assert submitted_code not in cache_values
    assert config.scope not in cache_keys
    assert config.scope not in cache_values
