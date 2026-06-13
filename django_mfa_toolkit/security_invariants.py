"""Local security invariant representation for the MVP MFA services."""

from __future__ import annotations

from dataclasses import dataclass
from inspect import signature

from django_mfa_toolkit import hotp, totp


FORBIDDEN_TARGET_PARAMETER_NAMES = frozenset(
    {
        "url",
        "uri",
        "host",
        "hostname",
        "target",
        "target_url",
        "endpoint",
        "credential",
        "credentials",
        "payload",
    }
)


@dataclass(frozen=True)
class ControlRequirement:
    id: str
    factor: str
    description: str
    implemented_by: tuple[str, ...]
    verification: str


@dataclass(frozen=True)
class SecurityInvariantCheck:
    id: str
    passed: bool
    detail: str


MVP_CONTROL_REQUIREMENTS = (
    ControlRequirement(
        id="secret-storage.encrypted-at-rest",
        factor="totp,hotp",
        description="MFA seeds cross persistence boundaries only as encrypted values.",
        implemented_by=("django_mfa_toolkit.secret_storage.encrypt_secret",),
        verification="tests/test_secret_storage.py::test_encrypt_secret_returns_persistable_value_without_plaintext",
    ),
    ControlRequirement(
        id="comparison.constant-time",
        factor="totp,hotp",
        description="Submitted OTPs are compared through pyotp's constant-time helper.",
        implemented_by=(
            "django_mfa_toolkit.totp._find_matching_timecode",
            "django_mfa_toolkit.hotp._find_matching_counter",
            "django_mfa_toolkit.hotp._find_matching_sequence",
        ),
        verification=(
            "tests/test_totp.py::test_verify_totp_uses_constant_time_pyotp_comparison; "
            "tests/test_hotp.py::test_verify_hotp_uses_constant_time_pyotp_comparison"
        ),
    ),
    ControlRequirement(
        id="totp.replay-prevention",
        factor="totp",
        description="TOTP verification rejects an already accepted timecode when supplied by the integration.",
        implemented_by=("django_mfa_toolkit.totp.verify_totp(last_accepted_timecode=...)",),
        verification="tests/test_totp.py::test_verify_totp_rejects_replayed_timecode",
    ),
    ControlRequirement(
        id="hotp.counter-advance",
        factor="hotp",
        description="HOTP counters advance only after successful verification.",
        implemented_by=("django_mfa_toolkit.hotp.verify_hotp",),
        verification=(
            "tests/test_hotp.py::test_verify_hotp_accepts_current_counter_and_advances_once; "
            "tests/test_hotp.py::test_verify_hotp_rejects_failed_code_without_advancing_and_records_audit"
        ),
    ),
    ControlRequirement(
        id="hotp.replay-prevention",
        factor="hotp",
        description="Previously accepted HOTP counters are rejected as replay inside a bounded replay window.",
        implemented_by=("django_mfa_toolkit.hotp.verify_hotp(replay_window=...)",),
        verification="tests/test_hotp.py::test_verify_hotp_rejects_previously_accepted_code_as_replay",
    ),
    ControlRequirement(
        id="hotp.audit",
        factor="hotp",
        description="HOTP verification and resynchronization return structured audit records for every attempt.",
        implemented_by=(
            "django_mfa_toolkit.hotp.HOTPAuditRecord",
            "django_mfa_toolkit.hotp.HOTPResyncAuditRecord",
        ),
        verification=(
            "tests/test_hotp.py::test_verify_hotp_rejects_failed_code_without_advancing_and_records_audit; "
            "tests/test_hotp.py::test_resync_hotp_accepts_multiple_consecutive_codes_and_advances_counter"
        ),
    ),
    ControlRequirement(
        id="hotp.resync-bounded",
        factor="hotp",
        description="HOTP resynchronization requires consecutive submissions and bounded search windows.",
        implemented_by=("django_mfa_toolkit.hotp.resync_hotp",),
        verification=(
            "tests/test_hotp.py::test_resync_hotp_accepts_multiple_consecutive_codes_and_advances_counter; "
            "tests/test_hotp.py::test_resync_hotp_rejects_excessive_drift_without_unbounded_search"
        ),
    ),
)


def get_mvp_control_requirements() -> tuple[ControlRequirement, ...]:
    """Return the static control-dependency representation for the MVP."""

    return MVP_CONTROL_REQUIREMENTS


def run_local_security_invariant_checks() -> tuple[SecurityInvariantCheck, ...]:
    """Run non-targetable local checks over the MVP verification surface."""

    return (
        _surface_has_no_target_parameters(),
        _control_requirements_are_represented(),
    )


def _surface_has_no_target_parameters() -> SecurityInvariantCheck:
    surfaces = (
        totp.enroll_totp,
        totp.verify_totp,
        hotp.enroll_hotp,
        hotp.verify_hotp,
        hotp.resync_hotp,
        run_local_security_invariant_checks,
    )
    discovered = sorted(
        {
            parameter.name
            for surface in surfaces
            for parameter in signature(surface).parameters.values()
            if parameter.name.lower() in FORBIDDEN_TARGET_PARAMETER_NAMES
        }
    )

    if discovered:
        return SecurityInvariantCheck(
            id="verification-surface.not-targetable",
            passed=False,
            detail=f"Forbidden target-like parameters found: {', '.join(discovered)}.",
        )
    return SecurityInvariantCheck(
        id="verification-surface.not-targetable",
        passed=True,
        detail="MVP verification helpers expose no URL, host, credential, target, or payload inputs.",
    )


def _control_requirements_are_represented() -> SecurityInvariantCheck:
    required_ids = {
        "secret-storage.encrypted-at-rest",
        "comparison.constant-time",
        "totp.replay-prevention",
        "hotp.counter-advance",
        "hotp.replay-prevention",
        "hotp.audit",
        "hotp.resync-bounded",
    }
    represented_ids = {requirement.id for requirement in MVP_CONTROL_REQUIREMENTS}
    missing = sorted(required_ids - represented_ids)

    if missing:
        return SecurityInvariantCheck(
            id="control-requirements.represented",
            passed=False,
            detail=f"Missing control requirements: {', '.join(missing)}.",
        )
    return SecurityInvariantCheck(
        id="control-requirements.represented",
        passed=True,
        detail="TOTP and HOTP MVP safeguards are represented as local control requirements.",
    )
