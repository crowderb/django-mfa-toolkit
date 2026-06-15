"""Local security invariant representation for the MVP MFA services."""

from __future__ import annotations

from dataclasses import dataclass
from inspect import signature
from typing import Literal

from django_mfa_toolkit import device_adapters, hotp, integration_checks, recovery_codes, session_elevation, totp


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


ControlNodeKind = Literal["control", "implementation", "verification", "compensating-control"]
ControlRelationshipKind = Literal["requires", "implemented-by", "verified-by", "satisfied-by-any"]


@dataclass(frozen=True)
class ControlGraphNode:
    id: str
    kind: ControlNodeKind
    label: str
    description: str


@dataclass(frozen=True)
class ControlGraphRelationship:
    source: str
    target: str
    kind: ControlRelationshipKind
    description: str


@dataclass(frozen=True)
class ControlGraph:
    nodes: tuple[ControlGraphNode, ...]
    relationships: tuple[ControlGraphRelationship, ...]


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
    ControlRequirement(
        id="django-persistence.stateful-verification",
        factor="totp,hotp",
        description="Model-backed device verification locks persisted state and advances only accepted MFA state.",
        implemented_by=(
            "django_mfa_toolkit.device_adapters.verify_totp_device",
            "django_mfa_toolkit.device_adapters.verify_hotp_device",
            "django_mfa_toolkit.device_adapters.resync_hotp_device",
        ),
        verification=(
            "tests/test_device_adapters.py; "
            "tests/test_django_integration_checks.py::test_local_totp_client_flow_enforces_mfa_replay_and_session_boundary; "
            "tests/test_django_integration_checks.py::test_local_hotp_persisted_device_rejects_replay_without_counter_advance"
        ),
    ),
    ControlRequirement(
        id="django-throttling.lockout",
        factor="totp,hotp",
        description="Django device adapters enforce local throttle checks before OTP verification.",
        implemented_by=(
            "django_mfa_toolkit.throttling",
            "django_mfa_toolkit.device_adapters.verify_totp_device(throttle_scope=...)",
            "django_mfa_toolkit.device_adapters.verify_hotp_device(throttle_scope=...)",
        ),
        verification=(
            "tests/test_throttling.py; "
            "tests/test_django_integration_checks.py::test_local_totp_client_flow_enforces_throttle_before_session_elevation"
        ),
    ),
    ControlRequirement(
        id="django-session-elevation.boundary",
        factor="totp,hotp",
        description="Post-MFA session elevation is a separate timestamped Django session boundary.",
        implemented_by=(
            "django_mfa_toolkit.session_elevation.mark_mfa_elevated",
            "django_mfa_toolkit.session_elevation.is_mfa_elevated",
            "django_mfa_toolkit.session_elevation.mfa_required",
        ),
        verification=(
            "tests/test_session_elevation.py; "
            "tests/test_django_integration_checks.py::test_local_totp_client_flow_enforces_mfa_replay_and_session_boundary"
        ),
    ),
    ControlRequirement(
        id="recovery-code.hashed-at-rest",
        factor="recovery-code",
        description="Recovery codes are persisted only as Django password hashes.",
        implemented_by=("django_mfa_toolkit.recovery_codes.create_recovery_code_batch",),
        verification="tests/test_recovery_codes.py::test_create_recovery_code_batch_returns_plaintext_once_and_persists_only_hashes",
    ),
    ControlRequirement(
        id="recovery-code.constant-time",
        factor="recovery-code",
        description="Recovery-code submissions are checked through Django's password hash verifier.",
        implemented_by=("django_mfa_toolkit.recovery_codes.verify_recovery_code",),
        verification="tests/test_recovery_codes.py::test_verify_recovery_code_accepts_once_and_rejects_replay",
    ),
    ControlRequirement(
        id="recovery-code.one-time-use",
        factor="recovery-code",
        description="Accepted recovery codes are marked used exactly once.",
        implemented_by=("django_mfa_toolkit.recovery_codes.verify_recovery_code",),
        verification="tests/test_recovery_codes.py::test_verify_recovery_code_accepts_once_and_rejects_replay",
    ),
    ControlRequirement(
        id="recovery-code.replay-prevention",
        factor="recovery-code",
        description="Used and replaced recovery codes are rejected as replay.",
        implemented_by=("django_mfa_toolkit.recovery_codes.verify_recovery_code",),
        verification=(
            "tests/test_recovery_codes.py::test_verify_recovery_code_accepts_once_and_rejects_replay; "
            "tests/test_recovery_codes.py::test_verify_recovery_code_rejects_replaced_code_without_consuming_active_code"
        ),
    ),
    ControlRequirement(
        id="recovery-code.throttling",
        factor="recovery-code",
        description="Recovery-code verification can enforce local throttling before hash comparison.",
        implemented_by=("django_mfa_toolkit.recovery_codes.verify_recovery_code(throttle_scope=...)",),
        verification="tests/test_recovery_codes.py::test_verify_recovery_code_throttles_before_code_comparison_without_consuming_code",
    ),
    ControlRequirement(
        id="recovery-code.audit",
        factor="recovery-code",
        description="Recovery-code verification and reset outcomes can be audited without submitted code material.",
        implemented_by=(
            "django_mfa_toolkit.recovery_codes.RecoveryCodeAuditRecord",
            "django_mfa_toolkit.models.MFAAuditEvent",
        ),
        verification=(
            "tests/test_recovery_codes.py::test_verify_recovery_code_accepts_once_and_rejects_replay; "
            "tests/test_recovery_codes.py::test_reset_recovery_code_batch_can_persist_reset_audit_without_code_material"
        ),
    ),
    ControlRequirement(
        id="recovery-code.session-elevation",
        factor="recovery-code",
        description="Accepted recovery-code verification marks a distinct post-MFA session factor.",
        implemented_by=("django_mfa_toolkit.session_elevation.mark_mfa_elevated(factor='recovery-code')",),
        verification="tests/test_integration_checks.py::test_recovery_code_in_process_client_flow_enforces_session_boundary",
    ),
)


MFA_CONTROL_GRAPH = ControlGraph(
    nodes=(
        ControlGraphNode(
            id="mfa.seed-confidentiality",
            kind="control",
            label="MFA seed confidentiality",
            description="MFA seeds must not cross persistence boundaries as plaintext or loggable values.",
        ),
        ControlGraphNode(
            id="secret-storage.encrypted-at-rest",
            kind="control",
            label="Encrypted secret storage",
            description="Persisted MFA seed material is encrypted and versioned through the secret-storage boundary.",
        ),
        ControlGraphNode(
            id="comparison.constant-time",
            kind="control",
            label="Constant-time comparison",
            description="OTP and secret-derived comparisons use vetted constant-time helpers.",
        ),
        ControlGraphNode(
            id="totp.verification",
            kind="control",
            label="TOTP verification",
            description="TOTP verification accepts only valid codes and rejects replayed timecodes.",
        ),
        ControlGraphNode(
            id="totp.replay-prevention",
            kind="control",
            label="TOTP replay prevention",
            description="Accepted TOTP timecodes are tracked and cannot be accepted again.",
        ),
        ControlGraphNode(
            id="hotp.verification",
            kind="control",
            label="HOTP verification",
            description="HOTP verification advances counters only after accepted codes.",
        ),
        ControlGraphNode(
            id="hotp.counter-advance",
            kind="control",
            label="HOTP counter advance",
            description="HOTP counters advance only after successful verification or resynchronization.",
        ),
        ControlGraphNode(
            id="hotp.replay-prevention",
            kind="control",
            label="HOTP replay prevention",
            description="Spent HOTP counters are rejected inside bounded replay windows.",
        ),
        ControlGraphNode(
            id="hotp.audit",
            kind="control",
            label="HOTP audit records",
            description="HOTP verification and resynchronization outcomes produce structured audit records.",
        ),
        ControlGraphNode(
            id="hotp.audit-persistence",
            kind="control",
            label="HOTP audit persistence",
            description="HOTP audit outcomes may be persisted locally without OTP or secret material.",
        ),
        ControlGraphNode(
            id="hotp.resync-bounded",
            kind="control",
            label="Bounded HOTP resynchronization",
            description="HOTP resynchronization uses consecutive submissions and bounded search windows.",
        ),
        ControlGraphNode(
            id="django-persistence.stateful-verification",
            kind="control",
            label="Stateful Django verification",
            description="Model-backed verification locks device rows and persists only accepted state transitions.",
        ),
        ControlGraphNode(
            id="django-throttling.lockout",
            kind="control",
            label="Django throttling and lockout",
            description="Django adapters enforce local throttle checks before OTP verification when configured.",
        ),
        ControlGraphNode(
            id="compensating-control.documented-lockout",
            kind="compensating-control",
            label="Documented external lockout",
            description="An integration may satisfy repeated-attempt control through a documented local lockout boundary.",
        ),
        ControlGraphNode(
            id="django-session-elevation.boundary",
            kind="control",
            label="Django session elevation boundary",
            description="Post-MFA state is a timestamped session boundary separate from password authentication.",
        ),
        ControlGraphNode(
            id="recovery-code.verification",
            kind="control",
            label="Recovery-code verification",
            description="Recovery-code verification accepts only active unused codes and rejects spent or replaced codes.",
        ),
        ControlGraphNode(
            id="recovery-code.hashed-at-rest",
            kind="control",
            label="Recovery-code hashed storage",
            description="Recovery codes are persisted only as password hashes, never as displayable plaintext.",
        ),
        ControlGraphNode(
            id="recovery-code.constant-time",
            kind="control",
            label="Recovery-code constant-time verification",
            description="Recovery-code submissions are checked through Django's password hash verifier.",
        ),
        ControlGraphNode(
            id="recovery-code.one-time-use",
            kind="control",
            label="Recovery-code one-time use",
            description="Accepted recovery codes are consumed exactly once.",
        ),
        ControlGraphNode(
            id="recovery-code.replay-prevention",
            kind="control",
            label="Recovery-code replay prevention",
            description="Used or replaced recovery codes cannot be accepted again.",
        ),
        ControlGraphNode(
            id="recovery-code.throttling",
            kind="control",
            label="Recovery-code throttling",
            description="Recovery-code verification can enforce local throttling before hash comparison.",
        ),
        ControlGraphNode(
            id="recovery-code.audit",
            kind="control",
            label="Recovery-code audit records",
            description="Recovery-code verification and reset outcomes can be audited without submitted code material.",
        ),
        ControlGraphNode(
            id="recovery-code.session-elevation",
            kind="control",
            label="Recovery-code session elevation",
            description="Accepted recovery-code verification marks a distinct post-MFA session factor.",
        ),
        ControlGraphNode(
            id="verification-surface.not-targetable",
            kind="control",
            label="Non-targetable verification surface",
            description="Local verification helpers expose no URL, host, credential, target, or payload inputs.",
        ),
        ControlGraphNode(
            id="implementation.secret-storage",
            kind="implementation",
            label="Secret storage module",
            description="django_mfa_toolkit.secret_storage",
        ),
        ControlGraphNode(
            id="implementation.device-adapters",
            kind="implementation",
            label="Django device adapters",
            description="django_mfa_toolkit.device_adapters",
        ),
        ControlGraphNode(
            id="implementation.audit-model",
            kind="implementation",
            label="MFA audit event model",
            description="django_mfa_toolkit.models.MFAAuditEvent",
        ),
        ControlGraphNode(
            id="implementation.session-elevation",
            kind="implementation",
            label="Session elevation helpers",
            description="django_mfa_toolkit.session_elevation",
        ),
        ControlGraphNode(
            id="implementation.recovery-codes",
            kind="implementation",
            label="Recovery-code helpers",
            description="django_mfa_toolkit.recovery_codes",
        ),
        ControlGraphNode(
            id="verification.local-tests",
            kind="verification",
            label="Local pytest verification",
            description="Fixture-bound pytest tests and Django test-client checks.",
        ),
    ),
    relationships=(
        ControlGraphRelationship(
            source="mfa.seed-confidentiality",
            target="secret-storage.encrypted-at-rest",
            kind="requires",
            description="Seed confidentiality requires encrypted storage at rest.",
        ),
        ControlGraphRelationship(
            source="secret-storage.encrypted-at-rest",
            target="implementation.secret-storage",
            kind="implemented-by",
            description="Encrypted storage is implemented by the secret-storage module.",
        ),
        ControlGraphRelationship(
            source="totp.verification",
            target="secret-storage.encrypted-at-rest",
            kind="requires",
            description="TOTP verification requires stored seeds to remain encrypted outside process memory.",
        ),
        ControlGraphRelationship(
            source="totp.verification",
            target="comparison.constant-time",
            kind="requires",
            description="TOTP verification requires constant-time OTP comparison.",
        ),
        ControlGraphRelationship(
            source="totp.verification",
            target="totp.replay-prevention",
            kind="requires",
            description="TOTP verification requires replay prevention through accepted timecode tracking.",
        ),
        ControlGraphRelationship(
            source="totp.verification",
            target="django-throttling.lockout",
            kind="satisfied-by-any",
            description="Repeated TOTP attempts require adapter throttling or a documented local lockout control.",
        ),
        ControlGraphRelationship(
            source="totp.verification",
            target="compensating-control.documented-lockout",
            kind="satisfied-by-any",
            description="Repeated TOTP attempts may be controlled by a documented local lockout boundary.",
        ),
        ControlGraphRelationship(
            source="hotp.verification",
            target="secret-storage.encrypted-at-rest",
            kind="requires",
            description="HOTP verification requires stored seeds to remain encrypted outside process memory.",
        ),
        ControlGraphRelationship(
            source="hotp.verification",
            target="comparison.constant-time",
            kind="requires",
            description="HOTP verification requires constant-time OTP comparison.",
        ),
        ControlGraphRelationship(
            source="hotp.verification",
            target="hotp.counter-advance",
            kind="requires",
            description="HOTP verification requires safe counter advancement.",
        ),
        ControlGraphRelationship(
            source="hotp.verification",
            target="hotp.replay-prevention",
            kind="requires",
            description="HOTP verification requires replay rejection for spent counters.",
        ),
        ControlGraphRelationship(
            source="hotp.verification",
            target="hotp.audit",
            kind="requires",
            description="HOTP verification requires audit records for security-relevant outcomes.",
        ),
        ControlGraphRelationship(
            source="hotp.verification",
            target="django-throttling.lockout",
            kind="satisfied-by-any",
            description="Repeated HOTP attempts require adapter throttling or a documented local lockout control.",
        ),
        ControlGraphRelationship(
            source="hotp.verification",
            target="compensating-control.documented-lockout",
            kind="satisfied-by-any",
            description="Repeated HOTP attempts may be controlled by a documented local lockout boundary.",
        ),
        ControlGraphRelationship(
            source="hotp.resync-bounded",
            target="hotp.audit",
            kind="requires",
            description="HOTP resynchronization requires auditable outcomes.",
        ),
        ControlGraphRelationship(
            source="hotp.audit-persistence",
            target="hotp.audit",
            kind="requires",
            description="Persisted HOTP audit events are derived from structured HOTP audit records.",
        ),
        ControlGraphRelationship(
            source="hotp.audit-persistence",
            target="implementation.audit-model",
            kind="implemented-by",
            description="Audit persistence is implemented by MFAAuditEvent and audit helper functions.",
        ),
        ControlGraphRelationship(
            source="django-persistence.stateful-verification",
            target="implementation.device-adapters",
            kind="implemented-by",
            description="Stateful verification is implemented by the Django device adapters.",
        ),
        ControlGraphRelationship(
            source="django-session-elevation.boundary",
            target="implementation.session-elevation",
            kind="implemented-by",
            description="Session elevation is implemented by the session-elevation helpers.",
        ),
        ControlGraphRelationship(
            source="recovery-code.verification",
            target="recovery-code.hashed-at-rest",
            kind="requires",
            description="Recovery-code verification requires persisted codes to be stored as hashes.",
        ),
        ControlGraphRelationship(
            source="recovery-code.verification",
            target="recovery-code.constant-time",
            kind="requires",
            description="Recovery-code verification requires password-hash verification for submitted values.",
        ),
        ControlGraphRelationship(
            source="recovery-code.verification",
            target="recovery-code.one-time-use",
            kind="requires",
            description="Recovery-code verification requires accepted codes to be consumed once.",
        ),
        ControlGraphRelationship(
            source="recovery-code.verification",
            target="recovery-code.replay-prevention",
            kind="requires",
            description="Recovery-code verification requires used and replaced codes to be rejected as replay.",
        ),
        ControlGraphRelationship(
            source="recovery-code.verification",
            target="recovery-code.audit",
            kind="requires",
            description="Recovery-code verification requires auditable verification outcomes.",
        ),
        ControlGraphRelationship(
            source="recovery-code.verification",
            target="recovery-code.session-elevation",
            kind="requires",
            description="Recovery-code verification can satisfy MFA only through a distinct session-elevation factor.",
        ),
        ControlGraphRelationship(
            source="recovery-code.verification",
            target="recovery-code.throttling",
            kind="satisfied-by-any",
            description="Repeated recovery-code attempts require package throttling or a documented local lockout control.",
        ),
        ControlGraphRelationship(
            source="recovery-code.verification",
            target="compensating-control.documented-lockout",
            kind="satisfied-by-any",
            description="Repeated recovery-code attempts may be controlled by a documented local lockout boundary.",
        ),
        ControlGraphRelationship(
            source="recovery-code.hashed-at-rest",
            target="implementation.recovery-codes",
            kind="implemented-by",
            description="Recovery-code hashing and batch storage are implemented by the recovery-code helpers.",
        ),
        ControlGraphRelationship(
            source="recovery-code.constant-time",
            target="implementation.recovery-codes",
            kind="implemented-by",
            description="Recovery-code verification is implemented by the recovery-code helpers.",
        ),
        ControlGraphRelationship(
            source="recovery-code.one-time-use",
            target="implementation.recovery-codes",
            kind="implemented-by",
            description="Recovery-code consumption is implemented by the recovery-code helpers.",
        ),
        ControlGraphRelationship(
            source="recovery-code.replay-prevention",
            target="implementation.recovery-codes",
            kind="implemented-by",
            description="Recovery-code replay rejection is implemented by the recovery-code helpers.",
        ),
        ControlGraphRelationship(
            source="recovery-code.throttling",
            target="implementation.recovery-codes",
            kind="implemented-by",
            description="Recovery-code throttling is integrated by the recovery-code helpers.",
        ),
        ControlGraphRelationship(
            source="recovery-code.audit",
            target="implementation.audit-model",
            kind="implemented-by",
            description="Recovery-code audit persistence is implemented by MFAAuditEvent.",
        ),
        ControlGraphRelationship(
            source="recovery-code.session-elevation",
            target="implementation.session-elevation",
            kind="implemented-by",
            description="Recovery-code session elevation uses the existing session-elevation helpers.",
        ),
        ControlGraphRelationship(
            source="verification-surface.not-targetable",
            target="verification.local-tests",
            kind="verified-by",
            description="The non-targetable local surface is verified through local tests.",
        ),
        ControlGraphRelationship(
            source="hotp.verification",
            target="verification.local-tests",
            kind="verified-by",
            description="HOTP verification controls are verified by fixture-bound tests.",
        ),
        ControlGraphRelationship(
            source="totp.verification",
            target="verification.local-tests",
            kind="verified-by",
            description="TOTP verification controls are verified by fixture-bound tests.",
        ),
        ControlGraphRelationship(
            source="recovery-code.verification",
            target="verification.local-tests",
            kind="verified-by",
            description="Recovery-code controls are verified by fixture-bound tests.",
        ),
    ),
)


def get_mvp_control_requirements() -> tuple[ControlRequirement, ...]:
    """Return the static control-dependency representation for the MVP."""

    return MVP_CONTROL_REQUIREMENTS


def get_mfa_control_graph() -> ControlGraph:
    """Return the machine-readable MFA control graph."""

    return MFA_CONTROL_GRAPH


def get_control_relationships(control_id: str) -> tuple[ControlGraphRelationship, ...]:
    """Return graph relationships originating from one control node."""

    return tuple(relationship for relationship in MFA_CONTROL_GRAPH.relationships if relationship.source == control_id)


def run_local_security_invariant_checks() -> tuple[SecurityInvariantCheck, ...]:
    """Run non-targetable local checks over the MVP verification surface."""

    return (
        _surface_has_no_target_parameters(),
        _control_requirements_are_represented(),
        _control_graph_is_consistent(),
    )


def _surface_has_no_target_parameters() -> SecurityInvariantCheck:
    surfaces = (
        totp.enroll_totp,
        totp.verify_totp,
        hotp.enroll_hotp,
        hotp.verify_hotp,
        hotp.resync_hotp,
        device_adapters.enroll_totp_device,
        device_adapters.verify_totp_device,
        device_adapters.enroll_hotp_device,
        device_adapters.verify_hotp_device,
        device_adapters.resync_hotp_device,
        session_elevation.mark_mfa_elevated,
        session_elevation.is_mfa_elevated,
        session_elevation.clear_mfa_elevation,
        session_elevation.mfa_required,
        run_local_security_invariant_checks,
        integration_checks.run_local_django_mfa_integration_checks,
        integration_checks.MFALocalIntegrationCheckMixin.assert_local_security_invariants_pass,
        integration_checks.MFALocalIntegrationCheckMixin.assert_totp_device_rejects_replay,
        integration_checks.MFALocalIntegrationCheckMixin.assert_hotp_device_rejects_replay_without_counter_advance,
        integration_checks.MFALocalIntegrationCheckMixin.assert_mfa_required_session_boundary,
        integration_checks.MFALocalIntegrationCheckMixin.assert_recovery_code_rejects_replay,
        integration_checks.MFALocalIntegrationCheckMixin.assert_recovery_code_session_boundary,
        recovery_codes.create_recovery_code_batch,
        recovery_codes.reset_recovery_code_batch,
        recovery_codes.verify_recovery_code,
        recovery_codes.normalize_recovery_code,
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
        "django-persistence.stateful-verification",
        "django-throttling.lockout",
        "django-session-elevation.boundary",
        "recovery-code.hashed-at-rest",
        "recovery-code.constant-time",
        "recovery-code.one-time-use",
        "recovery-code.replay-prevention",
        "recovery-code.throttling",
        "recovery-code.audit",
        "recovery-code.session-elevation",
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


def _control_graph_is_consistent() -> SecurityInvariantCheck:
    node_ids = {node.id for node in MFA_CONTROL_GRAPH.nodes}
    missing_references = sorted(
        {
            endpoint
            for relationship in MFA_CONTROL_GRAPH.relationships
            for endpoint in (relationship.source, relationship.target)
            if endpoint not in node_ids
        }
    )
    if missing_references:
        return SecurityInvariantCheck(
            id="control-graph.consistent",
            passed=False,
            detail=f"Control graph relationships reference missing nodes: {', '.join(missing_references)}.",
        )

    represented_ids = {requirement.id for requirement in MVP_CONTROL_REQUIREMENTS}
    missing_requirement_nodes = sorted(represented_ids - node_ids)
    if missing_requirement_nodes:
        return SecurityInvariantCheck(
            id="control-graph.consistent",
            passed=False,
            detail=f"Control graph is missing requirement nodes: {', '.join(missing_requirement_nodes)}.",
        )

    return SecurityInvariantCheck(
        id="control-graph.consistent",
        passed=True,
        detail="MFA control graph nodes and relationships are internally consistent.",
    )
