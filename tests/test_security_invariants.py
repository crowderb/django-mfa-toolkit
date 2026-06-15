from datetime import datetime, timezone
from inspect import signature

import pyotp

from django_mfa_toolkit.hotp import enroll_hotp, resync_hotp, verify_hotp
from django_mfa_toolkit.recovery_codes import (
    create_recovery_code_batch,
    normalize_recovery_code,
    reset_recovery_code_batch,
    verify_recovery_code,
)
from django_mfa_toolkit.secret_storage import decrypt_secret_text
from django_mfa_toolkit.security_invariants import (
    FORBIDDEN_TARGET_PARAMETER_NAMES,
    get_control_relationships,
    get_mfa_control_graph,
    get_mvp_control_requirements,
    run_local_security_invariant_checks,
)
from django_mfa_toolkit.totp import enroll_totp, verify_totp


def test_local_security_checks_are_non_targetable():
    assert signature(run_local_security_invariant_checks).parameters == {}

    results = run_local_security_invariant_checks()

    assert results
    assert all(result.passed for result in results)


def test_mvp_control_requirements_cover_required_totp_and_hotp_safeguards():
    requirement_ids = {requirement.id for requirement in get_mvp_control_requirements()}

    assert {
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
    }.issubset(requirement_ids)


def test_mfa_control_graph_represents_existing_requirements():
    graph = get_mfa_control_graph()
    node_ids = {node.id for node in graph.nodes}
    requirement_ids = {requirement.id for requirement in get_mvp_control_requirements()}

    assert requirement_ids.issubset(node_ids)
    assert graph.relationships
    assert all(relationship.source in node_ids for relationship in graph.relationships)
    assert all(relationship.target in node_ids for relationship in graph.relationships)


def test_mfa_control_graph_represents_compensating_lockout_controls():
    totp_relationships = get_control_relationships("totp.verification")
    hotp_relationships = get_control_relationships("hotp.verification")

    assert {
        ("django-throttling.lockout", "satisfied-by-any"),
        ("compensating-control.documented-lockout", "satisfied-by-any"),
    }.issubset({(relationship.target, relationship.kind) for relationship in totp_relationships})
    assert {
        ("django-throttling.lockout", "satisfied-by-any"),
        ("compensating-control.documented-lockout", "satisfied-by-any"),
    }.issubset({(relationship.target, relationship.kind) for relationship in hotp_relationships})


def test_mfa_control_graph_links_audit_persistence_to_audit_records_and_model():
    relationships = get_control_relationships("hotp.audit-persistence")

    assert {
        ("hotp.audit", "requires"),
        ("implementation.audit-model", "implemented-by"),
    }.issubset({(relationship.target, relationship.kind) for relationship in relationships})


def test_mfa_control_graph_represents_recovery_code_controls():
    relationships = get_control_relationships("recovery-code.verification")

    assert {
        ("recovery-code.hashed-at-rest", "requires"),
        ("recovery-code.constant-time", "requires"),
        ("recovery-code.one-time-use", "requires"),
        ("recovery-code.replay-prevention", "requires"),
        ("recovery-code.audit", "requires"),
        ("recovery-code.session-elevation", "requires"),
        ("recovery-code.throttling", "satisfied-by-any"),
        ("compensating-control.documented-lockout", "satisfied-by-any"),
        ("verification.local-tests", "verified-by"),
    }.issubset({(relationship.target, relationship.kind) for relationship in relationships})


def test_public_verification_surface_has_no_targetable_inputs():
    surfaces = (
        enroll_totp,
        verify_totp,
        enroll_hotp,
        verify_hotp,
        resync_hotp,
        create_recovery_code_batch,
        reset_recovery_code_batch,
        verify_recovery_code,
        normalize_recovery_code,
        run_local_security_invariant_checks,
    )

    for surface in surfaces:
        parameter_names = {name.lower() for name in signature(surface).parameters}

        assert parameter_names.isdisjoint(FORBIDDEN_TARGET_PARAMETER_NAMES)


def test_fixture_bound_totp_replay_invariant(synthetic_mfa_settings_override):
    at_time = datetime(2026, 6, 13, 16, 0, tzinfo=timezone.utc)
    enrollment = enroll_totp(account_name="synthetic@example.test", issuer_name="Toolkit")
    material = decrypt_secret_text(enrollment.persisted_secret)
    totp = pyotp.TOTP(material)
    submitted_code = totp.at(at_time)
    accepted_timecode = totp.timecode(at_time)

    accepted = verify_totp(
        encrypted_secret=enrollment.persisted_secret,
        submitted_code=submitted_code,
        at_time=at_time,
        valid_window=0,
    )
    replayed = verify_totp(
        encrypted_secret=enrollment.persisted_secret,
        submitted_code=submitted_code,
        at_time=at_time,
        valid_window=0,
        last_accepted_timecode=accepted_timecode,
    )

    assert accepted.accepted is True
    assert replayed.accepted is False
    assert replayed.failure_reason == "replay"


def test_fixture_bound_hotp_replay_and_audit_invariants(synthetic_mfa_settings_override):
    enrollment = enroll_hotp(account_name="synthetic@example.test", issuer_name="Toolkit")
    material = decrypt_secret_text(enrollment.persisted_secret)
    submitted_code = pyotp.HOTP(material).at(0)

    accepted = verify_hotp(
        encrypted_secret=enrollment.persisted_secret,
        submitted_code=submitted_code,
        server_counter=0,
        look_ahead=0,
    )
    replayed = verify_hotp(
        encrypted_secret=enrollment.persisted_secret,
        submitted_code=submitted_code,
        server_counter=accepted.next_counter,
        look_ahead=0,
        replay_window=1,
    )

    assert accepted.accepted is True
    assert accepted.audit_record.result_classification == "success"
    assert replayed.accepted is False
    assert replayed.audit_record.result_classification == "replay"
    assert replayed.audit_record.submitted_outcome == "rejected"
    assert replayed.next_counter == accepted.next_counter


def test_fixture_bound_hotp_resync_invariant(synthetic_mfa_settings_override):
    enrollment = enroll_hotp(account_name="synthetic@example.test", issuer_name="Toolkit")
    material = decrypt_secret_text(enrollment.persisted_secret)
    hotp = pyotp.HOTP(material)
    submitted_codes = [hotp.at(12), hotp.at(13)]

    result = resync_hotp(
        encrypted_secret=enrollment.persisted_secret,
        submitted_codes=submitted_codes,
        server_counter=5,
        search_window=20,
    )

    assert result.accepted is True
    assert result.matched_counter == 12
    assert result.next_counter == 14
    assert result.audit_record.result_classification == "resync_success"
