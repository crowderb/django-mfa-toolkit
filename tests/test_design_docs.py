from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]


def test_device_persistence_contracts_cover_required_security_controls():
    document = ROOT_DIR / ".docs" / "design" / "device-persistence-contracts.md"
    content = document.read_text(encoding="utf-8")

    required_terms = {
        "persisted_secret",
        "last_accepted_timecode",
        "hotp_counter",
        "select_for_update()",
        "transaction.atomic()",
        "secret-storage.encrypted-at-rest",
        "totp.replay-prevention",
        "hotp.counter-advance",
        "hotp.replay-prevention",
        "hotp.audit",
        "hotp.resync-bounded",
    }

    missing_terms = sorted(term for term in required_terms if term not in content)

    assert not missing_terms


def test_mvp_integration_guide_covers_end_to_end_django_path():
    document = ROOT_DIR / ".docs" / "design" / "mvp-integration-guide.md"
    content = document.read_text(encoding="utf-8")

    required_terms = {
        "End-to-End Django Flow",
        "enroll_totp_device",
        "enroll_hotp_device",
        "verify_totp_device",
        "verify_hotp_device",
        "resync_hotp_device",
        "mark_mfa_elevated",
        "mfa_required",
        "throttle_scope",
        "DJANGO_MFA_TOOLKIT_SECRET_ENCRYPTION_KEYS",
        "uv run pytest tests/test_device_adapters.py",
        "uv run pytest tests/test_django_integration_checks.py",
        "uv run pytest tests/test_session_elevation.py",
    }

    missing_terms = sorted(term for term in required_terms if term not in content)

    assert not missing_terms


def test_audit_persistence_contracts_cover_hotp_audit_boundary():
    document = ROOT_DIR / ".docs" / "design" / "audit-persistence-contracts.md"
    content = document.read_text(encoding="utf-8")

    required_terms = {
        "HOTPAuditRecord",
        "HOTPResyncAuditRecord",
        "event_type",
        "submitted_outcome",
        "result_classification",
        "server_counter",
        "matched_counter",
        "next_counter",
        "look_ahead",
        "search_window",
        "replay_window",
        "submitted_count",
        "attempted_at",
        "success",
        "counter_window_match",
        "invalid",
        "replay",
        "throttled",
        "resync_success",
        "excessive_drift",
        "submitted OTPs",
        "raw MFA seeds",
        "provisioning URIs",
        "persisted_secret",
        "transaction.atomic()",
        "hotp.audit",
        "hotp.counter-advance",
        "hotp.replay-prevention",
        "hotp.resync-bounded",
        "secret-storage.encrypted-at-rest",
    }

    missing_terms = sorted(term for term in required_terms if term not in content)

    assert not missing_terms


def test_control_graph_design_covers_agent_reasoning_model():
    document = ROOT_DIR / ".docs" / "design" / "control-graph.md"
    content = document.read_text(encoding="utf-8")

    required_terms = {
        "get_mfa_control_graph()",
        "ControlGraphNode",
        "ControlGraphRelationship",
        "requires",
        "implemented-by",
        "verified-by",
        "satisfied-by-any",
        "compensating-control.documented-lockout",
        "django-throttling.lockout",
        "hotp.audit-persistence",
        "verification-surface.not-targetable",
        "fixture-bound",
        "target URLs",
        "credentials",
    }

    missing_terms = sorted(term for term in required_terms if term not in content)

    assert not missing_terms


def test_recovery_code_support_design_covers_required_security_controls():
    document = ROOT_DIR / ".docs" / "design" / "recovery-code-support.md"
    content = document.read_text(encoding="utf-8")

    required_terms = {
        "No raw recovery codes are stored",
        "make_password()",
        "check_password()",
        "constant-time",
        "one-time use",
        "replay prevention",
        "throttling",
        "audit",
        "transaction.atomic()",
        "select_for_update()",
        "factor=\"recovery-code\"",
        "recovery-code.hashed-at-rest",
        "recovery-code.constant-time",
        "recovery-code.one-time-use",
        "recovery-code.replay-prevention",
        "recovery-code.throttling",
        "recovery-code.audit",
        "recovery-code.session-elevation",
        "target URLs",
        "credentials",
    }

    missing_terms = sorted(term for term in required_terms if term not in content)

    assert not missing_terms
