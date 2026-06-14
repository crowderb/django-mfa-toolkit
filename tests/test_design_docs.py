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
