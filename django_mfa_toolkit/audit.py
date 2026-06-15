from __future__ import annotations

from django_mfa_toolkit.hotp import HOTPAuditRecord, HOTPResyncAuditRecord
from django_mfa_toolkit.models import HOTPDevice, MFAAuditEvent


def create_hotp_audit_event(
    *,
    device: HOTPDevice,
    audit_record: HOTPAuditRecord,
) -> MFAAuditEvent:
    return MFAAuditEvent.objects.create(
        user=device.user,
        device=device,
        factor=MFAAuditEvent.Factor.HOTP,
        event_type=MFAAuditEvent.EventType.VERIFICATION,
        submitted_outcome=audit_record.submitted_outcome,
        result_classification=audit_record.result_classification,
        server_counter=audit_record.server_counter,
        matched_counter=audit_record.matched_counter,
        next_counter=audit_record.next_counter,
        look_ahead=audit_record.look_ahead,
        search_window=None,
        replay_window=audit_record.replay_window,
        submitted_count=None,
        attempted_at=audit_record.attempted_at,
    )


def create_hotp_resync_audit_event(
    *,
    device: HOTPDevice,
    audit_record: HOTPResyncAuditRecord,
) -> MFAAuditEvent:
    return MFAAuditEvent.objects.create(
        user=device.user,
        device=device,
        factor=MFAAuditEvent.Factor.HOTP,
        event_type=MFAAuditEvent.EventType.RESYNCHRONIZATION,
        submitted_outcome=audit_record.submitted_outcome,
        result_classification=audit_record.result_classification,
        server_counter=audit_record.server_counter,
        matched_counter=audit_record.matched_counter,
        next_counter=audit_record.next_counter,
        look_ahead=None,
        search_window=audit_record.search_window,
        replay_window=audit_record.replay_window,
        submitted_count=audit_record.submitted_count,
        attempted_at=audit_record.attempted_at,
    )
