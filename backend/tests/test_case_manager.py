"""Unit tests for the CaseManager service.

These tests rely on the fixtures defined in backend/conftest.py:

- ``clean_db`` (autouse) drops and recreates the SQLite tables for every test,
  so each test starts from an empty database.
- ``manager`` provides a fresh CaseManager wired to that database.
- ``make_enrichment`` / ``make_report`` build minimal valid Pydantic payloads.
"""
from datetime import datetime, timezone

import pytest

from models import CaseStatus, IOCType, Severity


# ── open_case ────────────────────────────────────────────────────────────────


def test_open_case_returns_case_with_expected_fields(
    manager, make_enrichment, make_report
):
    enrichment = make_enrichment(ioc="1.2.3.4", verdict="malicious", score=88)
    report = make_report(ioc="1.2.3.4", verdict="malicious", score=88,
                        severity=Severity.HIGH)

    case = manager.open_case(
        ioc="1.2.3.4",
        ioc_type=IOCType.IP,
        severity=Severity.HIGH,
        enrichment=enrichment,
        report=report,
    )

    assert case.ioc == "1.2.3.4"
    assert case.ioc_type == "ip"
    assert case.status == CaseStatus.OPEN
    assert case.severity == Severity.HIGH
    assert case.enrichment.score == 88
    assert case.report.title == "Triage of 1.2.3.4"
    assert case.analyst_notes is None


def test_open_case_generates_8_character_uppercase_id(
    manager, make_enrichment, make_report
):
    case = manager.open_case(
        ioc="8.8.8.8", ioc_type=IOCType.IP, severity=Severity.LOW,
        enrichment=make_enrichment(), report=make_report(),
    )

    assert len(case.case_id) == 8
    assert case.case_id == case.case_id.upper()


def test_open_case_generates_unique_ids(manager, make_enrichment, make_report):
    ids = {
        manager.open_case(
            ioc=f"10.0.0.{i}", ioc_type=IOCType.IP, severity=Severity.LOW,
            enrichment=make_enrichment(ioc=f"10.0.0.{i}"),
            report=make_report(ioc=f"10.0.0.{i}"),
        ).case_id
        for i in range(5)
    }
    assert len(ids) == 5


def test_open_case_seeds_timeline_with_open_event(
    manager, make_enrichment, make_report
):
    enrichment = make_enrichment(verdict="suspicious", score=42)
    case = manager.open_case(
        ioc="8.8.8.8", ioc_type=IOCType.IP, severity=Severity.MEDIUM,
        enrichment=enrichment, report=make_report(verdict="suspicious", score=42),
    )

    assert len(case.timeline) == 1
    event = case.timeline[0]
    assert event.action == "Case opened"
    assert event.analyst == "system"
    assert "Score: 42" in event.notes
    assert "Verdict: suspicious" in event.notes
    assert "8.8.8.8" in event.notes


def test_open_case_with_analyst_notes_adds_second_timeline_event(
    manager, make_enrichment, make_report
):
    case = manager.open_case(
        ioc="8.8.8.8", ioc_type=IOCType.IP, severity=Severity.LOW,
        enrichment=make_enrichment(), report=make_report(),
        analyst_notes="Triggered on WS-042",
    )

    assert case.analyst_notes == "Triggered on WS-042"
    assert len(case.timeline) == 2
    assert case.timeline[1].action == "Analyst note added"
    assert case.timeline[1].analyst == "analyst"
    assert case.timeline[1].notes == "Triggered on WS-042"


def test_open_case_with_none_ioc_type_falls_back_to_enrichment(
    manager, make_enrichment, make_report
):
    """AlertIntake.ioc_type is optional; the enrichment engine's type is used."""
    case = manager.open_case(
        ioc="evil.example.com", ioc_type=None, severity=Severity.LOW,
        enrichment=make_enrichment(ioc="evil.example.com", ioc_type="domain"),
        report=make_report(ioc="evil.example.com", ioc_type="domain"),
    )

    assert case.ioc_type == "domain"


def test_open_case_accepts_string_ioc_type(manager, make_enrichment, make_report):
    case = manager.open_case(
        ioc="8.8.8.8", ioc_type="ip", severity=Severity.LOW,
        enrichment=make_enrichment(), report=make_report(),
    )

    assert case.ioc_type == "ip"


def test_open_case_accepts_string_severity(manager, make_enrichment, make_report):
    case = manager.open_case(
        ioc="8.8.8.8", ioc_type=IOCType.IP, severity="critical",
        enrichment=make_enrichment(),
        report=make_report(severity=Severity.CRITICAL),
    )

    assert case.severity == Severity.CRITICAL


def test_open_case_sets_created_and_updated_to_same_timestamp(
    manager, make_enrichment, make_report
):
    case = manager.open_case(
        ioc="8.8.8.8", ioc_type=IOCType.IP, severity=Severity.LOW,
        enrichment=make_enrichment(), report=make_report(),
    )

    assert case.created_at == case.updated_at
    assert case.created_at.tzinfo is not None


def test_open_case_persists_case(manager, make_enrichment, make_report):
    """The case is committed and survives a fresh CaseManager instance."""
    from services.case_manager import CaseManager

    case = manager.open_case(
        ioc="8.8.8.8", ioc_type=IOCType.IP, severity=Severity.LOW,
        enrichment=make_enrichment(), report=make_report(),
    )

    reloaded = CaseManager().get_case(case.case_id)
    assert reloaded is not None
    assert reloaded.case_id == case.case_id


# ── list_cases ───────────────────────────────────────────────────────────────


def test_list_cases_empty(manager):
    assert manager.list_cases() == []


def test_list_cases_returns_all_cases(manager, make_enrichment, make_report):
    for i in range(3):
        manager.open_case(
            ioc=f"10.0.0.{i}", ioc_type=IOCType.IP, severity=Severity.LOW,
            enrichment=make_enrichment(ioc=f"10.0.0.{i}"),
            report=make_report(ioc=f"10.0.0.{i}"),
        )

    cases = manager.list_cases()
    assert len(cases) == 3
    assert {c.ioc for c in cases} == {"10.0.0.0", "10.0.0.1", "10.0.0.2"}


# ── get_case ─────────────────────────────────────────────────────────────────


def test_get_case_returns_none_for_unknown_id(manager):
    assert manager.get_case("DOESNOTEX") is None


def test_get_case_returns_case_with_full_payload(
    manager, make_enrichment, make_report
):
    enrichment = make_enrichment(verdict="malicious", score=95)
    report = make_report(verdict="malicious", score=95, severity=Severity.CRITICAL)
    opened = manager.open_case(
        ioc="8.8.8.8", ioc_type=IOCType.IP, severity=Severity.CRITICAL,
        enrichment=enrichment, report=report,
        analyst_notes="check this",
    )

    fetched = manager.get_case(opened.case_id)
    assert fetched is not None
    assert fetched.case_id == opened.case_id
    assert fetched.enrichment.score == 95
    assert fetched.report.severity == Severity.CRITICAL
    assert fetched.analyst_notes == "check this"
    assert len(fetched.timeline) == 2


# ── update_status ────────────────────────────────────────────────────────────


def test_update_status_returns_none_for_unknown_id(manager):
    assert manager.update_status("DOESNOTEX", CaseStatus.IN_PROGRESS) is None


def test_update_status_changes_status_and_appends_timeline(
    manager, make_enrichment, make_report
):
    case = manager.open_case(
        ioc="8.8.8.8", ioc_type=IOCType.IP, severity=Severity.LOW,
        enrichment=make_enrichment(), report=make_report(),
    )
    timeline_before = len(case.timeline)

    updated = manager.update_status(case.case_id, CaseStatus.IN_PROGRESS)

    assert updated is not None
    assert updated.status == CaseStatus.IN_PROGRESS
    assert len(updated.timeline) == timeline_before + 1
    assert updated.timeline[-1].action == "Status updated to in_progress"
    assert updated.timeline[-1].analyst == "analyst"


def test_update_status_advances_updated_at(
    manager, make_enrichment, make_report
):
    case = manager.open_case(
        ioc="8.8.8.8", ioc_type=IOCType.IP, severity=Severity.LOW,
        enrichment=make_enrichment(), report=make_report(),
    )

    updated = manager.update_status(case.case_id, CaseStatus.ESCALATED)

    assert updated.updated_at >= case.updated_at


# ── add_note ─────────────────────────────────────────────────────────────────


def test_add_note_returns_none_for_unknown_id(manager):
    assert manager.add_note("DOESNOTEX", "anything") is None


def test_add_note_appends_timeline_event(
    manager, make_enrichment, make_report
):
    case = manager.open_case(
        ioc="8.8.8.8", ioc_type=IOCType.IP, severity=Severity.LOW,
        enrichment=make_enrichment(), report=make_report(),
    )
    timeline_before = len(case.timeline)

    updated = manager.add_note(case.case_id, "Confirmed false positive")

    assert updated is not None
    assert len(updated.timeline) == timeline_before + 1
    last = updated.timeline[-1]
    assert last.action == "Note added"
    assert last.analyst == "analyst"
    assert last.notes == "Confirmed false positive"
    # add_note must NOT change the case status.
    assert updated.status == CaseStatus.OPEN


def test_add_note_advances_updated_at(manager, make_enrichment, make_report):
    case = manager.open_case(
        ioc="8.8.8.8", ioc_type=IOCType.IP, severity=Severity.LOW,
        enrichment=make_enrichment(), report=make_report(),
    )

    updated = manager.add_note(case.case_id, "more context")

    assert updated.updated_at >= case.updated_at


# ── close_case ───────────────────────────────────────────────────────────────


def test_close_case_returns_none_for_unknown_id(manager):
    assert manager.close_case("DOESNOTEX", "resolved") is None


def test_close_case_sets_status_and_records_resolution(
    manager, make_enrichment, make_report
):
    case = manager.open_case(
        ioc="8.8.8.8", ioc_type=IOCType.IP, severity=Severity.LOW,
        enrichment=make_enrichment(), report=make_report(),
    )

    closed = manager.close_case(case.case_id, "False positive: legitimate scan")

    assert closed is not None
    assert closed.status == CaseStatus.CLOSED
    assert closed.timeline[-1].action == "Case closed"
    assert closed.timeline[-1].notes == "False positive: legitimate scan"


def test_close_case_persists_to_database(
    manager, make_enrichment, make_report
):
    case = manager.open_case(
        ioc="8.8.8.8", ioc_type=IOCType.IP, severity=Severity.LOW,
        enrichment=make_enrichment(), report=make_report(),
    )
    manager.close_case(case.case_id, "done")

    fetched = manager.get_case(case.case_id)
    assert fetched.status == CaseStatus.CLOSED


# ── get_stats ────────────────────────────────────────────────────────────────


def test_get_stats_empty_database(manager):
    stats = manager.get_stats()

    assert stats["total"] == 0
    for status in CaseStatus:
        assert stats["by_status"][status.value] == 0
    for severity in Severity:
        assert stats["by_severity"][severity.value] == 0


def test_get_stats_counts_by_status_and_severity(
    manager, make_enrichment, make_report
):
    # Two open/low cases.
    for i in range(2):
        manager.open_case(
            ioc=f"1.1.1.{i}", ioc_type=IOCType.IP, severity=Severity.LOW,
            enrichment=make_enrichment(ioc=f"1.1.1.{i}"),
            report=make_report(ioc=f"1.1.1.{i}"),
        )

    # One high case, then escalate it.
    high_case = manager.open_case(
        ioc="2.2.2.2", ioc_type=IOCType.IP, severity=Severity.HIGH,
        enrichment=make_enrichment(ioc="2.2.2.2"),
        report=make_report(ioc="2.2.2.2", severity=Severity.HIGH),
    )
    manager.update_status(high_case.case_id, CaseStatus.ESCALATED)

    # One critical case, then close it.
    crit_case = manager.open_case(
        ioc="3.3.3.3", ioc_type=IOCType.IP, severity=Severity.CRITICAL,
        enrichment=make_enrichment(ioc="3.3.3.3"),
        report=make_report(ioc="3.3.3.3", severity=Severity.CRITICAL),
    )
    manager.close_case(crit_case.case_id, "contained")

    stats = manager.get_stats()
    assert stats["total"] == 4
    assert stats["by_status"]["open"] == 2
    assert stats["by_status"]["in_progress"] == 0
    assert stats["by_status"]["escalated"] == 1
    assert stats["by_status"]["closed"] == 1
    assert stats["by_severity"]["low"] == 2
    assert stats["by_severity"]["medium"] == 0
    assert stats["by_severity"]["high"] == 1
    assert stats["by_severity"]["critical"] == 1
