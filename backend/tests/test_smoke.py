"""Smoke test: verifies the pytest harness and the database fixture are wired up.

This is temporary scaffolding -- it confirms the application modules import
cleanly under the test harness and that the throwaway database starts empty.
It will be replaced by the full test_case_manager.py suite in the next step.
"""


def test_harness_and_empty_database(manager):
    """App modules import under the harness; the test database starts empty."""
    assert manager.list_cases() == []

    stats = manager.get_stats()
    assert stats["total"] == 0
    assert stats["by_status"]["open"] == 0
    assert stats["by_severity"]["low"] == 0
