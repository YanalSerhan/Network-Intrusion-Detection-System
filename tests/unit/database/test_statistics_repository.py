"""Tests for statistics snapshots, series windows and empty summaries."""

from datetime import UTC, datetime, timedelta

from network_defender.database.repositories import (
    StatisticsRepository,
)

# --------------------------------------------------------------------------
# Statistics
# --------------------------------------------------------------------------


def test_statistics_snapshots_and_summary(stats_repo: StatisticsRepository) -> None:
    now = datetime.now(UTC)
    for i in range(3):
        stats_repo.record_snapshot(
            total_packets=1000 * i,
            packets_per_second=100.0 * i,
            alerts_by_severity={"high": i},
            captured_at=now + timedelta(minutes=i),
        )

    assert stats_repo.summarise() == {"snapshots": 3, "peak_pps": 200.0, "mean_pps": 100.0}
    latest = stats_repo.get_latest()
    assert latest is not None and latest.packets_per_second == 200.0
    assert len(stats_repo.get_series(hours=24)) == 3


def test_statistics_series_respects_the_window(stats_repo: StatisticsRepository) -> None:
    now = datetime.now(UTC)
    stats_repo.record_snapshot(captured_at=now - timedelta(days=5))
    stats_repo.record_snapshot(captured_at=now)
    assert len(stats_repo.get_series(hours=24)) == 1


def test_empty_statistics_summarise_safely(stats_repo: StatisticsRepository) -> None:
    assert stats_repo.get_latest() is None
    assert stats_repo.summarise() == {"snapshots": 0, "peak_pps": 0.0, "mean_pps": 0.0}
