"""API tests for the statistics endpoints."""

from fastapi.testclient import TestClient

from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.services.alerts.models import Alert
from tests.fixtures.constants import PUBLIC_IP

STATISTICS = "/api/v1/statistics"
# --------------------------------------------------------------------------
# Statistics
# --------------------------------------------------------------------------


def test_statistics_summary_is_empty_initially(client: TestClient) -> None:
    body = client.get(STATISTICS).json()
    assert body["total_alerts"] == 0
    assert body["top_talkers"] == []
    assert body["alerts_by_severity"]["high"] == 0


def test_statistics_summary_counts_alerts(client: TestClient, seeded_alert: Alert) -> None:
    body = client.get(STATISTICS).json()

    assert body["total_alerts"] == 1
    assert body["alerts_by_severity"]["high"] == 1
    assert body["total_packets_retained"] == 1
    assert body["top_talkers"] == [{"ip": PUBLIC_IP, "alert_count": 1}]


def test_statistics_timeseries(client: TestClient, readonly_sdk: NetworkDefenderSDK) -> None:
    assert client.get(f"{STATISTICS}/timeseries").json() == []

    readonly_sdk._database_service.statistics.record_snapshot(
        total_alerts=3, packets_per_second=42.0
    )
    series = client.get(f"{STATISTICS}/timeseries", params={"hours": 24}).json()

    assert len(series) == 1
    assert series[0]["packets_per_second"] == 42.0


def test_timeseries_window_is_validated(client: TestClient) -> None:
    assert client.get(f"{STATISTICS}/timeseries", params={"hours": 0}).status_code == 422
    assert client.get(f"{STATISTICS}/timeseries", params={"hours": 99999}).status_code == 422
