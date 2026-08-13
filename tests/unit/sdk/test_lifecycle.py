"""
Unit tests for NetworkDefenderSDK lifecycle and health methods.

Complements test_sdk_capture.py which focuses on the capture-specific methods
added in Milestone 3. This file covers start/stop/get_health/get_gatekeeper.
"""

from unittest.mock import MagicMock, patch

# pyrefly: ignore [missing-import]
import pytest

from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.shared.config_models import AppConfig, CaptureConfig
from network_defender.shared.rate_limit_models import RateLimitConfig, ServiceRateLimitConfig

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sdk() -> NetworkDefenderSDK:
    cfg = AppConfig(capture=CaptureConfig(interface="eth0", max_packets_per_second=0))
    rate_cfg = RateLimitConfig(services={})
    return NetworkDefenderSDK(app_config=cfg, rate_limit_config=rate_cfg)


@pytest.fixture()
def sdk_with_gatekeeper() -> NetworkDefenderSDK:
    svc_cfg = ServiceRateLimitConfig(
        requests_per_minute=60,
        requests_per_day=1000,
        max_queue_depth=5,
        retry_attempts=0,
        retry_backoff_base_seconds=0.01,
    )
    cfg = AppConfig(capture=CaptureConfig(interface="eth0", max_packets_per_second=0))
    rate_cfg = RateLimitConfig(services={"my_api": svc_cfg})
    return NetworkDefenderSDK(app_config=cfg, rate_limit_config=rate_cfg)


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


@patch("network_defender.capture.service.AsyncSniffer")
def test_sdk_start_starts_all_services(
    mock_sniffer_cls: MagicMock, sdk: NetworkDefenderSDK
) -> None:
    mock_sniffer_cls.return_value = MagicMock()
    sdk.start()
    assert sdk._capture_service.is_running is True
    assert sdk._detection_service.is_running is True
    assert sdk._alert_service.is_running is True
    sdk.stop()


@patch("network_defender.capture.service.AsyncSniffer")
def test_sdk_stop_stops_all_services(
    mock_sniffer_cls: MagicMock, sdk: NetworkDefenderSDK
) -> None:
    mock_sniffer_cls.return_value = MagicMock()
    sdk.start()
    sdk.stop()
    assert sdk._capture_service.is_running is False
    assert sdk._detection_service.is_running is False
    assert sdk._alert_service.is_running is False


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@patch("network_defender.capture.service.AsyncSniffer")
def test_sdk_get_health_ok_when_all_running(
    mock_sniffer_cls: MagicMock, sdk: NetworkDefenderSDK
) -> None:
    mock_sniffer_cls.return_value = MagicMock()
    sdk.start()
    health = sdk.get_health()
    assert health["status"] == "ok"
    assert "capture" in health["components"]
    sdk.stop()


def test_sdk_get_health_degraded_when_stopped(sdk: NetworkDefenderSDK) -> None:
    health = sdk.get_health()
    assert health["status"] == "degraded"


# ---------------------------------------------------------------------------
# get_gatekeeper
# ---------------------------------------------------------------------------


def test_get_gatekeeper_returns_correct_instance(
    sdk_with_gatekeeper: NetworkDefenderSDK,
) -> None:
    from network_defender.shared.gatekeeper import ApiGatekeeper

    gk = sdk_with_gatekeeper.get_gatekeeper("my_api")
    assert isinstance(gk, ApiGatekeeper)


def test_get_gatekeeper_raises_for_unknown_service(
    sdk_with_gatekeeper: NetworkDefenderSDK,
) -> None:
    with pytest.raises(KeyError, match="no_such_service"):
        sdk_with_gatekeeper.get_gatekeeper("no_such_service")
