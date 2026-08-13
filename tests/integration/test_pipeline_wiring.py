"""Integration tests: packets reach the detectors and alerts come back out."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.services.detection import DetectionService
from network_defender.services.evaluation_loop import PeriodicEvaluator
from network_defender.shared.config_models import AppConfig, CaptureConfig, DetectionConfig
from network_defender.shared.rate_limit_models import RateLimitConfig


@pytest.fixture()
def sdk() -> NetworkDefenderSDK:
    cfg = AppConfig(capture=CaptureConfig(interface="eth0", max_packets_per_second=0))
    return NetworkDefenderSDK(app_config=cfg, rate_limit_config=RateLimitConfig(services={}))


@pytest.fixture()
def scan_pcap(tmp_path: Path) -> Path:
    """A 40-port SYN scan from a single source."""
    path = tmp_path / "scan.pcap"
    wrpcap(
        str(path),
        [
            Ether() / IP(src="192.168.1.66", dst="192.168.1.10") / TCP(dport=port, flags="S")
            for port in range(1000, 1040)
        ],
    )
    return path


# --------------------------------------------------------------------------
# Periodic evaluation
# --------------------------------------------------------------------------


def test_periodic_evaluator_runs_the_callback() -> None:
    calls: list[int] = []
    evaluator = PeriodicEvaluator(0.01, lambda: calls.append(1))
    evaluator.start()
    assert evaluator.is_running
    for _ in range(200):
        if calls:
            break
        __import__("time").sleep(0.01)
    evaluator.stop()
    assert calls
    assert not evaluator.is_running


def test_periodic_evaluator_survives_a_failing_callback() -> None:
    def boom() -> None:
        raise RuntimeError("detector exploded")

    evaluator = PeriodicEvaluator(0.01, boom)
    evaluator.run_once()  # must not raise


def test_periodic_evaluator_rejects_a_non_positive_interval() -> None:
    with pytest.raises(ValueError):
        PeriodicEvaluator(0, lambda: None)


def test_detection_stop_flushes_pending_detector_state() -> None:
    service = DetectionService(
        config_dir="config", config=DetectionConfig(evaluation_interval_seconds=3600)
    )
    service.start()
    assert service._evaluator.is_running
    service.stop()
    assert not service._evaluator.is_running

# --------------------------------------------------------------------------
# End-to-end
# --------------------------------------------------------------------------


@patch("network_defender.capture.service.AsyncSniffer")
def test_captured_packets_reach_the_detectors_and_raise_alerts(
    mock_sniffer: MagicMock, sdk: NetworkDefenderSDK, scan_pcap: Path
) -> None:
    mock_sniffer.return_value = MagicMock()
    sdk.start()
    try:
        sdk.start_capture_from_pcap(scan_pcap)
        assert sdk._detection_service.health_check()["packets_processed"] == 40

        sdk._detection_service.evaluate_detectors()
        triggered = {alert.rule_triggered for alert in sdk.list_alerts()}
        assert "TcpPortScanDetector" in triggered
        assert "TCP Port Scan" in triggered  # YAML rule fired too
    finally:
        sdk.stop()


@patch("network_defender.capture.service.AsyncSniffer")
def test_alert_storm_is_deduplicated_end_to_end(
    mock_sniffer: MagicMock, sdk: NetworkDefenderSDK, scan_pcap: Path
) -> None:
    mock_sniffer.return_value = MagicMock()
    sdk.start()
    try:
        sdk.start_capture_from_pcap(scan_pcap)
        sdk._detection_service.evaluate_detectors()
        # 40 packets matched the rule, but they collapse into one alert record.
        rule_alerts = [a for a in sdk.list_alerts() if a.rule_triggered == "TCP Port Scan"]
        assert len(rule_alerts) == 1
        assert rule_alerts[0].occurrences > 1
    finally:
        sdk.stop()


@patch("network_defender.capture.service.AsyncSniffer")
def test_malformed_packets_do_not_break_the_pipeline(
    mock_sniffer: MagicMock, sdk: NetworkDefenderSDK
) -> None:
    mock_sniffer.return_value = MagicMock()
    sdk._on_raw_packet(None)  # parse_safe returns None; must not raise
    assert sdk._detection_service.health_check()["packets_processed"] == 0
