"""Integration tests: config paths resolve and detector settings take effect."""

from pathlib import Path

import pytest

from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.services.detection import DetectionService
from network_defender.shared.config_models import AppConfig, CaptureConfig
from network_defender.shared.paths import PROJECT_ROOT, resolve_project_path
from network_defender.shared.rate_limit_models import RateLimitConfig


@pytest.fixture()
def sdk() -> NetworkDefenderSDK:
    cfg = AppConfig(capture=CaptureConfig(interface="eth0", max_packets_per_second=0))
    return NetworkDefenderSDK(app_config=cfg, rate_limit_config=RateLimitConfig(services={}))


# --------------------------------------------------------------------------
# Path resolution
# --------------------------------------------------------------------------


def test_relative_config_paths_anchor_to_the_project_root() -> None:
    resolved = resolve_project_path("rules/")
    assert resolved.is_absolute()
    assert resolved == (PROJECT_ROOT / "rules").resolve()


def test_absolute_paths_are_left_alone() -> None:
    assert resolve_project_path("/etc/nd/rules") == Path("/etc/nd/rules")

# --------------------------------------------------------------------------
# Detector configuration
# --------------------------------------------------------------------------


def test_detection_service_reads_the_real_detector_config() -> None:
    service = DetectionService(config_dir="config", rules_dir="rules")
    assert service.registry.config_data, "config/detectors.json was not loaded"
    assert "TcpPortScanDetector" in service.registry.config_data


def test_configured_thresholds_are_applied_not_defaults() -> None:
    service = DetectionService(config_dir="config", rules_dir="rules")
    service.registry.load_detectors()
    by_name = {d.name: d for d in service.registry.detectors}
    configured = service.registry.config_data["SynFloodDetector"]["syn_count_threshold"]
    assert by_name["SynFloodDetector"].config.syn_count_threshold == configured


def test_disabled_detectors_are_not_loaded(tmp_path: Path) -> None:
    (tmp_path / "detectors.json").write_text('{"TcpPortScanDetector": {"enabled": false}}')
    service = DetectionService(config_dir=tmp_path)
    service.registry.load_detectors()
    assert "TcpPortScanDetector" not in {d.name for d in service.registry.detectors}


def test_sdk_gives_detection_the_config_dir_and_the_rules_dir(sdk: NetworkDefenderSDK) -> None:
    assert sdk._detection_service.config_dir.name == "config"
    assert sdk._detection_service.rules_dir is not None
    assert sdk._detection_service.rules_dir.name == "rules"
    assert sdk._detection_service.rule_engine is not None
