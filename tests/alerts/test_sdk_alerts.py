"""Integration tests: alerts flowing through the SDK surface."""

from uuid import uuid4

from network_defender.constants import Severity
from network_defender.detectors.models import DetectionAlert
from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.shared.config_models import AppConfig
from network_defender.shared.rate_limit_models import RateLimitConfig

from .test_notifications import RecordingHook


def _sdk(app_config: AppConfig, rate_limit_config: RateLimitConfig) -> NetworkDefenderSDK:
    return NetworkDefenderSDK(app_config=app_config, rate_limit_config=rate_limit_config)


def test_detector_alerts_reach_the_sdk(
    app_config: AppConfig, rate_limit_config: RateLimitConfig, detection: DetectionAlert
) -> None:
    sdk = _sdk(app_config, rate_limit_config)
    sdk._on_detection(detection)

    alerts = sdk.list_alerts()
    assert len(alerts) == 1
    assert alerts[0].rule_triggered == "TcpPortScanDetector"
    # The SQL repository returns a fresh domain object per read, so compare by
    # value rather than identity — identity was never part of the port's contract.
    assert sdk.get_alert(alerts[0].alert_id) == alerts[0]
    assert sdk.get_alert(uuid4()) is None


def test_alert_statistics_breakdown(
    app_config: AppConfig, rate_limit_config: RateLimitConfig, detection: DetectionAlert
) -> None:
    sdk = _sdk(app_config, rate_limit_config)
    sdk._on_detection(detection)
    sdk._on_detection(
        DetectionAlert(
            detector_name="DataExfiltrationDetector",
            severity=Severity.CRITICAL,
            description="exfil",
            src_ip="10.0.0.9",
            evidence={"bytes_out": 500_000_000},
        )
    )

    stats = sdk.get_alert_statistics()
    assert stats["total_alerts"] == 2
    assert stats["by_severity"]["high"] == 1
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_severity"]["info"] == 0


def test_notification_hooks_can_be_registered_through_the_sdk(
    app_config: AppConfig, rate_limit_config: RateLimitConfig, detection: DetectionAlert
) -> None:
    sdk = _sdk(app_config, rate_limit_config)
    hook = RecordingHook()
    sdk.register_notification_hook(hook)

    sdk._on_detection(detection)
    assert len(hook.received) == 1


def test_health_includes_alert_component(
    app_config: AppConfig, rate_limit_config: RateLimitConfig
) -> None:
    sdk = _sdk(app_config, rate_limit_config)
    alerting = sdk.get_health()["components"]["alerting"]
    assert alerting["service"] == "AlertService"
    assert alerting["alerts_stored"] == 0
