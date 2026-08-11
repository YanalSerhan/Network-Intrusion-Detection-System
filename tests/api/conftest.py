"""
Fixtures for API tests.

The app is built with an injected SDK so the lifespan handler is bypassed and
the test controls the service lifecycle. The SDK runs in read-only mode, which
is exactly how the API runs in production — no capture interface is opened.
"""

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from network_defender.api.app import create_app
from network_defender.constants import Protocol, Severity
from network_defender.detectors.models import DetectionAlert
from network_defender.parser.models import ParsedPacket, TcpFlags
from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.services.alerts.models import Alert
from network_defender.shared.config_models import AppConfig, CaptureConfig
from network_defender.shared.rate_limit_models import RateLimitConfig

PUBLIC_IP = "45.155.205.233"


@pytest.fixture()
def sdk() -> Iterator[NetworkDefenderSDK]:
    """A read-only SDK bound to the per-test database."""
    config = AppConfig(capture=CaptureConfig(interface="eth0", max_packets_per_second=0))
    instance = NetworkDefenderSDK(
        app_config=config, rate_limit_config=RateLimitConfig(services={})
    )
    instance.start_readonly()
    try:
        yield instance
    finally:
        instance.stop_readonly()


@pytest.fixture()
def client(sdk: NetworkDefenderSDK) -> TestClient:
    """A test client over an app wired to the test SDK."""
    return TestClient(create_app(sdk=sdk))


@pytest.fixture()
def seeded_alert(sdk: NetworkDefenderSDK) -> Alert:
    """One stored alert with a packet of evidence attached."""
    sdk._on_detection(
        DetectionAlert(
            detector_name="TcpPortScanDetector",
            severity=Severity.HIGH,
            description="TCP Port Scan detected: 60 unique ports scanned.",
            src_ip=PUBLIC_IP,
            evidence={"unique_ports": 60},
        )
    )
    alert = sdk.list_alerts()[0]
    sdk._database_service.packets.save(
        ParsedPacket(
            timestamp=datetime.now(UTC),
            src_ip=PUBLIC_IP,
            dst_ip="10.0.0.1",
            src_port=51234,
            dst_port=443,
            protocol=Protocol.TCP,
            length=74,
            tcp_flags=TcpFlags(syn=True),
            raw_summary="TCP SYN",
        ),
        alert_id=alert.alert_id,
    )
    return alert


@pytest.fixture()
def seeded_rules(sdk: NetworkDefenderSDK) -> int:
    """The shipped YAML rules, snapshotted into the database."""
    engine = sdk._detection_service.rule_engine
    assert engine is not None
    engine.start()
    try:
        rules = engine.loader.registry.get_all_enabled_rules()
        sdk._database_service.rules.sync(rules)
    finally:
        engine.stop()
    return len(rules)
