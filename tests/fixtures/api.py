"""
Fixtures for API tests over a live FastAPI TestClient.

The app is built with an injected SDK so the lifespan handler is bypassed and
the test controls the service lifecycle. The SDK runs in read-only mode, which
is exactly how the API runs in production — no capture interface is opened.
"""

import pytest
from fastapi.testclient import TestClient

from network_defender.api.app import create_app
from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.services.alerts.models import Alert

from .builders import make_detection, make_packet
from .constants import PUBLIC_IP


@pytest.fixture()
def client(readonly_sdk: NetworkDefenderSDK) -> TestClient:
    """A test client over an app wired to the started, read-only SDK."""
    return TestClient(create_app(sdk=readonly_sdk))


@pytest.fixture()
def seeded_alert(readonly_sdk: NetworkDefenderSDK) -> Alert:
    """One stored alert with a packet of evidence attached."""
    readonly_sdk._on_detection(make_detection(src_ip=PUBLIC_IP))
    alert = readonly_sdk.list_alerts()[0]
    readonly_sdk._database_service.packets.save(
        make_packet(src_ip=PUBLIC_IP, dst_ip="10.0.0.1", raw_summary="TCP SYN"),
        alert_id=alert.alert_id,
    )
    return alert


@pytest.fixture()
def seeded_rules(readonly_sdk: NetworkDefenderSDK) -> int:
    """The shipped YAML rules, snapshotted into the database."""
    engine = readonly_sdk._detection_service.rule_engine
    assert engine is not None
    engine.start()
    try:
        rules = engine.loader.registry.get_all_enabled_rules()
        readonly_sdk._database_service.rules.sync(rules)
    finally:
        engine.stop()
    return len(rules)
