"""
Notification-hook test doubles.

These live outside a test module so both the alert service tests and the SDK
alert-operations tests can use them without importing across test packages —
an import that couples two suites and breaks the moment either is renamed.
"""

from network_defender.constants import Severity
from network_defender.services.alerts.models import Alert
from network_defender.services.alerts.notifications import NotificationHook


class RecordingHook(NotificationHook):
    """Test double that records every alert it receives."""

    def __init__(self, min_severity: Severity = Severity.INFO, enabled: bool = True) -> None:
        super().__init__(min_severity=min_severity, enabled=enabled)
        self.received: list[Alert] = []

    @property
    def name(self) -> str:
        return "recording"

    def send(self, alert: Alert) -> None:
        self.received.append(alert)


class ExplodingHook(NotificationHook):
    """Test double simulating a channel that is down."""

    @property
    def name(self) -> str:
        return "exploding"

    def send(self, alert: Alert) -> None:
        raise RuntimeError("channel unavailable")
