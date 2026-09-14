"""
Collecting the alerts one replay raised.

Data Setup:  Registered on the SDK before the capture is fed in.
Data Input:  Alerts the dispatcher delivers.
Data Output: Those alerts, in the order they were raised.

Why this exists
---------------
`replay` printed `sdk.list_alerts()`, which is every alert in the configured
database. That database is the operator's, it persists between runs, and an
alert's timestamp comes from the packet rather than from the clock — so a
second replay printed the first one's findings beside its own, ordered by when
each capture had been recorded, and no `since` filter could have separated
them. Replaying four files in a row reported fourteen alerts for a capture
that raises two.

Reading the dispatcher reports exactly what this run raised, and does it
through the extension point that already exists for the purpose rather than by
adding a query the SDK would then have to keep.
"""

from ..services.alerts.models import Alert
from ..services.alerts.notifications import NotificationHook


class ReplayCollector(NotificationHook):
    """
    Notification hook that keeps every alert it is handed.

    Usage:
        collector = ReplayCollector()
        sdk.register_notification_hook(collector)
        ...
        for alert in collector.alerts: ...
    """

    def __init__(self) -> None:
        """Start with an empty list; `min_severity` stays at INFO so nothing is filtered."""
        super().__init__()
        self.alerts: list[Alert] = []

    @property
    def name(self) -> str:
        """Unique channel name used in logs and health output."""
        return "replay-collector"

    def send(self, alert: Alert) -> None:
        """
        Keep the alert.

        Args:
            alert: An alert that survived deduplication and was persisted.
        """
        self.alerts.append(alert)
