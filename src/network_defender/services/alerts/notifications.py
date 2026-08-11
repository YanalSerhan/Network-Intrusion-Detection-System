"""
Alert notification hooks (extensible: email, webhook, Slack).

Data Setup:  Each hook receives its own config via __init__; credentials and
             endpoints come from .env / config, never from source literals.
Data Input:  Alert objects that survived deduplication.
Data Output: Side effects on external channels. Transport is stubbed here —
             every outbound call must route through the ApiGatekeeper once the
             Threat Intel / outbound layer lands in Milestone 8.

Design
------
`NotificationHook` is the extension point: subclass it, implement `send`, and
register the instance with the dispatcher. The dispatcher isolates failures so
one broken channel can never stop alert persistence (fail-open).
"""

from abc import ABC, abstractmethod

from network_defender.constants import SEVERITY_ORDER, Severity
from network_defender.shared.base import LoggableMixin

from .models import Alert


class NotificationHook(LoggableMixin, ABC):
    """
    Extension point for delivering alerts to an external channel.

    Subclasses implement `send`. `min_severity` lets an operator route only
    high-value alerts to noisy channels (e.g. page on critical, log the rest).
    """

    def __init__(self, min_severity: Severity = Severity.INFO, enabled: bool = True) -> None:
        """
        Initialise the hook.

        Args:
            min_severity: Lowest severity this channel should receive.
            enabled:      Whether the hook is active.
        """
        self.min_severity = min_severity
        self.enabled = enabled

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique channel name used in logs and health output."""

    @abstractmethod
    def send(self, alert: Alert) -> None:
        """Deliver a single alert to the channel."""

    def should_send(self, alert: Alert) -> bool:
        """Return True if this hook is enabled and the alert clears min_severity."""
        if not self.enabled:
            return False
        return SEVERITY_ORDER.get(alert.severity, 0) >= SEVERITY_ORDER.get(self.min_severity, 0)


class EmailNotificationHook(NotificationHook):
    """Stub email channel. SMTP delivery is wired up in a later milestone."""

    def __init__(
        self,
        recipients: list[str] | None = None,
        min_severity: Severity = Severity.HIGH,
        enabled: bool = False,
    ) -> None:
        """Initialise with the recipient list (loaded from config, not literals)."""
        super().__init__(min_severity=min_severity, enabled=enabled)
        self.recipients = recipients or []

    @property
    def name(self) -> str:
        """Channel name."""
        return "email"

    def send(self, alert: Alert) -> None:
        """Stub: record the intended delivery without contacting an SMTP server."""
        self.logger.info(
            "Email notification queued",
            extra={"alert_id": str(alert.alert_id), "recipients": len(self.recipients)},
        )


class WebhookNotificationHook(NotificationHook):
    """Stub generic HTTP webhook channel. Outbound HTTP routes via the gatekeeper."""

    def __init__(
        self,
        url: str | None = None,
        min_severity: Severity = Severity.MEDIUM,
        enabled: bool = False,
    ) -> None:
        """Initialise with the destination URL (loaded from config, not literals)."""
        super().__init__(min_severity=min_severity, enabled=enabled)
        self.url = url

    @property
    def name(self) -> str:
        """Channel name."""
        return "webhook"

    def send(self, alert: Alert) -> None:
        """Stub: record the intended POST without performing it."""
        self.logger.info(
            "Webhook notification queued",
            extra={"alert_id": str(alert.alert_id), "configured": self.url is not None},
        )


class SlackNotificationHook(NotificationHook):
    """Stub Slack channel. Uses an incoming-webhook URL supplied via .env."""

    def __init__(
        self,
        webhook_url: str | None = None,
        min_severity: Severity = Severity.HIGH,
        enabled: bool = False,
    ) -> None:
        """Initialise with the Slack incoming-webhook URL (from .env, never source)."""
        super().__init__(min_severity=min_severity, enabled=enabled)
        self.webhook_url = webhook_url

    @property
    def name(self) -> str:
        """Channel name."""
        return "slack"

    def send(self, alert: Alert) -> None:
        """Stub: record the intended Slack post without performing it."""
        self.logger.info(
            "Slack notification queued",
            extra={"alert_id": str(alert.alert_id), "configured": self.webhook_url is not None},
        )
