"""Unit tests for notification hooks and the dispatcher."""

from network_defender.constants import Severity
from network_defender.services.alerts.dispatcher import NotificationDispatcher
from network_defender.services.alerts.models import Alert
from network_defender.services.alerts.notifications import (
    EmailNotificationHook,
    NotificationHook,
    SlackNotificationHook,
    WebhookNotificationHook,
)

from .conftest import make_alert


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


def test_dispatch_reaches_registered_hooks() -> None:
    hook = RecordingHook()
    dispatcher = NotificationDispatcher([hook])
    alert = make_alert()

    assert dispatcher.dispatch(alert) == 1
    assert hook.received == [alert]


def test_hooks_can_be_registered_at_runtime() -> None:
    dispatcher = NotificationDispatcher()
    assert dispatcher.dispatch(make_alert()) == 0

    hook = RecordingHook()
    dispatcher.register(hook)
    assert len(dispatcher.hooks) == 1
    assert dispatcher.dispatch(make_alert()) == 1


def test_min_severity_filters_low_value_alerts() -> None:
    hook = RecordingHook(min_severity=Severity.CRITICAL)
    dispatcher = NotificationDispatcher([hook])

    assert dispatcher.dispatch(make_alert(severity=Severity.HIGH)) == 0
    assert dispatcher.dispatch(make_alert(severity=Severity.CRITICAL)) == 1


def test_disabled_hooks_are_skipped() -> None:
    hook = RecordingHook(enabled=False)
    assert NotificationDispatcher([hook]).dispatch(make_alert()) == 0
    assert hook.received == []


def test_failing_hook_does_not_block_others() -> None:
    good = RecordingHook()
    dispatcher = NotificationDispatcher([ExplodingHook(), good])

    assert dispatcher.dispatch(make_alert()) == 1
    assert len(good.received) == 1
    stats = dispatcher.get_stats()
    assert stats["failed"]["exploding"] == 1
    assert stats["delivered"]["recording"] == 1


def test_builtin_stub_hooks_are_disabled_by_default() -> None:
    hooks: list[NotificationHook] = [
        EmailNotificationHook(recipients=["soc@example.com"]),
        WebhookNotificationHook(url="https://example.invalid/hook"),
        SlackNotificationHook(webhook_url="https://example.invalid/slack"),
    ]
    assert [hook.name for hook in hooks] == ["email", "webhook", "slack"]
    assert all(not hook.enabled for hook in hooks)
    assert NotificationDispatcher(hooks).dispatch(make_alert(severity=Severity.CRITICAL)) == 0


def test_builtin_stub_hooks_deliver_when_enabled() -> None:
    hooks: list[NotificationHook] = [
        EmailNotificationHook(enabled=True),
        WebhookNotificationHook(enabled=True),
        SlackNotificationHook(enabled=True),
    ]
    dispatcher = NotificationDispatcher(hooks)
    assert dispatcher.dispatch(make_alert(severity=Severity.CRITICAL)) == 3
