"""
Notification dispatcher.

Data Setup:  Hooks are injected via __init__ or registered at runtime.
Data Input:  Alerts that survived deduplication.
Data Output: Fan-out to every registered hook; a per-channel delivery tally.

Fail-open contract: a hook that raises is logged and skipped. Notification is a
side channel — a broken Slack webhook must never prevent an alert from being
detected, scored, or persisted.
"""

from network_defender.shared.base import LoggableMixin

from .models import Alert
from .notifications import NotificationHook


class NotificationDispatcher(LoggableMixin):
    """
    Fans an alert out to every registered notification hook.

    Usage:
        dispatcher = NotificationDispatcher([SlackNotificationHook(enabled=True)])
        dispatcher.dispatch(alert)
    """

    def __init__(self, hooks: list[NotificationHook] | None = None) -> None:
        """
        Initialise the dispatcher.

        Args:
            hooks: Notification hooks to start with; more can be registered later.
        """
        self._hooks: list[NotificationHook] = list(hooks or [])
        self._delivered: dict[str, int] = {}
        self._failed: dict[str, int] = {}

    @property
    def hooks(self) -> list[NotificationHook]:
        """Registered hooks, in dispatch order."""
        return list(self._hooks)

    def register(self, hook: NotificationHook) -> None:
        """
        Add a hook to the dispatch chain.

        Args:
            hook: Any NotificationHook implementation.
        """
        self._hooks.append(hook)
        self.logger.info("Notification hook registered", extra={"hook": hook.name})

    def dispatch(self, alert: Alert) -> int:
        """
        Deliver an alert to every eligible hook.

        Args:
            alert: The alert to broadcast.

        Returns:
            Number of hooks that accepted the alert without raising.
        """
        delivered = 0
        for hook in self._hooks:
            if not hook.should_send(alert):
                continue
            try:
                hook.send(alert)
            except Exception as exc:  # noqa: BLE001 - fail open, never break alerting
                self._failed[hook.name] = self._failed.get(hook.name, 0) + 1
                self.logger.error(
                    "Notification hook failed",
                    extra={"hook": hook.name, "error": str(exc)},
                )
                continue
            self._delivered[hook.name] = self._delivered.get(hook.name, 0) + 1
            delivered += 1
        return delivered

    def get_stats(self) -> dict[str, dict[str, int]]:
        """
        Return per-channel delivery counters for health checks.

        Returns:
            Dict with 'delivered' and 'failed' counts keyed by hook name.
        """
        return {"delivered": dict(self._delivered), "failed": dict(self._failed)}
