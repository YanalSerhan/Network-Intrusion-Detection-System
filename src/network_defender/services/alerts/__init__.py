"""
Alert System (Milestone 7).

Owns the full alert lifecycle:

  DetectionAlert / matched Rule
        -> factory.build_alert()      (normalise into an Alert)
        -> confidence.score_alert()   (per-detector confidence)
        -> AlertDeduplicator          (collapse alert storms)
        -> AlertRepository            (persistence port)
        -> NotificationDispatcher     (email / webhook / Slack hooks)

Data Setup:  Repository and notification hooks are injected into AlertService.
Data Input:  DetectionAlert objects from the detection service; matched Rules
             from the rule engine.
Data Output: Persisted Alert records and dispatched notifications.
"""

from network_defender.constants import AlertSource, AlertStatus

from .confidence import score_alert, score_rule_match
from .dedup import AlertDeduplicator
from .dispatcher import NotificationDispatcher
from .factory import build_alert, build_rule_alert
from .mitre import lookup_mitre
from .models import Alert
from .notifications import (
    EmailNotificationHook,
    NotificationHook,
    SlackNotificationHook,
    WebhookNotificationHook,
)
from .repository import AlertRepository, InMemoryAlertRepository
from .service import AlertService

__all__ = [
    "Alert",
    "AlertDeduplicator",
    "AlertRepository",
    "AlertService",
    "AlertSource",
    "AlertStatus",
    "EmailNotificationHook",
    "InMemoryAlertRepository",
    "NotificationDispatcher",
    "NotificationHook",
    "SlackNotificationHook",
    "WebhookNotificationHook",
    "build_alert",
    "build_rule_alert",
    "lookup_mitre",
    "score_alert",
    "score_rule_match",
]
