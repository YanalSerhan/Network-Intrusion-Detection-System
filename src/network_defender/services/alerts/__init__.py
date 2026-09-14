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
from network_defender.services.alerts.confidence import score_alert, score_rule_match
from network_defender.services.alerts.dedup import AlertDeduplicator
from network_defender.services.alerts.dispatcher import NotificationDispatcher
from network_defender.services.alerts.factory import build_alert, build_rule_alert
from network_defender.services.alerts.mitre import lookup_mitre
from network_defender.services.alerts.models import Alert
from network_defender.services.alerts.notifications import (
    EmailNotificationHook,
    NotificationHook,
    SlackNotificationHook,
    WebhookNotificationHook,
)
from network_defender.services.alerts.repository import AlertRepository, InMemoryAlertRepository
from network_defender.services.alerts.service import AlertService

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
