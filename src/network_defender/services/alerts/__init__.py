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

from .models import Alert, AlertSource, AlertStatus

__all__ = ["Alert", "AlertSource", "AlertStatus"]
