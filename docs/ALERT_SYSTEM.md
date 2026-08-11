# Alert System (Milestone 7)

The alert system turns raw detections into triage-ready records. It lives in
`src/network_defender/services/alerts/` and is reached only through the SDK.

## Pipeline

```
DetectionAlert (detector)         Rule + ParsedPacket (rule engine)
        │                                    │
        └──────────┬─────────────────────────┘
                   ▼
            factory.build_alert()      normalise → MITRE attribution → confidence
                   ▼
            AlertDeduplicator          collapse storms inside the dedup window
                   ▼
            AlertRepository            persist (in-memory now, SQLAlchemy in M9)
                   ▼
            NotificationDispatcher     fan out to email / webhook / Slack hooks
```

A suppressed duplicate never reaches persistence or notification; it increments
`occurrences` and `last_seen` on the alert already tracked for its dedup key.

## Modules

| Module | Responsibility |
|---|---|
| `models.py` | The canonical `Alert` record and its dedup key. |
| `mitre.py` | Detector → MITRE ATT&CK tactic/technique lookup table. |
| `confidence.py` | Per-detector confidence scoring. |
| `dedup.py` | Windowed, memory-bounded correlation. |
| `repository.py` | `AlertRepository` port + `InMemoryAlertRepository` adapter. |
| `notifications.py` | `NotificationHook` extension point + email/webhook/Slack stubs. |
| `dispatcher.py` | Fail-open fan-out to registered hooks. |
| `factory.py` | Builds `Alert`s from detections and rule matches. |
| `service.py` | `AlertService` — orchestrates the pipeline, exposes queries. |

## The Alert model

| Field | Notes |
|---|---|
| `alert_id` | UUID4, assigned on creation. |
| `timestamp` / `last_seen` | UTC; `last_seen` advances on each merged duplicate. |
| `severity` | `info` \| `low` \| `medium` \| `high` \| `critical`. |
| `source` | `detector` or `rule_engine`. |
| `rule_triggered` | Detector class name or YAML rule name. |
| `src_ip` / `dst_ip` / `src_port` / `dst_port` / `protocol` | Network context. |
| `packet_summary` | One-line description of the offending traffic. |
| `confidence` | Float in `[0.0, 1.0]`. |
| `tactic` / `technique` | MITRE ATT&CK IDs, e.g. `TA0043` / `T1046`. |
| `status` | `new` \| `acknowledged` \| `resolved` \| `false_positive`. |
| `occurrences` | Number of identical events folded into this record. |
| `evidence` | Detector counters supporting the detection. |

## Confidence scoring

```
confidence = CONFIDENCE_BASE
           + severity_rank * CONFIDENCE_SEVERITY_WEIGHT
           + magnitude_ratio * CONFIDENCE_EVIDENCE_WEIGHT
```

`magnitude_ratio` measures how far past its reference threshold a detector
fired, saturating at 5× so one enormous burst cannot imply certainty. Detectors
in `FLAT_SCORE_DETECTORS` score on severity alone. Signature (YAML rule)
matches bypass the heuristic model and use `CONFIDENCE_RULE_ENGINE` with a
small severity penalty, since a rule either matched every condition or it
did not.

All weights live in `constants.py` — no thresholds are hardcoded in source.

## Deduplication

The dedup key is `(rule_triggered, src_ip, dst_ip, severity)`. Alerts sharing a
key inside `DEDUP_WINDOW_SECONDS` are merged. State is bounded twice over:
expired entries are pruned on every ingest, and the tracker LRU-evicts once
`DEDUP_MAX_TRACKED_KEYS` is exceeded — the OOM failure mode called out in the
Detection Engine PRD.

## Extension points

**Add a notification channel** — subclass `NotificationHook`, implement `name`
and `send`, then register it:

```python
sdk.register_notification_hook(MyPagerDutyHook(enabled=True,
                                               min_severity=Severity.CRITICAL))
```

Hooks are fail-open: one that raises is logged and skipped, never blocking
detection or persistence.

**Add a storage backend** — implement `AlertRepository` and pass it to
`AlertService(repository=...)`. Milestone 9 adds the SQLAlchemy adapter this
way, with no changes to the service.

**Add a detector** — add one entry to `DETECTOR_MITRE_MAP` (tactic/technique)
and, if the detector reports a magnitude, one entry to
`DETECTOR_EVIDENCE_PROFILE`. Unmapped detectors still work: they degrade to no
MITRE attribution and severity-only scoring rather than raising.

## SDK surface

```python
sdk.list_alerts(severity=Severity.CRITICAL, limit=50)
sdk.get_alert(alert_id)
sdk.get_alert_statistics()          # {'total_alerts': int, 'by_severity': {...}}
sdk.register_notification_hook(hook)
```

Detector alerts reach the pipeline automatically: the SDK wires
`DetectionService(alert_callback=...)` to the alert service at construction.
