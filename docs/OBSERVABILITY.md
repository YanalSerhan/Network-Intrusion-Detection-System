# Logging & Observability (Milestone 12)

Structured JSON logs, three separate streams, correlation IDs that survive the
pipeline's thread hand-offs, and redaction that runs on the handler so no call
site can forget it. Implementation in
`src/network_defender/observability/`.

## Log format

One JSON object per line:

```json
{"timestamp":"2026-08-11T20:24:52.011418+00:00","level":"INFO","logger":"network_defender.security","service":"network-defender-sensor","message":"Alert raised","correlation_id":"294a38edbbf74301","event":"alert_raised","alert_id":"9b18a890-…","rule":"TcpPortScanDetector","severity":"high","confidence":0.83,"src_ip":"45.155.205.233"}
```

| Field | Always present | Notes |
|---|---|---|
| `timestamp` | yes | ISO-8601, UTC. |
| `level` | yes | `DEBUG` … `CRITICAL`. |
| `logger` | yes | Dotted logger name. |
| `service` | yes | `network-defender-sensor` or `network-defender-api`, so a shared aggregator can tell them apart. |
| `message` | yes | Already interpolated. |
| `correlation_id` | when in scope | Ties together everything about one finding or request. |
| `source` | `WARNING`+ only | `module:function:line`. Omitted on `INFO` — it inflates volume for no benefit. |
| `exception` | on error | Full traceback, folded into one field. |
| *anything else* | — | Whatever the call site passed via `extra=`, merged at the top level so `alert_id` is queryable as `alert_id`. |

**Why single-line.** Aggregators split on newlines. A pretty-printed record
becomes several unrelated entries and a stack trace becomes dozens — exactly
when you most need them grouped.

## Streams

| Logger | Answers | Typical contents |
|---|---|---|
| `network_defender` | What did the software do? | Service lifecycle, failures, debugging. |
| `network_defender.security` | What did the network do? | `rule_match`, `detector_alert`, `alert_raised`. The detection record an incident review reads. |
| `network_defender.audit` | Who asked the system for what? | `http_request`, outbound API calls through the gatekeeper. |

Security and audit have `propagate = False`. Without it every detection record
would also be written by the application handler — doubling volume and mixing
the detection record into the debugging log.

## Destinations

**Console (stdout) is always configured.** Containers expect it, and the
orchestrator handles collection and rotation.

**Rotating files are opt-in**, for bare-metal deployments where nothing else
captures stdout. Enable in `config/logging_config.json`:

```json
{
  "level": "INFO",
  "files": {
    "enabled": true,
    "app": "logs/app.log",
    "security": "logs/security.log",
    "audit": "logs/audit.log",
    "max_bytes": 10485760,
    "backup_count": 5
  }
}
```

They are off by default so a stray `logs/` directory does not appear on every
test run. A missing or malformed config falls back to defaults rather than
raising — a typo should not silence the system that would report it.

## Correlation IDs

An ID is minted when a **detector or rule fires**, and when an **HTTP request
arrives**. It then follows that work through everything downstream:

```
detector fires ──▶ correlation_scope()
                     ├─ alert built, scored, deduplicated
                     ├─ alert persisted          ─┐
                     ├─ notifications dispatched   ├── all share one ID
                     └─ enrichment queued ─────────┘
                            │
                            └─▶ worker thread re-enters the scope
```

Query one ID and you get the whole life of an alert.

**Not per packet.** At the 10k pps target that would mint 10,000 UUIDs a second
for traffic that is almost entirely discarded, and the resulting logs would be
untraceable by volume alone.

**Threads.** `ContextVar` is not inherited by `threading.Thread`, and this
pipeline crosses three thread boundaries. The enrichment queue carries the ID
alongside the alert; `bind_correlation_id()` wraps any callable handed to a
thread.

**HTTP.** An inbound `X-Correlation-ID` is honoured rather than overwritten, so
a trace started upstream continues here. The ID is echoed in the response
header, so a user reporting a problem can quote it.

## Secret redaction

Runs as a **filter on every handler**, not at call sites. "Just don't log
secrets" fails in practice — a dict gets logged wholesale, an exception message
embeds a connection string, a new provider adds a token field. Logs are also
the artefact most likely to be shipped off-host or pasted into a ticket.

Redacted:

- Values of fields whose name contains `password`, `token`, `api_key`,
  `secret`, `authorization`, `credential`, `session`, … (case-insensitive,
  substring match, applied recursively into nested dicts and lists).
- Credential-shaped text anywhere: DSN passwords (`postgresql://u:pw@host`),
  `key=value` pairs, and `Bearer <token>`.
- Exception tracebacks, redacted at render — the filter runs before the
  traceback exists, so this is handled in the formatter.

Records are **never dropped**, only scrubbed: losing the operational signal
along with the secret would be worse.

Two bugs this caught during implementation, both now regression-tested:

1. A secret inside an exception message survived the filter entirely.
2. `Authorization: Bearer <token>` matched the generic key/value pattern first,
   redacting the word "Bearer" and leaving the token in plain sight. Pattern
   order now puts the Bearer rule first.

Access logs record the request path but **never the query string** — filters
carry IP addresses, and the WebSocket handshake carries the API key as
`?token=`.

## Usage

```python
from network_defender.observability import (
    correlation_scope, get_security_logger, setup_logging,
)

setup_logging(service="network-defender-sensor")   # once, at process start

with correlation_scope():
    get_security_logger().info(
        "Alert raised",
        extra={"event": "alert_raised", "alert_id": str(alert_id), "severity": "high"},
    )
```

`setup_logging` is idempotent, so importing a module twice cannot double every
log line.

## Testing

```bash
uv run pytest tests/observability
```

33 tests covering required fields, single-line output, source-location
gating, exception folding, redaction across text/fields/nesting/exceptions,
correlation scoping and restoration, the thread-boundary behaviour that makes
`bind_correlation_id` necessary, stream isolation, rotation settings, and
fallback on a broken config.
