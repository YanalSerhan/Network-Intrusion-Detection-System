# REST API

FastAPI service exposing alerts, evidence, statistics and rules. Lives in
`src/network_defender/api/`. The machine-readable contract is committed at
[`docs/openapi.json`](openapi.json); interactive docs are served at `/docs`
(Swagger UI) and `/redoc`.

## Running

```bash
uv run network-defender api                       # config/setup.json defaults
uv run network-defender api --port 9000 --reload  # overrides
```

Defaults come from `config/setup.json` (`api.host`, `api.port`). The
underlying command is `uvicorn network_defender.api.app:create_app --factory`;
`create_app` is a factory, so serving the attribute directly would hand
uvicorn the function rather than an application.

Three documentation surfaces, all live:

| URL | What it is |
|---|---|
| `/docs` | Swagger UI — every endpoint, with a request builder that works. |
| `/redoc` | The same contract as reference prose. |
| `/openapi.json` | The machine-readable schema, also committed at [`docs/openapi.json`](openapi.json). |

## Topology

This process serves the API and **does not capture packets**. Per PLAN.md §4
the engine and API are separate containers sharing a database:

```
[ sensor container ]  capture → parse → detect → alert ──┐
                                                          ├──▶ [ database ]
[  api container   ]  REST ◀── read ──────────────────────┘
```

`SDK.start_readonly()` brings up only the database, alerting and enrichment
services. The consequences are the point: the API needs no `CAP_NET_RAW`, and
it can be restarted or scaled horizontally without dropping a single packet.

## Endpoints

All paths are prefixed `/api/v1`.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/alerts` | List alerts. Filters: `severity`, `status`, `hours`, `limit`, `offset`. |
| `GET` | `/alerts/{alert_id}` | Full alert with evidence and enrichment. |
| `PATCH` | `/alerts/{alert_id}` | Update triage status. |
| `GET` | `/alerts/{alert_id}/packets` | Packets retained as evidence. |
| `POST` | `/alerts/{alert_id}/enrich` | Run threat intel enrichment now. |
| `GET` | `/packets` | List retained packets. Filters: `alert_id`, `protocol`, `src_ip`. |
| `GET` | `/packets/{packet_id}` | A single retained packet. |
| `GET` | `/statistics` | Totals, severity breakdown, top talkers, protocol distribution. |
| `GET` | `/statistics/timeseries` | Counter snapshots over a window. |
| `GET` | `/rules` | The loaded rule set. |
| `GET` | `/rules/{name}` | A single rule. |
| `PATCH` | `/rules/{name}` | Enable/disable at runtime. |
| `POST` | `/rules/reload` | Re-read rules from disk. |
| `GET` | `/health` | Readiness. Returns 503 when a required component is down. |
| `GET` | `/health/live` | Liveness. Touches nothing. |
| `GET` | `/config` | Non-secret runtime configuration. |

One endpoint is not under `/api/v1`, because it is a transport rather than
part of the data contract:

| `WS` | `/ws/live` | Alerts and counters, pushed as they happen. Authenticated with the same API key. |

### Pagination

Every list endpoint returns the same envelope, so a client writes one helper:

```json
{
  "items": [ ... ],
  "meta": { "limit": 100, "offset": 0, "count": 42, "total": 42, "has_more": false }
}
```

`limit` is capped at 500 — without a ceiling, one request becomes an unbounded
query and response body. `total` is omitted for filter combinations where
counting would double the cost of the common request.

### Errors

Every failure uses one shape, with a stable `code` clients branch on:

```json
{ "error": { "code": "not_found", "message": "No alert with id '...'.", "detail": null } }
```

| Code | Status | Meaning |
|---|---|---|
| `validation_error` | 422 | Bad input; `detail` lists offending fields. |
| `unauthorised` | 401 | Missing or wrong API key. |
| `not_found` | 404 | No such resource or route. |
| `conflict` | 409 | Not applicable in the current state. |
| `internal_error` | 500 | Unexpected failure; details are logged, never returned. |

FastAPI's defaults would emit three different shapes here (`{"detail": ...}`,
a bare list, and an HTML traceback). Normalising them means one client-side
parser, and no stack traces in HTTP responses.

## Authentication

Set `API_KEY` in `.env` and send it as `X-API-Key`:

```bash
curl -H "X-API-Key: $API_KEY" http://localhost:8000/api/v1/alerts
```

**Authentication is disabled when no key is configured.** That keeps local
development frictionless, but it also means an unconfigured deployment is
open — so `/config` reports `secrets_configured.API_KEY` and makes the gap
visible rather than silent. `/health` and `/health/live` are always
unauthenticated, since an orchestrator probing them has no credentials.

## Health probes

Liveness and readiness are deliberately different:

- **`/health/live`** touches nothing. If it checked the database, a database
  blip would make an orchestrator kill and restart healthy API pods, turning a
  dependency problem into an outage.
- **`/health`** checks the database and alerting, returning 503 when either is
  unhealthy, so a failing instance leaves the load balancer without being
  killed.

Capture and detection appear in the component list but are not required: they
run in the sensor container, so their absence here is expected.

## Rule toggling

`PATCH /rules/{name}` is a **runtime override**. It updates the running engine
and the database snapshot; it does not rewrite the YAML file. A service that
edits its own config fights hot-reload and diverges from what an operator
committed to git. The override is cleared by `POST /rules/reload` or a restart,
which is the right behaviour for an emergency "silence this noisy rule".

To change a rule permanently, edit its YAML file — hot-reload picks it up.


## A worked session

Every response below is real output from a database seeded by replaying three
sample captures:

```bash
uv run network-defender replay tests/data/pcaps/tcp_port_scan.pcap
uv run network-defender replay tests/data/pcaps/ssh_brute_force.pcap
uv run network-defender replay tests/data/pcaps/dns_tunneling.pcap
uv run network-defender api --port 8000
```

**1. What is going on at all?** `/statistics` is the one call a dashboard makes
first, and the aggregation runs in SQL rather than in Python:

```bash
curl -s localhost:8000/api/v1/statistics
```

```json
{"total_alerts": 6,
 "alerts_by_severity": {"info": 0, "low": 0, "medium": 2, "high": 4, "critical": 0},
 "total_packets_retained": 2,
 "top_talkers": [{"ip": "45.155.205.233", "alert_count": 5},
                 {"ip": "192.168.1.50", "alert_count": 1}],
 "protocol_distribution": {"tcp": 2}}
```

**2. Narrow to what matters.** List endpoints take filters and always return
the same envelope — `items` plus `meta`, so a client never has to guess whether
there is more:

```bash
curl -s "localhost:8000/api/v1/alerts?severity=high&limit=2"
```

```json
{"items": [
   {"alert_id": "0e9e4112-8a30-4d9c-acbf-35bf367672d6",
    "timestamp": "2026-08-19T18:52:46.266687Z",
    "severity": "high", "source": "detector",
    "rule_triggered": "DnsTunnelingDetector",
    "src_ip": "192.168.1.50", "confidence": 0.662,
    "tactic": "TA0011", "status": "new", "occurrences": 1}, ...],
 "meta": {"limit": 2, "offset": 0, "count": 2, "total": 4, "has_more": true}}
```

`occurrences` is the deduplication count: one row can stand for hundreds of
repeats of the same finding inside the dedup window, which is what stops a
scan from filling the table.

**3. Open one.** The detail endpoint adds everything the list view omits —
the description an analyst reads first, the evidence the detector based its
decision on, the MITRE technique, and enrichment if it has arrived:

```bash
curl -s localhost:8000/api/v1/alerts/0e9e4112-8a30-4d9c-acbf-35bf367672d6
```

```json
{"alert_id": "0e9e4112-8a30-4d9c-acbf-35bf367672d6",
 "severity": "high", "rule_triggered": "DnsTunnelingDetector",
 "confidence": 0.662, "tactic": "TA0011", "technique": "T1071.004",
 "description": "Possible DNS Tunneling: high frequency of high-entropy DNS queries.",
 "evidence": {"count": 60, "high_entropy": 59},
 "threat_intel": null}
```

`evidence` is the detector's own numbers, not a rendered string: 59 of 60
queries were above the entropy threshold. That is what makes an alert
arguable rather than merely assertive.

**4. Get the packets.** Evidence packets are retained per alert:

```bash
curl -s "localhost:8000/api/v1/alerts/{alert_id}/packets"
```

```json
{"items": [{"timestamp": "2023-11-14T22:13:21.533820Z",
            "src_ip": "45.155.205.233", "dst_ip": "192.168.1.10",
            "src_port": 20, "dst_port": 1014, "protocol": "tcp", "length": 54,
            "raw_summary": "tcp 45.155.205.233:20 \u2192 192.168.1.10:1014 len=54",
            "fields": {"tcp_flags": {"syn": true, "ack": false, ...}}}]}
```

**5. Enrich on demand.** Enrichment normally runs asynchronously; this forces
it for one alert and waits:

```bash
curl -s -X POST localhost:8000/api/v1/alerts/{alert_id}/enrich
```

It is best-effort by design. A provider outage degrades enrichment rather than
detection, so this can legitimately return an alert whose `threat_intel` is
still null. See [THREAT_INTEL.md](THREAT_INTEL.md).

**6. Triage it.** The only write in the whole API:

```bash
curl -s -X PATCH localhost:8000/api/v1/alerts/{alert_id} \
     -H 'Content-Type: application/json' -d '{"status": "acknowledged"}'
```

```json
{"alert_id": "0e9e4112-...", "status": "acknowledged",
 "rule_triggered": "DnsTunnelingDetector"}
```

Valid statuses are `new`, `acknowledged`, `resolved` and `false_positive`.
Anything else is a 422 that names the field and lists what was allowed:

```json
{"error": {"code": "validation_error", "message": "Request validation failed.",
           "detail": [{"field": "body.status",
                       "message": "Input should be 'new', 'acknowledged', 'resolved' or 'false_positive'",
                       "type": "enum"}]}}
```

**7. Follow it live.** Rather than polling, subscribe:

```python
import asyncio, json, websockets

async def watch() -> None:
    async with websockets.connect("ws://localhost:8000/ws/live") as socket:
        async for frame in socket:
            event = json.loads(frame)
            print(event["type"], event.get("payload", {}).get("rule_triggered", ""))

asyncio.run(watch())
```

The dashboard uses exactly this. With an API key configured, pass it as a
query parameter — a browser WebSocket cannot set headers.

**8. Check what is running.** `/health` reports per component, and returns 503
when a *required* one is down. On an API-only process capture and detection
are legitimately not running, which is why they report `unknown` rather than
failing the probe:

```bash
curl -s localhost:8000/api/v1/health      # readiness, 503 when degraded
curl -s localhost:8000/api/v1/health/live # liveness, touches nothing
```

`/config` returns the non-secret configuration the process actually loaded,
which is the quickest way to find out whether an environment override took
effect:

```json
{"version": "1.00",
 "api": {"host": "0.0.0.0", "port": 8000, "reload": false, "workers": 1},
 "capture": {"interface": "eth0", "bpf_filter": "", "snaplen": 65535, ...},
 "detection": {"evaluation_interval_seconds": 5.0, "evaluate_rules": true}}
```

Secrets never appear here. `/config` reports *whether* an API key is
configured, never the key.

## Architecture rule

Every handler parses inputs, calls **one** SDK method, and projects the result
onto a response schema. No filtering, scoring or persistence logic lives in a
route, which is what stops the API, CLI and dashboard from drifting apart.
Aggregation runs in SQL, so "top talkers" over a million alerts is one indexed
query rather than a million-row transfer into Python.

## Regenerating the contract

```bash
uv run python scripts/export_openapi.py
```

Committing the spec makes API changes a reviewable diff: a removed field or a
changed status code shows up in the pull request instead of being discovered by
a client at runtime.
