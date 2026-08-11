# REST API (Milestone 10)

FastAPI service exposing alerts, evidence, statistics and rules. Lives in
`src/network_defender/api/`. The machine-readable contract is committed at
[`docs/openapi.json`](openapi.json); interactive docs are served at `/docs`
(Swagger UI) and `/redoc`.

## Running

```bash
uv run uvicorn network_defender.api.app:create_app --factory --reload
```

Defaults come from `config/setup.json` (`api.host`, `api.port`).

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
