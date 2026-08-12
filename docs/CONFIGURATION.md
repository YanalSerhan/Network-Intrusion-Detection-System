# Configuration Reference (Milestone 13)

Every runtime setting, where it comes from, and what it does.

## Sources and precedence

Lowest to highest:

```
model defaults  <  config/*.json  <  ND__SECTION__KEY environment variables
```

Secrets are never in any of those — credentials come from `.env` only.

| File | Contents | Schema |
|---|---|---|
| `config/setup.json` | Capture, API, database, dashboard, detection, threat intel, maintenance | `AppConfig` |
| `config/rate_limits.json` | Per-service outbound rate limits | `RateLimitConfig` |
| `config/detectors.json` | Per-detector thresholds and enable flags | `DetectorConfig` subclasses |
| `config/logging_config.json` | Log level and optional file handlers | see [OBSERVABILITY.md](OBSERVABILITY.md) |
| `.env` (git-ignored) | API keys and the database URL | — |

Related settings stay in one file rather than six: they are always loaded as a
unit, and splitting them would multiply the ways startup can partially fail.

## Environment overrides

Any setting is overridable as `ND__SECTION__KEY`:

```bash
ND__CAPTURE__INTERFACE=eth1
ND__API__PORT=9000
ND__CAPTURE__PROMISCUOUS_MODE=false
ND__THREAT_INTEL__PROVIDERS='["whois","ip_api_geo"]'   # or: whois,ip_api_geo
```

A double underscore separates levels, because single underscores appear inside
key names (`max_packets_per_second`).

Values are coerced against the declared type. This matters more than it looks:
an environment variable is always a string, and `bool("false")` is `True` — so
without coercion, `PROMISCUOUS_MODE=false` would silently enable the thing you
meant to disable. A value that cannot be coerced is passed through so
validation reports it rather than guessing.

This exists so one container image can be built and configured per environment.
Without it, dev, staging and production each need a mounted config file
differing in two lines — which is exactly how those files drift apart.

## Invalid configuration

Startup **aborts** and prints every problem at once:

```
Invalid configuration in setup.json.
  - setup.json: 'api.port' Input should be a valid integer, unable to parse string as an integer (got: 'not-a-port')
  - setup.json: 'maintenance.statistics_interval_seconds' Input should be greater than 0 (got: -5.0)
```

A sensor running on silently-wrong thresholds is worse than one that refuses to
start: it looks healthy while detecting at the wrong sensitivity. Problems are
collected rather than raised one at a time, because fixing configuration one
restart per mistake is a miserable loop.

Malformed JSON is an error — settings were intended and are not being applied.
A *missing* file is not: every section has defaults.

Validate without starting anything:

```python
from network_defender.shared.config import validate_all
validate_all()   # {'setup.json': 'ok', 'rate_limits.json': 'ok'}
```

## `setup.json`

### `capture`

| Key | Default | Description |
|---|---|---|
| `interface` | `eth0` | Interface to capture on. |
| `bpf_filter` | `""` | BPF expression; empty means capture everything. |
| `snaplen` | `65535` | Max bytes captured per packet. |
| `promiscuous_mode` | `true` | Accept frames not addressed to this host. |
| `buffer_size` | `4096` | Capture ring buffer, KB. |
| `max_packets_per_second` | `10000` | Token-bucket limit; `0` = unlimited. |
| `protocol_allow_list` | `[]` | If non-empty, only these protocols pass downstream. |
| `protocol_deny_list` | `[]` | Protocols dropped before processing. |
| `pcap_output_dir` | `captures/` | Where saved PCAPs are written. |

### `api`

| Key | Default | Description |
|---|---|---|
| `host` / `port` | `0.0.0.0` / `8000` | Bind address. |
| `reload` | `false` | Auto-reload; development only. |
| `workers` | `1` | Uvicorn worker processes. |

### `database`

| Key | Default | Description |
|---|---|---|
| `url_env_var` | `DATABASE_URL` | Env var holding the connection URL. |
| `default_url` | `sqlite:///./network_defender.db` | Fallback when that var is unset. |
| `echo` | `false` | Log SQL statements. |

The URL is a credential (a PostgreSQL DSN embeds a password), so it comes from
`.env` rather than the `ND__` scheme, and `/config` redacts it.

### `dashboard`

| Key | Default | Description |
|---|---|---|
| `host` / `port` | `0.0.0.0` / `3000` | Reserved for a standalone dashboard server. |
| `default_theme` | `dark` | Theme before a user chooses one. |

### `detection`

| Key | Default | Description |
|---|---|---|
| `evaluation_interval_seconds` | `5.0` | How often stateful detectors are evaluated and their windows flushed. Nothing alerts without this. |
| `evaluate_rules` | `true` | Evaluate YAML signature rules per packet. |

### `threat_intel`

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | Master switch for enrichment. |
| `providers` | all four | Providers to construct, in priority order. |
| `cache_ttl_seconds` | `86400` | How long a response stays fresh. Reputation moves over days; a long TTL is what keeps lookups inside a ~10 req/min budget. |
| `cache_max_entries` | `10000` | In-memory bound before LRU eviction. |
| `breaker_failure_threshold` | `5` | Consecutive failures before a provider is cut out. |
| `breaker_reset_seconds` | `300` | Cooldown before one trial request. |
| `http_timeout_seconds` | `10` | Per-request timeout. |
| `enrich_private_ips` | `false` | Send RFC1918 addresses to third parties. Leave off: it leaks internal topology and no feed has an opinion on them. |

A provider is built only if it is **both** listed here **and** has a bucket in
`rate_limits.json` — so adding a provider and forgetting its limits cannot
bypass the gatekeeper (ADR 3).

### `maintenance`

| Key | Default | Description |
|---|---|---|
| `statistics_enabled` | `true` | Record counter snapshots. |
| `statistics_interval_seconds` | `60` | Also the resolution of the throughput chart. |
| `retention_enabled` | `true` | Prune rows past their window. |
| `retention_interval_seconds` | `3600` | Hourly suits day-scale windows and keeps DELETE cost off the hot path. |

Disabling `retention_enabled` means the database grows without bound.

### Top level

| Key | Default | Description |
|---|---|---|
| `version` | `1.00` | Config schema version. |
| `rules_dir` | `rules/` | YAML rules directory. Relative paths resolve from the project root, not the working directory. |
| `config_dir` | `config/` | Directory holding `detectors.json`. |
| `retention_days` | `30` | Alert retention window. |

## `rate_limits.json`

One entry per upstream service (`abuseipdb`, `ip_api`, `whois`):

| Key | Description |
|---|---|
| `requests_per_minute` | Hard ceiling; the gatekeeper blocks past it. |
| `requests_per_day` | Daily budget. |
| `max_queue_depth` | Pending requests before backpressure rejects new ones. |
| `retry_attempts` | Retries on transient failure. |
| `retry_backoff_base_seconds` | Base for exponential backoff. |

## `detectors.json`

Keyed by detector class name. Every detector accepts `enabled`; the rest are
per-detector thresholds, e.g.:

```json
{
  "TcpPortScanDetector": { "enabled": true, "time_window_seconds": 10, "unique_ports_threshold": 15 }
}
```

## Secrets

Only `.env`, never a config file:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Connection string. Overrides `database.default_url`. |
| `API_KEY` | Enables API authentication. **Unset means authentication is disabled.** |
| `ABUSEIPDB_API_KEY` | AbuseIPDB credential; the provider is skipped without it. |

`GET /api/v1/config` reports which secrets are *configured* as booleans, never
their values — so an unset `API_KEY` (and therefore an open API) is visible
rather than silent.

## Verifying

```bash
uv run python -c "from network_defender.shared.config import validate_all; print(validate_all())"
curl localhost:8000/api/v1/config | jq
```
