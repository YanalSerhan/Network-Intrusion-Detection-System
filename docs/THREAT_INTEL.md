# Threat intelligence

Enriches alerts with external context — IP reputation, geolocation, ASN and
registration data — without ever blocking detection. Lives in
`src/network_defender/services/threat_intel/` and is reached only through the SDK.

## Pipeline

```
AlertService  ──persists & notifies first──▶  (alert is already visible)
      │
      └─▶ EnrichmentWorker queue  ──background thread──▶  ThreatIntelService
                                                                │
                        ┌───────────────────────────────────────┤
                        ▼                                       ▼
                  eligible IP?                           for each provider:
                (public only, else skip)      cache → breaker → gatekeeper → HTTP
                                                                │
                                                    aggregate → Alert.threat_intel
                                                                │
                                                    repository.save(alert)
```

Enrichment costs up to four HTTP calls, each with a 10s timeout plus retries.
Running that inline would put tens of seconds between a detection and its alert
— against a PRD target of sub-100ms — and make detection throughput depend on a
third party's uptime. So alerts are raised, persisted and notified immediately,
then enriched a moment later.

## Providers

| Provider | Upstream | Supplies | Key required |
|---|---|---|---|
| `abuseipdb` | api.abuseipdb.com | Abuse confidence score (0–100) | Yes — `ABUSEIPDB_API_KEY` |
| `ip_api_geo` | ip-api.com | Country, region, city, coordinates | No |
| `ip_api_asn` | ip-api.com | AS number, organisation, ISP | No |
| `whois` | rdap.org | Network name, CIDR, registrant, abuse contact | No |

RDAP is used instead of port-43 WHOIS because it returns structured JSON over
HTTPS, so it shares the same gatekeeper-mediated HTTP path as everything else
rather than needing a raw socket and per-registry text parsing.

Geolocation and ASN are separate providers over one upstream so either can be
disabled or swapped for a commercial source without disturbing the other. They
deliberately **share the `ip_api` rate-limit bucket** — same host, one budget.

## Guarantees

**Every request passes the gatekeeper.** Providers call
`self.gatekeeper.execute(get_json, ...)`; `get_json` is the only code that
touches the network. The factory only constructs a provider when its bucket
exists in `config/rate_limits.json`, so there is no path that produces a
provider without one.

**Providers never raise.** Transport errors, non-2xx status, malformed JSON and
unexpected schemas all become `ProviderResult(status=ERROR)`. A dead provider
degrades enrichment; it never suppresses an alert.

**Private IPs are never sent anywhere.** RFC1918, loopback, link-local,
multicast, reserved and documentation ranges are refused before any request —
both to avoid leaking internal topology to a vendor and because no reputation
feed has an opinion on them.

**State is bounded everywhere.** The response cache is TTL-fresh and
LRU-capped; the enrichment queue drops oldest-first when full. Losing
enrichment is survivable; exhausting memory is not.

## Scoring

The aggregate reputation is the **maximum** across providers that expressed an
opinion, not the mean. An address flagged 95/100 by one feed and unknown to
three others is still dangerous; averaging would dilute that to 24 and bury it.
The per-provider breakdown is retained so an analyst can see who said what.

| Aggregate score | Verdict |
|---|---|
| no opinion | `unknown` |
| 0 – 24.9 | `clean` |
| 25 – 59.9 | `suspicious` |
| 60 – 100 | `malicious` |

Thresholds live in `constants.py`.

## Circuit breaker

Opens after `TI_BREAKER_FAILURE_THRESHOLD` consecutive failures and admits one
trial call after `TI_BREAKER_RESET_SECONDS`. Without it, every lookup against a
down provider pays the full timeout and burns all its retries — roughly 40
seconds per alert spent on a service already known to be failing.

The cache is checked **before** the breaker, so a tripped circuit still serves
data already known to be good.

## Adding a new provider

1. **Subclass `ThreatIntelProvider`** in `services/threat_intel/providers/`:

```python
from network_defender.constants import ProviderStatus
from ..base import ThreatIntelProvider
from ..http import get_json
from ..models import ProviderResult

VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


class VirusTotalProvider(ThreatIntelProvider):
    """Looks up an IP's detection ratio on VirusTotal."""

    requires_api_key = True

    @property
    def name(self) -> str:
        return "virustotal"

    def lookup(self, ip: str) -> ProviderResult:
        if not self.is_configured:
            return ProviderResult(
                provider=self.name, status=ProviderStatus.SKIPPED, error="key not set"
            )
        try:
            payload = self.gatekeeper.execute(
                get_json,
                VIRUSTOTAL_URL.format(ip=ip),
                headers={"x-apikey": self.api_key or ""},
            )
        except Exception as exc:          # never raise
            return self._error(str(exc))

        stats = payload["data"]["attributes"]["last_analysis_stats"]
        total = sum(stats.values()) or 1
        return ProviderResult(
            provider=self.name,
            status=ProviderStatus.OK,
            reputation_score=100.0 * stats.get("malicious", 0) / total,
        )
```

2. **Add its rate-limit bucket** to `config/rate_limits.json`:

```json
"virustotal": {
  "requests_per_minute": 4,
  "requests_per_day": 500,
  "max_queue_depth": 20,
  "retry_attempts": 2,
  "retry_backoff_base_seconds": 2.0
}
```

3. **Register it** in `services/threat_intel/factory.py`:

```python
PROVIDER_BUCKETS = [
    ...,
    (VirusTotalProvider, "virustotal"),
]
```

   If it needs a key, add the env var name to `constants.py`, `.env-example`,
   and the `api_keys` mapping in `build_providers`.

4. **Test it** with `respx`, mocking at the transport layer so URL building,
   headers, status handling and JSON decoding are all exercised. See
   `tests/unit/services/threat_intel/test_providers.py`.

No changes to `ThreatIntelService`, the cache, the breaker or the worker are
needed — they operate on the port, not on concrete providers.

## Configuration

`config/rate_limits.json` — one bucket per upstream service.
`.env` (git-ignored) — API keys only. `describe_secrets()` reports whether a key
is set without ever exposing its value, so health output stays safe to publish.

## SDK surface

```python
sdk.enrich_ip("45.155.205.233")      # ad-hoc lookup
sdk.enrich_alert_now(alert_id)       # synchronous; for an analyst opening an alert
sdk.get_threat_intel_status()        # providers, circuits, cache, worker stats
```

Alerts are enriched automatically in the background; `enrich_alert_now` exists
for the case where enrichment was dropped under load or has not run yet.
