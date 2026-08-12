"""
Constants for outbound integrations and transports.

Threat intel defaults, REST API metadata and live-feed tuning. Most of these
are *defaults* — the corresponding settings in config/setup.json override them.
"""

from enum import StrEnum

# ---------------------------------------------------------------------------
# Threat intelligence enrichment
# ---------------------------------------------------------------------------


class ProviderStatus(StrEnum):
    """Outcome of a single threat intel provider lookup."""

    OK = "ok"
    ERROR = "error"
    SKIPPED = "skipped"
    CIRCUIT_OPEN = "circuit_open"


class ThreatVerdict(StrEnum):
    """Aggregated reputation verdict for an IP address."""

    UNKNOWN = "unknown"
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


REPUTATION_MIN = 0.0
REPUTATION_MAX = 100.0
#: Aggregated score at or above which an IP is deemed suspicious / malicious.
REPUTATION_SUSPICIOUS_THRESHOLD = 25.0
REPUTATION_MALICIOUS_THRESHOLD = 60.0

#: Response cache: how long a lookup stays fresh, and how many entries are kept.
TI_CACHE_TTL_SECONDS = 86_400  # 24h — IP reputation moves slowly
TI_CACHE_MAX_ENTRIES = 10_000

#: Circuit breaker: consecutive failures before a provider is cut out, and how
#: long it stays cut out before a single trial request is allowed through.
TI_BREAKER_FAILURE_THRESHOLD = 5
TI_BREAKER_RESET_SECONDS = 300.0

#: Background enrichment worker.
TI_QUEUE_MAX_DEPTH = 1_000
TI_WORKER_POLL_SECONDS = 0.5

#: Outbound HTTP.
TI_HTTP_TIMEOUT_SECONDS = 10.0

#: Environment variable names holding provider API keys. Keys live in .env only.
ENV_ABUSEIPDB_API_KEY = "ABUSEIPDB_API_KEY"

# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------
API_TITLE = "Network Defender API"
API_VERSION = "v1"
API_PREFIX = "/api/v1"

#: Environment variable holding the API key. Authentication is disabled when
#: this is unset, so local development needs no configuration.
ENV_API_KEY = "API_KEY"

# ---------------------------------------------------------------------------
# Live dashboard feed
# ---------------------------------------------------------------------------
#: How often the server polls for new alerts. One poller serves every client,
#: so this is the total added database load regardless of viewer count.
LIVE_POLL_SECONDS = 2.0
#: Cap on alerts carried in one frame, so an alert storm cannot produce a
#: multi-megabyte message that stalls the browser.
LIVE_RECENT_ALERT_LIMIT = 50

