# Developer guide

How to work on Network Defender: getting set up, the rules the layering
depends on, and the two extension points — a new detector and a new threat
intelligence provider — with recipes that were run before being written down.

For coding standards and the pull request process see
[CONTRIBUTING.md](../CONTRIBUTING.md); for naming, [CONVENTIONS.md](CONVENTIONS.md).

## Setting up

```bash
uv sync --all-groups          # runtime, dev and research dependencies
uv run pytest                 # 1150+ tests, coverage gated at 85%
uv run ruff check
uv run mypy
uv run network-defender replay tests/data/pcaps/tcp_port_scan.pcap
```

`uv` is the only dependency manager; there is no `requirements.txt`, no
`setup.py` and no virtualenv to activate. `uv run` resolves the locked
environment, so a command that works for you works in CI.

Pre-commit hooks run ruff and mypy against the locked environment:

```bash
uv run pre-commit install
```

## Project structure

```
network-defender/
├── src/network_defender/       the library; everything importable
│   ├── capture/                Scapy sniffer, BPF filters, PCAP read/write
│   ├── parser/                 raw packet → ParsedPacket
│   ├── detectors/              base classes, registry, and impl/ (13 detectors)
│   ├── rules/                  YAML signature engine, windowed counters
│   ├── services/               capture, detection, alerts/, threat_intel/, maintenance
│   ├── database/               SQLAlchemy models, repositories, retention
│   ├── api/                    FastAPI app, routers/, schemas/, live/, static SPA
│   ├── sdk/                    NetworkDefenderSDK — the only entry point
│   ├── cli/                    `network-defender` sensor | api | replay
│   ├── shared/                 config, gatekeeper, credentials, paths, secrets
│   ├── observability/          structured logging, redaction, correlation IDs
│   └── constants/              names and defaults nothing else may hardcode
├── frontend/                   React + TypeScript dashboard (Vite)
├── config/                     detectors.json, setup.json, rate_limits.json
├── rules/                      YAML signature rules
├── migrations/                 Alembic revisions
├── scripts/                    pcap generation, benchmarks, sensitivity analysis
├── notebooks/                  detection_analysis.ipynb
├── research/                   committed sweep results
├── tests/                      unit/ mirrors src/; integration/, e2e/, performance/
└── docs/                       everything in this directory
```

### Where the checklist's packages actually live

The Milestone 22 checklist names `dashboard/`, `models/` and `utils/`. None
exists, and the deviations are decisions rather than drift — recorded here so
they read as such.

| Checklist name | Where it is | Why |
|---|---|---|
| `dashboard/` | `frontend/` (the SPA), `api/routers/dashboard.py` (serving it), `api/static/` (build output) | The dashboard is a TypeScript application with its own toolchain, tests and lockfile. Putting it under the Python package would make `uv` responsible for a Vite build. Serving it is 40 lines and belongs with the other routes. |
| `models/` | `parser/models.py`, `detectors/models.py`, `services/alerts/models.py`, `services/threat_intel/models.py`, `database/models.py`, `api/schemas/` | A single `models/` package would import from every layer, which is the shape that produces circular imports and a module nobody can change safely. Each package owns its own types, and the boundary crossings are explicit and few. |
| `utils/` | `shared/` | `utils` is a name that means "things with no home", and a directory called that accumulates them. `shared/` holds config loading, the gatekeeper, credential comparison, path resolution and secret access — each with a docstring saying what it is responsible for. Nothing goes there because it fits nowhere else. |

Two more worth knowing:

- **`constants/`** exists so that no threshold, path or magic string is written
  twice. If you are about to type a literal that another module also knows,
  it goes here — or, if an operator should be able to change it, in
  `config/`.
- **`services/alerts/` and `services/threat_intel/` are packages, not
  modules.** Both outgrew a file: alerting is deduplication, confidence
  scoring, MITRE mapping, notification and persistence, and each of those is
  separately testable.

### Tests mirror source

`tests/unit/<package>/test_<module>.py` for every module, so the test for a
file is always at the mirrored path and a failure names the file that broke.
`tests/integration/` wires real components together, `tests/e2e/` replays
captures through the SDK with nothing mocked, and `tests/performance/` holds
the throughput floors.

## The rules that hold the layering up

Three, and each exists because breaking it is easy and the damage is delayed.

**Every entry point goes through the SDK.** Routers, the CLI and any embedder
call `NetworkDefenderSDK`; nothing outside `sdk/` constructs or drives a
service. A handler that reached into `AlertService` directly would work, and
would be the first crack between what the API does and what the CLI does.
Importing a *model* from `services/*/models.py` is fine — those are the data
contract.

**Every outbound call goes through the gatekeeper.** `ApiGatekeeper` owns the
rate limits, the queue and the circuit breaker, and a provider cannot be
constructed without one. There is exactly one `httpx` call site in the
repository. Adding a second is how a provider quietly exceeds a free tier at
three in the morning.

**Every file stays under 150 lines** (ADR 4), enforced by
`tests/unit/test_file_length_limit.py`. When a module outgrows it, split along
the concern boundary rather than at the line count — the file name should
still say what failed.

## Adding a detector

Everything the registry needs is in the class. There is no list to update and
no registration call.

**1. Write the module** in `src/network_defender/detectors/impl/`. A detector
is a config model plus a class:

```python
"""
Detects hosts talking to an unusual number of distinct ASNs.

Data Setup:  A set of ASNs per source, cleared every window.
Data Input:  Parsed packets, one at a time.
Data Output: One DetectionAlert per source over the threshold.
"""

from pydantic import Field

from network_defender.constants import MitreTactic, Severity
from network_defender.detectors.models import DetectorConfig
from network_defender.parser.models import ParsedPacket

from .breadth import BreadthDetector


class AsnSpreadConfig(DetectorConfig):
    """Tunables for the ASN spread detector."""

    time_window_seconds: int = Field(default=60)
    unique_asn_threshold: int = Field(default=25)


class AsnSpreadDetector(BreadthDetector[AsnSpreadConfig]):
    """Detects one source reaching an unusual number of distinct networks."""

    evidence_key = "unique_asns"
    severity = Severity.MEDIUM
    tactic = MitreTactic.RECONNAISSANCE

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "AsnSpreadDetector"

    @property
    def threshold(self) -> int:
        """Distinct networks per window at or above which to report."""
        return self.config.unique_asn_threshold

    def counts(self, packet: ParsedPacket) -> bool:
        """Return True for packets worth attributing to a network."""
        return bool(packet.dst_ip)

    def peer(self, packet: ParsedPacket) -> str | None:
        """A destination network is the unit of breadth here."""
        return packet.dst_ip

    def describe(self, count: int) -> str:
        """Describe the finding for the analyst reading the alert."""
        return f"Unusual network spread: {count} distinct networks contacted."
```

**Pick the right base class.** Four exist and the choice is about what the
state is, not about convenience:

| Base | State per key | Use when |
|---|---|---|
| `DestinationCountingDetector` | an integer, keyed on `dst_ip` | volume aimed at a victim — floods |
| `SourceCountingDetector` | an integer, keyed on `src_ip` | volume produced by one host — brute force |
| `BreadthDetector` | a set, keyed on `src_ip` | how many *distinct* things a host touched |
| `BaseDetector` | whatever you need | timestamps, byte totals, anything else |

Counting and breadth are separate hierarchies because one holds an integer and
the other a set, and that difference is the measurement. If a client retrying
one port should count once, you want breadth.

**2. Add its configuration** to `config/detectors.json`:

```json
"AsnSpreadDetector": {
  "enabled": true,
  "time_window_seconds": 60,
  "unique_asn_threshold": 25
}
```

The registry validates this section against your config class. A malformed
section disables that one detector and logs why, rather than failing startup —
a sensor running twelve of thirteen detectors and saying so beats one that
refuses to start.

**3. Register the evidence key** in
`src/network_defender/services/alerts/reference_thresholds.py`:

```python
"AsnSpreadDetector": ("unique_asns", "unique_asn_threshold"),
```

Skipping this is not fatal — confidence scoring falls back to severity alone —
but the alert then carries a less informative score forever, silently.

**4. Write the tests first.** Mirror the path:
`tests/unit/detectors/impl/test_asn_spread.py`. At minimum: it fires at the
threshold, it does *not* fire one below it, and it clears its window. The
mutation spot check found `>=` weakened to `>` surviving in most count-based
detectors, so the boundary case is the one that earns its place.

**5. Add a scenario and a golden file.** A builder in
`scripts/pcap_scenarios/`, registered in that package's `SCENARIOS` dict, then:

```bash
uv run python scripts/generate_test_pcaps.py
ND_REFRESH_GOLDEN=1 uv run pytest tests/e2e/test_golden_detections.py
```

**Read the golden diff before committing it.** A golden file refreshed without
anyone looking is a regression test that has quietly stopped testing.

**6. Add it to the corpus.** `scripts/sensitivity/` needs at least two
positive cases at different intensities and — this is the part that matters —
a benign case shaped like your attack. Without one, your detector's precision
is 1.0 by construction, because nothing in the corpus could be mistaken for it.
`tests/unit/sensitivity/test_corpus_integrity.py` enforces the two intensities.

**7. Document it** in [DETECTORS.md](DETECTORS.md), including what it
confuses with.

## Adding a threat intelligence provider

**1. Subclass `ThreatIntelProvider`** in
`services/threat_intel/providers/`. Three rules, from the base class's own
docstring:

- `lookup()` must **never raise**. Return a `ProviderResult` with status
  `ERROR`. The system fails open: an alert is worth raising whether or not a
  third party is reachable.
- Every request goes through `self.gatekeeper.execute(...)`. A direct HTTP
  call bypasses rate limiting and violates ADR 3.
- Set `requires_api_key = True` if it cannot work without one, so the service
  skips it rather than burning retries on guaranteed 401s.

**2. Give it a rate-limit bucket** in `config/rate_limits.json`, and add it to
`PROVIDER_BUCKETS` in `services/threat_intel/factory.py`. Two gates,
deliberately: configuration says which providers an operator wants, the
rate-limit file says which have a budget, and a provider missing a bucket is
skipped even when enabled. That is what makes the gatekeeper mandatory *by
construction* rather than by review.

Providers hitting the same upstream host should share a bucket — the two
ip-api providers do, because limiting them separately would limit the host
twice over.

**3. Test it against canned responses** with `respx`. No test may reach the
network; the proxy environment variables are cleared so a developer behind a
corporate proxy gets the same result as CI. Cover the error path — that is the
one that decides whether the sensor keeps alerting during an outage.

## Adding a signature rule

Drop a YAML file in `rules/`; it is loaded at startup and reloadable at
runtime via `POST /api/v1/rules/reload`. The schema is in
[RULE_SCHEMA.md](RULE_SCHEMA.md).

Rules and detectors are different tools and choosing wrongly is the most
common mistake here. A rule matches **one packet** against a condition. A
detector accumulates state across many. If your idea contains the words
"distinct", "rate" or "over time", it is a detector — the shipped
`tcp_port_scan.yaml` rule counts SYN packets where the detector counts unique
ports, and consequently labels a SYN flood and an SSH brute force as port
scans.

## Testing

`tests/unit/` mirrors `src/network_defender/` one directory per package.
[TESTING.md](TESTING.md) is the full account; the short version:

- **Write the failing test first, and watch it fail.** A test that has never
  failed has not been shown to test anything.
- **A bug fix starts with a test that reproduces the bug.** If it passes
  before the fix, the bug is not understood yet.
- **A test name is a claim.** `test_syn_ack_replies_are_not_a_syn_scan` says
  what must be true; `test_syn_scan_2` says nothing.

```bash
uv run pytest tests/unit          # milliseconds; no files, threads or sockets
uv run pytest tests/e2e           # replays the sample captures
uv run pytest -m performance      # throughput and latency floors
scripts/mutation_spot_check.sh    # would the suite notice the code being wrong?
```
