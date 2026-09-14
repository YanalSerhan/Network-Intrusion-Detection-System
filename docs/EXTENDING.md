# Extending Network Defender

Three things are designed to be added from outside this repository: a
**detector**, a **threat intel provider**, and a **notification channel**. This
document is how, and what each contract requires of you.

There is a fourth extension point that needs no Python at all — a **YAML
signature rule** dropped into `rules/`. See
[RULE_SCHEMA.md](RULE_SCHEMA.md); the rest of this document is about code.

The working examples are in `tests/fixtures/example_plugin/`. They are real —
the test suite loads and runs them on every run — so if this document and they
ever disagree, believe them.

## The rule that shapes all of this

**Nothing here requires editing a file in `network_defender/`.** If you find
yourself adding a line to a list inside the package to make your extension
work, that is a bug in the extension points and worth reporting.

The corollary is that your code runs inside the sensor's detection thread, and
the system protects itself from you rather than trusting you. Every extension
is loaded, configured and invoked inside a failure boundary: an import error,
a bad config section, a constructor that raises, an `ingest` that throws on the
tenth packet — each is logged against your class's name and the sensor carries
on with everything else. You cannot take the sensor down, and you also cannot
tell that something went wrong without reading the log, so read it.

## Getting your code loaded

Two routes. They are equivalent; use whichever fits how your code is
distributed.

**A packaged extension** declares an entry point. Installing your distribution
is the entire installation step, and `pip uninstall` is the entire removal:

```toml
# your-extension/pyproject.toml
[project.entry-points."network_defender.detectors"]
jumbo-frames = "my_extension.detectors"

[project.entry-points."network_defender.providers"]
my-reputation = "my_extension.providers"
```

The value names a module; every eligible class in it is found. Naming a class
(`my_extension.detectors:JumboFrameDetector`) is legal and the class half is
ignored, because the module is scanned either way.

**A module beside your sensor** is named in `config/setup.json`, for the case
where packaging one file is more ceremony than it is worth:

```json
{
  "detection": { "detector_modules": ["my_extension.detectors"] },
  "threat_intel": { "provider_modules": ["my_extension.providers"] }
}
```

It must be importable by the sensor's interpreter — on `PYTHONPATH`, or
installed. Both routes are used together if both are present, and a module
named twice loads once.

## A detector

Subclass `BaseDetector`, pair it with a `DetectorConfig`, and implement three
methods. Import from `network_defender.plugins`, which is the surface that is
promised to you; the internal module layout has moved twice.

```python
from network_defender.constants import MitreTactic, Severity
from network_defender.parser.models import ParsedPacket
from network_defender.plugins import BaseDetector, DetectionAlert, DetectorConfig


class JumboFrameConfig(DetectorConfig):
    """Tunables, validated by Pydantic before your detector is constructed."""

    time_window_seconds: int = 60
    jumbo_bytes: int = 1500
    jumbo_count_threshold: int = 3


class JumboFrameDetector(BaseDetector[JumboFrameConfig]):
    """Counts oversized frames per source."""

    @property
    def name(self) -> str:
        return "JumboFrameDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        ...

    def evaluate(self) -> list[DetectionAlert]:
        ...
```

**The config class is found by name.** `JumboFrameDetector` looks for
`JumboFrameConfig` in the same module — the detector's name with `Detector`
replaced by `Config`. If it is absent you get the bare `DetectorConfig` and
none of your own fields, which is the most common way a new detector silently
ignores its thresholds.

**Your class name is your configuration key.** `detectors.json` is keyed by it,
so `{"JumboFrameDetector": {"jumbo_count_threshold": 10}}` is how an operator
tunes you, and `{"enabled": false}` is how they switch you off. A plugin whose
class name collides with a built-in is refused and logged, rather than being
handed thresholds meant for something else.

**`ingest` is called for every packet, on the capture path.** Do the cheap
part here — a counter, a set membership, a length comparison — and nothing
that blocks. No disk, no network, no lock you did not take yourself. A
detector that takes a millisecond per packet costs a thousand packets per
second of throughput.

**`evaluate` is called on a timer** (`detection.evaluation_interval_seconds`,
five seconds by default) and returns the alerts you want raised. Three things
about it are easy to get wrong:

- **Do not clear your state.** Expire it by *age*, against the packet
  timestamps you were given, not by the fact that you were asked. Clearing on
  evaluate makes your window tumbling and anchored to when the sensor
  happened to start, which means identical traffic detects or does not
  depending on phase. `detectors/window_counts.py`, `window_peers.py` and
  `window_timestamps.py` are sliding counters you can use directly.
- **Report an episode once.** `self.report_once(key, over_threshold)` returns
  True only on the evaluation that crosses the line, and re-arms when the
  condition clears. Without it a flood lasting a minute is twelve identical
  alerts.
- **Use packet time, not wall time.** Everything in this system takes its
  clock from packet timestamps, which is what makes replaying a capture give
  the same answer every time.

Build alerts with `self.emit_alert(...)` rather than constructing
`DetectionAlert` yourself: it sets `detector_name`, which the alert service
uses to choose MITRE mapping and confidence scoring. An alert with the wrong
name is misfiled, not merely mislabelled.

## A threat intel provider

Subclass `ThreatIntelProvider` and declare the rate-limit bucket your calls
come out of:

```python
from network_defender.constants import ProviderStatus
from network_defender.plugins import ProviderResult, ThreatIntelProvider


class ExampleReputationProvider(ThreatIntelProvider):
    rate_limit_bucket = "example_reputation"   # a key in config/rate_limits.json
    config_name = "example_reputation"         # what an operator enables
    requires_api_key = True

    @property
    def name(self) -> str:
        return "example_reputation"

    def lookup(self, ip: str) -> ProviderResult:
        response = self.gatekeeper.execute(...)
        return ProviderResult(provider=self.name, status=ProviderStatus.OK, ...)
```

**Every outbound call goes through `self.gatekeeper`.** This is
[ADR 3](PLAN.md#adr-3-centralized-api-gatekeeper), and it is enforced by construction rather than by
asking: you do not create your gatekeeper, the factory does, by looking up
`rate_limit_bucket` in `config/rate_limits.json` and constructing you with
what it finds. A provider that names no bucket is refused, and one whose
bucket an operator has not funded is skipped. There is no path to a provider
that makes unlimited calls, including for you.

Providers hitting the same upstream host should share a bucket. Being limited
twice over is being limited not at all.

**`lookup` must never raise.** Return a `ProviderResult` with
`ProviderStatus.ERROR` instead. The system fails open: enrichment is a bonus,
and an alert without it is still an alert.

Set `requires_api_key = True` if you need a credential, and read it from the
environment — never a literal. The service will skip you when it is absent
rather than spending retries on guaranteed 401s.

An operator enables you by adding your `config_name` to
`threat_intel.providers` and your bucket to `rate_limits.json`. Being
installed is not being switched on.

## A notification channel

Subclass `NotificationHook` and register it on a running SDK:

```python
from network_defender import NetworkDefenderSDK, NotificationHook


class SlackHook(NotificationHook):
    @property
    def name(self) -> str:
        return "slack"

    def send(self, alert) -> None:
        ...


sdk = NetworkDefenderSDK.create()
sdk.start()
sdk.register_notification_hook(SlackHook(min_severity=Severity.HIGH))
```

`min_severity` routes only what is worth a channel's noise. Failures are
isolated per hook, so one broken channel never stops an alert being persisted.

Hooks receive alerts that survived deduplication, in the order they were
raised. `cli/collector.py` is the smallest possible example: a hook that keeps
what it is handed, used by `network-defender replay` to report what that run
found rather than everything in the database.

## Checking that it worked

```bash
network-defender replay path/to/capture.pcap
```

The log line on startup says how many detectors loaded and how many came from
plugins. If yours is not among them, the reason is in the log above it — an
import error, a config section that would not validate, a name collision, or a
`config` parameter without a type annotation.

For a provider, `GET /health` lists the ones that were constructed. A provider
you expected and do not see was disabled, unfunded, or missing its key.

## What is deliberately not extensible

- **The parser.** `ParsedPacket` is the contract every detector depends on;
  letting a plugin change what a field means would make every other detector's
  behaviour depend on what else is installed.
- **The alert pipeline's shape.** Build, deduplicate, persist, notify, enrich,
  in that order. Hooks attach to the notify step; the order is not negotiable
  because persistence must not depend on a third party being reachable.
- **The gatekeeper.** See above. It is the one thing in this system that
  exists specifically to constrain code that has not been reviewed.
