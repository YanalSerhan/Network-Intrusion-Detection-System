# Detector sensitivity analysis — method

How this project measures what a detector threshold costs and buys. The
results are in [DETECTION_TUNING.md](DETECTION_TUNING.md); this file is the
method, so a reader can decide how much to believe them.

## The question

Every detector in `config/detectors.json` carries a number an operator is
expected to tune, and nothing in the repository has ever said what happens
when they tune it. "15 unique ports in 10 seconds" is a claim about a
trade-off — lower it and you catch slower scans, raise it and you stop
reporting the load balancer — but the trade-off had never been measured, so
the shipped values were judgement rather than evidence.

## What is measured

For each detector, a binary classification over a labelled corpus:

- **True positive** — a case labelled for this detector, on which it fired.
- **False positive** — a case *not* labelled for it, on which it fired.
- **False negative** — a case labelled for it, on which it stayed silent.
- **True negative** — a case not labelled for it, on which it stayed silent.

From those: precision, recall, F1, and false-positive rate.

Labels are per-detector rather than a single malicious/benign bit, and that
distinction does real work. A SYN flood is malicious and is not a port scan,
so the flood case is a positive sample for `SynFloodDetector` and a *negative*
sample for `TcpPortScanDetector`. A port-scan detector firing on a flood has
misfiled the finding, and an analyst chasing the wrong hypothesis is a cost
the metrics should carry.

Rates are `None`, not `0.0`, when their denominator is empty. A detector
configured so high it never fires has no precision — there is nothing it
claimed to be right about — and recording that as zero would place it on a
chart beside a detector that fired constantly and was always wrong.

## The corpus

`scripts/sensitivity/corpus_*.py`, 49 cases. Each case is one host behaving
one way for a bounded period.

**Attacks appear at several intensities.** A scan of twelve ports over two
minutes and one of sixty ports over three seconds are both scans, and the
threshold that separates them from ordinary traffic is exactly what is being
looked for. A corpus with one intensity per attack produces a step function
and answers nothing.

**Roughly half the corpus is benign traffic shaped like an attack.** This is
the part that took the design work, and without it every precision figure
would be 1.0 by construction — there would be nothing present that *could*
be mistaken. The negatives are drawn from the hosts whose job is to behave
like an attacker:

| Case | Which detector it competes with | Why it is hard |
|---|---|---|
| `busy_web_server_300` | SYN flood | Flood detectors key on the destination. Three hundred real clients and a distributed flood produce the same per-destination count. |
| `service_inventory_14ports` | port scan, SYN scan | A monitoring agent enumerating services is port fanout with a work ticket behind it. |
| `config_mgmt_ssh_14` | SSH brute force, lateral movement | Configuration management opens one SSH session per managed host, from one address. |
| `sso_portal_18` | HTTP brute force | An office behind one NAT address. The textbook cause of a brute-force false positive. |
| `telemetry_agent_60s_20` | beaconing | A telemetry agent posting exactly on a timer — the same shape as the beacon case, differing only in destination, which the detector does not look at. |
| `reputation_lookups_80q` | DNS tunnelling | An endpoint agent doing encoded reputation lookups. Byte for byte the shape of a tunnel. |
| `backup_upload_60mb` | exfiltration | The detector documents itself as having no opinion on destination. This case takes it at its word. |
| `snmp_poll_18_hosts` | lateral movement | Fan-out is a monitoring server's function. |
| `arp_housekeeping_9` | ARP spoofing | Duplicate-address detection after a lease renewal, a few packets below the attack. |
| `voip_stream_400` | UDP flood | Sustained single-source UDP at a rate no control protocol reaches. |

Some of these are not winnable. `reputation_lookups_80q` and
`backup_upload_60mb` are indistinguishable from the attacks they shadow using
only the fields a passive sensor reads, and they are in the corpus so the
measured precision reflects that rather than assuming it away.

**Arrival times are exponential, not evenly spaced.** The first version of the
corpus used a fixed step with ±15% jitter, whose coefficient of variation is
about 0.087 — *inside* the beaconing detector's 0.1 tolerance. Every burst in
the corpus therefore read as a beacon, and the beaconing column was measuring
the fixture. Exponential gaps are the standard model for packet arrivals and
have a coefficient of variation of 1.0. Deliberate regularity is now
`timing.cadence`'s job, used only by the cases that mean it.

## The two axes

**Threshold.** One parameter per detector, the one an operator turns, swept
over about ten values centred on the shipped default and stretched far enough
either side that the curve reaches both ends of its behaviour.

**Window.** The seconds of traffic a detector accumulates before it decides:
1, 5, 10, 30, 60, 300 and 3600.

The window axis is the *evaluation interval*, not the per-detector
`time_window_seconds`, and the reason matters more than the sweep does. Twelve
detector configurations declare a `time_window_seconds`, it is validated, it
is in `config/detectors.json` — and no detector reads it. Detector state is
cleared by `evaluate()`, and `evaluate()` is called by `PeriodicEvaluator` on
one shared timer taken from `detection.evaluation_interval_seconds` in
`config/setup.json`, which ships at 5.0 seconds. So the effective window for
every detector is five seconds, and a configuration reading "100 SYNs in 1
second" or "10 login attempts in 60 seconds" describes behaviour the code does
not implement. Sweeping the declared field would have produced twelve flat
lines; sweeping the interval measures the parameter that is actually live.

`SuspiciousPortDetector` is not swept. Its operating point is a port list, not
a number. It is still measured at its shipped configuration.

## The harness

`scripts/sensitivity/harness.py`. A case's packets are built once, parsed
once, and sorted into capture order; every grid point then replays that same
list through a *freshly constructed* detector — detectors are stateful, and
reusing one would carry a window's counters into the next configuration.

`replay` calls `evaluate()` once per elapsed window of capture time, which is
what `PeriodicEvaluator` does against wall time. Using capture time is the
only difference, and it is the one that makes a result reproducible.

Firing is monotone in every threshold here: raising it can only silence a
detector. `sweep._summarise` checks that rather than assuming it, and raises
if a detector fires at a high threshold while silent at a lower one — which
would invalidate every curve drawn from these results.

## Running it

```bash
uv sync --all-groups
uv run python scripts/run_sensitivity_sweep.py     # the grid
uv run python scripts/run_alert_timeline.py       # the composed half-hour
uv run python scripts/make_sensitivity_figures.py # docs/images/*.png
uv run jupyter lab notebooks/detection_analysis.ipynb
```

The corpus is seeded from `pcap_scenarios.common.RANDOM_SEED`, so a re-run
reproduces the committed results byte for byte. A diff in `research/` means a
detector changed behaviour, and that is the intended way to notice.

`tests/unit/sensitivity/` guards the corpus itself: labels must name detectors
the registry loads, names must be unique, every swept detector needs at least
two positive intensities, and every case must state why it is there. Each of
those failures is invisible in the results — the numbers stay plausible while
measuring progressively less.

## The composed timeline

The sweep replays each case in isolation, which is what makes precision and
recall well-defined. It is not what an analyst sees, and the difference turns
out to matter more than any single threshold.

`scripts/sensitivity/timeline.py` lays the same cases end to end on one clock:
half an hour with benign traffic running throughout and five attacks placed
inside it, replayed at the shipped configuration and at the recommended one
over identical packets. Each alert is recorded with the window boundary that
produced it — an alert does not exist until the evaluation that emits it — and
with whether an attack the detector is responsible for was running inside that
window.

This is where the corpus's composition stops being a convenience. Half of it
is attacks; a real segment is not, so every false-positive rate measured
against it is multiplied by a much larger denominator in production. An F1
score computed on a balanced corpus will always flatter a lowered threshold,
and the timeline is what prices that back in.

## What this does not measure

- **Synthetic traffic.** Every case is generated, so the corpus contains the
  attacks and the confusions its author thought of. It cannot report a false
  positive nobody imagined. Replaying labelled real captures would fix this
  and is the obvious next step.
- **One behaviour per case.** Real traffic is mixed, and a detector that
  behaves well in isolation can still drown in a busy segment.
- **Alert quality, not just presence.** A case counts as detected if the
  detector fired at all. Whether the alert named the right host, and whether
  the severity and confidence were useful, is not scored here.
- **Cost asymmetry.** F1 weights a missed attack and a false alarm equally.
  Nobody's operations do. The recommended defaults in
  [DETECTION_TUNING.md](DETECTION_TUNING.md) say where they depart from the
  F1 optimum and why.
