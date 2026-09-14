# Quality against ISO/IEC 25010

The eight product-quality characteristics, each with what this project
actually does about it, the evidence, and what is missing. Sub-characteristics
are named where they say something different from their parent.

Numbers are measured on a two-core container and quoted as orders of
magnitude, not benchmarks. Every one can be reproduced:

```bash
uv run pytest                    # 1,388 tests, coverage gate at 85%
uv run pytest -m performance     # the latency and throughput floors
uv run python scripts/run_sensitivity_sweep.py
```

A summary first, because the detail below is long and the shape of it matters
more than any row:

| Characteristic | State | The gap that matters most |
|---|---|---|
| Functional suitability | Measured, and mixed | Half the detectors miss the quiet half of their attack |
| Performance efficiency | Measured, and the ceiling is low | ~1,000 packets/second, set by the parser |
| Compatibility | Good | Linux only, in practice |
| Usability | Adequate for an operator, thin for an analyst | No triage workflow beyond a status field |
| Reliability | Good in the small, absent in the large | Single node; no HA, no failover |
| Security | Good for its size | One API key, all-or-nothing |
| Maintainability | The strongest characteristic | Lint and types are not enforced in CI |
| Portability | Good | No container images |

---

## 1. Functional suitability

**Completeness.** Thirteen detectors across reconnaissance, denial of service,
credential access, command and control and exfiltration, plus a YAML signature
engine, threat intel enrichment, a REST API and a dashboard. The PRD's
non-goals — blocking, TLS interception, host agents — are absent by decision
and recorded as such in [ROADMAP.md](ROADMAP.md).

**Correctness.** This is the characteristic with the most evidence and the
least comfortable answer. Against a 49-case labelled corpus, mean recall
across the twelve tunable detectors is **0.74**, up from 0.41 before Milestone
21 fixed the window implementation. Five detectors catch the loud version of
their attack and miss the subtle one. For five, benign and malicious ranges
overlap and *no* threshold separates them — the full accounting is in
[DETECTION_TUNING.md](DETECTION_TUNING.md) §4.

The measurement itself is the strongest claim here: a system that says 0.74 is
worth more than one that says nothing, and the corpus is half benign traffic
deliberately shaped like an attack, so precision is not 1.0 by construction.

**Appropriateness.** The composed half-hour timeline is the honest test: seven
alerts, six real, one false, five of five attacks found. An alert volume an
analyst would actually read.

**Gap.** The corpus is synthetic. Every number here comes from generated
traffic and contains the confusions its author thought of. Replaying labelled
real captures is the single biggest improvement available and would change
some of these figures.

## 2. Performance efficiency

**Time behaviour.** Per-packet detection latency p95 ≈ 0.24 ms, p99 ≈ 0.30 ms.
Detection ingest absorbs tens of thousands of packets per second. Parsing
manages on the order of **one thousand packets per second**, and that is the
number that matters: end to end this is a thousand-packet-per-second sensor
whatever the detectors can take.

That is a real limitation and worth stating plainly rather than quoting the
faster half. A thousand packets per second is a quiet office segment, not a
datacentre span. The cause is Scapy's per-packet dissection, which is also
what makes the parser correct and maintainable; changing it means hand-rolling
protocol parsing, which is a different project with a different defect
profile.

**Resource utilisation.** Bounded everywhere it could grow: detector windows
are bucketed so memory per key is fixed regardless of packet rate, the rule
engine LRU-evicts past 10,000 series, deduplication and the threat intel cache
are both capped, and the enrichment queue sheds rather than piling up.

**Capacity.** Single node, one sensor, one database. SQLite by default and
PostgreSQL through the same `DATABASE_URL`.

**Gap.** The floors in `tests/performance/` are set well below the measured
values so a shared CI runner does not produce flapping failures. They catch an
order-of-magnitude regression, not a 30% one.

## 3. Compatibility

**Co-existence.** Passive. It opens a raw socket in promiscuous mode and
writes to its own database; it does not modify traffic, hold a port other
services need, or require anything of the host beyond `CAP_NET_RAW`.

**Interoperability.** A REST API with a generated OpenAPI document, alerts
carrying MITRE ATT&CK tactic identifiers, PCAP as the input format, and PEP
561 type information for consumers. Notification hooks are the outbound
integration point.

**Gap.** No syslog, no CEF, no native SIEM export — an integrator writes a
notification hook. Classifiers claim Linux only, which is honest: the capture
path assumes a POSIX raw socket.

## 4. Usability

**Appropriateness recognisability.** Three commands, `network-defender
sensor|api|replay`, and `replay` needs no privileges and no interface — the
fastest path from clone to seeing a detector work is one command against a
committed capture.

**Learnability.** Twenty-six documents. [EXAMPLE_ATTACKS.md](EXAMPLE_ATTACKS.md)
walks through all thirteen captures with real output including the cases that
look wrong.

**Operability.** Configuration is JSON with a validated schema and clear
startup failures; rules hot-reload; `/health` reports every component.

**User error protection.** Config validation refuses contradictory settings at
startup rather than failing later — packet retention longer than alert
retention is rejected, because deleting an alert cascades to its packets.

**Gap.** Alert triage is a status field. No assignment, no notes, no
suppression rules, no way to tell the system "this host is a backup server,
stop telling me". For the detectors where benign and malicious overlap, that
absence is the difference between a documented false positive and a usable
one.

## 5. Reliability

**Maturity.** Every extension boundary is a failure boundary: one detector
raising does not stop the others, a malformed rule is logged and skipped, a
provider that throws returns an ERROR result, a broken notification channel
does not stop persistence. Enrichment fails open — an alert without threat
intel is still an alert.

**Fault tolerance.** A circuit breaker cuts a failing provider out after
repeated failures and retries after a reset window. The gatekeeper sheds
callers past its queue depth rather than letting them accumulate.

**Recoverability.** Alerts are persisted before notification, so nothing is
lost to a channel being unreachable. Database schema is Alembic-managed and
migrated on start. State that must not survive a restart — deduplication
windows, threshold caches — is explicitly reset.

**Availability gap.** Single node, no failover, no clustering. If the sensor
process is down, nothing is watching and nothing says so. There is no
watchdog, and the health endpoint cannot report that the thing serving it has
stopped.

## 6. Security

**Confidentiality.** Credentials come from the environment through exactly one
module, and a test fails if a second module reads the environment for one.
Secrets are redacted in logs; `.env` is git-ignored; gitleaks runs in CI on
every push.

**Integrity.** Rule files are validated on load and refused if they name a
private attribute — a rule is the kind of thing copied off a blog, and the
evaluator resolves dotted paths with `getattr`. The API sets a
content-security policy and bounds request parameters.

**Accountability.** Every finding gets a correlation ID at the moment it
exists, and everything downstream logs under it; a separate security log
records alerts raised and suppressed.

**Authenticity.** One API key, checked against a constant-time comparison, and
authentication is off when no key is set — `/config` reports which, so a
deployment that forgot is visible rather than silent.

**Gap, and it is the significant one.** No users, no roles, no audit of who
triaged what, and no rate limiting on failed authentication. One key that
grants everything is appropriate for a single-operator deployment and not for
a team. Put it behind a proxy. [THREAT_MODEL.md](THREAT_MODEL.md) is explicit
about what this system does and does not defend.

## 7. Maintainability

The strongest characteristic, and the one with the most enforcement rather
than intention.

**Modularity.** The layering is computed from the imports and checked against
the architecture on every run — see [BUILDING_BLOCKS.md](BUILDING_BLOCKS.md).
Adding a dependency between layers is a line someone writes deliberately.

**Reusability.** Detectors depend on packets and configuration and nothing
else, which is what lets the sensitivity harness replay 791 grid points with
no database, no services and no SDK.

**Modifiability.** Every source file is capped at 150 lines and a test names
the file that breaks it. Ruff with fifteen rule families, mypy strict over
`src`, `tests`, `scripts` and `migrations`. One import style, enforced. One
version, derived.

**Testability.** 1,388 tests, 97.5% branch coverage against an 85% gate, plus
golden files, thirteen end-to-end attack captures, performance floors and a
mutation spot check scoped to the detectors. Every component takes its
dependencies as constructor arguments; there is no singleton to reset.

**Analysability.** Structured JSON logging with correlation IDs; a
`/health` endpoint per component; committed research data so a behaviour
change arrives as a diff in `research/` rather than a number that quietly
moved.

**Gap.** **Ruff and mypy are not in CI.** They run in pre-commit hooks, which
means they are enforced on whoever installed them. The test suite, the
dependency audit and the secrets scan do run on every push. This is tracked
under Milestone 18 and is the most valuable single thing left on the list.

## 8. Portability

**Adaptability.** Python 3.12 and 3.13. SQLite and PostgreSQL through the same
`DATABASE_URL`. Every path in configuration resolves against a project root
that can be pointed anywhere with `ND_PROJECT_ROOT`, so configuration can live
outside the installation.

**Installability.** `uv build` produces a wheel that carries `config/`,
`rules/` and the migrations, verified by installing it into a clean
environment and replaying a capture through it. The entry point works with
nothing else present.

**Replaceability.** Detectors, providers and notification channels are all
replaceable from outside the package via entry points; see
[EXTENDING.md](EXTENDING.md).

**Gap.** No container images. Milestone 17 is unimplemented, so there is no
Dockerfile and no Compose file even though the architecture document describes
the topology they should express.

---

## Where this leaves it

The system is honest about itself, which is the property most of the above
depends on: the recall figures are measured and published, the threat model
says what it does not defend, the roadmap lists what is broken before what is
planned, and several sections of this document are worse reading than they
would be if nobody had measured.

Ranked by what would most improve the product:

1. **Lint and types in CI.** Cheap, and currently enforced only on people who
   installed the hooks.
2. **Labelled real captures.** Every functional-suitability number here rests
   on synthetic traffic.
3. **Suppression and triage.** The detectors that cannot be fixed by a
   threshold need an operator able to say "not this host".
4. **Containers.** The deployment story is written and not shipped.
5. **Parser throughput.** The real ceiling, and the most expensive to move.
