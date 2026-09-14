# Changelog

One number for the whole project, declared in
`src/network_defender/shared/version.py` and derived everywhere else. It moves
when behaviour someone outside this repository depends on changes: the package
surface in `__init__.py`, the REST API, the configuration schema, or what a
detector does with the same traffic.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions are [PEP 440](https://peps.python.org/pep-0440/); note that `1.00`
normalises to `1.0` in installed distribution metadata.

## [1.00] — Milestone 21

First version worth numbering. The milestones before this one built the
system; this one made it a package, and found that several things it claimed
to do it did not.

### Fixed

- **Detector windows were not implemented.** Twelve detector configurations
  declared a `time_window_seconds` that no code read: state was cleared by
  `evaluate()`, so every detector's real window was the shared
  `detection.evaluation_interval_seconds` — five seconds, against declared
  windows of up to an hour. Mean recall across the twelve tunable detectors
  was **0.41, with five detectors at 0.00**. Each detector now slides its own
  window over capture time.
- **Windows were tumbling and anchored to process start.** Whether a burst was
  detected depended on when the sensor happened to have been started. Windows
  now slide over packet timestamps, so a replay of the same capture gives the
  same answer every time.
- **A sustained attack was one alert per evaluation.** Detectors and signature
  rules both report a given key once per episode now, and re-arm when the
  condition clears.
- **`rules/tcp_port_scan.yaml` counted SYN packets, not ports**, so it labelled
  a SYN flood, an SSH brute force, a bulk transfer and lateral movement as
  port scans. The rule schema gained `distinct_field`; each shipped rule now
  fires on its own capture and no other.
- **The wheel did not run.** `config/`, `rules/` and `migrations/` were not in
  it, and the project root was inferred from this file's location — the
  interpreter's `lib/` directory once installed. The wheel now carries them,
  and `ND_PROJECT_ROOT` overrides.
- **`network-defender replay` printed the whole alert database**, not the
  capture's own findings, so replaying several files in a row reported all of
  them each time.
- **`DataExfiltrationDetector` counted internal transfers.** A nightly backup
  to an internal file server is not exfiltration; only bytes leaving the
  estate are counted now.

### Changed

- Four thresholds retuned against the working windows: `SynFloodDetector`
  100 → 40, `UdpFloodDetector` 200 → 75, `IcmpFloodDetector` 50 → 20,
  `SshBruteForceDetector` 10 → 12. Mean recall **0.41 → 0.74**. See
  [docs/DETECTION_TUNING.md](docs/DETECTION_TUNING.md).
- `detection.evaluation_interval_seconds` stays at 5.0 and is no longer a
  detection parameter: it decides how soon an alert surfaces, not whether it
  is found. The earlier recommendation to raise it to 60 is withdrawn.
- Imports are absolute and package-qualified throughout, enforced by ruff.
- Version is declared once and derived everywhere else.

### Added

- A public package surface: fourteen documented names in `__init__.py`,
  pinned by tests.
- `DnsTunnelingDetector.allowed_domains` and
  `DataExfiltrationDetector.allowed_destinations`, both shipping empty — the
  mechanism is the deliverable, the list is the operator's.
- Complete distribution metadata: classifiers, keywords, URLs, PEP 639
  licence, and an explicit sdist file list.
