# PRD: Detection Engine

## Overview
The Detection Engine evaluates parsed packets against a set of predefined signatures (rules) and behavioral heuristics to identify malicious activity.

## Requirements
- **Rule Engine:** Must load YAML-based rules dynamically from the file system.
- **Heuristic Detectors:** Must support stateful detectors (e.g., tracking failed logins over time, connection counts).
- **Interface:** Implement `BaseDetector` with `ingest(packet)` and `evaluate()` methods.
- **Performance:** Evaluation must be highly optimized (e.g., using fast lookups, efficient aggregation).
- **Extensibility:** Adding a new detector should require only creating a new class subclassing `BaseDetector` and dropping the module into `detectors/impl/`. The registry imports every module in that package and registers the concrete subclasses it finds; `detectors/` itself holds the base class, the models and the registry, and nothing there is scanned. See [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md).

## Core Detectors Needed
1. TCP Port Scan Detector
2. SYN Flood Detector
3. SSH Brute Force Detector
4. Suspicious Port Usage

All four ship, alongside nine more: SYN scan, UDP flood, ICMP flood, HTTP
brute force, ARP spoofing, DNS tunnelling, beaconing, data exfiltration and
lateral movement. [DETECTORS.md](DETECTORS.md) explains what each one measures
and what it misses.

## Edge Cases
- State accumulation (e.g., tracking open connections) leading to OOM. We must implement time-based expiration (windowing) for stateful trackers.

**Status:** met as of Milestone 21. Each detector slides its own
`time_window_seconds` over capture time and drops what falls out of it, so
state is bounded by the window rather than by how often `PeriodicEvaluator`
happens to fire. Per-key counters are bucketed, so memory is bounded by the
number of live keys regardless of packet rate.

Before that it was only half met: state was cleared in `evaluate()`, which did
bound it, but made the real window the shared
`detection.evaluation_interval_seconds` and left the per-detector field this
PRD implies read by nothing. [DETECTION_TUNING.md](DETECTION_TUNING.md)
quantifies what that cost — five detectors with a recall of 0.00.
