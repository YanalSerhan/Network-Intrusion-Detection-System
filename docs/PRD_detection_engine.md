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

**Status:** partially met, and the gap is measured. Every detector clears its
state in `evaluate()`, so state cannot grow without bound — but the window is
whenever `PeriodicEvaluator` fires, taken from
`detection.evaluation_interval_seconds`, and the per-detector
`time_window_seconds` this PRD implies is declared in configuration and read
by nothing. [DETECTION_TUNING.md](DETECTION_TUNING.md) quantifies what that
costs: five detectors have a recall of 0.00 as shipped. It is open under
Milestone 21.
