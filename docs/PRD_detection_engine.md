# PRD: Detection Engine

## Overview
The Detection Engine evaluates parsed packets against a set of predefined signatures (rules) and behavioral heuristics to identify malicious activity.

## Requirements
- **Rule Engine:** Must load YAML-based rules dynamically from the file system.
- **Heuristic Detectors:** Must support stateful detectors (e.g., tracking failed logins over time, connection counts).
- **Interface:** Implement `BaseDetector` with `ingest(packet)` and `evaluate()` methods.
- **Performance:** Evaluation must be highly optimized (e.g., using fast lookups, efficient aggregation).
- **Extensibility:** Adding a new detector should require only creating a new class subclassing `BaseDetector` and dropping it into the `detectors/` directory.

## Core Detectors Needed
1. TCP Port Scan Detector
2. SYN Flood Detector
3. SSH Brute Force Detector
4. Suspicious Port Usage

## Edge Cases
- State accumulation (e.g., tracking open connections) leading to OOM. We must implement time-based expiration (windowing) for stateful trackers.
