# PRD: Beaconing Detection Heuristic

## Overview
Malware often communicates with Command and Control (C2) servers using regular, periodic connections known as beaconing. This detector analyzes outbound connection intervals to identify periodic patterns.

## Requirements
- **State Tracking:** Track timestamps of outbound connections grouped by `(Source IP, Destination IP, Destination Port)`.
- **Statistical Analysis:** Calculate the variance or standard deviation of the inter-arrival times between connections.
- **Thresholds:** If the variance is extremely low over a minimum sample size (e.g., 10+ connections), classify it as potential beaconing.
- **Performance:** State must be pruned regularly (e.g., discard tracking for connections idle for > 24 hours).

## Edge Cases
- Legitimate background polling (e.g., NTP, telemetry updates) may mimic beaconing. Implement an allowlist mechanism for known safe destinations or ports.
