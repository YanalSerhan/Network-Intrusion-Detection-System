# PRD: Threat Intelligence Service

## Overview
The Threat Intelligence (TI) Service enriches alerts by querying external APIs for context (IP reputation, ASN, Geolocation) when suspicious activity is detected.

## Requirements
- **Provider Abstraction:** Define `ThreatIntelProvider` interface.
- **Providers:** Implement modules for standard lookups (e.g., AbuseIPDB, IP-API for geolocation).
- **API Gatekeeper Integration:** ALL outbound requests MUST route through the centralized API Gatekeeper to enforce rate limits.
- **Caching:** Implement a local cache (e.g., SQLite or in-memory) with configurable TTL to avoid redundant API calls for the same IP.
- **Circuit Breaker:** If a TI API goes down, the system must fail open (continue generating alerts without enrichment) rather than crashing.

## Edge Cases
- Handling HTTP 429 Too Many Requests: The gatekeeper must retry with exponential backoff and eventually drop requests if the queue is full.
