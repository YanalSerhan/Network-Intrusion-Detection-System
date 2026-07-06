# PRD: DNS Tunneling Heuristic

## Overview
DNS tunneling is used to exfiltrate data or establish C2 channels by encoding payloads into DNS query names. This detector identifies anomalous DNS traffic indicative of tunneling.

## Requirements
- **Metrics Evaluated:**
  - **Query Length:** Identify unusually long subdomains (e.g., `a1b2c3d4e5f6g7h8i9j0.malicious.com`).
  - **Entropy:** Calculate Shannon entropy of the query string. High entropy suggests encoded/encrypted data.
  - **Volume:** Monitor the volume of TXT or NULL record queries to a specific domain.
- **Integration:** The detector ingests only DNS-parsed packets from the stream.

## Edge Cases
- CDNs and certain anti-spam technologies use long, high-entropy subdomains. Threshold tuning and allowlists will be critical.
