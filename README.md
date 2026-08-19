# Network Defender

![Coverage](https://img.shields.io/badge/coverage-85%25-brightgreen.svg)
![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

A production-quality, modular Network Intrusion Detection System (IDS) in Python.

## Features
- Passive packet capture and analysis.
- Dynamically loaded YAML detection rules.
- Heuristic detectors for beaconing, tunneling, and scanning.
- Threat intelligence enrichment.
- Real-time dashboard and REST API.

## Installation
Ensure you have Python 3.12+ and `uv` installed.

```bash
uv sync
```

## Usage

Three ways to run the system, because they need different privileges.

**Replay a capture file.** No privileges, no interface, nothing to configure —
the fastest way to see a detector work:

```bash
uv run network-defender replay tests/data/pcaps/tcp_port_scan.pcap
```

```
2 alert(s) from tcp_port_scan.pcap:

  high     TcpPortScanDetector        confidence 0.75  45.155.205.233
           TCP Port Scan detected: 40 unique ports scanned.
  high     SynScanDetector            confidence 0.83  45.155.205.233
           SYN Scan detected: 40 unique ports targeted.
```

Thirteen sample captures ship in `tests/data/pcaps/`, one per attack. See
[docs/EXAMPLE_ATTACKS.md](docs/EXAMPLE_ATTACKS.md).

**Serve the API and dashboard.** No capture, so no elevated privileges:

```bash
uv run network-defender api                 # http://localhost:8000
uv run network-defender api --port 9000     # overrides api.port in config
```

The dashboard is at `/dashboard`, interactive API docs at `/docs`, and the
OpenAPI schema at `/openapi.json`.

**Capture live traffic.** Needs `CAP_NET_RAW` (or root) and the interface named
by `capture.interface` in `config/setup.json`:

```bash
sudo -E uv run network-defender sensor
```

The sensor and the API are separate processes on purpose: only the sensor
needs raw-socket access, so the HTTP surface runs with no capture capability
at all. `python -m network_defender` is equivalent to `network-defender` and
works without installing the console script.

Configuration lives in `config/*.json` with secrets in `.env`; see
[docs/CONFIGURATION.md](docs/CONFIGURATION.md) and `.env-example`.

## Development
```bash
uv sync --all-groups     # runtime and dev dependencies
uv run pytest            # full suite with coverage; reports land in reports/
uv run ruff check src tests scripts
uv run mypy src
```

See [docs/TESTING.md](docs/TESTING.md) for the test layout, the TDD workflow,
the sample captures and the mutation spot check, and
[docs/CONVENTIONS.md](docs/CONVENTIONS.md) for naming, and
[docs/CREDENTIALS.md](docs/CREDENTIALS.md) for credential handling, and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what this system does and does not defend.