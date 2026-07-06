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
Activate the virtual environment and start the application:

```bash
# Example start command
```

## Development
```bash
uv sync --dev
pytest
ruff check .
mypy src
```