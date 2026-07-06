# Network Defender — Project TODO

> A production-quality, modular Network Intrusion Detection System (IDS) in Python.
> This TODO follows professional software engineering standards: mandatory design
> docs (PRD/PLAN/TODO), SDK-based architecture, API gatekeeper for external calls,
> TDD with ≥85% coverage, `uv`-managed dependencies, strict lint/config hygiene,
> and a 150-line-per-file limit. Estimated effort: 2–3 months.
>
> Legend: `[ ]` = not started · `[~]` = in progress (edit manually) · `[x]` = done

---

## Milestone 0 — Governance & Mandatory Documentation

- [x] Create GitHub repository `network-defender`
- [x] Add `LICENSE` (MIT or Apache-2.0) and `.gitignore` (Python, Docker, IDE, `.env`)
- [x] Create `docs/` directory (mandatory)
- [x] Write `docs/PRD.md` — Product Requirements Document
  - [x] Project overview, problem statement, target users (SOC analyst / student portfolio)
  - [x] Goals, non-goals, and scope boundaries
  - [x] Success metrics / KPIs (detection accuracy, false-positive rate, latency)
  - [x] Functional & non-functional requirements
  - [x] User stories (e.g., "As a SOC analyst, I want to see live alerts…")
  - [x] Assumptions, dependencies, out-of-scope items
  - [x] Timeline with milestones and expected deliverables
- [x] Write `docs/PLAN.md` — Architecture & Planning Document
  - [x] C4 model diagrams (Context, Container, Component, Code)
  - [x] UML diagrams for key workflows (packet → parser → detector → alert)
  - [x] Deployment diagram (Docker Compose topology)
  - [x] Architecture Decision Records (ADRs) with rationale and trade-offs
  - [x] API contract sketch (endpoints, request/response schemas)
- [x] Write `docs/TODO.md` (this file) and keep it updated as the single source of truth
- [x] Write per-mechanism PRDs (mandatory for each major algorithm/subsystem):
  - [x] `docs/PRD_detection_engine.md` — rule engine + detector algorithms
  - [x] `docs/PRD_threat_intel.md` — enrichment provider architecture
  - [x] `docs/PRD_beaconing_detection.md` — statistical beaconing heuristic
  - [x] `docs/PRD_dns_tunneling.md` — DNS tunneling heuristic
  - [x] `docs/PRD_dashboard.md` — dashboard UX and data flow
- [x] Get design docs reviewed/approved (self-review checklist) before writing code
- [x] Set up a **Prompt Engineering Log** (`docs/PROMPT_LOG.md`) documenting any AI-assisted development: prompts used, context/goal, outputs, iterations, lessons learned

---

## Milestone 1 — Project Setup & Environment

- [x] Install Python 3.12+
- [x] Adopt `uv` as the exclusive package/dependency manager (no `pip install`, no `venv`/`python -m venv` directly)
- [x] Initialize project with `uv init` / `pyproject.toml`
- [x] Configure `pyproject.toml`: name, version (`0.1.0` start), description, license, authors
- [x] Add core dependencies via `uv add`: `scapy`, `fastapi`, `uvicorn`, `sqlalchemy`, `pydantic`, `pyyaml`
- [x] Add dev dependencies via `uv add --dev`: `pytest`, `pytest-cov`, `ruff`, `mypy`, `httpx`
- [x] Generate and commit `uv.lock`
- [x] Configure Ruff in `pyproject.toml` (`line-length = 100`, target `py312`, rule sets `E,F,W,I,N,UP,B,C4,SIM`)
- [x] Configure MyPy (strict mode where feasible)
- [x] Configure `pytest` and `[tool.coverage]` sections (`fail_under = 85`)
- [x] Set up pre-commit hooks (ruff, mypy, pytest quick-check)
- [x] Create `src/network_defender/` package layout (see Project Structure section)
- [x] Create `src/network_defender/__init__.py` exporting public API and `__version__`
- [x] Create `src/network_defender/constants.py` for immutable project constants
- [x] Create `src/network_defender/shared/version.py` starting at version `1.00`
- [x] Create `.env-example` with placeholder values for all secrets/config
- [x] Verify `.env`, `*.key`, `*.pem`, `credentials.json` are in `.gitignore`
- [x] Set up Git branching convention (`main`, `develop`, `feature/*`) and commit message convention
- [x] Write initial `README.md` skeleton (Installation, Usage, badges placeholder)
- [x] Configure GitHub repo settings: branch protection on `main`, required PR reviews

---

## Milestone 2 — Core Architecture & SDK Layer

- [x] Design layered architecture: `External Consumers → SDK → Domain Services → Infrastructure`
- [x] Create `src/network_defender/sdk/sdk.py` as the **single entry point** for all business logic
- [x] Ensure CLI, dashboard, and REST API only call through the SDK layer (no business logic in presentation layers)
- [x] Create `src/network_defender/services/` for domain services (capture, parsing, detection, alerting)
- [x] Create `src/network_defender/shared/config.py` — centralized configuration manager
- [x] Create `src/network_defender/shared/gatekeeper.py` — centralized API Gatekeeper for all outbound calls (threat intel APIs)
  - [x] Implement `ApiGatekeeper.__init__(config: RateLimitConfig)`
  - [x] Implement `execute(api_call, *args, **kwargs)` with pre-call rate-limit check
  - [x] Implement FIFO request queue with configurable max depth
  - [x] Implement backpressure signaling when queue is full
  - [x] Implement retry-with-backoff on transient failures
  - [x] Implement `get_queue_status() -> QueueStatus`
  - [x] Log every outbound API call (service, timestamp, result, latency)
  - [x] Ensure no code path calls external APIs directly, bypassing the gatekeeper
- [x] Design object-oriented structure avoiding code duplication:
  - [x] Extract shared logic into base classes or mixins where 2+ classes repeat behavior
  - [x] Ensure every mixin has a single responsibility and can be tested independently
  - [x] Use the Template Method pattern for repeated structured workflows (e.g., detector lifecycle)
- [x] Define "building block" design contract for each core component (Data Input / Data Output / Data Setup docstring convention)
- [x] Enforce single-responsibility, dependency-injectable, independently testable components across the codebase
- [x] Create `config/setup.json`, `config/rate_limits.json`, `config/logging_config.json` (versioned, `"version": "1.00"`)
- [x] Ensure zero hardcoded values (URLs, ports, thresholds, timeouts, API keys) in source code — all via config or `constants.py`/`Enum`

---

## Milestone 3 — Packet Capture Module (`app/capture/`)

- [x] Design `CaptureService` interface (start/stop/status)
- [x] Implement live capture from a selected network interface via Scapy
- [x] Implement interface auto-discovery / listing
- [x] Implement PCAP file reading (offline analysis mode)
- [x] Implement saving captured traffic to PCAP files
- [x] Implement BPF filter support (user-supplied filter strings)
- [x] Implement protocol-level filtering (allow/deny list)
- [x] Implement human-readable packet summaries
- [x] Add support for capturing: Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP
- [x] Add support for parsing DNS at capture layer (query extraction)
- [x] Add support for HTTP capture (clear-text)
- [x] Add support for HTTPS/TLS metadata-only capture (no decryption)
- [x] Add TLS handshake metadata extraction (ClientHello, SNI, cipher suites)
- [x] Implement graceful shutdown / signal handling for long-running capture
- [x] Implement capture rate limiting / backpressure to avoid overload
- [x] Add configuration for capture buffer size, snaplen, promiscuous mode
- [x] Write capture module docstrings (class, module, and function level)
- [x] Keep every file under the 150-line limit; split by protocol/concern if needed

---

## Milestone 4 — Packet Parser (`app/parser/`)

- [x] Design `PacketParser` interface returning a normalized `ParsedPacket` model (Pydantic)
- [x] Extract timestamp
- [x] Extract source IP / destination IP
- [x] Extract source port / destination port
- [x] Extract protocol identifier
- [x] Extract packet length
- [x] Extract TCP flags (SYN, ACK, FIN, RST, PSH, URG)
- [x] Extract DNS query name and record type
- [x] Extract HTTP method and path
- [x] Extract HTTP Host header
- [x] Extract HTTP User-Agent header
- [x] Extract TLS SNI when available
- [x] Handle malformed/truncated packets gracefully (no crashes)
- [x] Define Pydantic models for each protocol's parsed fields
- [x] Write parser unit tests covering valid, malformed, and edge-case packets
- [x] Benchmark parser throughput (packets/sec) as a baseline for performance tests

---

## Milestone 5 — Rule Engine (`app/rules/`)

- [ ] Define YAML rule schema (name, severity, enabled, conditions, window)
- [ ] Implement rule loader that auto-discovers and loads every `.yaml` file from `rules/`
- [ ] Implement rule validation (schema validation via Pydantic) with clear error messages
- [ ] Implement hot-reload of rules without restarting the application
- [ ] Implement condition evaluators (equality, threshold, regex, time-window aggregation)
- [ ] Support enabling/disabling individual rules via config
- [ ] Write example rule files for each detector category (see Milestone 6)
- [ ] Write rule engine unit tests (valid rules, invalid schema, disabled rules, edge cases)
- [ ] Document the rule YAML schema in `docs/`

---

## Milestone 6 — Detection Engine (`app/detectors/`)

- [ ] Design a `BaseDetector` abstract class defining the detector lifecycle (`ingest`, `evaluate`, `emit_alert`)
- [ ] Ensure new detectors can be added by subclassing, with zero changes to existing code (Open/Closed Principle)
- [ ] Implement TCP Port Scan detector
- [ ] Implement SYN Scan detector
- [ ] Implement SYN Flood detector
- [ ] Implement UDP Flood detector
- [ ] Implement ICMP Flood detector
- [ ] Implement ARP Spoofing detector (gratuitous ARP / MAC-IP mismatch tracking)
- [ ] Implement DNS Tunneling heuristic detector (entropy, query length, request frequency)
- [ ] Implement SSH Brute Force detector (failed connection counting per rule window)
- [ ] Implement HTTP Brute Force detector (auth failure pattern on web endpoints)
- [ ] Implement Beaconing Detection (periodicity/interval-variance analysis on outbound connections)
- [ ] Implement Suspicious Port Usage detector (non-standard port / service mismatch)
- [ ] Implement Large Data Exfiltration detector (outbound byte-volume thresholds)
- [ ] Implement Suspicious Internal Lateral Movement detector (internal-to-internal anomalous connections)
- [ ] Implement a detector registry/plugin loader (auto-discovers detector modules)
- [ ] Implement per-detector configuration (thresholds, enable/disable, sensitivity)
- [ ] Write unit tests for each detector using synthetic/crafted traffic scenarios
- [ ] Write integration tests combining rule engine + detectors against sample PCAPs
- [ ] Benchmark detector performance under sustained high packet rate

---

## Milestone 7 — Alert System (`app/services/alerts/`)

- [ ] Define `Alert` Pydantic model: UUID, timestamp, severity, rule triggered, source IP, destination IP, packet summary, confidence score, MITRE ATT&CK tactic
- [ ] Implement severity levels enum: Info, Low, Medium, High, Critical
- [ ] Implement MITRE ATT&CK tactic mapping table for each detector
- [ ] Implement confidence-score calculation logic per detector type
- [ ] Implement alert deduplication / correlation (avoid alert storms for the same event)
- [ ] Implement alert persistence to the database
- [ ] Implement alert-to-notification hooks (extensible: email, webhook, Slack — stub interfaces)
- [ ] Write unit tests for alert creation, deduplication, and severity assignment

---

## Milestone 8 — Threat Intelligence Enrichment (`app/services/threat_intel/`)

- [ ] Design a `ThreatIntelProvider` abstract interface for pluggable providers
- [ ] Implement malicious IP lookup provider (via public API, routed through API Gatekeeper)
- [ ] Implement ASN lookup provider
- [ ] Implement geolocation provider
- [ ] Implement WHOIS lookup provider
- [ ] Implement reputation score aggregation across providers
- [ ] Implement threat intel response caching (TTL-based) to reduce API calls
- [ ] Implement provider fallback / circuit-breaker on provider failure
- [ ] Store all API keys in `.env`, never in source code
- [ ] Write unit tests with mocked HTTP responses for each provider
- [ ] Write integration test verifying gatekeeper rate limiting is enforced end-to-end
- [ ] Document how to add a new threat intel provider (extension guide)

---

## Milestone 9 — Database Layer (`app/database/`, `app/models/`)

- [ ] Design SQLAlchemy models: `Packet`, `Alert`, `Rule`, `ThreatIntelCache`, `Statistics`
- [ ] Configure SQLite for development (file-based, versioned migration scripts)
- [ ] Configure SQLAlchemy engine abstraction to support PostgreSQL later without code changes
- [ ] Implement Alembic (or equivalent) migrations
- [ ] Implement repository pattern for data access (decouple services from ORM details)
- [ ] Implement database indices for common query patterns (source IP, timestamp, severity)
- [ ] Implement data retention/cleanup policy (archiving or pruning old packet records)
- [ ] Write unit tests for repository CRUD operations
- [ ] Write integration tests against a real (test) SQLite database
- [ ] Document schema in `docs/PLAN.md` (ERD or table description)

---

## Milestone 10 — REST API (`app/api/`, FastAPI)

- [ ] Design API contract (OpenAPI) for all endpoints before implementation
- [ ] Implement `/alerts` endpoints (list, filter, get by ID)
- [ ] Implement `/packets` endpoints (list, filter, get by ID)
- [ ] Implement `/statistics` endpoints (traffic summary, top talkers, protocol distribution)
- [ ] Implement `/rules` endpoints (list, get, enable/disable, reload)
- [ ] Implement `/health` endpoint (liveness/readiness)
- [ ] Implement `/config` endpoints (read current, non-secret configuration)
- [ ] Ensure every endpoint delegates to the SDK layer only — no business logic in route handlers
- [ ] Implement request validation via Pydantic models
- [ ] Implement pagination for list endpoints
- [ ] Implement authentication/authorization stub (API key or JWT) for future hardening
- [ ] Implement structured error responses (consistent error schema)
- [ ] Auto-generate and publish OpenAPI/Swagger docs
- [ ] Write API tests for every endpoint (happy path + error path)

---

## Milestone 11 — Dashboard (`app/dashboard/`)

- [ ] Choose frontend stack (e.g., React/Vue or server-rendered templates) and document the decision as an ADR
- [ ] Implement live traffic view (WebSocket or polling)
- [ ] Implement packets-per-second live chart
- [ ] Implement top source IPs widget
- [ ] Implement top destination IPs widget
- [ ] Implement protocol distribution chart
- [ ] Implement alerts timeline visualization
- [ ] Implement active alerts panel with severity color-coding
- [ ] Implement attack statistics summary panel
- [ ] Implement search page (query alerts/packets by filters)
- [ ] Implement alert detail view (full alert + related packet data + MITRE mapping)
- [ ] Implement raw packet viewer (hex/summary view)
- [ ] Implement dark mode toggle
- [ ] Ensure responsive layout (desktop/tablet/mobile breakpoints)
- [ ] Document UI screen flows and interactions (`docs/` UI documentation)
- [ ] Apply Nielsen's 10 usability heuristics as a design review checklist
- [ ] Perform basic accessibility review (contrast, keyboard navigation, ARIA labels)

---

## Milestone 12 — Logging & Observability (`app/utils/logging/`)

- [ ] Implement structured (JSON) logging configuration
- [ ] Implement separate log streams: application logs, security logs, audit logs
- [ ] Implement log rotation and retention policy
- [ ] Implement correlation IDs across capture → detection → alert pipeline for traceability
- [ ] Ensure no secrets are ever written to logs
- [ ] Write tests verifying log format and required fields

---

## Milestone 13 — Configuration Management (`configs/`)

- [ ] Create capture configuration file (interface, BPF filter, buffer size)
- [ ] Create logging configuration file
- [ ] Create database configuration file (dev/prod connection strings via env vars)
- [ ] Create rules directory path configuration
- [ ] Create dashboard configuration (host, port, theme default)
- [ ] Create threat intelligence configuration (providers, API keys via env, cache TTL)
- [ ] Create rate limit configuration (`config/rate_limits.json`) per external service
- [ ] Validate all configuration files against Pydantic schemas at startup
- [ ] Document every configuration option in `docs/`

---

## Milestone 14 — Testing & Quality Assurance

- [ ] Adopt TDD workflow (Red → Green → Refactor) for all new modules going forward
- [ ] Set up `tests/unit/` mirroring `src/` structure
- [ ] Set up `tests/integration/`
- [ ] Set up shared fixtures in `tests/conftest.py`
- [ ] Write unit tests for packet parser (all protocols + malformed input)
- [ ] Write unit tests for rule engine (valid/invalid rules, edge cases)
- [ ] Write unit tests for every detector module
- [ ] Write unit tests for alert system
- [ ] Write unit tests for threat intel providers (mocked)
- [ ] Write unit tests for database repositories
- [ ] Write API integration tests (FastAPI TestClient)
- [ ] Write end-to-end tests using sample/synthetic PCAP files representing each attack type
- [ ] Write performance tests (sustained packet throughput, detection latency under load)
- [ ] Ensure every public function/class has at least one test
- [ ] Ensure both the success path and the failure/error path are tested per module
- [ ] Mock all external dependencies (threat intel APIs, filesystem, DB) in unit tests
- [ ] Configure and enforce ≥85% global test coverage (`fail_under = 85`)
- [ ] Ensure no test file exceeds 150 lines (split into logical suites if needed)
- [ ] Add mutation-testing spot-check (optional stretch goal) for critical detectors
- [ ] Store expected test outputs / golden files for regression testing where applicable
- [ ] Publish coverage and pass/fail reports as CI artifacts

---

## Milestone 15 — Code Quality & Static Analysis

- [ ] Achieve zero `ruff check` violations across the codebase
- [ ] Achieve zero MyPy errors (or documented, justified `# type: ignore`)
- [ ] Verify zero hardcoded config-like values in source code (API URLs, ports, thresholds, secrets)
- [ ] Verify every module/class/function has a docstring explaining **why**, not just what
- [ ] Verify consistent naming conventions (descriptive variables/functions) project-wide
- [ ] Verify DRY principle — no duplicated logic blocks across 2+ files
- [ ] Enforce single-responsibility functions (short, focused, one job each)
- [ ] Audit all files for the 150-line limit; split oversized files by concern
- [ ] Run a full code review pass against the Final Checklist (Milestone 20)

---

## Milestone 16 — Security & Secrets Management

- [ ] Confirm no API keys, tokens, or passwords exist anywhere in source code or Git history
- [ ] Confirm all secrets are read exclusively via environment variables
- [ ] Confirm `.env` is git-ignored and `.env-example` is committed with placeholder values
- [ ] Implement periodic API key rotation guidance/documentation
- [ ] Apply principle of least privilege to any credentials used (DB, threat intel APIs)
- [ ] Run a secrets-scanning tool (e.g., `gitleaks`/`truffleHog`) in CI
- [ ] Document a basic threat model for Network Defender itself (what it protects against, its own attack surface)
- [ ] Add input validation/sanitization on all API and dashboard inputs (prevent injection)

---

## Milestone 17 — Docker & Deployment

- [ ] Write `Dockerfile` for the application (multi-stage build)
- [ ] Write `docker-compose.yml` for development (app + DB + dashboard)
- [ ] Write a separate production Docker Compose overlay (Postgres, hardened settings)
- [ ] Ensure containers run with least-privilege (non-root user, minimal base image)
- [ ] Ensure capture container has correct network capabilities (`NET_RAW`, `NET_ADMIN`) scoped minimally
- [ ] Document environment variables required for each deployment mode
- [ ] Add health checks to Docker Compose services
- [ ] Test full stack startup via `docker compose up` end-to-end

---

## Milestone 18 — CI/CD (GitHub Actions)

- [ ] Create workflow: run Ruff lint on every push/PR
- [ ] Create workflow: run MyPy type checks
- [ ] Create workflow: run full test suite with coverage gate (≥85%)
- [ ] Create workflow: run security checks (dependency audit, secrets scan)
- [ ] Create workflow: build Docker image and verify it starts successfully
- [ ] Configure workflow to run on multiple Python versions (3.12, 3.13) if feasible
- [ ] Publish coverage badge and CI status badge to `README.md`
- [ ] Gate PR merges on all checks passing (branch protection rule)

---

## Milestone 19 — Research, Sensitivity Analysis & Visualization

- [ ] Design a sensitivity-analysis process for detector thresholds (e.g., port-scan window, brute-force count)
- [ ] Run systematic experiments varying key detector parameters and record precision/recall/false-positive rate
- [ ] Build a Jupyter notebook (`notebooks/detection_analysis.ipynb`) analyzing results
- [ ] Produce comparison visualizations: precision/recall vs. threshold, ROC-style curves per detector
- [ ] Produce heatmaps for parameter sensitivity
- [ ] Produce time-series charts of alert volume during simulated attack scenarios
- [ ] Summarize findings and recommended default thresholds in `docs/`

---

## Milestone 20 — Documentation Finalization

- [ ] Write comprehensive `README.md`: overview, features, architecture diagram, folder structure, installation, quick start, screenshots, usage examples
- [ ] Write "Threat Model" documentation section
- [ ] Write "Example Attacks" walkthrough (how to simulate each detected attack type)
- [ ] Write "How Detections Work" explainer per detector
- [ ] Publish full API documentation (OpenAPI/Swagger link + narrative guide)
- [ ] Write Developer Guide (project structure, how to add a new detector/provider)
- [ ] Write Contribution Guide (coding standards, PR process, branch naming)
- [ ] Write Future Roadmap section (planned features, known limitations)
- [ ] Add architecture diagrams (C4, deployment) to `docs/`
- [ ] Add annotated screenshots of the dashboard
- [ ] Cross-check README against actual behavior (no stale instructions)

---

## Milestone 21 — Packaging, Versioning & Extensibility

- [ ] Package the project as an installable Python package (`pyproject.toml` metadata complete: name, description, license, authors, dependencies with pinned versions)
- [ ] Verify `src/network_defender/__init__.py` exposes public API and `__version__`
- [ ] Verify all imports are relative/package-qualified (no absolute path imports)
- [ ] Start global version at `1.00`; bump on meaningful changes; keep code, config, and rate-limit versions in sync
- [ ] Add a plugin/extension architecture for detectors and threat intel providers (documented extension points, lifecycle hooks)
- [ ] Document how to extend Network Defender without modifying core code
- [ ] Verify components are reusable, decoupled, and independently testable (building-block review)
- [ ] Map project quality against ISO/IEC 25010 characteristics (functional suitability, performance efficiency, compatibility, usability, reliability, security, maintainability, portability) and document gaps

---

## Milestone 22 — Final Submission Checklist

- [ ] `README.md` complete and accurate at repo root
- [ ] `docs/PRD.md`, `docs/PLAN.md`, `docs/TODO.md` present and current
- [ ] Per-mechanism PRDs present for detection engine, threat intel, beaconing, DNS tunneling, dashboard
- [ ] Architecture diagrams present and match implementation
- [ ] Prompt Engineering Log present and current (if AI-assisted)
- [ ] All source files under 150 lines with meaningful names and full docstrings
- [ ] Clear separation of concerns across `capture/`, `parser/`, `detectors/`, `rules/`, `dashboard/`, `database/`, `api/`, `models/`, `services/`, `utils/`
- [ ] SDK layer is the sole entry point for all business logic
- [ ] API Gatekeeper mediates all outbound threat-intel API calls with enforced rate limits and queueing
- [ ] No code duplication; shared logic factored into base classes/mixins
- [ ] TDD followed; every public function has ≥1 test; happy-path and error-path both covered
- [ ] Global test coverage ≥85%, verified in CI
- [ ] `ruff check` passes with zero violations
- [ ] No hardcoded values anywhere in source code
- [ ] All configuration in versioned files outside source code
- [ ] No secrets in code or Git history; `.env-example` present and current; `.gitignore` correct
- [ ] `uv` used exclusively for dependency/package management; `uv.lock` and `pyproject.toml` present
- [ ] Sensitivity analysis notebook and visualizations included
- [ ] Dashboard supports dark mode and is responsive
- [ ] Dockerfile and Docker Compose (dev + prod) build and run successfully
- [ ] GitHub Actions CI passes (lint, type-check, tests, coverage, security scan, Docker build)
- [ ] Git history is clean with meaningful commit messages and tagged releases
- [ ] Final review against ISO/IEC 25010 quality characteristics completed
