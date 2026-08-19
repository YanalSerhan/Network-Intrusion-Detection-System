# Code review pass — Milestone 15

A review of the codebase against the Milestone 22 final checklist, run at the
close of Milestone 15. Four independent reviewers covered structure, the API
gatekeeper, secrets and dependency hygiene, and whether the documentation
still describes the code. Every non-passing finding was then given to a
separate reviewer instructed to refute it; the ones below are what survived
that, with the location each was verified at.

Findings are recorded whether or not they were fixed here. A review that only
lists what someone had time to fix is a to-do list, not a review.

## Fixed in this milestone

| Finding | Where |
|---|---|
| A SQLite database named `:memory:` was committed at the repo root, containing real capture rows including a routable source IP. Created by passing `:memory:` as a filesystem path instead of the `sqlite:///:memory:` URL, then committed with the in-memory adapter change. `database/engine.py` already rejects the bare form, so nothing recreates it. | repo root, `.gitignore` |
| `TcpPortScanDetector`, `SynScanDetector` and `LateralMovementDetector` each carried their own copy of the same "count distinct peers per source" loop — roughly twenty lines apiece, differing in a threshold and an f-string. This is the shape `CountingDetector` could not absorb, because it tallies integers and these tally sets. | `detectors/impl/breadth.py` |
| `.env-example` listed `API_HOST` and `API_PORT`. Nothing has ever read either name; the real override is `ND__API__HOST` / `ND__API__PORT`. The template taught a configuration path that does not exist while omitting the one that does. | `.env-example` |
| The pre-commit `pytest-check` hook ran a bare `pytest`, resolving whatever was on `PATH` rather than the locked environment — the mypy hook directly above it already got this right. | `.pre-commit-config.yaml` |
| `docs/OBSERVABILITY.md` and `docs/THREAT_INTEL.md` gave test paths from before the Milestone 14 restructure. The command in OBSERVABILITY.md collected zero tests. | both files |
| `heuristics.py`'s module docstring listed which detector lived in which file. It was wrong about two of them, and the registry auto-discovers the package, so the inventory had no functional purpose and had already drifted. | `detectors/impl/heuristics.py` |

## Open — recorded against later milestones

These are real and verified. They are not code-quality defects, which is what
Milestone 15 covers, and each needs its own tests rather than a footnote in a
review commit. They are now TODO items under the milestone that owns them.

### Gatekeeper (Milestone 16)

The API gatekeeper is the component the PRD makes responsible for never
exceeding a provider's limits. Four of its guarantees are weaker than the
configuration implies:

1. **Retries are not counted.** `_window.record()` sits in the success branch
   only, so a failed request consumes no budget. With AbuseIPDB configured at
   10/minute and 3 retries, a provider outage fires 40 real requests a minute
   while the counter reads zero — and an HTTP 429 is exactly the case that
   rate limiting exists to prevent.
2. **`requests_per_day` is never enforced.** It is declared, validated,
   configured for all three services and documented as a daily budget, but no
   code reads it. AbuseIPDB's free tier is a hard 1000/day; at the configured
   rate the gatekeeper would issue 14,400.
3. **The queue never holds anything.** `execute()` appends and immediately
   dispatches, so `max_queue_depth` is unreachable and the backpressure error
   cannot fire. A caller that hits the limit blocks indefinitely inside
   `wait_for_slot()`, which is the opposite of backpressure.
4. **No lock.** The window is mutated from the enrichment worker and from the
   synchronous `/enrich` endpoint without synchronisation, so two threads can
   both pass the check before either records.

### Configuration reaching the code (Milestone 16)

`retention_days` is in `config/setup.json`, is validated, and is reported by
`GET /config` — but never reaches the pruner, which uses the `RetentionPolicy`
defaults. Setting it to 7 changes what the API reports and not what is
deleted. `packets_days` and `statistics_days` have no config key at all. This
is the same defect class as the confidence thresholds fixed earlier in this
milestone: a value copied into config, believed by operators, ignored by code.

### Documentation currency (Milestone 20) — **closed**

- `docs/PLAN.md`'s Level 3 diagram showed every detector subclassing
  `BaseDetector` directly, which stopped being true in Milestone 15. Redrawn,
  along with two other diagrams in that file that had never rendered.
- `docs/PRD_detection_engine.md` said a new detector is added by dropping it
  into `detectors/`; the registry scans `detectors/impl/`. Corrected.
- `docs/PROMPT_LOG.md` had one entry, for Milestone 0. Backfilled.
- `README.md`'s usage section contained a placeholder rather than a start
  command — because the project had no entry point. A CLI was added and the
  section now documents it.

### Structure (Milestone 20) — **closed**

The checklist names `dashboard/`, `models/` and `utils/` packages that do not
exist: the dashboard is `frontend/` plus one router, models live per-package,
and `utils/` is `shared/`. The layering is clean and the deviation is
reasonable — but it was undocumented, so it read as drift rather than as a
decision. Now a table in
[DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md#project-structure) mapping each
checklist name onto where the thing lives, and why.

## Confirmed as passing

- The gatekeeper is the only outbound path. A repository-wide search for
  `httpx`, `requests`, `urllib` and `aiohttp` finds exactly one call site, and
  it is inside a provider that cannot be constructed without a gatekeeper.
- The SDK is the sole entry point: no router or CLI reaches past it into a
  service.
- No secrets in the working tree or in git history.
- `uv` is the only dependency manager; no competing manifest exists.
- Every named environment variable the code reads is documented.
- All five per-mechanism PRDs exist.
