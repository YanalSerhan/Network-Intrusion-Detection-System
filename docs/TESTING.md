# Testing & Quality Assurance (Milestone 14)

714 tests, 97.5% branch coverage, gated at 85%. This document covers how the
suite is organised, the workflow it is written under, and what each layer is
responsible for proving.

## Running it

```bash
uv sync --all-groups          # once
uv run pytest                 # everything, with coverage
uv run pytest tests/unit      # fast: no database file, no threads, no sockets
uv run pytest tests/e2e       # replay the sample captures end to end
uv run pytest tests/performance   # throughput and latency floors
```

Reports land in `reports/` on every run — `coverage.xml` for tooling,
`htmlcov/` to read, `junit.xml` for CI's test view. The directory is
git-ignored; CI uploads it as an artifact with `if: always()`, so the failing
run is the one whose reports you can actually read.

## Test-driven development

New modules are written Red → Green → Refactor:

1. **Red.** Write the failing test first, and *watch it fail*. A test that has
   never failed has not been shown to test anything — it is as likely to be
   asserting on a typo in its own fixture as on the behaviour it names.
2. **Green.** Write the least code that passes it.
3. **Refactor.** Clean up with the test as a safety net, then run the whole
   suite, not just the file you were working in.

Two rules follow from this and are worth stating separately:

- **A bug fix starts with a test that reproduces the bug.** If the test passes
  before the fix, the bug is not understood yet. `test_heuristics_fixes.py`
  and `test_pipeline_wiring.py` exist for exactly this reason, and both name
  the defect they pin in the module docstring.
- **A test name is a claim.** `test_syn_ack_replies_are_not_a_syn_scan` says
  what must be true; `test_syn_scan_2` says nothing, and nobody can tell from
  a failure whether it is the code or the test that is wrong.

## Layout

`tests/unit/` mirrors `src/network_defender/` one directory per package, so
the tests for a module are always at the mirrored path.

| Directory | What it proves | Speed |
|---|---|---|
| `tests/unit/` | One module, its collaborators substituted. Success *and* failure paths. | Milliseconds |
| `tests/integration/` | Real components wired together — the API over a real SDK over a real SQLite file, the threat intel stack through its gatekeepers. | Under a second each |
| `tests/e2e/` | A capture file in, alerts in the database out, through the SDK. Nothing mocked in between. | A few seconds |
| `tests/performance/` | Throughput and latency floors. | Seconds |
| `tests/fixtures/` | Shared fixtures and builders. Not collected as tests. | — |
| `tests/data/` | Sample captures and golden files. See its README. | — |

Every file stays under 150 lines (ADR 4). When a module outgrows that, split
it along the concern boundary — `test_logging.py` became `test_json_format`,
`test_redaction`, `test_correlation` and `test_logging_setup` — so the file
name still says what failed.

## Fixtures

Everything shared lives in `tests/fixtures/`, grouped by subject and
re-exported from `tests/conftest.py`. A test never reaches sideways into
another package's conftest.

| Fixture | Gives you |
|---|---|
| `isolated_database` | Autouse. Every test gets its own SQLite file via `DATABASE_URL`, the same override production uses. |
| `sdk` | An SDK bound to that database, constructed but not started. |
| `readonly_sdk` | Already started in the read-only mode the REST API runs in. |
| `enrichment_sdk` / `maintenance_sdk` | Threat intel configured; maintenance timers pinned open. |
| `running_sdk` | Fully started with the live sniffer stubbed out, for capture replay. |
| `client` | A FastAPI `TestClient` over `readonly_sdk`. |
| `handler` | A logger wired to a capturing handler, isolated from global config. |

Builders (`make_alert`, `make_packet`, `make_detection`, `make_rule`) take
keyword overrides so a test states what makes it different rather than
restating every required field.

**Name the variant, do not fork the fixture.** Five suites once carried their
own `sdk` fixture, each free to drift. One fixture per distinct lifecycle,
named for the lifecycle, keeps the choice explicit at the point of use.

## Mocking policy

Unit tests substitute everything outside the module under test:

- **HTTP** — `respx`, against canned upstream bodies in
  `tests/fixtures/threat_intel.py`. No test may reach the network; the proxy
  environment variables are cleared so a developer behind a corporate proxy
  gets the same result as CI.
- **Filesystem** — `tmp_path`. No test writes into the repository.
- **Database** — a real SQLite file per test, not a mock. The repositories are
  thin enough that a mocked session would only assert that SQLAlchemy was
  called, and `:memory:` gives each connection its own private database, so
  cross-session behaviour would appear to work while proving nothing.
- **Capture** — `AsyncSniffer` is patched. Everything else on that path is
  real, including the replay code, which deliberately reuses the live packet
  callback.

Integration and end-to-end tests mock only the capture socket. That is the
point of them.

## Sample captures and golden files

`tests/data/pcaps/` holds one synthetic capture per attack, generated by
`scripts/generate_test_pcaps.py`. Each is tuned to cross exactly one
detector's threshold and stay clear of every other's, plus `benign.pcap`,
which must raise nothing — without it a detector that fires on everything
looks identical to one that works.

`tests/data/golden/` pins the full normalised detector output for each
capture: severity, tactic, addresses, description, evidence. To accept a
deliberate change:

```bash
ND_REFRESH_GOLDEN=1 uv run pytest tests/e2e/test_golden_detections.py
```

Then **read the diff** before committing it. A golden file refreshed without
anyone looking is a regression test that has quietly stopped testing.

## Mutation spot check

```bash
scripts/mutation_spot_check.sh              # run, then list survivors
scripts/mutation_spot_check.sh <mutant>     # show one mutant's diff
```

Coverage says a line was executed. Mutation testing says whether the suite
would have *noticed the line being wrong*, which for a detector is the whole
question: one that quietly stops detecting still satisfies every assertion
about the alerts it does raise.

Scoped to `src/network_defender/detectors`, currently killing 447 of 523
mutants. It is a spot check, not a gate — it takes minutes, and a surviving
mutant is a question to answer, not a build to fail.

Read the survivors like this: **a surviving mutant is a change to the source
that no test objected to.** Sometimes that is fine (mutated text inside a log
message). Sometimes it is a missing test, and the ones it found here were
real — both scan detectors' ingest filters could be rewired from `and` to
`or`, and `>=` could be weakened to `>` in most count-based detectors,
silently turning "alert on 10 attempts" into "alert on 11".

## Performance floors

Every floor sits one to two orders of magnitude below the measured figure
(detection ingest runs around 95 000 pkt/s against a 500 pkt/s floor). These
tests exist to catch an order-of-magnitude regression — a per-packet
allocation, an accidental O(n²) — not to certify a number that depends on
which runner picked up the job. Measurements are printed, so a CI log shows
the trend rather than just pass or fail.

`test_detection_latency` asserts on p95 and p99 rather than the mean: a sensor
that keeps up on average but stalls for 200 ms every few thousand packets
still drops traffic. A companion test compares the mean ingest cost of the
first and last tenth of a long run, which is what catches per-packet work that
is really proportional to accumulated state.

## Continuous integration

`.github/workflows/tests.yml` installs with `uv sync --frozen` — a stale
`uv.lock` fails there rather than quietly testing versions nobody pinned —
runs the suite, writes the coverage table into the job summary, and uploads
`reports/` as an artifact.

The coverage gate lives in `pyproject.toml`, so CI and a laptop enforce the
same number from the same file.

## Secrets scanning

```bash
gitleaks detect --config .gitleaks.toml --redact       # tree and full history
gitleaks detect --config .gitleaks.toml --no-git       # working tree only
```

CI runs the first form on every push and PR, and weekly on a schedule — a
scanner that only runs on pull requests misses exactly the commits nobody
reviewed. History is scanned with `fetch-depth: 0`, because a secret removed
from the tip is still in every clone, and finding it there is the only finding
that matters.

`.gitleaks.toml` extends the upstream rule set rather than replacing it; a
hand-rolled pattern list is a list of the leaks someone thought of. Every
allowlist entry states why it is safe, because an unexplained one is how a
real finding gets silenced by someone assuming a predecessor checked.

The redaction tests are allowlisted under both their current and pre-Milestone-14
paths. They contain credential-shaped strings because that is the input — each
asserts the logging filter rewrites it — and history is scanned, so an
allowlist that only knows the current layout goes blind on every commit before
the move.

`tests/unit/security/` covers the same ground in milliseconds on every test
run, with a much narrower rule set. The two are complementary: that suite
catches a paste while it is still uncommitted, gitleaks catches everything
else.

