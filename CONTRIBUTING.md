# Contributing

Thanks for looking. This document is the part that is not enforced by a tool —
everything a linter can check is already in `pyproject.toml` and
`.pre-commit-config.yaml`, and the rest is here because an unwritten
convention lasts until the first person who has not read the codebase.

## Before you start

```bash
uv sync --all-groups
uv run pre-commit install
uv run pytest
```

`uv` is the only dependency manager. There is no `requirements.txt`, no
`setup.py` and no virtualenv to activate; `uv run` resolves the locked
environment, so what passes for you passes in CI.

If you are adding a detector or a threat intelligence provider, the recipes
are in [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md).

## Coding standards

Enforced automatically — a pull request that fails these will not be reviewed
until it passes, and none of it is negotiable in review:

| Check | Command | Configured in |
|---|---|---|
| Lint (13 rule families, including docstrings and complexity) | `uv run ruff check` | `pyproject.toml` |
| Types, strict, across `src`, `tests`, `scripts`, `migrations` | `uv run mypy` | `pyproject.toml` |
| Tests, branch coverage gated at 85% | `uv run pytest` | `pyproject.toml` |
| No file over 150 lines | part of the suite | `tests/unit/test_file_length_limit.py` |
| No committed secrets | `gitleaks detect --config .gitleaks.toml` | `.gitleaks.toml` |

The parts a tool cannot check:

**Write the test first, and watch it fail.** A test that has never failed has
not been shown to test anything — it is as likely to be asserting on a typo in
its own fixture as on the behaviour it names. A bug fix starts with a test
that reproduces the bug; if it passes before the fix, the bug is not
understood yet.

**A test name is a claim.** `test_syn_ack_replies_are_not_a_syn_scan` says what
must be true. `test_syn_scan_2` says nothing, and nobody can tell from a
failure whether it is the code or the test that is wrong.

**Comments say why, not what.** The code says what it does. A comment earns
its place by recording the alternative that was rejected, the bug that a line
prevents, or the constraint that is not visible locally. `# increment the
counter` is noise; `# sorted first: out-of-order arrivals produce negative
intervals, which mask real beacons` is the reason the next person does not
"simplify" it.

**Every module has a docstring saying what it is responsible for**, in the
`Data Setup / Data Input / Data Output` form the rest of the codebase uses.
Ruff enforces that one exists; only you can make it say something.

**150 lines is a proxy, not a target.** When a module outgrows it, split along
the concern boundary so the file name still says what failed — not at line
150. Nothing claims 150 is special, only that a number a build enforces is
worth more than a number a review is supposed to remember.

**No hardcoded values.** Thresholds, limits and paths live in `config/*.json`;
secrets live in the environment. A magic number in a detector is a number an
operator cannot tune and a reviewer cannot see. Ruff's `PLR2004` catches most
of it.

Naming has its own document: [docs/CONVENTIONS.md](docs/CONVENTIONS.md). The
short version is one word per concept, and verb prefixes that mean specific
things — `get_` returns one thing or `None`, `list_` returns many.

## Architectural rules

Three, and a pull request that breaks one will be sent back regardless of how
well it is written, because the damage is delayed:

1. **Everything goes through the SDK.** Routers, the CLI and embedders call
   `NetworkDefenderSDK`; nothing outside `sdk/` constructs or drives a
   service. Importing a *model* is fine — those are the data contract.
2. **Every outbound call goes through the gatekeeper.** There is exactly one
   `httpx` call site in the repository, and a provider cannot be constructed
   without a gatekeeper. Adding a second call site is how a free tier gets
   exceeded at three in the morning.
3. **Detectors are discovered, not registered.** Drop a module into
   `detectors/impl/` and the registry finds it. There is no list to update, so
   there is no list to forget.

These are ADRs 2 to 4 in [docs/PLAN.md](docs/PLAN.md). If you think one is
wrong, say so in an issue and propose an ADR — that is a legitimate outcome
and a better conversation than a pull request that quietly routes around it.

## Branches

```
<type>/<short-description>
```

`feat/beaconing-jitter-tolerance`, `fix/gatekeeper-daily-budget`,
`docs/threat-model`, `refactor/counting-detectors`,
`test/rule-engine-windows`, `chore/bump-scapy`.

Lower case, hyphens, no ticket numbers — a branch name should still mean
something to somebody who does not have the tracker open. Branch from `main`
and rebase rather than merge, so history stays readable.

## Commits

The convention is visible in `git log` and worth matching:

```
<type>(<scope>): <what changed, imperative, lower case, no full stop>

<why it changed, and what was considered instead>
```

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `ci`, `chore`. The scope is
optional and is a component — `fix(gatekeeper):`, `feat(cli):`.

**The body is the valuable part.** A subject line says what a diff already
shows. The body should say what a diff cannot: why this approach, what was
rejected, what the defect actually was, and what is still open. If a commit
fixes something subtle, describe the failure — the next person to hit it will
search for the symptom, not the fix.

Commits are small and self-contained. Each one should leave the suite green;
"WIP" commits get squashed before review.

## Pull requests

1. Branch from `main`.
2. Make the change, with tests, in commits that each leave the build green.
3. Run `uv run pytest`, `uv run ruff check` and `uv run mypy` locally. CI runs
   the same commands from the same configuration, so a green local run means
   a green CI run.
4. Update the documentation that your change makes wrong. Not "documentation"
   in general — the specific file. Detector behaviour touches
   [docs/DETECTORS.md](docs/DETECTORS.md); configuration touches
   [docs/CONFIGURATION.md](docs/CONFIGURATION.md) and `.env-example`; the API
   contract means regenerating `docs/openapi.json`.
5. Open the pull request against `main`, describing what changed and why, and
   what you *did not* do.
6. Tick the checklist below.

### Checklist

- [ ] Tests written before the code, and watched to fail
- [ ] `uv run pytest` green, coverage not reduced
- [ ] `uv run ruff check` and `uv run mypy` clean
- [ ] No file over 150 lines
- [ ] No hardcoded thresholds, paths or secrets
- [ ] Docstrings on new modules, classes and public functions
- [ ] Documentation updated, including `docs/openapi.json` if the API changed
- [ ] Golden files refreshed *and the diff read*, if detector output changed

## Reporting a security issue

Do not open a public issue. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
for what is in scope; the residual risks listed there are known and do not
need reporting, though better mitigations for them are very welcome.

## Reporting a bug

The useful ones say what you expected, what happened, and how to reproduce it.
A `.pcap` that triggers the behaviour is worth more than any description —
`network-defender replay` takes one, which makes a report something a
maintainer can run rather than interpret.
