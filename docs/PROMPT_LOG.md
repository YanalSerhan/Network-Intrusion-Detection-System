# Prompt engineering log

This project was built with AI assistance. This log records how, so the result
can be judged knowing where it came from — and so that what the method
repeatedly failed to catch is written down beside what it did well.

## How to read this

**Entries from Milestone 14 onward are first-hand**: the prompts are quoted
verbatim from the sessions that produced those commits. **Entries before that
are reconstructed** from `git log` and from the single contemporaneous entry
that was recorded at the time. Their prompts are given as the shape used
rather than as exact text, and are marked *(reconstructed)*. Inventing
verbatim prompts for sessions nobody kept a record of would make this document
worth less than the gap it is filling.

102 commits, 2026-07-06 to 2026-08-19.

## The working method

One pattern, used for every milestone:

```
can you fully implement phase <N> in the TODO.md file.
i want you to commit each task you finish one at a time.
```

`docs/TODO.md` holds every milestone as a checklist of specific, testable
items. That file — not the prompt — carried the requirements. The prompt's
whole job was to point at a milestone and set the commit granularity.

Three constraints were restated across sessions and did most of the work:

- **One commit per checklist item**, with the checkbox ticked in the same
  commit. This forces the work to decompose, and an item that cannot be
  committed on its own is an item that was not understood.
- **Commit, do not push.** Every session's output stayed reviewable.
- **Report what you found, not only what you built.** This is what produced
  the findings sections in the milestones below rather than just the fixes.

## Log

### Milestones 0–4 — scaffolding through the detection engine *(reconstructed)*

- **Date:** 2026-07-06
- **Goal:** Project architecture, planning documents, packet capture, the
  parser, the rule engine, and the first heuristic detectors.
- **Prompt shape:** "can you fully implement Milestone 0 in the
  @[docs/TODO.md] file", repeated per milestone. Milestone 0's is the one
  prompt recorded at the time and is verbatim.
- **Result:** PRD, PLAN, per-mechanism PRDs, the SDK skeleton, the gatekeeper,
  capture, parser, rules, and three detectors.
- **Lesson recorded at the time:** defining strict milestones in TODO.md
  guided the work more effectively than describing the goal in the prompt.

### Milestones 7–12 — alerts, threat intel, database, API, dashboard, observability *(reconstructed)*

- **Date:** 2026-08-11
- **Goal:** The whole vertical slice, from a detection to a rendered alert.
- **Result:** 40 commits. Each subsystem arrived as five or six — models, then
  the mechanism, then wiring, then tests, then its document.
- **What went wrong, and was caught:** `fix: connect the detection pipeline
  and correct rule/detector defects` exists because the alert system was built
  and tested in isolation and was not actually receiving detections.
  Subsystems built to a specification pass their own tests and do not
  necessarily meet.
- **Lesson:** one end-to-end test replaying real traffic through the real
  pipeline is worth more than any number of per-layer unit tests. It arrived
  in Milestone 14 and should have existed by Milestone 7.

### Milestone 13 — configuration *(reconstructed)*

- **Date:** 2026-08-12
- **Result:** Environment overrides, fail-fast validation, and
  `fix(config): make enrich_private_ips and http_timeout_seconds take effect`
  — the first instance of a defect class this project kept finding: a value
  that is configured, validated, documented, and read by nothing.

### Milestone 14 — testing and QA

- **Date:** 2026-08-13
- **Prompt:** *"can you fully implement phase 14 in the TODO.md file. i want
  you to commit each task you finish one at the time."*
- **Clarifications given:** one commit per logical unit; commit locally, do
  not push; implement the full milestone including the stretch goals.
- **Result:** 714 tests, unit tests mirroring `src/`, thirteen synthetic
  attack captures, golden files, throughput floors, and a mutation spot check.
- **What the mutation check found:** both scan detectors' ingest filters could
  be rewired from `and` to `or`, and `>=` could be weakened to `>` in most
  count-based detectors, with no test objecting. Coverage was 97% at the time.
- **Lesson:** high coverage says the lines ran. It does not say a test would
  notice them being wrong, and for a detector that is the whole question.

### Milestone 15 — code quality and static analysis

- **Date:** 2026-08-13
- **Prompt:** *"now let's move on to phase 15. do one commit per task"*
- **Clarifications given:** Python only, the frontend is out of scope; enforce
  whatever can be enforced mechanically rather than by review.
- **Result:** 13 ruff rule families, strict mypy across four directories, a
  test that fails the build when a file exceeds 150 lines, and two refactors
  that removed six copies of the same detector loop.
- **What it found:** confidence scoring used a *second copy* of the detector
  thresholds, and the two had already drifted — exfiltration scored against
  100 MB while firing at 50 MB. A SQLite database named `:memory:` had been
  committed at the repository root, holding real capture rows.
- **Lesson:** "enforce what is mechanisable" was the highest-leverage
  instruction in the project. A rule a reviewer is supposed to remember is a
  rule that holds until the reviewer is tired.

### Milestone 16 — security and secrets

- **Date:** 2026-08-19
- **Prompt:** *"now let's move on and fully implement phase 16"*
- **Result:** Gatekeeper fixes, constant-time credential comparison, secrets
  scanning in CI, input hardening, and the threat model.
- **What it found:** four of the gatekeeper's advertised guarantees did not
  hold — retries were not counted, the daily budget was never enforced, the
  queue never held anything so backpressure could not fire, and two threads
  shared it with no lock. `retention_days` was configured, validated, reported
  by the API, and never reached the pruner.
- **Lesson:** the Milestone 13 defect class, twice more. A value in a
  configuration file is a claim, and nothing had been checking the claims.

### Milestone 19 — research and sensitivity analysis

- **Date:** 2026-08-19
- **Prompt:** *"can you fully implement phase 19 and skip phases 17 and 18 and
  come back to them later?"*
- **Result:** A 49-case labelled corpus, a 777-point parameter sweep, a
  notebook, four figure families, and `docs/DETECTION_TUNING.md`.
- **What it found:** every detector declares a `time_window_seconds`; no code
  reads one. **Five of the twelve tunable detectors have a recall of 0.00 on
  live traffic as shipped.** Nothing in fifteen milestones had noticed,
  because every test either replays a capture — flushed once at the end, so
  the whole file is one window — or drives a detector directly.
- **The most important lesson in this log:** *asking for measurement found
  more than asking for review ever did.* Fifteen milestones of code review,
  linting, type checking and a thousand tests did not surface this; one
  milestone that asked "how well does it actually detect" surfaced it in an
  afternoon. A prompt that says "check this is good" gets an opinion. A prompt
  that says "measure this and report the number" gets a number, and numbers
  can be wrong in ways opinions cannot.
- **Second lesson:** the first version of the corpus used evenly-spaced
  arrivals with ±15% jitter, whose coefficient of variation sits *inside* the
  beaconing detector's tolerance — so every burst read as a beacon and that
  column was measuring the fixture rather than the detector. Generated test
  data has to be checked against the thing it is testing, not against
  intuition.

### Milestone 20 — documentation

- **Date:** 2026-08-19
- **Prompt:** *"can you fully implement phase 20? don't push to github just
  commit."*
- **Result:** README, contribution guide, developer guide, architecture,
  per-detector explainer, example-attack walkthrough, roadmap, API narrative
  guide, dashboard screenshots — and a CLI.
- **What it found — five defects, every one from writing documentation:**
  1. The project had **no entry point at all**. The README's usage section
     held `# Example start command` because there was nothing to put there.
  2. **Uvicorn was serving no WebSockets**, having no protocol library
     declared as a dependency, so the dashboard was an empty shell in any real
     deployment. The whole test suite passed against it, because Starlette's
     `TestClient` implements the protocol itself.
  3. **The Content-Security-Policy was refusing `index.html`'s inline
     script** — the one that applies the theme before first paint, so being
     refused caused precisely the flash it existed to prevent.
  4. **Every static file outside `assets/` was served as `index.html`**, at
     status 200, so the browser silently refused to execute it.
  5. **`pytest -m performance` collected zero tests.** The marker was
     declared, documented, and carried by nothing.
- **Lesson:** *writing an instruction is a test of that instruction.* None of
  those was found by reading code. Each was found by trying to do what a
  document said — taking the screenshot, running the command, following the
  recipe. A documentation milestone is a cheap integration test, provided the
  documentation is written by doing rather than by describing.

## What this method is bad at

Recorded because a log that lists only successes is advertising.

- **It builds to specifications, and specifications do not meet.** Milestones
  7 through 12 produced six subsystems that each passed their own tests and
  did not connect. The fix commit is in the history.
- **It will assert plausible things.** Every number in this repository that
  was not pasted from a command's output was, at some point, a guess. The
  countermeasure that worked was mechanical: run it, paste the output, and
  make the results reproducible so a diff catches the drift.
- **It is bad at noticing what is absent.** A missing entry point, a marker
  nothing carries, a dependency nobody declared — none of these looks wrong
  when you read the code, because there is nothing there to look at. All of
  them were found by *using* the system.
- **It follows a checklist past the point where the checklist is wrong.** The
  Milestone 22 checklist names `dashboard/`, `models/` and `utils/` packages
  that should not exist in this design. It took until Milestone 15's review to
  say so out loud, and until Milestone 20 to write down why.
- **It needs to be told to report bad news.** The instruction to record what
  was found rather than only what was built is what produced
  `docs/CODE_REVIEW.md`, `docs/DETECTION_TUNING.md`, and the "three things
  that look wrong, and are" section of the attack walkthrough. Without it the
  same work would have produced the same fixes and none of the findings.
