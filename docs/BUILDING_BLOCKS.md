# Building-block review

Whether the pieces of this system are reusable, decoupled and independently
testable — checked rather than asserted, because the answer to "is it modular"
is always yes until someone measures it.

Three claims, three ways of testing them, and what each found. The mechanised
parts live in `tests/unit/architecture/` so they stay true; this document is
what the measurement *meant*.

## 1. Decoupled

**Method.** The real import graph between top-level packages, computed from
the AST, compared against the layering the architecture claims.
`tests/unit/architecture/test_layering.py` holds the allowed edges: adding one
is now a line someone writes in that file, not something that happens.

**What it found.** Three edges that should not have existed. All three worked
fine, which is the point — a layering violation does not announce itself, it
just means the piece can no longer be lifted out on its own.

| Edge | Why it was wrong | Resolution |
|---|---|---|
| `api` → `database.column_widths` | An HTTP router imported an ORM column width to bound a path parameter. The limit is a rule about rule names, not a fact about storage; the router only reached into persistence because that was where the number happened to be. | `RULE_NAME_MAX_LENGTH` moved to `constants`; the column is sized to it. |
| `detectors` → `plugins` → `detectors` | The registry imported `plugins.discovery`, and `plugins/__init__` imports `detectors.base`. A cycle that worked only because the import was of a submodule rather than of a partially-initialised package — the kind of thing that works until someone adds a line to an `__init__`. | Discovery moved to `shared/extension_discovery.py`. Two layers need it and it is not domain logic, which is what `shared/` is for. `plugins/` is now a façade nothing inside the package imports. |
| `services.alerts` → a module-level cache nothing invalidated | Not an import edge, but the same failure: `reference_thresholds` read `detectors.json` once per process while the detector registry re-read it on every load. A sensor restarted in-process after an operator edited a threshold scored confidence against the old value. | `AlertService._do_start` resets it, beside the deduplicator reset that was already there for the same reason. |

**What it confirmed.** Three properties worth having, now pinned by tests:

- **`detectors` depends on `constants`, `parser` and `shared`, and nothing
  else.** No database, no services, no SDK. This is why
  `scripts/sensitivity/` can replay a 49-case corpus through real detectors
  with no infrastructure at all, and why the sensitivity analysis exists. The
  first detector that reaches for an alert repository would end that quietly,
  so a test says so out loud.
- **`database` depends on `services`, not the other way round.** That reads
  backwards and is correct: the domain model and the repository *interface*
  live under `services/alerts/`, and the SQLAlchemy implementation depends on
  them. The adapter depends on the port.
- **`api` and `cli` reach the system only through `sdk`.** Their other edges
  are to models — the types they serialise — and not to any service's
  behaviour. Two entry points that could each define "start" differently, and
  do not.

## 2. Independently testable

**Method.** Every component's constructor was read for what it demands, and
the suite was read for what it actually constructs.

**What it found.** Nothing broken, and one property worth naming: **no
component reaches for global state to find its collaborators.** Every service
takes its dependencies as constructor arguments with defaults — `AlertService`
builds an in-memory repository when given none, `DetectionService` takes a
config directory and two callbacks, every provider takes its gatekeeper. There
is no service locator and no singleton to reset between tests.

The evidence that this is real rather than aspirational is the shape of the
suite. `tests/unit/detectors/` constructs detectors with a config object and
feeds them packets. `tests/unit/rules/` drives the engine with no database.
`tests/unit/services/alerts/` exercises the full alert pipeline against an
in-memory repository. None of them starts an SDK, and the integration tests
that do exist are there to test the wiring specifically.

Five module-level mutables exist, all private and all process-level by
intent: an `lru_cache` on filter compilation, the correlation-ID `ContextVar`,
a logging-configured-once flag, a dotenv-loaded-once flag, and the threshold
cache above. Only the last was load-bearing, and only it was wrong.

## 3. Reusable

**Method.** Reusability is not a property of a module in isolation; it is
whether the piece has in fact been reused somewhere its author did not build
it for. So: where has it?

**What it found.** Four places, which is the strongest evidence available:

- **The sensitivity harness** (`scripts/sensitivity/`) uses the detector
  layer, the parser and nothing else, against generated traffic that has never
  been near a socket. 791 grid points, no database.
- **The replay path** feeds the same packet callback the live sniffer does, so
  `network-defender replay` exercises the production pipeline rather than a
  test double of it.
- **Golden-file tests** drive `DetectionService` directly — no threads, no
  clock, no database — which is what makes their output diffable.
- **Plugins.** A third-party detector subclasses the same base class, reads
  the same config file and is invoked by the same registry. Nothing about the
  extension path is a parallel implementation, which is the usual way a plugin
  system ends up behaving differently from the built-ins.

The counter-example is worth stating too. `services/` is 42 files and the
largest package, and it holds two different kinds of thing: the domain models
(`alerts/models.py`, `threat_intel/models.py`) and the services that operate
on them. That is why `database` has to import from `services` to see an
`Alert`. It works, and the dependency direction is right, but a package named
for behaviour is holding the vocabulary — and if this system grew a second
consumer of the domain model that was not a service, the models would want
moving out. Recorded rather than done: the change is large, the current
arrangement is not wrong, and doing it without a reason beyond tidiness is how
a refactor becomes a regression.

## What this review is not

It measures structure, not quality of the code inside each block. A layer can
depend only on what it should and still be the wrong abstraction. The ISO/IEC
25010 mapping in [QUALITY.md](QUALITY.md) is the wider assessment; this is the
narrow, checkable part of it.
