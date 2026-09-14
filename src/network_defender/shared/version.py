"""
The single source of truth for the project version.

Everything that reports a version derives it from here: `PROJECT_VERSION` in
constants, the `version` field both config schemas default to, the REST API's
`/health` and OpenAPI document, and `network-defender --version`. Four of
those were separate literals reading "1.00" and agreeing by coincidence.

The exception is `pyproject.toml`, which cannot import anything — a build
backend reads it before this package exists. It carries its own literal, and
`tests/unit/packaging/` fails if the two drift. Note that PEP 440 normalises
`1.00` to `1.0` in installed distribution metadata, so compare parsed
versions rather than strings when the two have to agree.

This module imports nothing, deliberately: it is imported by `constants`,
which is imported by nearly everything, and a dependency here would be a
cycle waiting for its second edge.

Bumping it
----------
One number for the whole project, starting at 1.00. Raise it when behaviour
someone outside this repository depends on changes: the package surface in
`__init__.py`, the REST API, the configuration schema, or what a detector
does with the same traffic. Record what changed in CHANGELOG.md in the same
commit — a version that moves without a line saying why is a number, not a
version.
"""

__version__ = "1.00"
