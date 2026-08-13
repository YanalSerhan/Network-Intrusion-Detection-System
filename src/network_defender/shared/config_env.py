"""
Environment variable overrides for configuration.

Data Setup:  Reads the process environment (and `.env`).
Data Input:  A raw config dict parsed from JSON.
Data Output: The same dict with environment overrides applied.

Convention: `ND__SECTION__KEY`, e.g. `ND__CAPTURE__INTERFACE=eth1` sets
`capture.interface`. A double underscore separates levels because single
underscores appear inside key names (`max_packets_per_second`).

A container image should be built once and configured per environment. Without
this, dev, staging and production each need a mounted config file differing in
two lines — which is how those files drift apart.

Values arrive as strings and are coerced against the model by `config_coerce`.
"""

import os
from typing import Any

from pydantic import BaseModel

from .config_coerce import coerce, field_annotation

#: Prefix marking an override. Namespaced so unrelated variables in a shared
#: container environment cannot collide with configuration.
ENV_PREFIX = "ND__"
ENV_SEPARATOR = "__"

#: ND__SECTION__KEY splits into exactly two parts; anything deeper is not a
#: path this configuration format has.
_SECTION_AND_KEY = 2

def collect_overrides(
    model: type[BaseModel], environ: dict[str, str] | None = None
) -> dict[str, Any]:
    """
    Read `ND__*` variables into a nested override dict.

    Args:
        model:   Config model, used to coerce values to declared types.
        environ: Environment mapping; defaults to `os.environ`.

    Returns:
        A nested dict such as `{"capture": {"interface": "eth1"}}`.
    """
    source = environ if environ is not None else dict(os.environ)
    overrides: dict[str, Any] = {}

    for name, raw in source.items():
        if not name.startswith(ENV_PREFIX):
            continue

        path = name[len(ENV_PREFIX) :].lower().split(ENV_SEPARATOR)
        if len(path) == 1:
            overrides[path[0]] = raw
        elif len(path) == _SECTION_AND_KEY:
            section, key = path
            overrides.setdefault(section, {})[key] = coerce(
                raw, field_annotation(model, section, key)
            )
        # Deeper paths are ignored: the schema is two levels, and silently
        # accepting `ND__A__B__C` would imply support that does not exist.

    return overrides


def apply_overrides(raw: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """
    Merge overrides into a config dict, one level deep.

    Args:
        raw:       Config parsed from JSON.
        overrides: Output of `collect_overrides`.

    Returns:
        A new dict; the input is not mutated.
    """
    merged = {key: dict(value) if isinstance(value, dict) else value for key, value in raw.items()}

    for section, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(section), dict):
            merged[section].update(value)
        else:
            merged[section] = value

    return merged
