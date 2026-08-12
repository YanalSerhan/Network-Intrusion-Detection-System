"""
Environment variable overrides for configuration.

Data Setup:  Reads the process environment (and `.env`).
Data Input:  A raw config dict parsed from JSON.
Data Output: The same dict with environment overrides applied.

Convention: `ND__SECTION__KEY`, e.g. `ND__CAPTURE__INTERFACE=eth1` sets
`capture.interface`. A double underscore separates levels because single
underscores appear inside key names (`max_packets_per_second`) and would make
the split ambiguous.

Why this exists
---------------
A container image should be built once and configured per environment. Without
env overrides, dev, staging and production each need a mounted config file that
differs in two lines — which is how those files drift apart. This keeps one
committed `setup.json` as the baseline and lets deployments differ by
environment alone.

Values arrive as strings and are coerced against the Pydantic model, so
`ND__API__PORT=9000` produces an int and `ND__CAPTURE__PROMISCUOUS_MODE=false`
produces a bool rather than the string "false", which is truthy and would
silently enable what an operator meant to disable.
"""

import json
import os
from typing import Any

from pydantic import BaseModel

#: Prefix marking an override. Namespaced so unrelated variables in a shared
#: container environment cannot collide with configuration.
ENV_PREFIX = "ND__"
ENV_SEPARATOR = "__"

TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def _coerce(raw: str, annotation: Any) -> Any:
    """
    Convert an environment string to the type the model expects.

    Args:
        raw:        The environment value.
        annotation: The field's declared type, or None if unknown.

    Returns:
        The coerced value; the original string when no rule applies.
    """
    text = raw.strip()

    if annotation is bool:
        lowered = text.lower()
        if lowered in TRUE_VALUES:
            return True
        if lowered in FALSE_VALUES:
            return False
        # Anything else is left as-is so validation reports it, rather than
        # being silently treated as True the way a bare string would be.
        return text

    if annotation is int:
        return int(text) if _looks_numeric(text) else text
    if annotation is float:
        return float(text) if _looks_numeric(text) else text

    if annotation in (list, dict) or str(annotation).startswith(("list", "dict")):
        # Lists and dicts arrive as JSON, e.g. ND__THREAT_INTEL__PROVIDERS='["whois"]'
        try:
            return json.loads(text)
        except ValueError:
            # Fall back to a comma-separated list, which is friendlier to type
            # by hand in a shell than JSON quoting.
            return [item.strip() for item in text.split(",") if item.strip()]

    return text


def _looks_numeric(text: str) -> bool:
    """Return True if the text parses as a number."""
    try:
        float(text)
    except ValueError:
        return False
    return True


def _field_annotation(model: type[BaseModel], section: str, key: str) -> Any:
    """Return the declared type of `section.key`, or None if unknown."""
    section_field = model.model_fields.get(section)
    if section_field is None:
        return None

    nested = section_field.annotation
    if isinstance(nested, type) and issubclass(nested, BaseModel):
        field = nested.model_fields.get(key)
        return field.annotation if field else None
    return None


def collect_overrides(model: type[BaseModel], environ: dict[str, str] | None = None) -> dict[
    str, Any
]:
    """
    Read `ND__*` variables into a nested override dict.

    Args:
        model:   The config model, used to coerce values to declared types.
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
        elif len(path) == 2:
            section, key = path
            overrides.setdefault(section, {})[key] = _coerce(
                raw, _field_annotation(model, section, key)
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
