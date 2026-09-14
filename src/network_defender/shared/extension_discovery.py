"""
Finding extension modules that live outside this package.

Data Setup:  Entry points declared by installed distributions, plus module
             names an operator lists in configuration.
Data Input:  An entry-point group name, a list of module paths, or a package.
Data Output: Imported modules, with every failure isolated and logged.

It lives in `shared/` rather than in `plugins/` for a reason the building-block
review found: `plugins/__init__.py` is a façade that imports from `detectors`
and `services`, so a detector importing `plugins.discovery` made the package
depend on the façade that depends on it. It worked, because the import was of
a submodule rather than of a partially-initialised package — which is the kind
of thing that works until someone adds a line to an `__init__`. Discovery is
needed by two layers and is not domain logic, which is what `shared/` is for.

Two routes in, because there are two kinds of author.

**Entry points** are for a packaged extension. A distribution declares
`[project.entry-points."network_defender.detectors"]` and installing it is the
whole installation step — nothing to edit, and uninstalling removes it. This
is how a plugin ecosystem works in Python, and the reason it is here rather
than a directory of files to drop in is that a dropped file has no version, no
dependencies and no way to be uninstalled.

**Configured module paths** are for the operator who has a detector in a
module beside their sensor and no interest in packaging it. `detection`'s
`detector_modules` and `threat_intel`'s `provider_modules` take dotted paths,
imported the same way and held to the same contract.

One rule governs both: a plugin that fails to import is logged and skipped,
never raised. An intrusion detection sensor that will not start because a
third-party extension has a syntax error has turned someone else's bug into
an outage of the thing watching the network.
"""

import importlib
import logging
from importlib.metadata import entry_points
from pathlib import Path
from types import ModuleType

logger = logging.getLogger(__name__)

#: Entry-point group for modules containing BaseDetector subclasses.
DETECTOR_GROUP = "network_defender.detectors"

#: Entry-point group for modules containing ThreatIntelProvider subclasses.
PROVIDER_GROUP = "network_defender.providers"


def _import(dotted_path: str, source: str) -> ModuleType | None:
    """
    Import one module, or log why it could not be imported.

    Args:
        dotted_path: Module to import.
        source:      Where the name came from, for the log line. A person
                     debugging needs to know whether to look at their config
                     or at something they installed.

    Returns:
        The module, or None.
    """
    try:
        return importlib.import_module(dotted_path)
    except Exception as exc:  # noqa: BLE001 - one bad plugin must not stop the sensor
        logger.error("Plugin module %s (%s) failed to import: %s", dotted_path, source, exc)
        return None


def discover_modules(group: str, configured: list[str] | None = None) -> list[ModuleType]:
    """
    Import every extension module declared for one extension point.

    Args:
        group:      Entry-point group name (`DETECTOR_GROUP`, `PROVIDER_GROUP`).
        configured: Extra dotted module paths from configuration.

    Returns:
        Imported modules, deduplicated, in the order found: entry points
        first, then configured paths. Order decides nothing except which log
        line appears first; both routes are equal.
    """
    found: dict[str, ModuleType] = {}

    for entry in entry_points(group=group):
        # `entry.value` may name an attribute (`pkg.mod:Class`); the registry
        # scans whole modules, so only the module half is used.
        module = _import(entry.value.split(":", 1)[0], f"entry point {entry.name}")
        if module is not None:
            found[module.__name__] = module

    for dotted_path in configured or []:
        module = _import(dotted_path, "configuration")
        if module is not None:
            found.setdefault(module.__name__, module)

    if found:
        logger.info("Discovered %d plugin module(s) for %s: %s",
                    len(found), group, ", ".join(sorted(found)))
    return list(found.values())


def import_package_modules(package_name: str) -> list[ModuleType]:
    """
    Import every module in one package, for the built-in detectors.

    Here rather than in the registry because it is the same operation as
    `discover_modules` on the other route — turn a name into imported modules
    without letting one failure take the rest with it — and the two should not
    drift apart in how they handle a module that will not load.

    Args:
        package_name: Dotted path of the package to scan.

    Returns:
        Its modules, excluding `__init__`, in a stable order. Empty if the
        package itself cannot be imported, which is logged.
    """
    try:
        package = importlib.import_module(package_name)
        if package.__file__ is None:
            raise ImportError(f"Package {package_name} has no __file__")
        package_path = Path(package.__file__).parent
    except ImportError as exc:
        logger.error("Failed to import package %s: %s", package_name, exc)
        return []

    modules = []
    for child in sorted(package_path.glob("*.py")):
        if child.name == "__init__.py":
            continue
        module = _import(f"{package_name}.{child.stem}", f"package {package_name}")
        if module is not None:
            modules.append(module)
    return modules
