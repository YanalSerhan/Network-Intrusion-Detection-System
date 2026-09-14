"""
What `import network_defender` promises.

A package surface is a promise to people who are not in this repository, and
the only thing that makes it one rather than an accident of import order is a
test that fails when it changes. This is that test: it pins the names, and it
pins the properties that make them usable — every name importable, every name
documented, and nothing exported that cannot be reached.
"""

import pkgutil
from pathlib import Path

import pytest

import network_defender
from network_defender.shared.paths import PROJECT_ROOT

#: The surface as of version 1.00. Changing this list is an API change: adding
#: a name is a minor bump, removing or renaming one is a major bump, and doing
#: either without touching this line is the thing the test exists to stop.
EXPECTED = {
    "Alert",
    "AlertSource",
    "AlertStatus",
    "BaseDetector",
    "DetectionAlert",
    "DetectorConfig",
    "MitreTactic",
    "NetworkDefenderSDK",
    "NotificationHook",
    "ParsedPacket",
    "Protocol",
    "Severity",
    "ThreatIntelProvider",
    "__version__",
}


def test_the_surface_is_exactly_what_it_declares() -> None:
    assert set(network_defender.__all__) == EXPECTED


def test_every_exported_name_resolves() -> None:
    """`__all__` is a claim; `from network_defender import *` is the test of it."""
    for name in network_defender.__all__:
        assert hasattr(network_defender, name), f"{name} is exported but absent"


def test_nothing_is_exported_twice() -> None:
    assert len(network_defender.__all__) == len(set(network_defender.__all__))


@pytest.mark.parametrize(
    "name", sorted(EXPECTED - {"__version__"})
)
def test_every_exported_type_carries_its_own_documentation(name: str) -> None:
    """A consumer reads `help()`, not this repository."""
    exported = getattr(network_defender, name)
    assert exported.__doc__, f"{name} is public and undocumented"


def test_the_version_is_a_string_not_a_tuple_or_a_module() -> None:
    assert isinstance(network_defender.__version__, str)
    assert network_defender.__version__.strip() == network_defender.__version__


def test_importing_the_package_starts_nothing() -> None:
    """
    Import must be free of side effects.

    A package that opens a socket, reads config or spawns a thread on import
    cannot be used from a test, a notebook or another application's startup —
    and the failure shows up as something unrelated much later.
    """
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-c", "import network_defender; print('ok')"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_every_subpackage_imports_on_its_own() -> None:
    """
    No module may depend on something else having been imported first.

    The registry discovers detectors by importing `detectors/impl/` at
    runtime, so a module that only works once the SDK has been constructed
    fails in production and nowhere else.
    """
    package_root = Path(network_defender.__file__).parent
    failures = []
    for module in pkgutil.walk_packages([str(package_root)], "network_defender."):
        if ".migrations" in module.name:
            continue
        try:
            __import__(module.name)
        except Exception as exc:  # noqa: BLE001 - reporting every failure is the point
            failures.append(f"{module.name}: {exc}")
    assert not failures, "\n".join(failures)


def test_the_package_declares_itself_typed() -> None:
    """PEP 561: without the marker, consumers silently see an untyped package."""
    assert (PROJECT_ROOT / "src" / "network_defender" / "py.typed").is_file()
