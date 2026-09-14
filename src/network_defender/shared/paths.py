"""
Project path resolution.

Data Setup:  Derives the project root from this file's location, or from the
             data bundled into an installed wheel.
Data Input:  Relative or absolute path strings from configuration.
Data Output: Absolute Path objects.

Why this exists
---------------
Config values such as `rules_dir: "rules/"` are relative. Resolving them
against the current working directory means the application behaves
differently depending on where it was launched from: run from anywhere but
the repository root and the rule loader silently creates an empty `rules/`
directory and loads zero rules. Every relative config path is therefore
anchored to the project root instead, matching how config/ is already located.

Which root, though
------------------
Four levels up from this file is the repository root when running from a
checkout, and `site-packages/../..` — the interpreter's `lib/python3.13` — when
installed from a wheel. The installed case was not handled at all: `pip
install network-defender` then `network-defender replay` looked for
`.venv/lib/python3.13/config/detectors.json`, announced it would use defaults,
and then died trying to run migrations from a `migrations/` directory that
also did not exist. Every test passed throughout, because the suite runs from
the checkout where the guess happens to be right.

So the root is now chosen rather than assumed, in three steps:

1. `ND_PROJECT_ROOT`, for an operator who keeps configuration outside the
   installation — `/etc/network-defender`, a mounted volume, a config
   management checkout.
2. The repository root, when this file is inside one. This is the developer
   and the editable install, and it must keep winning there or a checkout
   would silently read the bundled defaults instead of its own edited files.
3. The copy bundled into the package, which is what an installed wheel uses.
"""

import os
from pathlib import Path

#: Environment variable naming an explicit root. Checked first.
PROJECT_ROOT_ENV_VAR = "ND_PROJECT_ROOT"

#: Data shipped inside the wheel: config/, rules/, migrations/, alembic.ini.
#: Populated by the build's force-include; absent in a checkout, where the
#: real directories are found at the repository root instead.
BUNDLED_ROOT = Path(__file__).resolve().parent.parent / "_bundled"

#: src/network_defender/shared/paths.py -> up four levels.
_CHECKOUT_ROOT = Path(__file__).resolve().parent.parent.parent.parent


def _resolve_root() -> Path:
    """Return the directory that relative configuration paths anchor to."""
    override = os.environ.get(PROJECT_ROOT_ENV_VAR)
    if override:
        return Path(override).expanduser().resolve()
    if (_CHECKOUT_ROOT / "config").is_dir():
        return _CHECKOUT_ROOT
    if BUNDLED_ROOT.is_dir():
        return BUNDLED_ROOT
    # Neither: a partial installation. Returning the checkout guess keeps the
    # failure message pointing somewhere a person can reason about.
    return _CHECKOUT_ROOT


#: Repository root, an operator's override, or the bundled data directory.
PROJECT_ROOT = _resolve_root()

#: Directory holding setup.json, detectors.json, rate_limits.json, logging_config.json.
CONFIG_DIR = PROJECT_ROOT / "config"


def resolve_project_path(path: str | Path) -> Path:
    """
    Resolve a configured path to an absolute location.

    Absolute paths are returned unchanged; relative paths are anchored to the
    project root rather than the current working directory.

    Args:
        path: Path from configuration (e.g. "rules/", "/etc/nd/rules").

    Returns:
        An absolute Path.
    """
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return (PROJECT_ROOT / candidate).resolve()
