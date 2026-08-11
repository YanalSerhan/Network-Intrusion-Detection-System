"""
Project path resolution.

Data Setup:  Derives the project root from this file's location.
Data Input:  Relative or absolute path strings from configuration.
Data Output: Absolute Path objects.

Why this exists
---------------
Config values such as `rules_dir: "rules/"` are relative. Resolving them against
the current working directory means the application behaves differently
depending on where it was launched from: run from anywhere but the repository
root and the rule loader silently creates an empty `rules/` directory and loads
zero rules. Every relative config path is therefore anchored to the project
root instead, matching how config/ is already located.
"""

from pathlib import Path

#: Repository root: src/network_defender/shared/paths.py -> up four levels.
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent

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
