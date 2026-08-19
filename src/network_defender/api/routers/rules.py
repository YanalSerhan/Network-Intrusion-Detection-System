"""
/rules endpoints.

Data Setup:  SDK injected per request.
Data Input:  Rule names and toggle bodies.
Data Output: The loaded rule set and reload results.

Toggling is a **runtime override**: it marks the rule disabled in the running
engine and the database snapshot, and does not rewrite the YAML file. A service
that edits its own config files fights hot-reload and any git-managed rule set,
and makes the on-disk state disagree with what an operator last committed. The
override therefore reverts on reload or restart, which is the safe default for
an emergency "silence this noisy rule" action.
"""

from typing import Annotated

from fastapi import APIRouter, Path

from ...database.column_widths import RULE_NAME_LENGTH
from ..dependencies import AuthDep, PaginationDep, SdkDep
from ..errors import NotFoundError
from ..schemas.common import build_meta
from ..schemas.resources import RulePage, RuleReloadResult, RuleToggle, RuleView

#: Bounded to the column that stores it. Without a limit the name is
#: unbounded free text that is reflected back in a 404 message and written to
#: a log line — neither is an injection, but both are work an unauthenticated
#: caller should not be able to ask for by the megabyte.
NameParam = Annotated[str, Path(description="Rule name.", max_length=RULE_NAME_LENGTH)]

router = APIRouter(prefix="/rules", tags=["rules"], dependencies=[AuthDep])


@router.get("", response_model=RulePage, summary="List detection rules")
def list_rules(sdk: SdkDep, pagination: PaginationDep) -> RulePage:
    """Return the currently loaded rule set, ordered by name."""
    rules = sdk.get_loaded_rules()
    page = rules[pagination.offset : pagination.offset + pagination.limit]
    return RulePage(
        items=[RuleView(**rule) for rule in page],
        meta=build_meta(len(page), pagination.limit, pagination.offset, total=len(rules)),
    )


@router.post("/reload", response_model=RuleReloadResult, summary="Reload rules from disk")
def reload_rules(sdk: SdkDep) -> RuleReloadResult:
    """
    Re-read every rule file and refresh the snapshot.

    Also clears any runtime enable/disable overrides, since the files on disk
    are the source of truth.
    """
    return RuleReloadResult(status="success", loaded_rules_count=sdk.reload_rules())


@router.get("/{name}", response_model=RuleView, summary="Get a rule")
def get_rule(
    sdk: SdkDep,
    name: NameParam,
) -> RuleView:
    """
    Return a single rule by name.

    Raises:
        NotFoundError: If no rule has this name.
    """
    rule = sdk.get_rule(name)
    if rule is None:
        raise NotFoundError(f"No rule named '{name}'.")
    return RuleView(**rule)


@router.patch("/{name}", response_model=RuleView, summary="Enable or disable a rule")
def toggle_rule(
    sdk: SdkDep,
    name: NameParam,
    toggle: RuleToggle,
) -> RuleView:
    """
    Enable or disable a rule at runtime, without touching its YAML file.

    Raises:
        NotFoundError: If no rule has this name.
    """
    rule = sdk.set_rule_enabled(name, toggle.enabled)
    if rule is None:
        raise NotFoundError(f"No rule named '{name}'.")
    return RuleView(**rule)
