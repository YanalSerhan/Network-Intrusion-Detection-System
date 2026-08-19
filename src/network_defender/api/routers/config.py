"""
/config endpoints.

Data Setup:  SDK injected per request.
Data Input:  None.
Data Output: Non-secret runtime configuration.

Everything returned here is safe to show an operator. Credentials are never
included: the database URL is redacted (it may carry a password) and API keys
are reported as booleans only, so the response answers "is a key configured?"
without ever answering "what is it?".

That boolean matters. Authentication is disabled when no key is set, so a
deployment that forgot to configure one is open; surfacing the flag makes that
visible instead of silent.
"""

from fastapi import APIRouter

from ...constants import ENV_ABUSEIPDB_API_KEY, ENV_API_KEY
from ..dependencies import AuthDep, SdkDep
from ..schemas.operations import ConfigResponse

router = APIRouter(prefix="/config", tags=["config"], dependencies=[AuthDep])

#: Database settings safe to expose. `default_url` and any env-sourced URL are
#: excluded because a PostgreSQL DSN embeds credentials.
SAFE_DATABASE_KEYS = ("url_env_var", "echo")


@router.get("", response_model=ConfigResponse, summary="Get runtime configuration")
def get_config(sdk: SdkDep) -> ConfigResponse:
    """Return the active configuration with every secret redacted."""
    app_config = sdk.get_app_config()
    database = app_config.database.model_dump()

    return ConfigResponse(
        version=app_config.version,
        api=app_config.api.model_dump(),
        capture=app_config.capture.model_dump(),
        detection=app_config.detection.model_dump(),
        dashboard=app_config.dashboard.model_dump(),
        database={key: database[key] for key in SAFE_DATABASE_KEYS},
        retention=app_config.retention.model_dump(),
        secrets_configured=sdk.describe_configured_secrets(
            ENV_API_KEY, ENV_ABUSEIPDB_API_KEY
        ),
    )
