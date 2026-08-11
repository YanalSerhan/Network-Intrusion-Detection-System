"""
API routers, one module per resource.

Every handler delegates to the SDK: routers parse inputs, call one SDK method
and project the result onto a response schema. No business logic lives here.
"""
