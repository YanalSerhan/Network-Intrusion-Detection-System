"""
REST API and live WebSocket transport.

Everything here delegates to the SDK: routers translate HTTP into SDK calls
and SDK results into response models, and hold no business logic of their own.
"""
