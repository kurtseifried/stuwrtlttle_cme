"""CME Server configuration via environment variables."""

import os

# Database backend: "sqlite" or "postgres"
DB_BACKEND = os.environ.get("CME_DB_BACKEND", "sqlite")

# PostgreSQL connection
PG_HOST = os.environ.get("CME_PG_HOST", "localhost")
PG_PORT = int(os.environ.get("CME_PG_PORT", "5432"))
PG_USER = os.environ.get("CME_PG_USER", "cme")
PG_PASSWORD = os.environ.get("CME_PG_PASSWORD", "cme")
PG_DATABASE = os.environ.get("CME_PG_DATABASE", "cme")

# Server transport: "stdio" or "streamable-http"
TRANSPORT = os.environ.get("CME_TRANSPORT", "stdio")

# HTTP server settings (only used with streamable-http transport)
HTTP_HOST = os.environ.get("CME_HTTP_HOST", "0.0.0.0")
HTTP_PORT = int(os.environ.get("CME_HTTP_PORT", "8000"))
