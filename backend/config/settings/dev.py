"""
Development settings for MayaTrail backend.

Enables DEBUG mode, relaxed CORS, and connects to a local or
docker-compose PostgreSQL instance via DATABASE_URL.
"""

from decouple import config

from .base import *  # noqa: F401, F403

# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

DEBUG = True

ALLOWED_HOSTS = ["*"]

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": config("POSTGRES_DB", default="mayatrail"),
        "USER": config("POSTGRES_USER", default="mayatrail"),
        "PASSWORD": config("POSTGRES_PASSWORD", default="mayatrail"),
        "HOST": config("POSTGRES_HOST", default="db"),
        "PORT": config("POSTGRES_PORT", default="5432"),
    }
}

# ---------------------------------------------------------------------------
# CORS — allow all origins in development
# ---------------------------------------------------------------------------

CORS_ALLOW_ALL_ORIGINS = True
