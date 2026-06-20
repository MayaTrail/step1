"""
Base Django settings shared across all environments.

Environment-specific settings files (dev.py, prod.py) import from here
and override only what they need.  All secrets are read via python-decouple
so that no credentials ever appear in source code.
"""

import os
from pathlib import Path

from decouple import config

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[2]  # backend/ locally, /app in container

# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

SECRET_KEY = config("SECRET_KEY")

ALLOWED_HOSTS = []

# ---------------------------------------------------------------------------
# Application definition
# ---------------------------------------------------------------------------

DJANGO_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

THIRD_PARTY_APPS = [
    "rest_framework",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    "corsheaders",
    "django_celery_beat",
]

LOCAL_APPS = [
    "apps.users",
    "apps.connectors",
    "apps.infrastructure",
    "apps.emulations",
    "apps.logs",
    "apps.metrics",
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "apps.users.middleware.DemoExpiryMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# ---------------------------------------------------------------------------
# Database — overridden per environment
# ---------------------------------------------------------------------------

DATABASES = {}

# ---------------------------------------------------------------------------
# Custom user model
# ---------------------------------------------------------------------------

AUTH_USER_MODEL = "users.User"

# ---------------------------------------------------------------------------
# Password validation
# ---------------------------------------------------------------------------

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# ---------------------------------------------------------------------------
# Internationalisation
# ---------------------------------------------------------------------------

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# ---------------------------------------------------------------------------
# Static files
# ---------------------------------------------------------------------------

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# Django REST Framework
# ---------------------------------------------------------------------------

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
}

# ---------------------------------------------------------------------------
# SimpleJWT
# ---------------------------------------------------------------------------

from datetime import timedelta

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=1),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "AUTH_HEADER_TYPES": ("Bearer",),
    "TOKEN_OBTAIN_SERIALIZER": "apps.users.serializers.MayaTrailTokenObtainPairSerializer",
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
}

# Google OAuth client ID — used by GoogleOAuthView to verify id_tokens.
# Obtain from Google Cloud Console -> APIs & Services -> Credentials.
GOOGLE_CLIENT_ID = config("GOOGLE_CLIENT_ID", default="")

# ---------------------------------------------------------------------------
# Celery
# ---------------------------------------------------------------------------

CELERY_BROKER_URL = config("REDIS_URL", default="redis://localhost:6379/0")
CELERY_RESULT_BACKEND = config("REDIS_URL", default="redis://localhost:6379/0")
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = "UTC"
# Route all tasks that don't specify a queue explicitly to "default".
# Without this, Celery uses its built-in "celery" queue name, which none
# of the worker services consume.
CELERY_TASK_DEFAULT_QUEUE = "default"

# Celery Beat schedule — runs every 15 minutes to destroy expired stacks.
from celery.schedules import crontab  # noqa: E402

CELERY_BEAT_SCHEDULE = {
    "auto-destroy-expired-stacks": {
        "task": "emulations.auto_destroy_expired_stacks",
        "schedule": crontab(minute="*/15"),
    },
}

# ---------------------------------------------------------------------------
# Emulations
# ---------------------------------------------------------------------------
# Base directory under which emulation packages are mounted.
# Each emulation's Pulumi program lives at {EMULATIONS_BASE_DIR}/{type}/infra/.
# In docker-compose, ./emulations is mounted at /opt/emulations.
# The parent of this directory (/opt) is inserted into sys.path by the
# registry and tasks so that `import emulations.*` resolves correctly.

EMULATIONS_BASE_DIR = config("EMULATIONS_BASE_DIR", default="")

# ---------------------------------------------------------------------------
# Registration gate
# ---------------------------------------------------------------------------
# When set to a non-empty string, every registration request must include
# this exact invite code.  Set to "" (empty) to allow open registration.

REGISTRATION_INVITE_CODE = config("REGISTRATION_INVITE_CODE", default="")

# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------
# By default, emails are printed to the console (handy for development).
# In production, override EMAIL_BACKEND and provide SMTP credentials.

EMAIL_BACKEND = config(
    "EMAIL_BACKEND",
    default="django.core.mail.backends.console.EmailBackend",
)
EMAIL_HOST = config("EMAIL_HOST", default="smtp.gmail.com")
EMAIL_PORT = config("EMAIL_PORT", default=587, cast=int)
EMAIL_HOST_USER = config("EMAIL_HOST_USER", default="")
EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD", default="")
EMAIL_USE_TLS = config("EMAIL_USE_TLS", default=True, cast=bool)
DEFAULT_FROM_EMAIL = config("DEFAULT_FROM_EMAIL", default="MayaTrail <noreply@mayatrail.tech>")

# ---------------------------------------------------------------------------
# OTP settings
# ---------------------------------------------------------------------------

OTP_EXPIRY_MINUTES = config("OTP_EXPIRY_MINUTES", default=10, cast=int)
OTP_MAX_ATTEMPTS = config("OTP_MAX_ATTEMPTS", default=5, cast=int)

# ---------------------------------------------------------------------------
# Demo mode
# ---------------------------------------------------------------------------
# Duration in minutes for demo sandbox sessions. After this window the
# middleware blocks all protected API calls until the user connects AWS.

DEMO_DURATION_MINUTES = config("DEMO_DURATION_MINUTES", default=5, cast=int)
