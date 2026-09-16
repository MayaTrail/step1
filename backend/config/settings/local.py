"""
Local settings for running the app on a workstation without Docker.

config.settings.dev targets the docker-compose PostgreSQL service, so it cannot
start on a machine with no database running. This module inherits dev and swaps
in a file-backed sqlite database, which is enough to exercise everything that
does not touch AWS: signing in, the playbook editor, and the read-only
catalogue endpoints.

It is a development convenience, not a deployment target. Nothing in
docker-compose.yml or any Dockerfile references it, and nothing should - the
same contract config.settings.ci carries.

Usage:
    set DJANGO_SETTINGS_MODULE=config.settings.local
    python manage.py migrate
    python manage.py runserver 8000

Emulation deploy, attack and destroy still require the Celery worker, Redis and
real AWS credentials. Those paths are expected to fail here.
"""

from pathlib import Path

from .dev import *  # noqa: F401, F403

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# sqlite instead of the compose PostgreSQL service. The file lives beside
# manage.py so it survives between runs and can simply be deleted to reset.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "local.sqlite3",
    }
}

# The Vite dev server proxies /api to this process, so same-origin rules do not
# apply; keep CORS open as dev does.
CORS_ALLOW_ALL_ORIGINS = True

# Celery has no broker here. Run tasks inline so a stray .delay() raises in the
# request instead of vanishing into a queue nothing is consuming.
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
