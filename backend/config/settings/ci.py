"""
Test-only settings for the automated test suite.

NOT usable for running the application. It swaps in an in-memory sqlite database
and an empty URL configuration, so a server started with these settings would
have no routes and no persistent storage. Nothing in docker-compose.yml or any
Dockerfile references this module, and nothing should.

Its purpose is to keep the test run cheap. Every test in the suite is a
SimpleTestCase, so none of them touches the database or resolves a URL, but
Django still loads the database driver and imports ROOT_URLCONF during system
checks. config/urls.py wires every app's views, and those views import their
tasks module, which pulls in pulumi, boto3 and the rest of the runtime stack.
Pointing ROOT_URLCONF at an empty module cuts that chain: the suite then needs
only django, python-decouple, PyYAML, celery, and feedparser + requests for the
threat intel parser tests (see requirements-test.txt) — around 90 MB installed
instead of 450 MB. boto3 stays out because no test imports apps.threatintel's
storage or tasks module.
"""

from .base import *  # noqa: F401, F403

DEBUG = False

ALLOWED_HOSTS = ["*"]

# No test needs persistence. sqlite also removes the psycopg2 dependency, which
# Django would otherwise import while validating the DATABASES setting.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

ROOT_URLCONF = "config.ci_urls"

# Only the apps whose models or code the suite actually loads. apps.users owns
# AUTH_USER_MODEL, and apps.infrastructure is required because
# emulations.EmulationRun.stack is a foreign key to infrastructure.Stack;
# omitting it fails the system check with fields.E300. apps.threatintel has no
# models — it is listed so `manage.py test apps.threatintel` can discover its
# suite. The remaining apps (connectors, logs, ai) are not referenced by any
# test or by these models.
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "apps.users",
    "apps.infrastructure",
    "apps.emulations",
    "apps.metrics",
    "apps.threatintel",
]
