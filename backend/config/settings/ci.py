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
only django, python-decouple, PyYAML and celery (see requirements-test.txt),
which is roughly 86 MB installed instead of 450 MB.
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
# omitting it fails the system check with fields.E300. apps.guardrails and
# apps.threatintel have no models and are listed only so their test labels
# resolve. apps.workflows does own models, and they carry foreign keys to
# infrastructure.Stack and emulations.EmulationRun, both already present. The
# remaining apps (connectors, logs, ai) are not referenced by any test or by
# these models.
#
# apps.playbooks owns the Playbook model and apps.authored_detections owns
# AuthoredDetection; both have database-backed tests, so their migrations run
# against the in-memory sqlite above. Their view tests import DRF and skip
# themselves when it is absent, the same way the detection-validator test skips
# without pySigma.
# Build the test database straight from the models, with no migration graph.
#
# Four apps ship no migrations on purpose (docker-compose generates them at
# container start), which leaves workflows/0001 depending on
# infrastructure.__first__ -- a node that does not exist. Nothing noticed while
# every suite here was a SimpleTestCase, because Django only builds the test
# database when a test actually asks for one. The moment a database-backed test
# joins the run it fails during setup, before a single assertion executes.
#
# Setting a module to None tells Django to create that app's tables from its
# current models, which is what the test database wants anyway: these tests
# assert on model behaviour, never on migration history.
MIGRATION_MODULES = {
    "users": None,
    "infrastructure": None,
    "emulations": None,
    "logs": None,
    "workflows": None,
    "ai": None,
    "playbooks": None,
    "authored_detections": None,
}

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "apps.users",
    "apps.infrastructure",
    "apps.emulations",
    "apps.metrics",
    "apps.guardrails",
    "apps.threatintel",
    "apps.workflows",
    "apps.playbooks",
    "apps.authored_detections",
]
