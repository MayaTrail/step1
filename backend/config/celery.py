"""
Celery application instance for MayaTrail backend.

Autodiscovers tasks from all INSTALLED_APPS.  The broker and result
backend URLs are read from Django settings which in turn use
python-decouple to pull them from the environment.
"""

import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")

app = Celery("mayatrail")

# Read configuration from Django settings using the CELERY_ namespace prefix.
app.config_from_object("django.conf:settings", namespace="CELERY")

# Automatically discover tasks.py modules in every installed app.
app.autodiscover_tasks()

# Route infrastructure stack tasks (deploy/destroy/refresh/preview) to the
# enterprise queue.  Pulumi is only installed in the enterprise worker image
# (Dockerfile.worker), and that worker consumes --queues=enterprise.  Without
# this route these tasks would land on the default queue, which has no consumer,
# so a Destroy/Deploy triggered from the Stacks page would never run.  The
# emulation tasks already set queue="enterprise" explicitly at call time.
app.conf.task_routes = {
    "infrastructure.*": {"queue": "enterprise"},
}
