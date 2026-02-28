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
