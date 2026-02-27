"""
WSGI config for the MayaTrail backend project.

Exposes the WSGI callable as a module-level variable named ``application``.
Used by gunicorn in production and the Django development server.
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")

application = get_wsgi_application()
