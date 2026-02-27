"""
ASGI config for the MayaTrail backend project.

Exposes the ASGI callable as a module-level variable named ``application``.
Required for async-capable servers (e.g. Daphne, Uvicorn).
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")

application = get_asgi_application()
