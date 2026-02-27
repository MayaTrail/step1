"""
Config package init — ensures the Celery app is loaded when Django starts
so that @shared_task decorators in all apps are properly registered.
"""

from .celery import app as celery_app  # noqa: F401

__all__ = ["celery_app"]
