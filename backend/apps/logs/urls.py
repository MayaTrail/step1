"""
URL routing for the logs app.

Mounted at /api/logs/ in config/urls.py.
"""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import LogEntryViewSet

router = DefaultRouter()
router.register(r"", LogEntryViewSet, basename="log")

urlpatterns = [
    path("", include(router.urls)),
]
