"""
URL routing for the infrastructure app.

Mounted at /api/stacks/ in config/urls.py.
Uses DRF DefaultRouter which generates the standard CRUD routes plus
any @action routes defined on the ViewSet.
"""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import StackViewSet

router = DefaultRouter()
router.register(r"", StackViewSet, basename="stack")

urlpatterns = [
    path("", include(router.urls)),
]
