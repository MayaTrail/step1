"""
URL routing for the simulations app.

Mounted at /api/simulations/ in config/urls.py.
"""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import SimulationRunViewSet

router = DefaultRouter()
router.register(r"", SimulationRunViewSet, basename="simulation")

urlpatterns = [
    path("", include(router.urls)),
]
