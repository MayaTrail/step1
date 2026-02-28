"""
Root URL configuration for the MayaTrail backend.

All application routers are mounted here under the /api/ prefix.
Django admin is available at /admin/.
"""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/auth/", include("apps.users.urls")),
    path("api/stacks/", include("apps.infrastructure.urls")),
    path("api/simulations/", include("apps.simulations.urls")),
    path("api/logs/", include("apps.logs.urls")),
]
