"""
URL routing for the authored_detections app.

Mounted at /api/detections/authored/ in config/urls.py.

Route ordering: the literal 'generate/' and 'validate/' routes come before the
'<uuid:pk>/' routes. The uuid converter would not match those words anyway, but
the ordering matches the convention elsewhere and survives a looser converter.
"""

from django.urls import path

from .views import (
    AuthoredDetectionDetailView,
    AuthoredDetectionListCreateView,
    DetectionExportView,
    DetectionGenerateView,
    DetectionValidateAdhocView,
    DetectionValidateSavedView,
)

app_name = "authored_detections"

urlpatterns = [
    path("", AuthoredDetectionListCreateView.as_view(), name="list-create"),
    path("generate/", DetectionGenerateView.as_view(), name="generate"),
    path("validate/", DetectionValidateAdhocView.as_view(), name="validate-adhoc"),
    path("<uuid:pk>/", AuthoredDetectionDetailView.as_view(), name="detail"),
    path("<uuid:pk>/validate/", DetectionValidateSavedView.as_view(), name="validate"),
    path("<uuid:pk>/export/", DetectionExportView.as_view(), name="export"),
]
